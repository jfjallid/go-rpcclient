// MIT License
//
// # Copyright (c) 2025 Jimmy Fjällid
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"sort"

	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc/mssamr"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/golog"
	"golang.org/x/term"
)

var (
	scanner          *bufio.Scanner
	handlers         = make(map[string]interface{})
	cleanupCallbacks = make([]func(*shell), 0)
	helpFunctions    = make(map[int]func(*shell))
)

type shell struct {
	options                 *localOptions
	dcip                    string
	prompt                  string
	lcwd                    string
	rcwd                    string
	authenticated           bool
	nullSession             bool
	t                       *term.Terminal
	share                   string
	binds                   map[string]interface{}
	files                   []*smb.File
	samrHandles             map[string]*mssamr.SamrHandle
	samrDomainIds           map[string]*msdtyp.SID
	samrNetbiosDomain       string
	regHiveHandles          map[byte][]byte
	regOpenCreateKeyOptions uint32
	verbose                 bool
	helpMapKeys             []int // Ordered list of keys for the helpFunctions map
}

const (
	OpenConn          = "open"
	Login             = "login"
	LoginHash         = "login_hash"
	LoginKrb          = "login_krb"
	Logout            = "logout"
	CloseConn         = "close"
	ExitShell         = "exit"
	ToggleVerboseMode = "toggleverbose"
)

var usageMap = map[string]string{
	OpenConn:          OpenConn + " <host> [port]",
	Login:             Login + "[domain/username] [passwd]",
	LoginHash:         LoginHash + "[domain/username] [nthash]",
	LoginKrb:          LoginKrb + "[domain/username] [pw] [spn]",
	Logout:            Logout,
	CloseConn:         CloseConn,
	ExitShell:         ExitShell,
	ToggleVerboseMode: ToggleVerboseMode,
}

var descriptionMap = map[string]string{
	OpenConn:          "Opens a new SMB connection against the target host/port",
	Login:             "Logs into the current SMB connection, no parameters for NULL connection",
	LoginHash:         "Logs into the current SMB connection using the password hashes",
	LoginKrb:          "Logs into the current SMB connection using Kerberos. If nothing specified, checks for CCACHE if SPN is not specified, a hostname must have been used to open the connection.",
	Logout:            "Ends the current SMB session but keeps the connection",
	CloseConn:         "Closes the current SMB connection",
	ExitShell:         "Terminates the server process (and this session)",
	ToggleVerboseMode: "Toggle verbose outprints",
}

// Combination of all usage keys
var allKeys []string

var generalUsageKeys = []string{
	OpenConn,
	Login,
	LoginHash,
	LoginKrb,
	Logout,
	CloseConn,
	ExitShell,
	ToggleVerboseMode,
}

func completer(line string) (completions []string) {
	for _, key := range allKeys {
		if strings.HasPrefix(key, line) {
			completions = append(completions, key)
		}
	}
	return
}

func (self *shell) showCustomHelpFunc(usageWidth int, heading string, usageKeys []string) {
	self.printf("[%s]\n", heading)
	for _, key := range usageKeys {
		usage, usageExists := usageMap[key]
		description, descriptionExists := descriptionMap[key]
		if !usageExists {
			usage = key
		}
		if !descriptionExists {
			description = "No description available"
		}
		self.printf("  %-*s %s\n", usageWidth, usage, description)
	}
}

func (self *shell) getConfirmation(s string) bool {
	self.t.SetPrompt("")
	defer self.t.SetPrompt(self.prompt)

	self.printf("%s [y/n]: ", s)
	response, err := self.t.ReadLine()
	if err != nil {
		self.println(err)
		return false
	}
	response = strings.ToLower(strings.TrimSpace(response))
	if response == "y" || response == "yes" {
		return true
	}
	return false
}

func (self *shell) getInput(heading, prompt string) (input string, err error) {
	self.t.SetPrompt("")
	defer self.t.SetPrompt(self.prompt)
	self.t.SetPrompt(prompt)
	self.println(heading)
	input, err = self.t.ReadLine()
	if err != nil {
		self.printf("Error reading from stdin: %s\n", err)
		return
	}
	return
}

func parseArgs(input string) []string {
	var args []string
	var currentArg string
	inQuotes := false
	input = strings.TrimSpace(input)
	// Handle escaped backslashes which is not required in interactive mode
	input = strings.ReplaceAll(input, "\\\\", "\\")

	for _, char := range input {
		switch char {
		case ' ':
			if inQuotes {
				currentArg += string(char)
			} else {
				if currentArg != "" {
					args = append(args, currentArg)
					currentArg = ""
				}
			}
		case '"', '\'':
			inQuotes = !inQuotes
			if !inQuotes {
				//currentArg += string(char) // Keep quotes?
				args = append(args, currentArg)
				currentArg = ""
			}
		default:
			currentArg += string(char)
		}
	}

	if currentArg != "" {
		args = append(args, currentArg)
	}

	return args
}

func parseNumericArg(s string, numType any) (val any, err error) {
	hexVal := strings.HasPrefix(s, "0x")
	_, ok := numType.(uint32)
	if ok {
		var v uint64
		if hexVal {
			v, err = strconv.ParseUint(s[2:], 16, 32)
		} else {
			v, err = strconv.ParseUint(s, 10, 32)
		}
		val = uint32(v)
		return
	}
	_, ok = numType.(uint64)
	if ok {
		if hexVal {
			val, err = strconv.ParseUint(s[2:], 16, 64)
		} else {
			val, err = strconv.ParseUint(s, 10, 64)
		}
		return
	}
	return
}

func toggleVerboseMode(self *shell, argArr interface{}) {
	if self.verbose {
		self.verbose = false
		self.println("Verbose mode deactivated!")
		return
	}
	self.println("Verbose mode activated!")
	self.verbose = true
}

func newShell(args *connArgs) *shell {
	o := args.opts
	s := shell{
		options:        o,
		dcip:           args.dcIP,
		prompt:         "# ",
		rcwd:           string(filepath.Separator),
		share:          "IPC$",
		binds:          make(map[string]interface{}),
		samrHandles:    make(map[string]*mssamr.SamrHandle),
		samrDomainIds:  make(map[string]*msdtyp.SID),
		regHiveHandles: make(map[byte][]byte),
	}
	if !o.smbOptions.ManualLogin {
		s.authenticated = true
	}
	if o.noInitialCon {
		// Failed initial network connection or provided none
		o.c = nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		log.Errorln(err)
		return nil
	}
	s.lcwd = cwd
	//NOTE strings must be lower case
	handlers["help"] = showHelpFunc
	handlers["?"] = showHelpFunc
	handlers[ToggleVerboseMode] = toggleVerboseMode
	handlers[OpenConn] = openConnectionFunc
	handlers[CloseConn] = closeConnectionFunc
	handlers[Login] = loginFunc
	handlers[LoginHash] = loginHashFunc
	handlers["login_kerberos"] = loginKerberosFunc // Extra alias
	handlers[LoginKrb] = loginKerberosFunc
	handlers[Logout] = logoutFunc

	// Order help functions
	s.helpMapKeys = make([]int, 0, len(helpFunctions))
	for k := range helpFunctions {
		s.helpMapKeys = append(s.helpMapKeys, k)
	}
	sort.Ints(s.helpMapKeys)

	return &s
}

func showHelpFunc(self *shell, args interface{}) {
	self.showCustomHelpFunc(40, "General commands", generalUsageKeys)
	self.println()
	for _, i := range self.helpMapKeys {
		fn := helpFunctions[i]
		fn(self)
		self.println()
	}
}

func openConnectionFunc(self *shell, argArr interface{}) {
	var err error
	usage := "Usage: " + usageMap[OpenConn]
	if self.options.c != nil {
		self.println("Closing existing connection first")
		closeConnection(self)
		self.options.c = nil
	}
	args := argArr.([]string)
	if len(args) < 1 {
		self.println("Invalid arguments. Expected host and optionally a port parameter")
		self.println(usage)
		return
	}
	host := args[0]
	port := 445
	if len(args) > 1 {
		portStr := args[1]
		port, err = strconv.Atoi(portStr)
		if err != nil {
			self.printf("Failed to parse port as number: %s\n", err)
			self.println(usage)
			return
		}
		if port < 1 || port > 65535 {
			self.println("Invalid port!")
			self.println(usage)
			return
		}
	}

	self.options.smbOptions.Host = host
	self.options.smbOptions.Port = port
	self.options.smbOptions.Initiator = nil
	self.options.smbOptions.ManualLogin = true
	self.options.c, err = smb.NewConnection(*self.options.smbOptions)
	if err != nil {
		self.println(err)
		self.options.c = nil
		return
	}
	self.printf("Connected to %s:%d\n", host, port)
}

func closeConnection(self *shell) {
	if self.authenticated {
		logout(self)
	}
	self.options.c.Close()
	self.options.c = nil
	return
}

func closeConnectionFunc(self *shell, argArr interface{}) {
	if self.options.c == nil {
		self.println("No connection open")
		return
	}
	closeConnection(self)
	return
}

func executeLogin(self *shell) {
	err := self.options.c.SessionSetup()
	if err != nil {
		self.println(err)
		return
	}
	self.authenticated = true
	self.nullSession = self.options.c.IsNullSession()
	authUsername := self.options.c.GetAuthUsername()
	self.printf("[+] Login successful as %s\n", authUsername)
	return
}

func loginFunc(self *shell, argArr interface{}) {
	if self.options.c == nil {
		self.println("Open a connection before attempting to login")
		return
	}

	err := logout(self)
	if err != nil {
		self.println(err)
		return
	}

	args := argArr.([]string)
	if len(args) < 1 {
		err = self.options.c.SetInitiator(&spnego.NTLMInitiator{
			NullSession: true,
		})
	} else {
		userdomain := args[0]
		domain := ""
		username := ""
		localUser := false
		parts := strings.Split(userdomain, "/")
		if len(parts) > 1 {
			domain = parts[0]
			username = parts[1]
		} else {
			username = parts[0]
			localUser = true
		}

		pass := ""
		if len(args) > 1 {
			pass = args[1]
		} else {
			self.printf("Enter password: ")
			passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			self.println()
			if err != nil {
				self.println(err)
				return
			}
			pass = string(passBytes)
		}

		err = self.options.c.SetInitiator(&spnego.NTLMInitiator{
			User:      username,
			Password:  pass,
			Domain:    domain,
			LocalUser: localUser,
		})
	}

	if err != nil {
		self.println(err)
		return
	}

	executeLogin(self)
}

func loginHashFunc(self *shell, argArr interface{}) {
	if self.options.c == nil {
		self.println("Open a connection before attempting to login")
		return
	}

	err := logout(self)
	if err != nil {
		self.println(err)
		return
	}

	args := argArr.([]string)
	if len(args) < 1 {
		err = self.options.c.SetInitiator(&spnego.NTLMInitiator{
			NullSession: true,
		})
	} else {
		userdomain := args[0]
		domain := ""
		username := ""
		localUser := false
		parts := strings.Split(userdomain, "/")
		if len(parts) > 1 {
			domain = parts[0]
			username = parts[1]
		} else {
			username = parts[0]
			localUser = true
		}

		var hashBytes []byte
		var hash string

		if len(args) > 1 {
			hash = args[1]
		} else {
			self.printf("Enter NT Hash (hex): ")
			hashStringBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			self.println()
			if err != nil {
				self.println(err)
				return
			}
			hash = string(hashStringBytes)
		}
		hashBytes, err = hex.DecodeString(hash)
		if err != nil {
			self.println(err)
			return
		}

		err = self.options.c.SetInitiator(&spnego.NTLMInitiator{
			User:      username,
			Hash:      hashBytes,
			Domain:    domain,
			LocalUser: localUser,
		})
	}

	if err != nil {
		self.println(err)
		return
	}

	executeLogin(self)
}

func loginKerberosFunc(self *shell, argArr interface{}) {
	if self.options.c == nil {
		self.println("Open a connection before attempting to login")
		return
	}

	err := logout(self)
	if err != nil {
		self.println(err)
		return
	}

	args := argArr.([]string)
	if len(args) < 1 {
		spn := ""
		ip := net.ParseIP(self.options.smbOptions.Host)
		if ip != nil {
			// Ask for SPN
			self.printf("Enter SPN (cifs/<hostname>) ")
			input, err := self.t.ReadLine()
			if err != nil {
				self.println(err)
				return
			}
			self.println()
			spn = input
		} else {
			spn = "cifs/" + self.options.smbOptions.Host
		}
		self.options.c.SetInitiator(&spnego.KRB5Initiator{SPN: spn, DCIP: self.dcip})
	} else {
		userdomain := args[0]
		domain := ""
		username := ""
		parts := strings.Split(userdomain, "/")
		if len(parts) > 1 {
			domain = parts[0]
			username = parts[1]
		} else {
			self.println("Invalid username")
			return
		}

		pass := ""
		spn := ""

		ip := net.ParseIP(self.options.smbOptions.Host)
		if len(args) > 2 {
			pass = args[1]
			spn = args[2]
		} else if len(args) > 1 {
			pass = args[1]
			// Check if host is a hostname or ip
			if ip == nil {
				spn = "cifs/" + self.options.smbOptions.Host
			} else {
				self.printf("Enter SPN (cifs/<hostname>) ")
				input, err := self.t.ReadLine()
				if err != nil {
					self.println(err)
					return
				}
				self.println()
				spn = input
			}
		} else {
			self.printf("Enter password: ")
			passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			self.println()
			if err != nil {
				self.println(err)
				return
			}
			pass = string(passBytes)
			// Check if host is a hostname or ip
			if ip == nil {
				spn = "cifs/" + self.options.smbOptions.Host
			} else {
				self.printf("Enter SPN (cifs/<hostname>) ")
				input, err := self.t.ReadLine()
				if err != nil {
					self.println(err)
					return
				}
				self.println()
				spn = input
			}
		}

		err = self.options.c.SetInitiator(&spnego.KRB5Initiator{
			User:     username,
			Password: pass,
			Domain:   domain,
			SPN:      spn,
			DCIP:     self.dcip,
		})
	}

	if err != nil {
		self.println(err)
		return
	}

	executeLogin(self)
}

func closeAllBinds(self *shell) error {
	// Do some cleanup before logging out
	// Call registred cleanup functions
	for _, fn := range cleanupCallbacks {
		fn(self)
	}
	for i, _ := range self.binds {
		delete(self.binds, i)
	}
	for i, _ := range self.files {
		self.files[i].CloseFile()
	}
	self.files = []*smb.File{}

	return nil
}

func logout(self *shell) error {
	if !self.authenticated {
		return nil
	}
	closeAllBinds(self)
	self.rcwd = ""
	self.lcwd = ""
	self.authenticated = false
	return self.options.c.Logoff()
}

func logoutFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	if self.options.c == nil {
		return
	}

	logout(self)
	return
}

func longestCommonPrefix(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	prefix := strs[0]
	for _, str := range strs[1:] {
		for strings.Index(str, prefix) != 0 {
			prefix = prefix[:len(prefix)-1]
			if prefix == "" {
				return ""
			}
		}
	}
	return prefix
}

func (self *shell) cmdloop() {
	//allKeys = []string{}
	allKeys = append(allKeys, generalUsageKeys...)
	fmt.Println("Welcome to the interactive shell!\nType 'help' for a list of commands")

	self.t = term.NewTerminal(os.Stdin, self.prompt)
	// Try to get the terminal size
	width, height, err := term.GetSize(int(os.Stdin.Fd()))
	if err == nil {
		err = self.t.SetSize(width, height)
		if err != nil {
			self.printf("Failed to set terminal size: %s", err)
		}
	}
	if useRawTerminal {
		// Unfortunately we can't capture signals like ctrl-c or ctrl-d in RawMode
		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			self.println(err)
			return
		}
		defer term.Restore(int(os.Stdin.Fd()), oldState)

		self.t.AutoCompleteCallback = func(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
			if key == '\t' {
				cmd := line[:pos]
				args := line[pos:]
				completions := completer(cmd)
				if len(completions) > 0 {
					commonPrefix := longestCommonPrefix(completions)
					if len(commonPrefix) > pos {
						newLine = commonPrefix + args
						newPos = len(commonPrefix)
						ok = true
						return
					} else {
						self.println()
						for _, completion := range completions {
							self.printf("%s - %s\n", usageMap[completion], descriptionMap[completion])
						}
						return line, pos, true
					}
				}
			}
			return
		}
	}

	// Disable logging from smb library as it interferes with the terminal emulation output
	golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	golog.Set("github.com/jfjallid/go-smb/msdtyp", "msdtyp", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	log.SetLogLevel(golog.LevelNone)

	defer self.options.c.TreeDisconnect(self.share)
	defer closeAllBinds(self)

OuterLoop:
	for {
		input, err := self.t.ReadLine()
		if err != nil {
			if err == io.EOF {
				break OuterLoop
			}
			self.printf("Error reading from stdin: %s\n", err)
			return
		}
		input = strings.TrimSpace(input)
		if strings.Compare(input, "exit") == 0 {
			break OuterLoop
		}
		cmd, rest, found := strings.Cut(input, " ")
		var args []string
		if found {
			args = parseArgs(rest)
		}
		cmd = strings.ToLower(cmd)
		if val, ok := handlers[cmd]; ok {
			fn, ok := val.(func(*shell, interface{}))
			if !ok {
				self.println("Wrong function signature for registered handler")
			} else {
				fn(self, args)
			}
		} else if cmd != "" {
			self.printf("Unknown command: (%s)\n", input)
		}
	}
	self.t.SetPrompt("")
	self.println("Bye!")
}
