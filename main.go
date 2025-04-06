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
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	rundebug "runtime/debug"

	"golang.org/x/net/proxy"
	"golang.org/x/term"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/golog"
)

var log = golog.Get("")
var release string = "0.1.0"
var flags *flag.FlagSet

var helpMsg = `
    Usage: ` + os.Args[0] + ` <service> [options]

    <service>:
          --lsad                Interact with the Local Security Authority
          --samr                Interact with the Security Account Manager
          --wkst                Interact with the Workstation Service
          --srvs                Interact with the Server Service
      -i, --interactive         Launch interactive mode
      ` + helpConnectionOptions + `
`
var helpConnectionOptions = `
    General options:
          --host <ip/hostname>  Hostname or ip address of remote server. Must be hostname when using Kerberos
      -P, --port [port]         SMB Port (default 445)
      -d, --domain [name/fqdn]  Domain name to use for login
      -u, --user   [string]     Username. Not required for Kerberos auth
      -p, --pass   [string]     Password. Prompted if not specified
      -n, --no-pass             Disable password prompt and send no credentials
          --hash   [hex]        Hex encoded NT Hash for user password
          --local               Authenticate as a local user instead of domain user
          --null                Attempt null session authentication
      -k, --kerberos            Use Kerberos authentication. (KRB5CCNAME will be checked on Linux)
          --dc-ip     [ip]      Optionally specify ip of KDC when using Kerberos authentication
          --target-ip [ip]      Optionally specify ip of target when using Kerberos authentication
          --aes-key   [hex]     Use a hex encoded AES128/256 key for Kerberos authentication
      -t, --timeout   [int]     Dial timeout in seconds (default 5)
          --relay               Start an SMB listener that will relay incoming
                                NTLM authentications to the remote server and
                                use that connection. NOTE that this forces SMB 2.1
                                without encryption.
          --relay-port [port]   Listening port for relay (default 445)
          --socks-host [target] Establish connection via a SOCKS5 proxy server
          --socks-port [port]   SOCKS5 proxy port (default 1080)
          --noenc               Disable smb encryption
          --smb2                Force smb 2.1
          --debug               Enable debug logging
          --verbose             Enable verbose logging
      -v, --version             Show version
`

// Custom types to help with argument parsing and validation
type ridList []uint32
type nameList []string
type rightsList []string
type SID struct {
	s string
	v *msdtyp.SID
}

func (n *ridList) String() string {
	return fmt.Sprintf("%v", *n)
}

func (n *ridList) Set(value string) error {
	parts := strings.Split(value, ",")
	for i, _ := range parts {
		str := strings.TrimSpace(parts[i])
		if strings.Contains(str, " ") {
			return fmt.Errorf("Rids should be separated by comma, not by space.")
		}
		if str != "" {
			v, err := strconv.ParseUint(str, 10, 32)
			if err != nil {
				return err
			}
			*n = append(*n, uint32(v))
		}
	}

	return nil
}

func (n *nameList) String() string {
	return fmt.Sprintf("%v", *n)
}

func (n *nameList) Set(value string) error {
	parts := strings.Split(value, ",")
	for i, _ := range parts {
		str := strings.TrimSpace(parts[i])
		if strings.Contains(str, " ") {
			return fmt.Errorf("names should be separated by comma, not by space.")
		}
		if str != "" {
			*n = append(*n, str)
		}
	}

	return nil
}

func (n *rightsList) String() string {
	return fmt.Sprintf("%v", *n)
}

func (n *rightsList) Set(value string) error {
	parts := strings.Split(value, ",")
	for i, _ := range parts {
		str := strings.TrimSpace(parts[i])
		if strings.Contains(str, " ") {
			return fmt.Errorf("Rights should be separated by comma, not by space.")
		}
		if str != "" {
			*n = append(*n, str)
		}
	}

	return nil
}

func (n *SID) String() string {
	return n.s
}

func (n *SID) Set(value string) error {
	// Check if valid SID
	sid, err := msdtyp.ConvertStrToSID(value)
	n.s = value
	n.v = sid
	return err
}

func (n *SID) Get() *msdtyp.SID {
	return n.v
}

func isFlagSet(name string) bool {
	found := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func printVersion() {
	fmt.Printf("Version: %s\n", release)
	bi, ok := rundebug.ReadBuildInfo()
	if !ok {
		log.Errorln("Failed to read build info to locate version imported modules")
	}
	for _, m := range bi.Deps {
		fmt.Printf("Package: %s, Version: %s\n", m.Path, m.Version)
	}
	return
}

type localOptions struct {
	c            *smb.Connection
	noInitialCon bool
	smbOptions   *smb.Options
}

type connArgs struct {
	host        string
	username    string
	password    string
	hash        string
	domain      string
	socksIP     string
	targetIP    string
	dcIP        string
	aesKey      string
	port        int
	dialTimeout int
	socksPort   int
	relayPort   int
	noEnc       bool
	forceSMB2   bool
	localUser   bool
	nullSession bool
	relay       bool
	noPass      bool
	kerberos    bool
	interactive bool
	opts        *localOptions
}

type generalArgs struct {
	debug   bool
	version bool
	verbose bool
	samr    bool
	lsad    bool
	srvs    bool
	wkst    bool
}

type userArgs struct {
	connArgs
	generalArgs
	// LSAD actions
	enumAccounts  bool
	enumRights    bool
	addRights     bool
	removeRights  bool
	getDomainInfo bool
	purgeRights   bool
	// SAMR actions
	enumDomains          bool
	enumUsers            bool
	listGroups           bool
	listLocalAdmins      bool
	listGroupMembers     bool
	addToLocalGroup      bool
	removeFromLocalGroup bool
	addLocalAdmin        bool
	createUser           bool
	deleteUser           bool
	queryUser            bool
	resetUserPassword    bool
	changeUserPassword   bool
	translateSid         bool
	lookupSid            bool
	lookupRids           bool
	lookupNames          bool
	lookupDomain         bool
	// WKST actions
	enumSessions bool
	// SRVS actions
	// enumSessions
	enumShares    bool
	getServerInfo bool
	// arguments
	sid                 SID
	rights              rightsList
	systemRights        bool
	rid                 uint64
	userRid             uint64
	rids                ridList
	localDomain         string
	name                string
	userPassword        string
	netbiosComputerName string
	alias               bool
	level               int
	limit               int
	oldNTHash           string
	newPass             string
	names               nameList
}

func addConnectionArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.StringVar(&argv.host, "host", "", "")
	flagSet.StringVar(&argv.username, "u", "", "")
	flagSet.StringVar(&argv.username, "user", "", "")
	flagSet.StringVar(&argv.password, "p", "", "")
	flagSet.StringVar(&argv.password, "pass", "", "")
	flagSet.StringVar(&argv.hash, "hash", "", "")
	flagSet.StringVar(&argv.domain, "d", "", "")
	flagSet.StringVar(&argv.domain, "domain", "", "")
	flagSet.IntVar(&argv.port, "P", 445, "")
	flagSet.IntVar(&argv.port, "port", 445, "")
	flagSet.BoolVar(&argv.debug, "debug", false, "")
	flagSet.BoolVar(&argv.verbose, "verbose", false, "")
	flagSet.BoolVar(&argv.noEnc, "noenc", false, "")
	flagSet.BoolVar(&argv.forceSMB2, "smb2", false, "")
	flagSet.BoolVar(&argv.localUser, "local", false, "")
	flagSet.IntVar(&argv.dialTimeout, "t", 5, "")
	flagSet.IntVar(&argv.dialTimeout, "timeout", 5, "")
	flagSet.BoolVar(&argv.nullSession, "null", false, "")
	flagSet.BoolVar(&argv.relay, "relay", false, "")
	flagSet.IntVar(&argv.relayPort, "relay-port", 445, "")
	flagSet.StringVar(&argv.socksIP, "socks-host", "", "")
	flagSet.IntVar(&argv.socksPort, "socks-port", 1080, "")
	flagSet.BoolVar(&argv.noPass, "no-pass", false, "")
	flagSet.BoolVar(&argv.noPass, "n", false, "")
	flagSet.BoolVar(&argv.kerberos, "k", false, "")
	flagSet.BoolVar(&argv.kerberos, "kerberos", false, "")
	flagSet.StringVar(&argv.targetIP, "target-ip", "", "")
	flagSet.StringVar(&argv.dcIP, "dc-ip", "", "")
	flagSet.StringVar(&argv.aesKey, "aes-key", "", "")
}

func addSamrArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.BoolVar(&argv.enumDomains, "enum-domains", false, "")
	flagSet.BoolVar(&argv.enumUsers, "enum-users", false, "")
	flagSet.BoolVar(&argv.lookupDomain, "lookup-domain", false, "")
	flagSet.BoolVar(&argv.lookupRids, "lookup-rids", false, "")
	flagSet.BoolVar(&argv.lookupNames, "lookup-names", false, "")
	flagSet.BoolVar(&argv.lookupSid, "lookup-sid", false, "")
	flagSet.BoolVar(&argv.addToLocalGroup, "add-member", false, "")
	flagSet.BoolVar(&argv.removeFromLocalGroup, "remove-member", false, "")
	flagSet.BoolVar(&argv.listLocalAdmins, "list-admins", false, "")
	flagSet.BoolVar(&argv.listGroupMembers, "list-members", false, "")
	flagSet.BoolVar(&argv.addLocalAdmin, "make-admin", false, "")
	flagSet.BoolVar(&argv.createUser, "create-user", false, "")
	flagSet.BoolVar(&argv.changeUserPassword, "change-password", false, "")
	flagSet.BoolVar(&argv.resetUserPassword, "reset-password", false, "")
	flagSet.BoolVar(&argv.listGroups, "list-groups", false, "")
	flagSet.BoolVar(&argv.deleteUser, "delete-user", false, "")
	flagSet.BoolVar(&argv.queryUser, "query-user", false, "")
	flagSet.BoolVar(&argv.translateSid, "translate-sid", false, "")
	flagSet.StringVar(&argv.localDomain, "local-domain", "", "")
	flagSet.Uint64Var(&argv.rid, "rid", 0, "")
	flagSet.Uint64Var(&argv.userRid, "user-rid", 0, "")
	flagSet.Var(&argv.rids, "rids", "")
	flagSet.StringVar(&argv.name, "name", "", "")
	flagSet.StringVar(&argv.userPassword, "user-pass", "", "")
	flagSet.StringVar(&argv.netbiosComputerName, "netbios", "", "")
	flagSet.BoolVar(&argv.alias, "alias", false, "")
	flagSet.IntVar(&argv.limit, "limit", 50, "")
	flagSet.Var(&argv.sid, "sid", "")
	flagSet.StringVar(&argv.oldNTHash, "old-hash", "", "")
	flagSet.StringVar(&argv.newPass, "new-pass", "", "")
	flagSet.Var(&argv.names, "names", "")
}

func addLsadArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.BoolVar(&argv.enumAccounts, "enum-accounts", false, "")
	flagSet.BoolVar(&argv.enumRights, "enum-rights", false, "")
	flagSet.BoolVar(&argv.addRights, "add", false, "")
	flagSet.BoolVar(&argv.removeRights, "remove", false, "")
	flagSet.BoolVar(&argv.purgeRights, "purge", false, "")
	flagSet.BoolVar(&argv.getDomainInfo, "getinfo", false, "")
	flagSet.Var(&argv.sid, "sid", "")
	flagSet.Var(&argv.rights, "rights", "")
	flagSet.BoolVar(&argv.systemRights, "system", false, "")
}

func addWkstArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.BoolVar(&argv.enumSessions, "enum-sessions", false, "")
	flagSet.IntVar(&argv.level, "level", 0, "")
}

func addSrvsArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.BoolVar(&argv.enumSessions, "enum-sessions", false, "")
	flagSet.BoolVar(&argv.enumShares, "enum-shares", false, "")
	flagSet.BoolVar(&argv.getServerInfo, "get-info", false, "")
	flagSet.IntVar(&argv.level, "level", 0, "")
}

func handleArgs() (action byte, argv *userArgs, err error) {
	flags = flag.NewFlagSet("", flag.ExitOnError)
	flags.Usage = func() {
		fmt.Println(helpMsg)
		os.Exit(0)
	}
	argv = &userArgs{}
	flags.BoolVar(&argv.samr, "samr", false, "")
	flags.BoolVar(&argv.lsad, "lsad", false, "")
	flags.BoolVar(&argv.srvs, "srvs", false, "")
	flags.BoolVar(&argv.wkst, "wkst", false, "")
	flags.BoolVar(&argv.connArgs.interactive, "i", false, "")
	flags.BoolVar(&argv.connArgs.interactive, "interactive", false, "")
	flags.BoolVar(&argv.version, "v", false, "")
	flags.BoolVar(&argv.version, "version", false, "")

	if len(os.Args) < 2 {
		flags.Usage()
	}

	// Parse only first argument
	err = flags.Parse(os.Args[1:2])
	if err != nil {
		log.Errorf("Here be Err: %s\n", err)
		return
	}
	if argv.version {
		return
	}

	numAction := 0
	if argv.samr {
		numAction++
	}
	if argv.lsad {
		numAction++
	}
	if argv.srvs {
		numAction++
	}
	if argv.wkst {
		numAction++
	}
	if argv.interactive {
		numAction++
	}
	if numAction != 1 {
		fmt.Println("Must specify ONE action. No more, no less")
		flags.Usage()
	}
	if argv.interactive {
		action = 1
	} else if argv.lsad {
		flags.Usage = func() {
			fmt.Println(helpLsadOptions)
			os.Exit(0)
		}
		addLsadArgs(flags, argv)
		action = 2
	} else if argv.samr {
		flags.Usage = func() {
			fmt.Println(helpSamrOptions)
			os.Exit(0)
		}
		addSamrArgs(flags, argv)
		action = 3
	} else if argv.wkst {
		flags.Usage = func() {
			fmt.Println(helpWkstOptions)
			os.Exit(0)
		}
		addWkstArgs(flags, argv)
		action = 4
	} else if argv.srvs {
		flags.Usage = func() {
			fmt.Println(helpSrvsOptions)
			os.Exit(0)
		}
		addSrvsArgs(flags, argv)
		action = 5
	}

	addConnectionArgs(flags, argv)
	err = flags.Parse(os.Args[1:])
	if err != nil {
		log.Errorf("error: %s\n", err)
		return
	}

	return
}

func makeConnection(args *connArgs) (err error) {
	var hashBytes []byte
	var aesKeyBytes []byte
	if args.hash != "" {
		hashBytes, err = hex.DecodeString(args.hash)
		if err != nil {
			fmt.Println("Failed to decode hash")
			log.Errorln(err)
			return
		}
	}

	if args.aesKey != "" {
		aesKeyBytes, err = hex.DecodeString(args.aesKey)
		if err != nil {
			fmt.Println("Failed to decode aesKey")
			log.Errorln(err)
			return
		}
		if len(aesKeyBytes) != 16 && len(aesKeyBytes) != 32 {
			fmt.Println("Invalid keysize of AES Key")
			return
		}
	}

	if args.noPass {
		args.password = ""
		hashBytes = nil
		aesKeyBytes = nil
	} else {
		if (args.password == "") && (hashBytes == nil) && (aesKeyBytes == nil) {
			if (args.username != "") && (!args.nullSession) {
				// Check if password is already specified to be empty
				if !isFlagSet("P") && !isFlagSet("pass") {
					fmt.Printf("Enter password: ")
					var passBytes []byte
					passBytes, err = term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil {
						log.Errorln(err)
						return
					}
					args.password = string(passBytes)
				}
			}
		}
	}

	args.opts = &localOptions{}
	smbOptions := smb.Options{
		Host:                  args.targetIP,
		Port:                  args.port,
		DisableEncryption:     args.noEnc,
		ForceSMB2:             args.forceSMB2,
		RequireMessageSigning: false,
	}
	args.opts.smbOptions = &smbOptions

	if !args.kerberos && (hashBytes == nil) && (aesKeyBytes == nil) && (args.password == "") && !args.nullSession && args.interactive {
		// Skip login for now
		smbOptions.ManualLogin = true
	}

	if args.kerberos {
		smbOptions.Initiator = &spnego.KRB5Initiator{
			User:     args.username,
			Password: args.password,
			Domain:   args.domain,
			Hash:     hashBytes,
			AESKey:   aesKeyBytes,
			SPN:      "cifs/" + args.host,
			DCIP:     args.dcIP,
		}
	} else {
		smbOptions.Initiator = &spnego.NTLMInitiator{
			User:        args.username,
			Password:    args.password,
			Hash:        hashBytes,
			Domain:      args.domain,
			LocalUser:   args.localUser,
			NullSession: args.nullSession,
		}
	}

	// Only if not using SOCKS
	if args.socksIP == "" {
		smbOptions.DialTimeout, err = time.ParseDuration(fmt.Sprintf("%ds", args.dialTimeout))
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	if args.socksIP != "" {
		var dialSocksProxy proxy.Dialer
		dialSocksProxy, err = proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", args.socksIP, args.socksPort), nil, proxy.Direct)
		if err != nil {
			log.Errorln(err)
			return
		}
		smbOptions.ProxyDialer = dialSocksProxy
	}

	if args.relay {
		smbOptions.RelayPort = args.relayPort
		args.opts.c, err = smb.NewRelayConnection(smbOptions)
	} else {
		args.opts.c, err = smb.NewConnection(smbOptions)
	}
	if err != nil {
		log.Criticalln(err)
		args.opts.noInitialCon = true
		if !args.interactive {
			return
		}
	}

	if args.opts.c.IsSigningRequired() {
		log.Noticeln("[-] Signing is required")
	} else {
		log.Noticeln("[+] Signing is NOT required")
	}

	if !smbOptions.ManualLogin {
		if args.opts.c.IsAuthenticated() {
			log.Noticef("[+] Login successful as %s\n", args.opts.c.GetAuthUsername())
		} else {
			log.Noticeln("[-] Login failed")
			return
		}
	}

	return
}

func main() {
	var err error

	action, args, _ := handleArgs()

	if args.debug {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/msdtyp", "msdtyp", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mslsad", "mslsad", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mssamr", "mssamr", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mswkst", "mswkst", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mssrvs", "mssrvs", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetFlags(golog.LstdFlags | golog.Lshortfile)
		log.SetLogLevel(golog.LevelDebug)
	} else if args.verbose {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/msdtyp", "msdtyp", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mslsad", "mslsad", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mssamr", "mssamr", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mswkst", "mswkst", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mssrvs", "mssrvs", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetLogLevel(golog.LevelInfo)
	} else {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/msdtyp", "msdtyp", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mslsad", "mslsad", golog.LevelNone, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mssamr", "mssamr", golog.LevelNone, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mswkst", "mswkst", golog.LevelNone, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mssrvs", "mssrvs", golog.LevelNone, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
	}

	if args.version {
		printVersion()
		return
	}

	if args.host == "" && args.targetIP == "" {
		log.Errorln("Must specify a hostname or ip")
		flags.Usage()
		return
	}
	if args.host != "" && args.targetIP == "" {
		args.targetIP = args.host
	}

	if args.socksIP != "" && isFlagSet("timeout") {
		log.Errorln("When a socks proxy is specified, --timeout is not supported")
		flags.Usage()
		return
	}

	if args.dialTimeout < 1 {
		log.Errorln("Valid value for the timeout is > 0 seconds")
		return
	}

	switch action {
	case 1:
		err = makeConnection(&args.connArgs)
		if err != nil {
			log.Errorln(err)
			return
		}
		if !args.opts.c.IsAuthenticated() {
			// Login failed
			args.opts.smbOptions.ManualLogin = true
		}
		shell := newShell(&args.connArgs)
		if shell == nil {
			log.Errorln("Failed to start an interactive shell")
			return
		}
		shell.cmdloop()
		return
	case 2:
		err = handleLsaRpc(args)
		if err != nil {
			log.Errorln(err)
			return
		}
	case 3:
		err = handleSamr(args)
		if err != nil {
			log.Errorln(err)
			return
		}
	case 4:
		err = handleWkst(args)
		if err != nil {
			log.Errorln(err)
			return
		}
	case 5:
		err = handleSrvs(args)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	return
}
