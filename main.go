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
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
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
var release string = "0.2.2"
var flags *flag.FlagSet

var helpMsg = `
    Usage: ` + os.Args[0] + ` <service> [options]

    <service>:
          --lsad                Interact with the Local Security Authority
          --samr                Interact with the Security Account Manager
          --wkst                Interact with the Workstation Service
          --srvs                Interact with the Server Service
          --scmr                Interact with the Service Control Manager
          --rrp                 Interact with the Remote Registry
      -i, --interactive         Launch interactive mode
      ` + helpConnectionOptions + `
`
var helpConnectionOptions = `
    General options:
          --host <ip/hostname>   Hostname or ip address of remote server. Must be hostname when using Kerberos
      -P, --port <port>          SMB Port (default 445)
      -d, --domain <name/fqdn>   Domain name to use for login
      -u, --user   <string>      Username. Not required for Kerberos auth
      -p, --pass   <string>      Password. Prompted if not specified
      -n, --no-pass              Disable password prompt and send no credentials
          --hash   <hex>         Hex encoded NT Hash for user password
          --local                Authenticate as a local user instead of domain user
          --null                 Attempt null session authentication
      -k, --kerberos             Use Kerberos authentication. (KRB5CCNAME will be checked on Linux)
          --dc-ip     <ip>       Optionally specify ip of KDC when using Kerberos authentication
          --target-ip <ip>       Optionally specify ip of target when using Kerberos authentication
          --aes-key   <hex>      Use a hex encoded AES128/256 key for Kerberos authentication
          --dns-host <ip[:port]> Override system's default DNS resolver
          --dns-tcp              Force DNS lookups over TCP. Default true when using --socks-host
      -t, --timeout <duration>   Dial timeout specified in 5s, 1m, 10m format (default 5s)
          --relay                Start an SMB listener that will relay incoming
                                 NTLM authentications to the remote server and
                                 use that connection. NOTE that this forces SMB 2.1
                                 without encryption.
          --relay-port <port>    Listening port for relay (default 445)
          --socks-host <target>  Establish connection via a SOCKS5 proxy server
          --socks-port <port>    SOCKS5 proxy port (default 1080)
          --noenc                Disable smb encryption
          --smb2                 Force smb 2.1
          --debug                Enable debug logging
          --verbose              Enable verbose logging
          --resolve-sids         Attempt to translate SIDs using MS-LSAT
      -v, --version              Show version
`

// Custom types to help with argument parsing and validation
type ridList []uint32
type stringList []string
type sidList []SID

type SID struct {
	s string
	v *msdtyp.SID
}
type binaryArg []byte

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

func (n *stringList) String() string {
	return fmt.Sprintf("%v", *n)
}

func (n *stringList) Set(value string) error {
	parts := strings.Split(value, ",")
	for i, _ := range parts {
		str := strings.TrimSpace(parts[i])
		if strings.Contains(str, " ") {
			return fmt.Errorf("List of strings should be separated by comma, not by space.")
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

func (n *binaryArg) String() string {
	return hex.EncodeToString(*n)
}

func (n *binaryArg) Set(value string) error {
	value = strings.TrimPrefix(value, "0x")
	val, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("Invalid hex string for argument")
	}
	*n = val
	return nil
}

func (n *sidList) String() string {
	var sb strings.Builder
	for _, item := range *n {
		fmt.Fprintf(&sb, "%s,", item.s)
	}
	return sb.String()
}

func (n *sidList) Set(value string) error {
	parts := strings.Split(value, ",")
	for i, _ := range parts {
		str := strings.TrimSpace(parts[i])
		if strings.Contains(str, " ") {
			return fmt.Errorf("Sids should be separated by comma, not by space.")
		}
		if str != "" {
			var s SID
			err := s.Set(str)
			if err != nil {
				return fmt.Errorf("Failed to parse SID from user argument: %s", err.Error())
			}
			*n = append(*n, s)
		}
	}

	return nil
}

func (n *sidList) GetStrings() []string {
	res := make([]string, 0)
	for _, item := range *n {
		res = append(res, item.s)
	}
	return res
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
	socksHost   string
	targetIP    string
	dcIP        string
	aesKey      string
	dnsHost     string
	port        int
	dialTimeout time.Duration
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
	dnsTCP      bool
	opts        *localOptions
}

type generalArgs struct {
	debug       bool
	version     bool
	verbose     bool
	samr        bool
	lsad        bool
	srvs        bool
	wkst        bool
	scmr        bool
	rrp         bool
	resolveSids bool
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
	// LSAT actions
	lookupSids  bool
	getUserName bool
	// lookupNames bool
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
	createComputer       bool
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
	enumShares      bool
	getServerInfo   bool
	getFileSecurity bool
	// SCMR actions
	enumServices        bool
	enumServiceConfigs  bool
	getServiceConfig    bool
	getServiceStatus    bool
	changeServiceConfig bool
	startService        bool
	controlService      bool
	createService       bool
	deleteService       bool
	// RRP actions
	getKeyValue    bool
	setKeyValue    bool
	deleteValue    bool
	deleteKey      bool
	createKey      bool
	saveKey        bool
	enumKeys       bool
	enumValues     bool
	getKeyInfo     bool
	getKeySecurity bool
	setKeySecurity bool
	// arguments
	sid                 SID
	sids                sidList
	rights              stringList
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
	names               stringList
	serviceState        uint64
	serviceType         uint64
	serviceStartType    uint64
	serviceErrorControl uint64
	arguments           stringList
	serviceAction       string
	exePath             string
	startName           string
	displayName         string
	key                 string
	stringValue         string
	dwordValue          uint64
	qwordValue          uint64
	binaryValue         binaryArg
	remotePath          string
	ownerSid            SID
	debugPrivilege      bool
	createAndStart      bool
	share               string
	filePath            string
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
	flagSet.DurationVar(&argv.dialTimeout, "t", time.Second*5, "")
	flagSet.DurationVar(&argv.dialTimeout, "timeout", time.Second*5, "")
	flagSet.BoolVar(&argv.nullSession, "null", false, "")
	flagSet.BoolVar(&argv.relay, "relay", false, "")
	flagSet.IntVar(&argv.relayPort, "relay-port", 445, "")
	flagSet.StringVar(&argv.socksHost, "socks-host", "", "")
	flagSet.IntVar(&argv.socksPort, "socks-port", 1080, "")
	flagSet.BoolVar(&argv.noPass, "no-pass", false, "")
	flagSet.BoolVar(&argv.noPass, "n", false, "")
	flagSet.BoolVar(&argv.kerberos, "k", false, "")
	flagSet.BoolVar(&argv.kerberos, "kerberos", false, "")
	flagSet.StringVar(&argv.targetIP, "target-ip", "", "")
	flagSet.StringVar(&argv.dcIP, "dc-ip", "", "")
	flagSet.StringVar(&argv.aesKey, "aes-key", "", "")
	flagSet.StringVar(&argv.dnsHost, "dns-host", "", "")
	flagSet.BoolVar(&argv.dnsTCP, "dns-tcp", false, "")
	flagSet.BoolVar(&argv.resolveSids, "resolve-sids", false, "")

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
	flagSet.BoolVar(&argv.createComputer, "create-computer", false, "")
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
	flagSet.Var(&argv.sids, "sids", "")
	flagSet.Var(&argv.rights, "rights", "")
	flagSet.IntVar(&argv.level, "level", 1, "")
	flagSet.BoolVar(&argv.systemRights, "system", false, "")
	flagSet.BoolVar(&argv.getUserName, "whoami", false, "")
	flagSet.BoolVar(&argv.getUserName, "get-username", false, "")
	flagSet.BoolVar(&argv.lookupSids, "lookup-sids", false, "")
	flagSet.BoolVar(&argv.lookupNames, "lookup-names", false, "")
	flagSet.Var(&argv.names, "names", "")
}

func addWkstArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.BoolVar(&argv.enumSessions, "enum-sessions", false, "")
	flagSet.IntVar(&argv.level, "level", 0, "")
}

func addSrvsArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.BoolVar(&argv.enumSessions, "enum-sessions", false, "")
	flagSet.BoolVar(&argv.enumShares, "enum-shares", false, "")
	flagSet.BoolVar(&argv.getServerInfo, "get-info", false, "")
	flagSet.BoolVar(&argv.getFileSecurity, "get-file-security", false, "")
	flagSet.IntVar(&argv.level, "level", 0, "")
	flagSet.StringVar(&argv.share, "share", "", "")
	flagSet.StringVar(&argv.filePath, "path", "", "")
}

func addScmrArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.BoolVar(&argv.enumServices, "enum-services", false, "")
	flagSet.BoolVar(&argv.enumServiceConfigs, "enum-service-configs", false, "")
	flagSet.BoolVar(&argv.getServiceConfig, "get-service-config", false, "")
	flagSet.BoolVar(&argv.getServiceStatus, "get-service-status", false, "")
	flagSet.BoolVar(&argv.changeServiceConfig, "change-service-config", false, "")
	flagSet.BoolVar(&argv.startService, "start-service", false, "")
	flagSet.BoolVar(&argv.controlService, "control-service", false, "")
	flagSet.BoolVar(&argv.createService, "create-service", false, "")
	flagSet.BoolVar(&argv.deleteService, "delete-service", false, "")
	flagSet.Uint64Var(&argv.serviceType, "service-type", 0x30, "")
	flagSet.Uint64Var(&argv.serviceStartType, "start-type", 0x3, "")
	flagSet.Uint64Var(&argv.serviceErrorControl, "error-control", 0x1, "")
	flagSet.Uint64Var(&argv.serviceState, "service-state", 0x3, "")
	flagSet.StringVar(&argv.name, "name", "", "")
	flagSet.StringVar(&argv.serviceAction, "action", "", "")
	flagSet.Var(&argv.arguments, "args", "")
	flagSet.StringVar(&argv.exePath, "exe-path", "", "")
	flagSet.StringVar(&argv.startName, "start-name", "", "")
	flagSet.StringVar(&argv.userPassword, "start-pass", "", "")
	flagSet.StringVar(&argv.displayName, "display-name", "", "")
	flagSet.BoolVar(&argv.createAndStart, "start", false, "")
}

func addRrpArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.BoolVar(&argv.getKeyValue, "get-value", false, "")
	flagSet.BoolVar(&argv.setKeyValue, "set-value", false, "")
	flagSet.BoolVar(&argv.deleteValue, "delete-value", false, "")
	flagSet.BoolVar(&argv.deleteKey, "delete-key", false, "")
	flagSet.BoolVar(&argv.createKey, "create-key", false, "")
	flagSet.BoolVar(&argv.saveKey, "save-key", false, "")
	flagSet.BoolVar(&argv.enumKeys, "enum-keys", false, "")
	flagSet.BoolVar(&argv.enumValues, "enum-values", false, "")
	flagSet.BoolVar(&argv.getKeyInfo, "get-key-info", false, "")
	flagSet.BoolVar(&argv.getKeySecurity, "get-key-security", false, "")
	flagSet.StringVar(&argv.name, "name", "", "")
	flagSet.StringVar(&argv.key, "key", "", "")
	flagSet.StringVar(&argv.stringValue, "string-val", "", "")
	flagSet.Uint64Var(&argv.dwordValue, "dword-val", 0, "")
	flagSet.Uint64Var(&argv.qwordValue, "qword-val", 0, "")
	flagSet.Var(&argv.binaryValue, "binary-val", "")
	flagSet.StringVar(&argv.remotePath, "remote-path", "", "")
	flagSet.Var(&argv.ownerSid, "owner", "")
	flagSet.BoolVar(&argv.debugPrivilege, "use-debug-privilege", false, "")
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
	flags.BoolVar(&argv.scmr, "scmr", false, "")
	flags.BoolVar(&argv.rrp, "rrp", false, "")
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
	if argv.scmr {
		numAction++
	}
	if argv.rrp {
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
	} else if argv.scmr {
		flags.Usage = func() {
			fmt.Println(helpScmrOptions)
			os.Exit(0)
		}
		addScmrArgs(flags, argv)
		action = 6
	} else if argv.rrp {
		flags.Usage = func() {
			fmt.Println(helpRRPOptions)
			os.Exit(0)
		}
		addRrpArgs(flags, argv)
		action = 7
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
	var p uint64
	// Validate format
	if isFlagSet("dns-host") {
		parts := strings.Split(args.dnsHost, ":")
		if len(parts) < 2 {
			if args.dnsHost != "" {
				args.dnsHost += ":53"
				parts = append(parts, "53")
				log.Infoln("No port number specified for --dns-host so assuming port 53")
			} else {
				fmt.Println("Invalid --dns-host")
				flag.Usage()
				return
			}
		}
		ip := net.ParseIP(parts[0])
		if ip == nil {
			fmt.Println("Invalid --dns-host. Not a valid ip host address")
			flag.Usage()
			return
		}
		p, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			fmt.Printf("Invalid --dns-host. Failed to parse port: %s\n", err)
			return
		}
		if p < 1 {
			fmt.Println("Invalid --dns-host port number")
			flag.Usage()
			return
		}
	}

	if args.dialTimeout < time.Second {
		err = fmt.Errorf("Valid value for the timeout is >= 1 seconds")
		return
	}

	if args.socksHost != "" && args.socksPort < 1 {
		fmt.Println("Invalid --socks-port")
		flag.Usage()
		return
	}

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

	if args.dnsHost != "" {
		protocol := "udp"
		if args.dnsTCP {
			protocol = "tcp"
		}
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: args.dialTimeout,
				}
				return d.DialContext(ctx, protocol, args.dnsHost)
			},
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

	if args.socksHost != "" {
		var dialSocksProxy proxy.Dialer
		dialSocksProxy, err = proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", args.socksHost, args.socksPort), nil, proxy.Direct)
		if err != nil {
			log.Errorln(err)
			return
		}
		smbOptions.ProxyDialer = dialSocksProxy
	}

	if !args.kerberos && (hashBytes == nil) && (aesKeyBytes == nil) && (args.password == "") && !args.nullSession && args.interactive {
		// Skip login for now
		smbOptions.ManualLogin = true
	}

	if args.kerberos {
		smbOptions.Initiator = &spnego.KRB5Initiator{
			User:        args.username,
			Password:    args.password,
			Domain:      args.domain,
			Hash:        hashBytes,
			AESKey:      aesKeyBytes,
			SPN:         "cifs/" + args.host,
			DCIP:        args.dcIP,
			DialTimout:  args.dialTimeout,
			ProxyDialer: smbOptions.ProxyDialer,
			DnsHost:     args.dnsHost,
			DnsTCP:      args.dnsTCP,
			Host:        args.host,
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

	// Set DialTimeout for go-smb
	smbOptions.DialTimeout = args.dialTimeout

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

	if !args.interactive {
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
			golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/msscmr", "msscmr", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
			golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/msrrp", "msrrp", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
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
			golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/msscmr", "msscmr", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
			golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/msrrp", "msrrp", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
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
			golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/msscmr", "msscmr", golog.LevelNone, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
			golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/msrrp", "msrrp", golog.LevelNone, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
			golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		}
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
	case 6:
		err = handleScmr(args)
		if err != nil {
			log.Errorln(err)
			return
		}
	case 7:
		err = handleRrp(args)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	return
}
