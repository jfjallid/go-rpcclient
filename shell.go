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

	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/mslsad"
	"github.com/jfjallid/go-smb/smb/dcerpc/mssamr"
	"github.com/jfjallid/go-smb/smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/smb/dcerpc/mswkst"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/golog"
	"golang.org/x/term"
)

var (
	scanner  *bufio.Scanner
	handlers = make(map[string]interface{})
)

type shell struct {
	options           *localOptions
	dcip              string
	prompt            string
	lcwd              string
	rcwd              string
	authenticated     bool
	nullSession       bool
	t                 *term.Terminal
	share             string
	binds             map[string]interface{}
	files             []*smb.File
	samrHandles       map[string]*mssamr.SamrHandle
	samrDomainIds     map[string]*msdtyp.SID
	samrNetbiosDomain string
}

const (
	OpenConn             = "open"
	Login                = "login"
	LoginHash            = "login_hash"
	LoginKrb             = "login_krb"
	Logout               = "logout"
	CloseConn            = "close"
	ExitShell            = "exit"
	SamrEnumDomains      = "samrenumdomains"
	SamrEnumUsers        = "samrenumusers"
	SamrEnumGroups       = "samrenumgroups"
	SamrEnumAliases      = "samrenumaliases"
	SamrTranslateSid     = "samrtranslatesid"
	SamrLookupDomain     = "samrlookupdomain"
	SamrLookupSid        = "samrlookupsid"
	SamrLookupRids       = "samrlookuprids"
	SamrListGroupMembers = "samrlistgroupmembers"
	SamrListAliasMembers = "samrlistaliasmembers"
	SamrListLocalAdmins  = "samrlistlocaladmins"
	SamrAddMemberToGroup = "samraddgroupmember"
	SamrAddMemberToAlias = "samraddaliasmember"
	SamrDelGroupMember   = "samrdelgroupmember"
	SamrDelAliasMember   = "samrdelaliasmember"
	SamrCreateUser       = "samrcreateuser"
	SamrQueryUser        = "samrqueryuser"
	SamrDeleteUser       = "samrdeleteuser"
	SamrMakeAdmin        = "samrmakeadmin"
	SamrChangePassword   = "samrchangepassword"
	SamrResetPassword    = "samrresetpassword"
	LsadEnumAccounts     = "lsaenumaccounts"
	LsadEnumAccRights    = "lsaenumaccrights"
	LsadAddRights        = "lsaaddrights"
	LsadDelRights        = "lsadelrights"
	LsadGetDominfo       = "lsagetdominfo"
	LsadPurgeRights      = "lsapurgerights"
	SrvsEnumSessions     = "srvsenumsessions"
	SrvsEnumShares       = "srvsenumshares"
	SrvsGetInfo          = "srvsgetinfo"
	WkstEnumSessions     = "wkstenumsessions"
)

var usageMap = map[string]string{
	OpenConn:             OpenConn + " <host> [port]",
	Login:                Login + "[domain/username] [passwd]",
	LoginHash:            LoginHash + "[domain/username] [nthash]",
	LoginKrb:             LoginKrb + "[domain/username] [pw] [spn]",
	Logout:               Logout,
	CloseConn:            CloseConn,
	ExitShell:            ExitShell,
	SamrEnumDomains:      SamrEnumDomains,
	SamrEnumUsers:        SamrEnumUsers + " [domain]",
	SamrEnumGroups:       SamrEnumGroups + " [domain]",
	SamrEnumAliases:      SamrEnumAliases + " [domain]",
	SamrTranslateSid:     SamrTranslateSid + " <SID>",
	SamrLookupDomain:     SamrLookupDomain + " [domain]",
	SamrLookupSid:        SamrLookupSid + " <RID>",
	SamrLookupRids:       SamrLookupRids + " <RID [RID...]>",
	SamrListGroupMembers: SamrListGroupMembers + " <RID> [domain]",
	SamrListAliasMembers: SamrListAliasMembers + " <RID> [domain]",
	SamrListLocalAdmins:  SamrListLocalAdmins,
	SamrQueryUser:        SamrQueryUser + " <RID>|<samAccountName> [domain]",
	SamrDeleteUser:       SamrDeleteUser + " <RID/SID> [domain]",
	SamrAddMemberToAlias: SamrAddMemberToAlias + " <GroupRID> <SID> [domain]",
	SamrAddMemberToGroup: SamrAddMemberToGroup + " <GroupRID> <User RID> [domain]",
	SamrDelGroupMember:   SamrDelGroupMember + " <GroupRID> <User RID> [domain]",
	SamrDelAliasMember:   SamrDelAliasMember + " <Group RID> <SID> [domain]",
	SamrMakeAdmin:        SamrMakeAdmin + " <SID>",
	SamrChangePassword:   SamrChangePassword + " <samAccountName>",
	SamrResetPassword:    SamrResetPassword + " <RID|SID> [domain]",
	SamrCreateUser:       SamrCreateUser + " <name> [domain]",
	LsadEnumAccounts:     LsadEnumAccounts,
	LsadEnumAccRights:    LsadEnumAccRights + " <SID>",
	LsadAddRights:        LsadAddRights + " <SID> <rights...>",
	LsadDelRights:        LsadDelRights + " <SID> <rights...>",
	LsadGetDominfo:       LsadGetDominfo,
	LsadPurgeRights:      LsadPurgeRights + " <SID>",
	SrvsEnumSessions:     SrvsEnumSessions + " [level]",
	SrvsEnumShares:       SrvsEnumShares,
	SrvsGetInfo:          SrvsGetInfo + "[level]",
	WkstEnumSessions:     WkstEnumSessions + "[level]",
}

var descriptionMap = map[string]string{
	OpenConn:             "Opens a new SMB connection against the target host/port",
	Login:                "Logs into the current SMB connection, no parameters for NULL connection",
	LoginHash:            "Logs into the current SMB connection using the password hashes",
	LoginKrb:             "Logs into the current SMB connection using Kerberos. If nothing specified, checks for CCACHE if SPN is not specified, a hostname must have been used to open the connection.",
	Logout:               "Ends the current SMB session but keeps the connection",
	CloseConn:            "Closes the current SMB connection",
	ExitShell:            "Terminates the server process (and this session)",
	SamrEnumDomains:      "List Samr domains",
	SamrEnumUsers:        "List Samr users",
	SamrEnumGroups:       "List Samr groups",
	SamrEnumAliases:      "List Samr aliases",
	SamrTranslateSid:     "Translate SID to name",
	SamrLookupDomain:     "Lookup Samr domain name to SID",
	SamrLookupSid:        "Convert RID to SID in domain",
	SamrLookupRids:       "Convert list of RIDs to names in domain",
	SamrListGroupMembers: "List group members",
	SamrListAliasMembers: "List alias members",
	SamrListLocalAdmins:  "List local admins",
	SamrQueryUser:        "Query user information",
	SamrDeleteUser:       "Delete user",
	SamrAddMemberToAlias: "Add principal to alias",
	SamrAddMemberToGroup: "Add principal to group",
	SamrDelGroupMember:   "Remove group member",
	SamrDelAliasMember:   "Remove alias member",
	SamrMakeAdmin:        "Add SID to local admins group (RID 544)",
	SamrChangePassword:   "Change user password. Leave current password empty to supply NT Hash instead",
	SamrResetPassword:    "Force change a user's password",
	SamrCreateUser:       "Create Samr user",
	LsadEnumAccounts:     "List LSA accounts",
	LsadEnumAccRights:    "List LSA rights assigned to account specified by SID",
	LsadAddRights:        "Add list of LSA rights to account specified by SID",
	LsadDelRights:        "Remove list of LSA rights from account specified by SID",
	LsadGetDominfo:       "Get primary domain name and domain SID",
	LsadPurgeRights:      "Removes all LSA rights for the specified SID",
	SrvsEnumSessions:     "List network sessions (supported levels 0, 10, 502. Default 10)",
	SrvsEnumShares:       "List SMB Shares",
	SrvsGetInfo:          "Get Server info (supported levels 100,101,102. Default 101. 102 requires admin privileges)",
	WkstEnumSessions:     "List logged in users (Required admin privileges) (supported levels 0, 1. Default level: 1)",
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
}

var samrUsageKeys = []string{
	SamrEnumDomains,
	SamrEnumUsers,
	SamrEnumGroups,
	SamrEnumAliases,
	SamrTranslateSid,
	SamrLookupDomain,
	SamrLookupSid,
	SamrLookupRids,
	SamrListGroupMembers,
	SamrListAliasMembers,
	SamrListLocalAdmins,
	SamrAddMemberToGroup,
	SamrAddMemberToAlias,
	SamrDelGroupMember,
	SamrDelAliasMember,
	SamrCreateUser,
	SamrQueryUser,
	SamrDeleteUser,
	SamrMakeAdmin,
	SamrChangePassword,
	SamrResetPassword,
}

var lsadUsageKeys = []string{
	LsadEnumAccounts,
	LsadEnumAccRights,
	LsadAddRights,
	LsadDelRights,
	LsadGetDominfo,
	LsadPurgeRights,
}

var srvsUsageKeys = []string{
	SrvsEnumSessions,
	SrvsEnumShares,
	SrvsGetInfo,
}

var wkstUsageKeys = []string{
	WkstEnumSessions,
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

// func newShell(o *localOptions) *shell {
func newShell(args *connArgs) *shell {
	o := args.opts
	s := shell{
		options:       o,
		dcip:          args.dcIP,
		prompt:        "# ",
		rcwd:          string(filepath.Separator),
		share:         "IPC$",
		binds:         make(map[string]interface{}),
		samrHandles:   make(map[string]*mssamr.SamrHandle),
		samrDomainIds: make(map[string]*msdtyp.SID),
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
	handlers["help"] = s.showHelpFunc
	handlers["?"] = s.showHelpFunc
	handlers[LsadEnumAccounts] = s.getLSAAccount
	handlers[LsadEnumAccRights] = s.getLSAAccountRights
	handlers[LsadAddRights] = s.addLSAAccountRights
	handlers[LsadDelRights] = s.removeLSAAccountRights
	handlers[LsadPurgeRights] = s.purgeLSAAccountRights
	handlers[LsadGetDominfo] = s.getLSAPrimaryDomainInfo
	handlers[SrvsGetInfo] = s.getServerInfoFunc
	handlers[SrvsEnumSessions] = s.getNetSessionsFunc
	handlers[SrvsEnumShares] = s.listSharesFunc
	handlers[WkstEnumSessions] = s.getSessionsFunc
	handlers[SamrEnumDomains] = s.getSamrDomains
	handlers[SamrEnumUsers] = s.getSamrUsers
	handlers[SamrEnumGroups] = s.getSamrGroups
	handlers[SamrEnumAliases] = s.getSamrAliases
	handlers[SamrTranslateSid] = s.samrTranslateSid
	handlers[SamrLookupDomain] = s.samrLookupDomain
	handlers[SamrLookupSid] = s.samrLookupSid
	handlers[SamrLookupRids] = s.samrLookupRids
	handlers[SamrListGroupMembers] = s.listGroupMembers
	handlers[SamrListAliasMembers] = s.listAliasMembers
	handlers[SamrListLocalAdmins] = s.listLocalAdmins
	handlers[SamrQueryUser] = s.samrQueryUser
	handlers[SamrDeleteUser] = s.samrDeleteUser
	handlers[SamrAddMemberToAlias] = s.addMemberToLocalAlias
	handlers[SamrAddMemberToGroup] = s.addLocalGroupMember
	handlers[SamrDelGroupMember] = s.removeLocalGroupMember
	handlers[SamrDelAliasMember] = s.removeMemberFromLocalAlias
	handlers[SamrMakeAdmin] = s.addLocalAdmin
	handlers[SamrChangePassword] = s.samrChangeUserPassword
	handlers[SamrResetPassword] = s.samrResetUserPassword
	handlers[SamrCreateUser] = s.samrCreateUser

	handlers[OpenConn] = s.openConnectionFunc
	handlers[CloseConn] = s.closeConnectionFunc
	handlers[Login] = s.loginFunc
	handlers[LoginHash] = s.loginHashFunc
	handlers["login_kerberos"] = s.loginKerberosFunc // Extra alias
	handlers[LoginKrb] = s.loginKerberosFunc
	handlers[Logout] = s.logoutFunc
	return &s
}

func (self *shell) showHelpFunc(args interface{}) {
	//self.println(helpMsgShell)
	self.showCustomHelpFunc(40, "General commands", generalUsageKeys)
	self.println()
	self.showCustomHelpFunc(40, "MS-SRVS", srvsUsageKeys)
	self.println()
	self.showCustomHelpFunc(40, "MS-WKST", wkstUsageKeys)
	self.println()
	self.showCustomHelpFunc(40, "MS-LSAD", lsadUsageKeys)
	self.println()
	self.showCustomHelpFunc(52, "MS-SAMR", samrUsageKeys)
}

func (self *shell) getSrvsHandle() (rpccon *mssrvs.RPCCon, err error) {

	val, found := self.binds["srvs"]
	if !found {
		var f *smb.File
		f, err = self.options.c.OpenFile(self.share, mssrvs.MSRPCSrvSvcPipe)
		if err != nil {
			return
		}
		self.files = append(self.files, f)
		var bind *dcerpc.ServiceBind
		bind, err = dcerpc.Bind(f, mssrvs.MSRPCUuidSrvSvc, mssrvs.MSRPCSrvSvcMajorVersion, mssrvs.MSRPCSrvSvcMinorVersion, dcerpc.MSRPCUuidNdr)
		if err != nil {
			self.println("Failed to bind to service")
			return
		}
		rpccon = mssrvs.NewRPCCon(bind)
		self.binds["srvs"] = rpccon
	} else {
		rpccon = val.(*mssrvs.RPCCon)
	}
	return
}

func (self *shell) getWkstHandle() (rpccon *mswkst.RPCCon, err error) {
	val, found := self.binds["wkst"]
	if !found {
		var f *smb.File
		f, err = self.options.c.OpenFile(self.share, mswkst.MSRPCWksSvcPipe)
		if err != nil {
			return
		}
		self.files = append(self.files, f)
		var bind *dcerpc.ServiceBind
		bind, err = dcerpc.Bind(f, mswkst.MSRPCUuidWksSvc, mswkst.MSRPCWksSvcMajorVersion, mswkst.MSRPCWksSvcMinorVersion, dcerpc.MSRPCUuidNdr)
		if err != nil {
			self.println("Failed to bind to service")
			return
		}
		rpccon = mswkst.NewRPCCon(bind)
		self.binds["wkst"] = rpccon
	} else {
		rpccon = val.(*mswkst.RPCCon)
	}
	return
}

func (self *shell) getLsadHandle() (rpccon *mslsad.RPCCon, err error) {
	val, found := self.binds["lsad"]
	if !found {
		var f *smb.File
		f, err = self.options.c.OpenFile(self.share, mslsad.MSRPCLsaRpcPipe)
		if err != nil {
			return
		}
		self.files = append(self.files, f)
		var bind *dcerpc.ServiceBind
		bind, err = dcerpc.Bind(f, mslsad.MSRPCUuidLsaRpc, mslsad.MSRPCLsaRpcMajorVersion, mslsad.MSRPCLsaRpcMinorVersion, dcerpc.MSRPCUuidNdr)
		if err != nil {
			self.println("Failed to bind to service")
			return
		}
		rpccon = mslsad.NewRPCCon(bind)
		self.binds["lsad"] = rpccon
	} else {
		rpccon = val.(*mslsad.RPCCon)
	}
	return
}

func (self *shell) getSamrHandle() (rpccon *mssamr.RPCCon, err error) {
	val, found := self.binds["samr"]
	var samrConnectHandle *mssamr.SamrHandle
	if !found {
		var f *smb.File
		f, err = self.options.c.OpenFile(self.share, mssamr.MSRPCSamrPipe)
		if err != nil {
			return
		}
		self.files = append(self.files, f)
		var bind *dcerpc.ServiceBind
		bind, err = dcerpc.Bind(f, mssamr.MSRPCUuidSamr, mssamr.MSRPCSamrMajorVersion, mssamr.MSRPCSamrMinorVersion, dcerpc.MSRPCUuidNdr)
		if err != nil {
			self.println("Failed to bind to service")
			return
		}
		rpccon = mssamr.NewRPCCon(bind)
		self.binds["samr"] = rpccon
		if !self.nullSession {
			samrConnectHandle, err = rpccon.SamrConnect5("")
			if err != nil {
				return
			}
			self.samrHandles["connect"] = samrConnectHandle
		}
	} else {
		rpccon = val.(*mssamr.RPCCon)
		if _, found := self.samrHandles["connect"]; !found && !self.nullSession {
			samrConnectHandle, err = rpccon.SamrConnect5("")
			if err != nil {
				return
			}
			self.samrHandles["connect"] = samrConnectHandle
		}
	}
	return
}

func (self *shell) getSamrDomainHandle(rpccon *mssamr.RPCCon, domainName string) (domainHandle *mssamr.SamrHandle, err error) {
	var found bool
	var domainId *msdtyp.SID
	if domainName == "" {
		domainName, err = self.getSamrNetbiosDomain()
		if err != nil {
			return
		}
	}
	domainHandle, found = self.samrHandles[domainName]
	if !found {
		connectHandle, found := self.samrHandles["connect"]
		if !found {
			err = fmt.Errorf("Something went wrong with SamrConnect handle")
			return
		}
		domainId, err = rpccon.SamrLookupDomain(connectHandle, domainName)
		if err != nil {
			return
		}
		domainHandle, err = rpccon.SamrOpenDomain(connectHandle, 0, domainId)
		if err != nil {
			return
		}
		self.samrHandles[domainName] = domainHandle
		self.samrDomainIds[domainName] = domainId
	}
	return
}

func (self *shell) listSharesFunc(args interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	rpccon, err := self.getSrvsHandle()
	if err != nil {
		self.println(err)
		return
	}

	shares, err := getShares(rpccon, "")
	if err != nil {
		self.println(err)
		return
	}
	for _, share := range shares {
		self.println(share)
	}
}

func (self *shell) getServerInfoFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SrvsGetInfo]
	args := argArr.([]string)
	level := 101

	if len(args) > 0 {
		val, err := strconv.ParseInt(args[0], 10, 32)
		if err != nil {
			self.println("Error parsing level")
			self.println(usage)
			return
		} else if (val < 100) || (val > 102) {
			self.println("Must specify a valid level (100, 101 or 102)")
			self.println(usage)
			return
		}
		level = int(val)
	}

	rpccon, err := self.getSrvsHandle()
	if err != nil {
		self.println(err)
		return
	}

	info, err := getServerInfo(rpccon, level)
	if err != nil {
		self.println(err)
		return
	}
	for _, item := range info {
		self.print(item)
	}
	return
}

func (self *shell) getSessionsFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[WkstEnumSessions]
	args := argArr.([]string)
	level := 1
	if len(args) > 0 {
		val, err := strconv.ParseInt(args[0], 10, 32)
		if err != nil {
			self.println("Error parsing level")
			self.println(usage)
			return
		} else if (val != 0) && (val != 1) {
			self.println("Must specify a valid level (0 or 1)")
			self.println(usage)
			return
		}
		level = int(val)
	}

	rpccon, err := self.getWkstHandle()
	if err != nil {
		self.println(err)
		return
	}

	sessions, err := getWkstSessions(rpccon, level)
	if err != nil {
		self.println(err)
		return
	}
	for _, item := range sessions {
		self.print(item)
	}
}

func (self *shell) getNetSessionsFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SrvsEnumSessions]
	args := argArr.([]string)
	level := 10
	if len(args) > 0 {
		val, err := strconv.ParseInt(args[0], 10, 32)
		if err != nil {
			self.println("Error parsing level")
			self.println(usage)
			return
		} else if (val != 0) && (val != 10) && (val != 502) {
			self.println("Must specify a valid level (0, 10 or 502)")
			self.println(usage)
			return
		}
		level = int(val)
	}

	rpccon, err := self.getSrvsHandle()
	if err != nil {
		self.println(err)
		return
	}

	sessions, err := getSrvsSessions(rpccon, level)
	if err != nil {
		self.println(err)
		return
	}
	for _, item := range sessions {
		self.print(item)
	}

	return
}

func (self *shell) openConnectionFunc(argArr interface{}) {
	var err error
	usage := "Usage: " + usageMap[OpenConn]
	if self.options.c != nil {
		self.println("Closing existing connection first")
		self.closeConnection()
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

func (self *shell) closeConnection() {
	if self.authenticated {
		self.logout()
	}
	self.options.c.Close()
	self.options.c = nil
	return
}

func (self *shell) closeConnectionFunc(argArr interface{}) {
	if self.options.c == nil {
		self.println("No connection open")
		return
	}
	self.closeConnection()
	return
}

func (self *shell) executeLogin() {
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

func (self *shell) loginFunc(argArr interface{}) {
	if self.options.c == nil {
		self.println("Open a connection before attempting to login")
		return
	}

	err := self.logout()
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

	self.executeLogin()
}

func (self *shell) loginHashFunc(argArr interface{}) {
	if self.options.c == nil {
		self.println("Open a connection before attempting to login")
		return
	}

	err := self.logout()
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

	self.executeLogin()
}

func (self *shell) loginKerberosFunc(argArr interface{}) {
	if self.options.c == nil {
		self.println("Open a connection before attempting to login")
		return
	}

	err := self.logout()
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

	self.executeLogin()
}

func (self *shell) closeAllBinds() error {
	// Do some cleanup before logging out
	for i, _ := range self.files {
		self.files[i].CloseFile()
	}
	// Close SAMR handles
	if len(self.samrHandles) > 0 {
		rpccon, err := self.getSamrHandle()
		if err == nil {
			for _, v := range self.samrHandles {
				rpccon.SamrCloseHandle(v)
			}
		}
	}
	for i, _ := range self.samrDomainIds {
		delete(self.binds, i)
	}
	for i, _ := range self.binds {
		delete(self.binds, i)
	}
	return nil
}

func (self *shell) logout() error {
	if !self.authenticated {
		return nil
	}
	self.closeAllBinds()
	self.rcwd = ""
	self.lcwd = ""
	self.authenticated = false
	return self.options.c.Logoff()
}

func (self *shell) logoutFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	if self.options.c == nil {
		return
	}

	self.logout()
	return
}

func (self *shell) getLSAAccount(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}

	rpccon, err := self.getLsadHandle()
	if err != nil {
		self.println(err)
		return
	}

	accounts, err := getLSAAccounts(rpccon)
	if err != nil {
		self.println(err)
		return
	}
	for _, item := range accounts {
		self.println(item)
	}
}

func (self *shell) getLSAAccountRights(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[LsadEnumAccRights]

	args := argArr.([]string)
	sidStr := ""
	if len(args) < 1 {
		self.println(usage)
		return
	} else {
		sid, err := msdtyp.ConvertStrToSID(args[0])
		if err != nil {
			self.println("Error parsing SID")
			self.println(usage)
			return
		}
		sidStr = sid.ToString()
	}

	rpccon, err := self.getLsadHandle()
	if err != nil {
		self.println(err)
		return
	}

	rights, err := rpccon.ListAccountRights(sidStr)
	if err != nil {
		self.println(err)
		return
	}
	for _, right := range rights {
		self.println(right)
	}
}

func (self *shell) addLSAAccountRights(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[LsadAddRights]

	args := argArr.([]string)
	sidStr := ""
	var rights []string
	if len(args) < 2 {
		self.println(usage)
		return
	} else {
		sid, err := msdtyp.ConvertStrToSID(args[0])
		if err != nil {
			self.println("Error parsing SID")
			self.println(usage)
			return
		}
		sidStr = sid.ToString()
		rights = append(rights, args[1:]...)
		// sanity check
		for _, item := range rights {
			if strings.Contains(item, ",") {
				self.println("List of rights should be separated by spaces")
				self.println(usage)
				return
			}
		}
	}

	rpccon, err := self.getLsadHandle()
	if err != nil {
		self.println(err)
		return
	}

	err = rpccon.AddAccountRights(sidStr, rights)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Rights added!")
}

func (self *shell) removeLSAAccountRights(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[LsadDelRights]

	args := argArr.([]string)
	sidStr := ""
	var rights []string
	if len(args) < 2 {
		self.println(usage)
		return
	} else {
		sid, err := msdtyp.ConvertStrToSID(args[0])
		if err != nil {
			self.println("Error parsing SID")
			self.println(usage)
			return
		}
		sidStr = sid.ToString()
		rights = append(rights, args[1:]...)
		// sanity check
		for _, item := range rights {
			if strings.Contains(item, ",") {
				self.println("List of rights should be separated by spaces")
				self.println(usage)
				return
			}
		}
	}

	rpccon, err := self.getLsadHandle()
	if err != nil {
		self.println(err)
		return
	}

	err = rpccon.RemoveAccountRights(sidStr, rights, false)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Rights removed!")
}

func (self *shell) purgeLSAAccountRights(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[LsadPurgeRights]

	args := argArr.([]string)
	sidStr := ""
	if len(args) < 1 {
		self.println(usage)
		return
	} else {
		sid, err := msdtyp.ConvertStrToSID(args[0])
		if err != nil {
			self.println("Error parsing SID")
			self.println(usage)
			return
		}
		sidStr = sid.ToString()
	}

	rpccon, err := self.getLsadHandle()
	if err != nil {
		self.println(err)
		return
	}

	err = rpccon.RemoveAccountRights(sidStr, nil, true)
	if err != nil {
		self.println(err)
		return
	}
	self.println("all rights removed!")
}

func (self *shell) getLSAPrimaryDomainInfo(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}

	rpccon, err := self.getLsadHandle()
	if err != nil {
		self.println(err)
		return
	}

	domInfo, err := rpccon.GetPrimaryDomainInfo()
	if err != nil {
		self.println(err)
		return
	}
	self.printf("Domain: %s, SID: %s\n", domInfo.Name, domInfo.Sid.ToString())
}

func (self *shell) getSamrDomains(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}

	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	handle, found := self.samrHandles["connect"]
	if !found {
		self.println("Something went wrong with SamrConnect handle")
		return
	}

	domains, err := rpccon.SamrEnumDomains(handle)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Domains:")
	for _, name := range domains {
		self.println(name)
	}
}

func (self *shell) getSamrUsers(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}

	usage := "Usage: " + usageMap[SamrEnumUsers]
	args := argArr.([]string)
	listLocalUsers := true
	var domainName string
	if len(args) > 0 {
		listLocalUsers = false
		domainName = strings.ToLower(args[0])
	}
	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	var users []mssamr.SamprRidEnumeration
	if listLocalUsers {
		// Only listing max around 30 users here. For more, skip interactive mode
		users, err = rpccon.ListLocalUsers("", 30)
		if err != nil {
			self.println(err)
			return
		}
	} else {
		domainHandle, err := self.getSamrDomainHandle(rpccon, domainName)
		if err != nil {
			self.println(err)
			self.println(usage)
			return
		}
		// Only listing max around 30 users here. For more, skip interactive mode
		users, err = rpccon.SamrEnumDomainUsers(domainHandle, mssamr.UserNormalAccount, 30*39)
		if err != nil {
			self.println(err)
			return
		}
	}
	self.println("Listing up to a max of about 30 users:")
	for _, user := range users {
		self.printf("Rid: %d, Name: %s\n", user.RelativeId, user.Name)
	}
}

func (self *shell) getSamrGroups(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrEnumGroups]
	var domainName string

	args := argArr.([]string)
	listLocalGroups := true
	if len(args) > 0 {
		listLocalGroups = false
		domainName = strings.ToLower(args[0])
	}
	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	var groups []mssamr.SamprRidEnumeration
	if listLocalGroups {
		groups, err = rpccon.ListLocalGroups("")
		if err != nil {
			self.println(err)
			return
		}
	} else {
		domainHandle, err := self.getSamrDomainHandle(rpccon, domainName)
		if err != nil {
			self.println(err)
			self.println(usage)
			return
		}
		groups, err = rpccon.SamrEnumerateGroupsInDomain(domainHandle, 0)
		if err != nil {
			self.println(err)
			return
		}
	}
	self.println("Groups:")
	for _, group := range groups {
		self.printf("Rid: %d, Name: %s\n", group.RelativeId, group.Name)
	}
}

func (self *shell) getSamrAliases(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrEnumAliases]

	args := argArr.([]string)
	domainName := ""
	if len(args) > 0 {
		domainName = strings.ToLower(args[0])
	}
	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	//TODO maybe support doing the steps manually to avoid uneccessary request?
	groups, err := rpccon.ListDomainAliases(domainName)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}

	self.println("Aliases:")
	for _, group := range groups {
		self.printf("Rid: %d, Name: %s\n", group.RelativeId, group.Name)
	}
}

func (self *shell) getSamrNetbiosDomain() (domainName string, err error) {
	if self.samrNetbiosDomain != "" {
		return self.samrNetbiosDomain, nil
	}
	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	handle, found := self.samrHandles["connect"]
	if !found {
		self.println("Something went wrong with SamrConnect handle")
		return
	}
	self.samrNetbiosDomain, err = getSamrNetbiosDomain(rpccon, handle)
	if err != nil {
		self.println(err)
		return
	}
	domainName = self.samrNetbiosDomain
	return
}

func (self *shell) listGroupMembers(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrListGroupMembers]
	args := argArr.([]string)
	var domainName string
	numArgs := len(args)
	if numArgs < 1 {
		self.println(usage)
		return
	} else if numArgs > 1 {
		domainName = strings.ToLower(args[1])
	}
	groupRid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}

	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	if domainName == "" {
		domainName, err = self.getSamrNetbiosDomain()
		if err != nil {
			self.println(err)
			return
		}
	}
	// Check if we already have an open handle
	domainHandle, err := self.getSamrDomainHandle(rpccon, domainName)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	groupHandleName := fmt.Sprintf("%s-group:%d", domainName, groupRid)
	handleLocalGroup, found := self.samrHandles[groupHandleName]
	if !found {
		handleLocalGroup, err = rpccon.SamrOpenGroup(domainHandle, 0, uint32(groupRid))
		if err != nil {
			self.println(err)
			return
		}
		self.samrHandles[groupHandleName] = handleLocalGroup
	}
	var members []mssamr.SamrGroupMember
	members, err = rpccon.SamrGetMembersInGroup(handleLocalGroup)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Members in group:")
	for _, member := range members {
		self.printf("Member RID: %d\n", member.RID)
	}
}

func (self *shell) addLocalGroupMember(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrAddMemberToGroup]
	args := argArr.([]string)
	var domainName string
	numArgs := len(args)
	if numArgs < 2 {
		self.println(usage)
		return
	} else if numArgs > 2 {
		domainName = strings.ToLower(args[2])
	}
	groupRid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	userRid, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}

	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	if domainName == "" {
		domainName, err = self.getSamrNetbiosDomain()
		if err != nil {
			self.println(err)
			return
		}
	}
	// Check if we already have an open handle
	domainHandle, err := self.getSamrDomainHandle(rpccon, domainName)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	groupHandleName := fmt.Sprintf("%s-group:%d", domainName, groupRid)
	handleLocalGroup, found := self.samrHandles[groupHandleName]
	if !found {
		handleLocalGroup, err = rpccon.SamrOpenGroup(domainHandle, 0, uint32(groupRid))
		if err != nil {
			self.println(err)
			return
		}
		self.samrHandles[groupHandleName] = handleLocalGroup
	}
	err = rpccon.SamrAddMemberToGroup(handleLocalGroup, uint32(userRid), 0)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Added user to group")
}

func (self *shell) removeLocalGroupMember(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrDelGroupMember]
	args := argArr.([]string)
	var domainName string
	numArgs := len(args)
	if numArgs < 2 {
		self.println(usage)
		return
	} else if numArgs > 2 {
		domainName = strings.ToLower(args[2])
	}
	groupRid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	userRid, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}

	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	if domainName == "" {
		domainName, err = self.getSamrNetbiosDomain()
		if err != nil {
			self.println(err)
			return
		}
	}
	// Check if we already have an open handle
	domainHandle, err := self.getSamrDomainHandle(rpccon, domainName)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	groupHandleName := fmt.Sprintf("%s-group:%d", domainName, groupRid)
	handleLocalGroup, found := self.samrHandles[groupHandleName]
	if !found {
		handleLocalGroup, err = rpccon.SamrOpenGroup(domainHandle, 0, uint32(groupRid))
		if err != nil {
			self.println(err)
			return
		}
		self.samrHandles[groupHandleName] = handleLocalGroup
	}
	err = rpccon.SamrRemoveMemberFromGroup(handleLocalGroup, uint32(userRid))
	if err != nil {
		self.println(err)
		return
	}
	self.println("Removed user from group")
}

func (self *shell) samrTranslateSid(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrTranslateSid]

	args := argArr.([]string)
	if len(args) < 1 {
		self.println(usage)
		return
	}
	sid, err := msdtyp.ConvertStrToSID(args[0])
	if err != nil {
		self.println(err)
		return
	}
	sidStruct := &SID{s: args[0], v: sid}
	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	handle, found := self.samrHandles["connect"]
	if !found {
		self.println("Something went wrong with SamrConnect handle")
		return
	}
	name, err := translateSid(rpccon, handle, sidStruct)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	self.println(name)
}

func (self *shell) listAliasMembers(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrListAliasMembers]
	args := argArr.([]string)
	var domainName string
	numArgs := len(args)
	if numArgs < 1 {
		self.println(usage)
		return
	} else if numArgs > 1 {
		domainName = strings.ToLower(args[1])
	}
	aliasRid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}

	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	// Check if we already have an open handle
	domainHandle, err := self.getSamrDomainHandle(rpccon, domainName)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	aliasHandleName := fmt.Sprintf("%s-alias:%d", domainName, aliasRid)
	handleLocalAlias, found := self.samrHandles[aliasHandleName]
	if !found {
		handleLocalAlias, err = rpccon.SamrOpenAlias(domainHandle, 0, uint32(aliasRid))
		if err != nil {
			self.println(err)
			return
		}
		self.samrHandles[aliasHandleName] = handleLocalAlias
	}
	var members []msdtyp.SID
	members, err = rpccon.SamrGetMembersInAlias(handleLocalAlias)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Members in alias:")
	for _, member := range members {
		self.printf("Member SID: %s\n", member.ToString())
	}
}

func (self *shell) addMemberToLocalAlias(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrAddMemberToAlias]
	args := argArr.([]string)
	var domainName string
	numArgs := len(args)
	if numArgs < 2 {
		self.println(usage)
		return
	} else if numArgs > 2 {
		domainName = strings.ToLower(args[2])
	}
	aliasRid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	userSid, err := msdtyp.ConvertStrToSID(args[1])
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}

	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	// Check if we already have an open handle
	domainHandle, err := self.getSamrDomainHandle(rpccon, domainName)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	aliasHandleName := fmt.Sprintf("%s-alias:%d", domainName, aliasRid)
	handleLocalAlias, found := self.samrHandles[aliasHandleName]
	if !found {
		handleLocalAlias, err = rpccon.SamrOpenAlias(domainHandle, 0, uint32(aliasRid))
		if err != nil {
			self.println(err)
			return
		}
		self.samrHandles[aliasHandleName] = handleLocalAlias
	}
	err = rpccon.SamrAddMemberToAlias(handleLocalAlias, userSid)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Added member to alias")
}

func (self *shell) removeMemberFromLocalAlias(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrDelAliasMember]

	args := argArr.([]string)
	var domainName string
	numArgs := len(args)
	if numArgs < 2 {
		self.println(usage)
		return
	} else if numArgs > 2 {
		domainName = strings.ToLower(args[2])
	}
	aliasRid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	userSid, err := msdtyp.ConvertStrToSID(args[1])
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}

	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	// Check if we already have an open handle
	domainHandle, err := self.getSamrDomainHandle(rpccon, domainName)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	aliasHandleName := fmt.Sprintf("%s-alias:%d", domainName, aliasRid)
	handleLocalAlias, found := self.samrHandles[aliasHandleName]
	if !found {
		handleLocalAlias, err = rpccon.SamrOpenAlias(domainHandle, 0, uint32(aliasRid))
		if err != nil {
			self.println(err)
			return
		}
		self.samrHandles[aliasHandleName] = handleLocalAlias
	}
	err = rpccon.SamrRemoveMemberFromAlias(handleLocalAlias, userSid)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Removed member from alias")
}

func (self *shell) listLocalAdmins(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	self.listAliasMembers([]string{"544", "builtin"})
}

func (self *shell) addLocalAdmin(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrMakeAdmin]
	args := argArr.([]string)
	numArgs := len(args)
	if numArgs < 1 {
		self.println(usage)
		return
	}
	_, err := msdtyp.ConvertStrToSID(args[0])
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	self.addMemberToLocalAlias([]string{"544", args[0], "builtin"})
}

func (self *shell) samrLookupDomain(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrLookupDomain]

	args := argArr.([]string)
	if len(args) < 1 {
		self.println(usage)
		return
	}
	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	handle, found := self.samrHandles["connect"]
	if !found {
		self.println("Something went wrong with SamrConnect handle")
		return
	}
	domainId, err := rpccon.SamrLookupDomain(handle, args[0])
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	self.printf("Domain SID: %s\n", domainId.ToString())
}

func (self *shell) samrLookupSid(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrLookupSid]
	args := argArr.([]string)
	if len(args) < 2 {
		self.println(usage)
		return
	}
	domainName := strings.ToLower(args[0])
	rid, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	// Check if we already have an open handle
	domainHandle, err := self.getSamrDomainHandle(rpccon, domainName)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}

	sid, err := rpccon.SamrRidToSid(domainHandle, uint32(rid))
	if err != nil {
		self.println(err)
		return
	}
	self.printf("SID of the RID (%d): %s\n", rid, sid.ToString())
}

func (self *shell) samrQueryUser(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrQueryUser]

	domainName := ""
	args := argArr.([]string)
	if len(args) < 1 {
		self.println(usage)
		return
	} else if len(args) > 1 {
		domainName = strings.ToLower(args[1])
	}
	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	// Check if we already have an open handle
	domainHandle, err := self.getSamrDomainHandle(rpccon, domainName)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	var rid uint32
	// Determine if user provided a RID or a samAccountName
	val, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		// Assume it is a samAccountName instead
		// Lookup user Rid in domain
		var items []mssamr.SamrRidMapping
		items, err = lookupNamesInDomain(rpccon, domainHandle, []string{args[0]})
		if err != nil {
			if err == mssamr.ResponseCodeMap[mssamr.StatusNoneMapped] {
				err = fmt.Errorf("samAccountName (%s) not found in domain", args[0])
			}
			self.println(err)
			return
		}
		rid = items[0].RID

	} else {
		rid = uint32(val)
	}

	userHandle, err := rpccon.SamrOpenUser(domainHandle, 0, rid)
	if err != nil {
		self.println(err)
		return
	}

	var info *mssamr.SamprUserAllInformation
	result, err := rpccon.SamrGetUserInfo2(userHandle, mssamr.UserAllInformation)
	info = result.(*mssamr.SamprUserAllInformation)

	self.printf("Username: %s\nDescription: %s\nUser Rid: %d\nLast Logon: %s\nPassword Last Changed: %s\nPassword Can Change: %s\nUserAcountControl: 0x%x\nBadPwdCount: %d\nLogonCount: %d\nPassword expired: %v\n", info.Username, info.AdminComment, info.UserId, info.LastLogon.ToString(), info.PasswordLastSet.ToString(), info.PasswordCanChange.ToString(), info.UserAccountControl, info.BadPasswordCount, info.LogonCount, info.PasswordExpired)
}

func (self *shell) samrCreateUser(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrCreateUser]

	domainName := ""
	args := argArr.([]string)
	if len(args) < 1 {
		self.println(usage)
		return
	} else if len(args) > 1 {
		domainName = strings.ToLower(args[1])
	}
	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	// Check if we already have an open handle
	domainHandle, err := self.getSamrDomainHandle(rpccon, domainName)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}

	// Need domainName to create SID (if it was not provided)
	if domainName == "" {
		domainName, err = self.getSamrNetbiosDomain()
		if err != nil {
			self.println(err)
			return
		}
	}
	// Need domainId to create the SID
	domainId, found := self.samrDomainIds[domainName]
	if !found {
		self.printf("Something weird going on. DomainSid for %s should be cached already\n", domainName)
		return
	}

	userHandle, userRid, err := rpccon.SamrCreateUserInDomain(domainHandle, args[0], 0)
	if err != nil {
		self.println(err)
		return
	}
	defer rpccon.SamrCloseHandle(userHandle)
	userSID := fmt.Sprintf("%s-%d", domainId.ToString(), userRid)
	self.printf("Created user named (%s) with SID: %s\n", args[0], userSID)

	self.printf("Optionally enter user password: ")
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	self.println()
	if err != nil {
		self.println(err)
		return
	}
	userPassword := string(passBytes)
	if userPassword == "" {
		self.println("Account will probably not be useable until a password has been set")
		return
	} else {
		// Activate the account
		input := &mssamr.SamrUserInfoInput{
			UserAccountControl: mssamr.UserNormalAccount | mssamr.UserDontExpirePassword,
			NewPassword:        userPassword,
		}
		err = rpccon.SamrSetUserInfo2(userHandle, input)
		if err != nil {
			self.println(err)
			return
		}
	}
}

func (self *shell) samrDeleteUser(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrDeleteUser]
	domainName := ""
	args := argArr.([]string)
	if len(args) < 1 {
		self.println(usage)
		return
	} else if len(args) > 1 {
		domainName = strings.ToLower(args[1])
	}
	rid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}

	// Check if we already have an open handle
	domainHandle, err := self.getSamrDomainHandle(rpccon, domainName)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	userHandle, err := rpccon.SamrOpenUser(domainHandle, 0, uint32(rid))
	if err != nil {
		self.println(err)
		return
	}
	// No need to close the handle when deleting the user

	err = rpccon.SamrDeleteUser(userHandle)
	if err != nil {
		self.println(err)
		return
	}
}

func (self *shell) samrResetUserPassword(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrResetPassword]
	domainName := ""
	var userSid *msdtyp.SID
	args := argArr.([]string)
	if len(args) < 1 {
		// Either specify SID or domain + rid
		self.println(usage)
		return
	} else if len(args) > 1 {
		domainName = strings.ToLower(args[1])
	}
	// Try to see if user provided a RID
	rid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		// Maybe user provided a SID?
		userSid, err = msdtyp.ConvertStrToSID(args[0])
		if err != nil {
			self.println("Invalid RID or SID")
			self.println(err)
			self.println(usage)
			return
		}
	}
	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}
	var domainHandle *mssamr.SamrHandle
	if userSid != nil {
		// Extract domainId from SID
		parts := strings.Split(userSid.ToString(), "-")
		domainSidStr := strings.Join(parts[:len(parts)-1], "-")
		localDomainId, err := msdtyp.ConvertStrToSID(domainSidStr)
		if err != nil {
			self.println(err)
			self.println(usage)
			return
		}
		rid = uint64(userSid.SubAuthorities[userSid.NumAuth-1])
		handle, found := self.samrHandles["connect"]
		if !found {
			self.println("Something went wrong with SamrConnect handle")
			return
		}
		domainHandle, err = rpccon.SamrOpenDomain(handle, 0, localDomainId)
		if err != nil {
			self.println(err)
			return
		}
		// Since the handle is opened without knowing the domain name we will close it manually
		defer rpccon.SamrCloseHandle(domainHandle)
	} else {
		// Check if we already have an open handle
		domainHandle, err = self.getSamrDomainHandle(rpccon, domainName)
		if err != nil {
			self.println(err)
			self.println(usage)
			return
		}
	}

	userHandle, err := rpccon.SamrOpenUser(domainHandle, 0, uint32(rid))
	if err != nil {
		self.println(err)
		return
	}
	defer rpccon.SamrCloseHandle(userHandle)

	self.printf("Enter new password: ")
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	self.println()
	if err != nil {
		self.println(err)
		return
	}
	userPassword := string(passBytes)
	input := &mssamr.SamrUserInfoInput{
		NewPassword: userPassword,
	}
	err = rpccon.SamrSetUserInfo2(userHandle, input)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Updated the user's password")
}

func (self *shell) samrChangeUserPassword(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrChangePassword]
	userName := ""
	args := argArr.([]string)
	if len(args) < 1 {
		self.println(usage)
		return
	} else {
		userName = args[0]
	}
	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}

	self.printf("Enter account password (leave empty for hash): ")
	currPassBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	self.println()
	if err != nil {
		self.println(err)
		return
	}
	currPassword := string(currPassBytes)
	var currNTHash []byte
	if currPassword == "" {
		self.println("Provided password was empty")
		self.printf("Enter account's NT Hash: ")
		currHexStringBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		self.println()
		if err != nil {
			self.println(err)
			return
		}
		currNTHash, err = hex.DecodeString(string(currHexStringBytes))
		if err != nil {
			self.println(err)
			return
		}
	}
	self.printf("Enter new password: ")
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	self.println()
	if err != nil {
		self.println(err)
		return
	}
	newPassword := string(passBytes)
	err = rpccon.SamrChangePassword2(userName, currPassword, newPassword, currNTHash)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Successfully changed user's password!")
}

func (self *shell) samrLookupRids(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrLookupSid]

	args := argArr.([]string)
	if len(args) < 2 {
		self.println(usage)
		return
	}
	domainName := strings.ToLower(args[0])

	var ridList []uint32
	for _, ridStr := range args[1:] {
		// sanity check
		if strings.Contains(ridStr, ",") {
			self.println("List of rids should be separated by spaces")
			self.println(usage)
			return
		}
		rid, err := strconv.ParseUint(ridStr, 10, 32)
		if err != nil {
			self.println(err)
			self.println(usage)
			return
		}
		ridList = append(ridList, uint32(rid))
	}
	rpccon, err := self.getSamrHandle()
	if err != nil {
		self.println(err)
		return
	}

	// Check if we already have an open handle
	domainHandle, err := self.getSamrDomainHandle(rpccon, domainName)
	if err != nil {
		self.println(err)
		self.println(usage)
		return
	}
	var items []mssamr.SamrRidMapping
	items, err = rpccon.SamrLookupIdsInDomain(domainHandle, ridList)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Translated RIDs:")
	for _, item := range items {
		self.printf("Name: %s, RID: %d, Use: %s\n", item.Name, item.RID, mssamr.SidType[item.Use])
	}
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
	allKeys = []string{}
	allKeys = append(allKeys, generalUsageKeys...)
	allKeys = append(allKeys, samrUsageKeys...)
	allKeys = append(allKeys, wkstUsageKeys...)
	allKeys = append(allKeys, srvsUsageKeys...)
	allKeys = append(allKeys, lsadUsageKeys...)
	fmt.Println("Welcome to the interactive shell!\nType 'help' for a list of commands")

	self.t = term.NewTerminal(os.Stdin, self.prompt)
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
				completions := completer(line[:pos])
				if len(completions) > 0 {
					commonPrefix := longestCommonPrefix(completions)
					if len(commonPrefix) > pos {
						newLine = commonPrefix
						newPos = len(newLine)
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
	golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mssrvs", "mssrvs", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mssamr", "mssamr", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mslsad", "mslsad", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mswkst", "mswkst", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	log.SetLogLevel(golog.LevelNone)

	defer self.options.c.TreeDisconnect(self.share)
	defer self.closeAllBinds()

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
		if strings.Compare(input, "exit") == 0 {
			break OuterLoop
		}
		parts := strings.Split(input, " ")
		cmd := input
		args := []string{}
		if len(parts) > 1 {
			cmd = strings.ToLower(parts[0])
			args = parts[1:]
		} else {
			cmd = strings.ToLower(cmd)
		}

		if val, ok := handlers[cmd]; ok {
			fn := val.(func(interface{}))
			fn(args)
		} else if cmd != "" {
			self.printf("Unknown command: (%s)\n", input)
		}
	}
	self.t.SetPrompt("")
	self.println("Bye!")
}
