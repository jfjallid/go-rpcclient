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
	"fmt"
	"maps"
	"os"
	"strconv"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/mslsad"
	"github.com/jfjallid/go-smb/smb/dcerpc/mssamr"
	"github.com/jfjallid/golog"
	"golang.org/x/term"
)

const (
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
)

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

var samrUsageMap = map[string]string{
	SamrEnumDomains:      SamrEnumDomains,
	SamrEnumUsers:        SamrEnumUsers + " [domain]",
	SamrEnumGroups:       SamrEnumGroups + " [domain]",
	SamrEnumAliases:      SamrEnumAliases + " [domain]",
	SamrTranslateSid:     SamrTranslateSid + " <SID>",
	SamrLookupDomain:     SamrLookupDomain + " <domain>",
	SamrLookupSid:        SamrLookupSid + " <domain> <RID>",
	SamrLookupRids:       SamrLookupRids + " <RID[,RID...]> [domain]",
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
}

var samrDescriptionMap = map[string]string{
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
}

func samrCleanup(self *shell) {
	// Close SAMR handles
	if len(self.samrHandles) > 0 {
		rpccon, err := self.getSamrHandle()
		if err == nil {
			for i, v := range self.samrHandles {
				err = rpccon.SamrCloseHandle(v)
				delete(self.samrHandles, i)
			}
		}
	}
	for i, _ := range self.samrDomainIds {
		delete(self.binds, i)
	}
}

func printSamrHelp(self *shell) {
	self.showCustomHelpFunc(52, "MS-SAMR", samrUsageKeys)
}

func init() {
	maps.Copy(usageMap, samrUsageMap)
	maps.Copy(descriptionMap, samrDescriptionMap)
	allKeys = append(allKeys, samrUsageKeys...)
	cleanupCallbacks = append(cleanupCallbacks, samrCleanup)
	golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mssamr", "mssamr", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	handlers[SamrEnumDomains] = getSamrDomains
	handlers[SamrEnumUsers] = getSamrUsers
	handlers[SamrEnumGroups] = getSamrGroups
	handlers[SamrEnumAliases] = getSamrAliases
	handlers[SamrTranslateSid] = samrTranslateSid
	handlers[SamrLookupDomain] = samrLookupDomain
	handlers[SamrLookupSid] = samrLookupSid
	handlers[SamrLookupRids] = samrLookupRids
	handlers[SamrListGroupMembers] = listGroupMembers
	handlers[SamrListAliasMembers] = listAliasMembers
	handlers[SamrListLocalAdmins] = listLocalAdmins
	handlers[SamrQueryUser] = samrQueryUser
	handlers[SamrDeleteUser] = samrDeleteUser
	handlers[SamrAddMemberToAlias] = addMemberToLocalAlias
	handlers[SamrAddMemberToGroup] = addLocalGroupMember
	handlers[SamrDelGroupMember] = removeLocalGroupMember
	handlers[SamrDelAliasMember] = removeMemberFromLocalAlias
	handlers[SamrMakeAdmin] = addLocalAdmin
	handlers[SamrChangePassword] = samrChangeUserPassword
	handlers[SamrResetPassword] = samrResetUserPassword
	handlers[SamrCreateUser] = samrCreateUser
	helpFunctions[4] = printSamrHelp
}

func (self *shell) getSamrHandle() (rpccon *mssamr.RPCCon, err error) {
	val, found := self.binds["samr"]
	var samrConnectHandle *mssamr.SamrHandle
	if !found {
		var f *smb.File
		f, err = self.options.c.OpenFile(self.share, mssamr.MSRPCSamrPipe)
		if err != nil {
			if err == smb.StatusMap[smb.StatusObjectNameNotFound] {
				err = fmt.Errorf("Named pipe not available. Is the service running?")
			}
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

func getSamrDomains(self *shell, argArr interface{}) {
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

func getSamrUsers(self *shell, argArr interface{}) {
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

func getSamrGroups(self *shell, argArr interface{}) {
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

func getSamrAliases(self *shell, argArr interface{}) {
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

func listGroupMembers(self *shell, argArr interface{}) {
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
	var names []string
	if self.resolveSids {
		// Attempt to translate SIDs
		rpcconLsat, err := self.getLsadHandle()
		if err != nil {
			self.println(err)
			return
		}

		domainSid := self.samrDomainIds[domainName].ToString()
		var sids []string
		for _, item := range members {
			sids = append(sids, fmt.Sprintf("%s-%d", domainSid, item.RID))
		}
		res, err := rpcconLsat.LsarLookupSids2(1, sids)
		if err != nil {
			self.println(err)
			return
		}
		for _, item := range res.TranslatedNames {
			if item.Use == mslsad.SidTypeUnknown {
				names = append(names, "<unknown>")
			} else {
				if item.DomainIndex != -1 {
					names = append(names, fmt.Sprintf("%s\\%s", res.ReferencedDomains[item.DomainIndex].Name, item.Name))
				} else {
					names = append(names, item.Name)
				}
			}
		}
	}
	var sb strings.Builder
	self.println("Members in group:")
	for i, member := range members {
		fmt.Fprintf(&sb, "Member RID: %d", member.RID)
		if len(names) > 0 {
			fmt.Fprintf(&sb, " (%s)", names[i])
		}
		fmt.Fprintf(&sb, "\n")
	}
	self.println(sb.String())
}

func addLocalGroupMember(self *shell, argArr interface{}) {
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

func removeLocalGroupMember(self *shell, argArr interface{}) {
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

func samrTranslateSid(self *shell, argArr interface{}) {
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

func listAliasMembers(self *shell, argArr interface{}) {
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
	var names []string
	var sids []string
	for _, item := range members {
		sids = append(sids, item.ToString())
	}

	if self.resolveSids {
		// Attempt to translate SIDs
		rpcconLsat, err := self.getLsadHandle()
		if err != nil {
			self.println(err)
			return
		}
		res, err := rpcconLsat.LsarLookupSids2(1, sids)
		if err != nil {
			self.println(err)
			return
		}
		for _, item := range res.TranslatedNames {
			if item.Use == mslsad.SidTypeUnknown {
				names = append(names, "<unknown>")
			} else {
				if item.DomainIndex != -1 {
					names = append(names, fmt.Sprintf("%s\\%s", res.ReferencedDomains[item.DomainIndex].Name, item.Name))
				} else {
					names = append(names, item.Name)
				}
			}
		}
	}
	var sb strings.Builder
	self.println("Members in alias:")
	for i, sid := range sids {
		fmt.Fprintf(&sb, "Member SID: %s", sid)
		if len(names) > 0 {
			fmt.Fprintf(&sb, " (%s)", names[i])
		}
		fmt.Fprintf(&sb, "\n")
	}
	self.println(sb.String())
}

func addMemberToLocalAlias(self *shell, argArr interface{}) {
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

func removeMemberFromLocalAlias(self *shell, argArr interface{}) {
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

func listLocalAdmins(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	listAliasMembers(self, []string{"544", "builtin"})
}

func addLocalAdmin(self *shell, argArr interface{}) {
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
	addMemberToLocalAlias(self, []string{"544", args[0], "builtin"})
}

func samrLookupDomain(self *shell, argArr interface{}) {
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

func samrLookupSid(self *shell, argArr interface{}) {
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

func samrQueryUser(self *shell, argArr interface{}) {
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

func samrCreateUser(self *shell, argArr interface{}) {
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

func samrDeleteUser(self *shell, argArr interface{}) {
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

func samrResetUserPassword(self *shell, argArr interface{}) {
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

func samrChangeUserPassword(self *shell, argArr interface{}) {
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

func samrLookupRids(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SamrLookupRids]

	var domainName string
	args := argArr.([]string)
	if len(args) < 1 {
		self.println(usage)
		return
	} else if len(args) > 1 {
		domainName = strings.ToLower(args[1])
	}

	var ridList []uint32
	for _, ridStr := range strings.Split(args[0], ",") {
		// sanity check
		rid, err := strconv.ParseUint(ridStr, 10, 32)
		if err != nil {
			self.println(err)
			self.println(usage)
			return
		}
		ridList = append(ridList, uint32(rid))
	}
	if len(ridList) == 0 {
		self.println("Must provide at least one RID to lookup")
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
			self.println(usage)
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
