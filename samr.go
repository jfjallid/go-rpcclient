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
	"os"
	"strconv"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/mssamr"
	"golang.org/x/term"
)

var helpSamrOptions = `
    Usage: ` + os.Args[0] + ` --samr [options] <action>
    ` + helpConnectionOptions + `
    Action:
          --enum-domains       List SAMR Domains
          --enum-users         List users (--local-domain or --netbios to specify a different domain)
          --list-groups        List domain groups (or aliases with --alias)
          --list-admins        List members of local administrators group
          --list-members       List members of group or alias
          --add-member         Add member to group (use --rid) or alias (use --sid)
          --remove-member      Remove member from group (use --user-rid) or alias (use --sid)
          --create-user        Create local user
          --translate-sid      Convert SID to name of principal
          --lookup-sid         Translate --rid in --local-domain to a SID
          --lookup-rids        Translate --rids to names in domain specified by --local-domain
          --lookup-names       Translate --names to rids in domain specified by --local-domain
          --lookup-domain      Lookup domain SID for --local-domain
          --change-password    Change password of user. Leave current password empty to supply NT Hash instead
          --reset-password     Reset/force change password of user
          --make-admin         Add user to local administrators group
          --delete-user        Delete local user specified by --user-rid
          --query-user         Query local user specified by --user-rid or --name

    SAMR options:
          --sid      <SID>      Target SID of format "S-1-5-...
          --rid      <RID>      Target RID
          --user-rid <RID>      Only used when removing local user from a group
          --rids     <LIST>     Comma-separated list of RIDs to lookup in specified domain
          --local-domain <name> Samr domain name to target. Typically "Builtin" or NetBios name of machine
                                Changes the domain for the action from the default for most actions
          --name <string>       Username of local account to create or query
          --names <LIST>        Comma-separated list of samAccountNames to lookup in specified domain
          --user-pass <string>  Password for --create-user or current password for --change-password.
                                Mutually exclusive with --old-hash
          --netbios <string>    NetBios computername
          --alias               Use the "alias" version of add/remove/list member commands
          --limit <int>         Indication of how many users return max
          --old-hash <hex>      Current NT Hash which is used with --change-password
          --new-pass <string>   New password for --change-password. Skip parameter to trigger prompt.
`

func translateSid(rpccon *mssamr.RPCCon, handle *mssamr.SamrHandle, sid *SID) (name string, err error) {
	var localDomainId *msdtyp.SID
	// Determine type of SID
	auth := sid.v.GetAuthority()
	if (auth == 5) && (sid.v.SubAuthorities[0] == 21) { // NT System authority, Domain SID
		if len(sid.v.SubAuthorities) == 4 {
			// Domain SID without a RID
			// Return error directly if only provided a domainSID without the RID part
			// It is not possible to lookup a domain SID using SAMR except enumerating the domains, looking up the names and comparing with the output
			err = fmt.Errorf("Cannot translate a domain SID. Must be a RID part at the end.")
			return
		}
	}

	// Extract domainId from SID
	parts := strings.Split(sid.s, "-")
	domainSidStr := strings.Join(parts[:len(parts)-1], "-")
	localDomainId, err = msdtyp.ConvertStrToSID(domainSidStr)
	if err != nil {
		log.Errorln(err)
		return
	}
	log.Infof("Trying to lookup the SID: %s\n", sid.s)
	var localDomainHandle *mssamr.SamrHandle
	localDomainHandle, err = rpccon.SamrOpenDomain(handle, 0, localDomainId)
	if err != nil {
		if err == mssamr.ResponseCodeMap[mssamr.StatusNoSuchDomain] {
			log.Noticeln("Domain does not exist on this machine")
			return
		}
		log.Errorln(err)
		return
	}
	rid, err := strconv.ParseUint(parts[len(parts)-1], 10, 32)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer rpccon.SamrCloseHandle(localDomainHandle)
	var names []mssamr.SamrRidMapping
	names, err = rpccon.SamrLookupIdsInDomain(localDomainHandle, []uint32{uint32(rid)})
	if err != nil {
		if err == mssamr.ResponseCodeMap[mssamr.StatusNoneMapped] {
			err = fmt.Errorf("SID was not found in domain. RID part was unknown")
		}
		log.Errorln(err)
		return
	}
	if len(names) > 0 {
		name = names[0].Name
	}
	return
}

func getSamrNetbiosDomain(rpccon *mssamr.RPCCon, handle *mssamr.SamrHandle) (netbiosName string, err error) {
	var domains []string
	domains, err = rpccon.SamrEnumDomains(handle)
	var otherDomains []string
	for _, domain := range domains {
		if domain != "Builtin" {
			otherDomains = append(otherDomains, domain)
		}
	}
	if len(otherDomains) != 1 {
		err = fmt.Errorf("Failed to automatically identity the Netbios domain. Select the correct domain and use it as an argument from the available domains: %v\n", domains)
		return
	}
	netbiosName = strings.ToLower(otherDomains[0])
	return
}

func lookupNamesInDomain(rpccon *mssamr.RPCCon, domainHandle *mssamr.SamrHandle, names []string) (items []mssamr.SamrRidMapping, err error) {
	items, err = rpccon.SamrLookupNamesInDomain(domainHandle, names)
	if err != nil {
		if err != mssamr.ResponseCodeMap[mssamr.StatusSomeNotMapped] {
			log.Errorln(err)
			return
		}
	}
	return
}

func lookupNames(rpccon *mssamr.RPCCon, handle *mssamr.SamrHandle, domainName string, names []string) (items []mssamr.SamrRidMapping, err error) {
	var domainId *msdtyp.SID
	domainId, err = rpccon.SamrLookupDomain(handle, domainName)
	if err != nil {
		log.Errorln(err)
		return
	}
	var domainHandle *mssamr.SamrHandle
	domainHandle, err = rpccon.SamrOpenDomain(handle, 0, domainId)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer rpccon.SamrCloseHandle(domainHandle)
	return lookupNamesInDomain(rpccon, domainHandle, names)
}

func handleSamr(args *userArgs) (err error) {
	var passBytes []byte
	numActions := 0
	if args.enumDomains {
		numActions++
	}
	if args.addToLocalGroup {
		if args.rid == 0 {
			log.Errorln("Must specify a --rid of local group/alias to add a member")
			return
		}
		if args.alias {
			if args.sid.v == nil {
				log.Errorln("Must specify a --sid to add member to alias")
				return
			}
		} else if args.userRid == 0 {
			log.Errorln("Must specify a --user-rid which should be added to the local group")
			return
		}
		numActions++
	}
	if args.listLocalAdmins {
		args.rid = 544
		numActions++
	}
	if args.listGroupMembers {
		numActions++
	}
	if args.removeFromLocalGroup {
		if !args.alias {
			if args.userRid == 0 {
				log.Errorln("Must specify --user-rid when removing a local user from a local group")
				return
			}
		} else if args.sid.v == nil {
			log.Errorln("Must specify a --sid to remove from alias")
			return
		}
		numActions++
	}
	if args.createUser {
		if args.name == "" {
			log.Errorln("Must specify a username (--name) for the new account")
			return
		}
		if args.userPassword == "" {
			fmt.Printf("Enter password for new account: ")
			passBytes, err = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				log.Errorln(err)
				return
			}
			args.userPassword = string(passBytes)
		}
		numActions++
	}
	if args.lookupRids {
		numActions++
		if len(args.rids) == 0 {
			log.Errorln("Must specify --rids when looking up rids")
			return
		}
	}
	if args.lookupNames {
		numActions++
		if len(args.names) == 0 {
			log.Errorln("Must specify --names when looking up names")
			return
		}
	}
	if args.lookupSid {
		if args.localDomain == "" {
			log.Errorln("Must specify a --local-domain to search for the --rid")
			return
		}
		if args.rid == 0 {
			log.Errorln("Must specify --rid to lookup in domain")
			return
		}
		numActions++
	}
	if args.lookupDomain {
		if args.localDomain == "" {
			log.Errorln("Must specify a --local-domain to lookup")
			return
		}
		numActions++
	}
	if args.listGroups {
		numActions++
	}
	if args.resetUserPassword {
		if args.sid.v == nil {
			if (args.localDomain == "") || (args.rid == 0) {
				log.Errorln("Must specify either user domain (--local-domain) and user RID (--rid) or user SID (--sid) when changing password")
				return
			}
		}
		numActions++
	}
	if args.changeUserPassword {
		// Check for username
		if args.name == "" {
			log.Errorln("Must specify a samAccountName with --name when changing password")
			return
		}
		if (args.userPassword != "") && (args.oldNTHash != "") {
			log.Errorln("--old-hash and --user-pass are mutually exclusive")
			return
		}
		numActions++
	}
	if args.enumUsers {
		numActions++
	}
	if args.translateSid {
		if args.sid.s == "" {
			log.Errorln("Must specify a --sid to convert to a name")
			return
		}
		numActions++
	}
	if args.addLocalAdmin {
		if args.sid.s == "" {
			log.Errorln("Must specify a --sid to add as local admin")
			return
		}
		numActions++
	}
	if args.deleteUser {
		if args.userRid == 0 {
			log.Errorln("Must specify --user-rid when removing a local user")
			return
		}
		numActions++
	}
	if args.queryUser {
		if (args.userRid == 0) && (args.name == "") {
			log.Errorln("Must specify --user-rid or --name when querying a local user")
			return
		}
		numActions++
	}
	if numActions != 1 {
		fmt.Println("Must specify ONE action. No more, no less")
		flags.Usage()
		return
	}

	if (args.listGroupMembers || args.removeFromLocalGroup) && (args.rid == 0) {
		log.Errorln("Must specify a --rid of local group to list or remove members")
		return
	}

	// Make the connection!
	err = makeConnection(&args.connArgs)
	if err != nil {
		log.Errorln(err)
		return
	}
	conn := args.opts.c
	defer conn.Close()

	share := "IPC$"
	err = conn.TreeConnect(share)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer conn.TreeDisconnect(share)
	f, err := conn.OpenFile(share, mssamr.MSRPCSamrPipe)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer f.CloseFile()

	bind, err := dcerpc.Bind(f, mssamr.MSRPCUuidSamr, mssamr.MSRPCSamrMajorVersion, mssamr.MSRPCSamrMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		log.Errorln("Failed to bind to service")
		log.Errorln(err)
		return
	}

	rpccon := mssamr.NewRPCCon(bind)
	fmt.Println("Successfully performed Bind to Samr service")

	if args.changeUserPassword {
		var currPassBytes []byte
		var newPassBytes []byte
		var currNTHash []byte
		var currHexStringBytes []byte
		if args.oldNTHash != "" {
			currNTHash, err = hex.DecodeString(args.oldNTHash)
			if err != nil {
				log.Errorln(err)
				return
			}
		} else if args.userPassword == "" { // No pass or NT hash specified
			fmt.Printf("Enter current account password (leave empty for NT Hash): ")
			currPassBytes, err = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				log.Errorln(err)
				return
			}
			if len(currPassBytes) > 0 {
				args.userPassword = string(currPassBytes)
			} else {
				fmt.Printf("Enter account's NT Hash: ")
				currHexStringBytes, err = term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err != nil {
					log.Errorln(err)
					return
				}
				currNTHash, err = hex.DecodeString(string(currHexStringBytes))
				if err != nil {
					log.Errorln(err)
					return
				}
			}
		}
		if args.newPass == "" {
			fmt.Printf("Enter new password: ")
			newPassBytes, err = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				log.Errorln(err)
				return
			}
			args.newPass = string(newPassBytes)
		}
		err = rpccon.SamrChangePassword2(args.name, args.userPassword, args.newPass, currNTHash)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Successfully changed password!")
		return
	}

	// The rest of the commands requires a connect handle

	handle, err := rpccon.SamrConnect5("")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer rpccon.SamrCloseHandle(handle)

	if args.enumDomains {
		domains, err2 := rpccon.SamrEnumDomains(handle)
		err = err2
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Domains:")
		for _, name := range domains {
			fmt.Println(name)
		}
		return
	} else if args.enumUsers {
		var users []mssamr.SamprRidEnumeration
		if args.localDomain != "" {
			var domainId *msdtyp.SID
			domainId, err = rpccon.SamrLookupDomain(handle, args.localDomain)
			if err != nil {
				log.Errorln(err)
				return
			}
			var domainHandle *mssamr.SamrHandle
			domainHandle, err = rpccon.SamrOpenDomain(handle, 0, domainId)
			if err != nil {
				log.Errorln(err)
				return
			}
			defer rpccon.SamrCloseHandle(domainHandle)
			users, err = rpccon.SamrEnumDomainUsers(domainHandle, mssamr.UserNormalAccount, uint32(args.limit*39))
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Printf("Found %d Domain Users:\n", len(users))
		} else {
			users, err = rpccon.ListLocalUsers(args.netbiosComputerName, uint32(args.limit))
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Printf("Found %d Local Users:\n", len(users))
		}
		for _, user := range users {
			fmt.Printf("Rid: %d, Name: %s\n", user.RelativeId, user.Name)
		}
		return
	} else if args.createUser {
		var sid string
		sid, err = rpccon.CreateLocalUser(args.name, args.userPassword, args.netbiosComputerName)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Printf("Created user %s with SID: %s\n", args.name, sid)
		return
	} else if args.addLocalAdmin {
		err = rpccon.AddLocalAdmin(args.sid.s)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Added principal as local admin")
		return
	} else if args.lookupRids {
		domainName := args.netbiosComputerName
		if args.localDomain != "" {
			domainName = args.localDomain
		}
		if domainName == "" {
			domainName, err = getSamrNetbiosDomain(rpccon, handle)
			if err != nil {
				log.Errorln(err)
				return
			}
		}
		var domainId *msdtyp.SID
		domainId, err = rpccon.SamrLookupDomain(handle, domainName)
		if err != nil {
			log.Errorln(err)
			return
		}
		var domainHandle *mssamr.SamrHandle
		domainHandle, err = rpccon.SamrOpenDomain(handle, 0, domainId)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer rpccon.SamrCloseHandle(domainHandle)
		var items []mssamr.SamrRidMapping
		items, err = rpccon.SamrLookupIdsInDomain(domainHandle, args.rids)
		if err != nil {
			if err != mssamr.ResponseCodeMap[mssamr.StatusSomeNotMapped] {
				log.Errorln(err)
				return
			}
		}
		fmt.Println("Translated RIDs:")
		for _, item := range items {
			fmt.Printf("Name: %s, RID: %d, Use: %s\n", item.Name, item.RID, mssamr.SidType[item.Use])
		}
		return
	} else if args.lookupNames {
		domainName := args.netbiosComputerName
		if args.localDomain != "" {
			domainName = args.localDomain
		}
		if domainName == "" {
			domainName, err = getSamrNetbiosDomain(rpccon, handle)
			if err != nil {
				log.Errorln(err)
				return
			}
		}
		var items []mssamr.SamrRidMapping
		items, err = lookupNames(rpccon, handle, domainName, args.names)
		fmt.Println("Translated Names:")
		for _, item := range items {
			fmt.Printf("Name: %s, RID: %d, Use: %s\n", item.Name, item.RID, mssamr.SidType[item.Use])
		}
		return
	} else if args.lookupSid {
		domainId, err2 := rpccon.SamrLookupDomain(handle, args.localDomain)
		err = err2
		if err != nil {
			log.Errorln(err)
			return
		}
		handleLocal, err2 := rpccon.SamrOpenDomain(handle, 0, domainId)
		err = err2
		if err != nil {
			log.Errorln(err)
			return
		}
		defer rpccon.SamrCloseHandle(handleLocal)
		sid, err2 := rpccon.SamrRidToSid(handleLocal, uint32(args.rid))
		err = err2
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Printf("SID of the RID (%d): %s\n", args.rid, sid.ToString())
		return
	} else if args.lookupDomain {
		domainId, err2 := rpccon.SamrLookupDomain(handle, args.localDomain)
		err = err2
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Printf("Domain SID: %s\n", domainId.ToString())
		return
	} else if args.resetUserPassword {
		if args.newPass == "" {
			fmt.Printf("Enter new password: ")
			passBytes, err = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				log.Errorln(err)
				return
			}
			args.newPass = string(passBytes)
		}

		var localDomainId *msdtyp.SID
		if args.sid.v != nil {
			// Extract domainId from SID
			parts := strings.Split(args.sid.s, "-")
			domainSidStr := strings.Join(parts[:len(parts)-1], "-")
			localDomainId, err = msdtyp.ConvertStrToSID(domainSidStr)
			if err != nil {
				log.Errorln(err)
				return
			}
			args.rid = uint64(args.sid.v.SubAuthorities[args.sid.v.NumAuth-1])
		} else {
			localDomainId, err = rpccon.SamrLookupDomain(handle, args.localDomain)
			if err != nil {
				log.Errorln(err)
				return
			}
		}
		var handleLocalDomain *mssamr.SamrHandle
		handleLocalDomain, err = rpccon.SamrOpenDomain(handle, 0, localDomainId)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer rpccon.SamrCloseHandle(handleLocalDomain)

		var userHandle *mssamr.SamrHandle
		userHandle, err = rpccon.SamrOpenUser(handleLocalDomain, 0, uint32(args.rid))
		if err != nil {
			log.Errorln(err)
			return
		}
		defer rpccon.SamrCloseHandle(userHandle)
		input := &mssamr.SamrUserInfoInput{
			NewPassword: args.newPass,
		}
		err = rpccon.SamrSetUserInfo2(userHandle, input)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Updated the user's password")
		return
	} else if args.listGroups {
		var groups []mssamr.SamprRidEnumeration
		domainName := args.netbiosComputerName
		if args.localDomain != "" {
			// prefer --local-domain over --netbios
			domainName = args.localDomain
		}
		if args.alias {
			groups, err = rpccon.ListDomainAliases(domainName)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Aliases:")
		} else {
			groups, err = rpccon.ListLocalGroups(domainName)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Groups:")
		}
		for _, group := range groups {
			fmt.Printf("Rid: %d, Name: %s\n", group.RelativeId, group.Name)
		}
		return
	} else if args.deleteUser {
		err = rpccon.DeleteLocalUser(uint32(args.userRid), args.netbiosComputerName)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("User deleted!")
		return
	} else if args.queryUser {
		var info *mssamr.SamprUserAllInformation
		domainName := args.netbiosComputerName
		if args.localDomain != "" {
			domainName = args.localDomain
		}
		if domainName == "" {
			domainName, err = getSamrNetbiosDomain(rpccon, handle)
			if err != nil {
				log.Errorln(err)
				return
			}
		}

		userRid := uint32(args.userRid)
		if args.userRid == 0 {
			// Lookup user Rid in domain
			var items []mssamr.SamrRidMapping
			items, err = lookupNames(rpccon, handle, domainName, []string{args.name})
			if err != nil {
				if err == mssamr.ResponseCodeMap[mssamr.StatusNoneMapped] {
					err = fmt.Errorf("samAccountName not found in domain")
				}
				log.Errorln(err)
				return
			}
			userRid = items[0].RID

		}
		info, err = rpccon.QueryLocalUserAllInfo(userRid, domainName)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Printf("Username: %s\nDescription: %s\nUser Rid: %d\nLast Logon: %s\nPassword Last Changed: %s\nPassword Can Change: %s\nUserAcountControl: 0x%x\nBadPwdCount: %d\nLogonCount: %d\nPassword expired: %v\n", info.Username, info.AdminComment, info.UserId, info.LastLogon.ToString(), info.PasswordLastSet.ToString(), info.PasswordCanChange.ToString(), info.UserAccountControl, info.BadPasswordCount, info.LogonCount, info.PasswordExpired)
		return
	} else if args.translateSid {
		name := ""
		name, err = translateSid(rpccon, handle, &args.sid)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println(name)
		return
	}
	if !(args.listLocalAdmins || args.addToLocalGroup || args.removeFromLocalGroup || args.listGroupMembers) {
		fmt.Println("No action handler")
		return
	}
	// Operation on local group
	var domainName string
	if args.listLocalAdmins {
		domainName = "Builtin"
		args.alias = true
	} else {
		if args.localDomain != "" {
			domainName = args.localDomain
		} else if args.netbiosComputerName != "" {
			domainName = args.netbiosComputerName
		} else {
			var domains []string
			domains, err = rpccon.SamrEnumDomains(handle)
			var otherDomains []string
			for _, domain := range domains {
				if domain != "Builtin" {
					otherDomains = append(otherDomains, domain)
				}
			}
			if len(otherDomains) != 1 {
				err = fmt.Errorf("Failed to automatically identity the Netbios domain. Select the correct domain and use it as an argument from the available domains: %v\n", domains)
				log.Errorln(err)
				return
			}
			domainName = otherDomains[0]
		}
	}

	domainId, err := rpccon.SamrLookupDomain(handle, domainName)
	if err != nil {
		log.Errorln(err)
		return
	}
	handleDomain, err := rpccon.SamrOpenDomain(handle, 0, domainId)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer rpccon.SamrCloseHandle(handleDomain)
	var handleLocalGroup *mssamr.SamrHandle
	if args.alias {
		handleLocalGroup, err = rpccon.SamrOpenAlias(handleDomain, 0, uint32(args.rid))
	} else {
		handleLocalGroup, err = rpccon.SamrOpenGroup(handleDomain, 0, uint32(args.rid))
	}
	if err != nil {
		log.Errorln(err)
		return
	}
	defer rpccon.SamrCloseHandle(handleLocalGroup)

	if args.addToLocalGroup {
		if args.alias {
			err = rpccon.SamrAddMemberToAlias(handleLocalGroup, args.sid.v)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Member added to alias")
		} else {
			err = rpccon.SamrAddMemberToGroup(handleLocalGroup, uint32(args.userRid), 0)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Member added to group")
		}
		return
	} else if args.removeFromLocalGroup {
		if args.alias {
			err = rpccon.SamrRemoveMemberFromAlias(handleLocalGroup, args.sid.v)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Member removed from alias")
		} else {
			err = rpccon.SamrRemoveMemberFromGroup(handleLocalGroup, uint32(args.userRid))
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Member removed from group")
		}
		return
	} else if args.listLocalAdmins {
		var members []msdtyp.SID
		members, err = rpccon.SamrGetMembersInAlias(handleLocalGroup)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Local admins:")
		for _, member := range members {
			fmt.Printf("Member: %s\n", member.ToString())
		}
		return
	} else if args.listGroupMembers {
		if args.alias {
			var members []msdtyp.SID
			members, err = rpccon.SamrGetMembersInAlias(handleLocalGroup)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Members in alias:")
			for _, member := range members {
				fmt.Printf("Member: %s\n", member.ToString())
			}
		} else {
			var members []mssamr.SamrGroupMember
			members, err = rpccon.SamrGetMembersInGroup(handleLocalGroup)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Members in group:")
			for _, member := range members {
				fmt.Printf("Member RID: %d\n", member.RID)
			}
		}
		return
	}
	return
}
