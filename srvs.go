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
	"fmt"
	"os"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/mslsad"
	"github.com/jfjallid/go-smb/smb/dcerpc/mssrvs"
)

var helpSrvsOptions = `
    Usage: ` + os.Args[0] + ` --srvs [options] <action>
    ` + helpConnectionOptions + `
    Action:
          --enum-sessions      List sessions (supported levels 0, 10, 502. Default 10)
          --enum-shares        List SMB Shares
          --get-info           Get Server info (supported levels 100,101,102. Default 101. 102 requires admin privileges)
          --get-file-security  Get security descriptor for file/folder on specified share

    SRVS options:
          --level <int>        Level of information to return
          --share <string>     Name of share to query for security descriptor
          --path  <string>     Path to file or folder to get security descriptor for
`

func getShares(rpccon *mssrvs.RPCCon, hostname string) (shares []string, err error) {
	var result []mssrvs.NetShare
	result, err = rpccon.NetShareEnumAll(hostname)
	if err != nil {
		log.Errorln(err)
		return
	}
	for _, netshare := range result {
		name := netshare.Name[:len(netshare.Name)]
		if (netshare.TypeId == mssrvs.StypeDisktree) || (netshare.TypeId == mssrvs.StypeIPC) {
			shares = append(shares, name)
		}
	}
	return
}

func getSrvsSessions(rpccon *mssrvs.RPCCon, level int) (sessions []string, err error) {
	var result *mssrvs.SessionEnum
	result, err = rpccon.NetSessionEnum("", "", level)
	if err != nil {
		log.Errorln(err)
		return
	}
	switch result.Level {
	case 0:
		sic := result.SessionInfo.(*mssrvs.SessionInfoContainer0)
		for i := 0; i < int(sic.EntriesRead); i++ {
			si := sic.Buffer[i]
			sessions = append(sessions, fmt.Sprintf("host: %s\n", si.Cname))
		}
	case 10:
		sic := result.SessionInfo.(*mssrvs.SessionInfoContainer10)
		for i := 0; i < int(sic.EntriesRead); i++ {
			si := sic.Buffer[i]
			sessions = append(sessions, fmt.Sprintf("host: %s, user: %s, active: %6d, idle: %6d\n", si.Cname, si.Username, si.Time, si.IdleTime))
		}
	case 502:
		sic := result.SessionInfo.(*mssrvs.SessionInfoContainer502)
		for i := 0; i < int(sic.EntriesRead); i++ {
			si := sic.Buffer[i]
			guest := si.UserFlags&0x1 == 0x1
			noEnc := si.UserFlags&0x2 == 0x2

			sessions = append(sessions, fmt.Sprintf("host: %s, user: %s, clienttype %s, transport: %s, guest: %v, noEnc: %v, active: %6d, idle: %6d, numOpens: %6d\n", si.Cname, si.Username, si.ClType, si.Transport, guest, noEnc, si.Time, si.IdleTime, si.NumOpens))
		}
	default:
		sessions = append(sessions, fmt.Sprintf("Unknown result with level %d\n", result.Level))
	}
	return
}

func getServerInfo(rpccon *mssrvs.RPCCon, level int) (info []string, err error) {
	var result *mssrvs.NetServerInfo
	result, err = rpccon.NetServerGetInfo("", level)
	if err != nil {
		log.Errorln(err)
		return
	}
	switch result.Level {
	case 100:
		si := result.Pointer.(*mssrvs.NetServerInfo100)
		info = append(info, fmt.Sprintf("Server Name: %s\n", si.Name))
	case 101:
		si := result.Pointer.(*mssrvs.NetServerInfo101)
		info = append(info, fmt.Sprintf("Version Major: %d\n", si.VersionMajor))
		info = append(info, fmt.Sprintf("Version Minor: %d\n", si.VersionMinor))
		info = append(info, fmt.Sprintf("Server Name: %s\n", si.Name))
		info = append(info, fmt.Sprintf("Server Comment: %s\n", si.Comment))
	case 102:
		si := result.Pointer.(*mssrvs.NetServerInfo102)
		info = append(info, fmt.Sprintf("Version Major: %d\n", si.VersionMajor))
		info = append(info, fmt.Sprintf("Version Minor: %d\n", si.VersionMinor))
		info = append(info, fmt.Sprintf("Server Name: %s\n", si.Name))
		info = append(info, fmt.Sprintf("Server Comment: %s\n", si.Comment))
		info = append(info, fmt.Sprintf("Server UserPath: %s\n", si.Userpath))
		info = append(info, fmt.Sprintf("Simultaneous Users: %d\n", si.Users))
	default:
		info = append(info, fmt.Sprintf("Unknown result with level %d\n", result.Level))
	}
	return
}

func handleSrvs(args *userArgs) (err error) {
	numActions := 0
	if args.enumSessions {
		if !isFlagSet("level") {
			args.level = 10
		} else {
			switch args.level {
			case 0:
			case 10:
			case 502:
			default:
				fmt.Println("Invalid level for srvs --enum-sessions")
				return
			}
		}
		numActions++
	}
	if args.enumShares {
		numActions++
	}
	if args.getServerInfo {
		if !isFlagSet("level") {
			args.level = 101
		} else {
			switch args.level {
			case 100:
			case 101:
			case 102:
			default:
				fmt.Println("Invalid level for srvs --get-info")
				return
			}
		}
		numActions++
	}
	if args.getFileSecurity {
		if args.share == "" {
			fmt.Println("Must specify a --share to retrieve file security info")
			return
		}
		if args.filePath == "" {
			fmt.Println("No --path specifed so using a default path of \\")
			args.filePath = "\\"
		}
		numActions++
	}
	if numActions != 1 {
		fmt.Println("Must specify ONE action. No more, no less")
		flags.Usage()
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
	f, err := conn.OpenFile(share, mssrvs.MSRPCSrvSvcPipe)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer f.CloseFile()

	bind, err := dcerpc.Bind(f, mssrvs.MSRPCUuidSrvSvc, mssrvs.MSRPCSrvSvcMajorVersion, mssrvs.MSRPCSrvSvcMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		log.Errorln("Failed to bind to service")
		log.Errorln(err)
		return
	}

	rpccon := mssrvs.NewRPCCon(bind)
	fmt.Println("Successfully performed Bind to Srvs service")

	var rpcconLsat *mslsad.RPCCon
	if args.resolveSids {
		var f2 *smb.File
		f2, err = conn.OpenFile(share, mslsad.MSRPCLsaRpcPipe)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer f2.CloseFile()
		var bind2 *dcerpc.ServiceBind
		bind2, err = dcerpc.Bind(f2, mslsad.MSRPCUuidLsaRpc, mslsad.MSRPCLsaRpcMajorVersion, mslsad.MSRPCLsaRpcMinorVersion, dcerpc.MSRPCUuidNdr)
		if err != nil {
			log.Errorln("Failed to bind to LSARPC service")
			log.Errorln(err)
			return
		}

		rpcconLsat = mslsad.NewRPCCon(bind2)
	}

	if args.enumSessions {
		var sessions []string
		sessions, err = getSrvsSessions(rpccon, args.level)
		if err != nil {
			log.Errorln(err)
			return
		}
		for _, item := range sessions {
			fmt.Println(item)
		}
		return
	} else if args.enumShares {
		var shares []string
		shares, err = getShares(rpccon, args.host)
		if err != nil {
			log.Errorln(err)
			return
		}
		for _, name := range shares {
			fmt.Println(name)
		}
		return
	} else if args.getServerInfo {
		var info []string
		info, err = getServerInfo(rpccon, args.level)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("ServerInfo:")
		for _, item := range info {
			fmt.Print(item)
		}
	} else if args.getFileSecurity {
		if strings.Contains(args.filePath, ":") {
			// Remove drive prefix
			args.filePath = strings.SplitN(args.filePath, ":", 2)[1]
			log.Infoln("Removed leading drive letter from file path")
		}

		var sd *msdtyp.SecurityDescriptor
		var names []string
		sd, names, err = getFileSecurity(rpccon, rpcconLsat, args.share, args.filePath, args.resolveSids)
		if err != nil {
			log.Errorln(err)
			return
		}

		fmt.Printf("Security information for share: %s, file: %s\n", args.share, args.filePath)
		var sb strings.Builder
		if sd.OwnerSid != nil {
			fmt.Fprintf(&sb, "OwnerSid: %s", sd.OwnerSid.ToString())
			if args.resolveSids && len(names) > 0 {
				fmt.Fprintf(&sb, "(%s)", names[0])
			}
			sb.WriteRune('\n')
			names = names[1:]
		}
		if sd.GroupSid != nil {
			fmt.Fprintf(&sb, "GroupSid: %s", sd.GroupSid.ToString())
			if args.resolveSids && len(names) > 0 {
				fmt.Fprintf(&sb, "(%s)", names[0])
			}
			sb.WriteRune('\n')
			names = names[1:]
		}
		if sd.Dacl != nil {
			fmt.Fprintln(&sb, "DACL entries:")
			daclPermissions := sd.Dacl.Permissions()
			for _, item := range daclPermissions.Entries {
				fmt.Fprintf(&sb, "AceType: %s\nAceFlags: %s\nSid: %s\n", item.AceType, item.AceFlagStrings, item.Sid)
				if args.resolveSids && len(names) > 0 {
					fmt.Fprintf(&sb, "Name: %s\n", names[0])
					names = names[1:]
				}
				fmt.Fprintf(&sb, "Permissions: ")
				permissions := ""
				for _, perm := range item.Permissions {
					permissions = fmt.Sprintf("%s,%s", permissions, perm)
				}
				sb.WriteString(strings.TrimPrefix(permissions, ","))
				sb.WriteString("\n\n")
			}
		}
		if sd.Sacl != nil {
			fmt.Fprintln(&sb, "SACL entries:")
			saclPermissions := sd.Sacl.Permissions()
			for _, item := range saclPermissions.Entries {
				fmt.Fprintf(&sb, "AceType: %s\nAceFlags: %s\nSid: %s\n", item.AceType, item.AceFlagStrings, item.Sid)
				if args.resolveSids && len(names) > 0 {
					fmt.Fprintf(&sb, "Name: %s\n", names[0])
					names = names[1:]
				}
				fmt.Fprintf(&sb, "Permissions: ")
				permissions := ""
				for _, perm := range item.Permissions {
					permissions = fmt.Sprintf("%s,%s", permissions, perm)
				}
				sb.WriteString(strings.TrimPrefix(permissions, ","))
				sb.WriteString("\n\n")
			}
		}
		fmt.Println(sb.String())
	}
	return
}

func getFileSecurity(rpccon *mssrvs.RPCCon, rpcconLsat *mslsad.RPCCon, share, path string, resolveSids bool) (sd *msdtyp.SecurityDescriptor, names []string, err error) {
	sd, err = rpccon.NetGetFileSecurity(share, path)
	if err != nil {
		log.Errorln(err)
		return
	}
	if resolveSids {
		var sids []string
		if sd.OwnerSid != nil {
			sids = append(sids, sd.OwnerSid.ToString())
		}
		if sd.GroupSid != nil {
			sids = append(sids, sd.GroupSid.ToString())
		}
		if sd.Dacl != nil {
			perms := sd.Dacl.Permissions()
			for _, item := range perms.Entries {
				sids = append(sids, item.Sid)
			}
		}
		if sd.Sacl != nil {
			perms := sd.Sacl.Permissions()
			for _, item := range perms.Entries {
				sids = append(sids, item.Sid)
			}
		}
		// Attempt to translate SIDs
		res, err := rpcconLsat.LsarLookupSids2(1, sids)
		if err != nil {
			log.Errorln(err)
		} else {
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
	}
	return
}
