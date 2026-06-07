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

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mslsad"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb"
)

var helpSrvsOptions = `
    Usage: ` + os.Args[0] + ` srvs [options] <action>
    ` + helpConnectionOptions + `
    Action:
          --enum-sessions      List sessions (supported levels 0, 10, 502. Default 10)
          --enum-shares        List SMB Shares (supported levels 1, 501, 502. Default 1)
          --get-share-info     Get info for a single share (supported levels 0, 1, 2, 501, 502. Default 2)
          --set-share-info     Modify a share. Specify --share and one of --comment or --share-flags
          --enum-disks         List disk drives on the server
          --get-info           Get Server info (supported levels 100,101,102. Default 101. 102 requires admin privileges)
          --get-file-security  Get security descriptor for file/folder on specified share

    SRVS options:
          --level <int>        Level of information to return
          --share <string>     Name of share to query or modify
          --path  <string>     Path to file or folder to get security descriptor for.
                               Omitted, "\", "/" or "" resolve to the share root
          --comment <string>   New comment/remark to set with --set-share-info
          --share-flags <uint> New share flags to set with --set-share-info (accepts 0x hex)
`

// formatUses renders a SHARE_INFO uses counter, mapping the "no limit"
// sentinel (0xffffffff) to a readable string.
func formatUses(v uint32) string {
	if v == 0xffffffff {
		return "unlimited"
	}
	return fmt.Sprintf("%d", v)
}

// appendNetShareFields writes the NetShare fields populated by the given info
// level to sb. The security descriptor (level 502) is handled separately by
// appendNetShare so it can resolve SIDs.
func appendNetShareFields(sb *strings.Builder, ns *mssrvs.NetShare, level int) {
	fmt.Fprintf(sb, "Name: %s\n", ns.Name)
	if level == 0 {
		return
	}
	fmt.Fprintf(sb, "Type: %s\n", ns.Type)
	fmt.Fprintf(sb, "Comment: %s\n", ns.Comment)
	switch level {
	case 501:
		fmt.Fprintf(sb, "Flags: 0x%08x\n", ns.Flags)
	case 2, 502:
		fmt.Fprintf(sb, "Permissions: 0x%08x\n", ns.Permissions)
		fmt.Fprintf(sb, "Max Uses: %s\n", formatUses(ns.MaxUses))
		fmt.Fprintf(sb, "Current Uses: %d\n", ns.CurrentUses)
		fmt.Fprintf(sb, "Path: %s\n", ns.Path)
	}
}

// appendNetShare writes a complete human-readable representation of ns at the
// given info level to sb, including the security descriptor (level 502) with
// optional SID resolution via rpcconLsat.
func appendNetShare(sb *strings.Builder, rpcconLsat *mslsad.RPCCon, ns *mssrvs.NetShare, level int, resolveSids bool) {
	appendNetShareFields(sb, ns, level)
	if ns.SecurityDescriptor != nil {
		fmt.Fprintln(sb, "Security descriptor:")
		var names []string
		if resolveSids {
			names = resolveSidStrings(rpcconLsat, collectSidsFromSD(ns.SecurityDescriptor))
		}
		appendSecurityDescriptor(sb, ns.SecurityDescriptor, names, resolveSids, nil)
	}
}

// getSharesFormatted enumerates the shares on host at the given info level and
// returns one formatted block per share. Supported levels are 1, 501 and 502.
func getSharesFormatted(rpccon *mssrvs.RPCCon, rpcconLsat *mslsad.RPCCon, host string, level int, resolveSids bool) (lines []string, err error) {
	var shares []mssrvs.NetShare
	shares, err = rpccon.NetShareEnumAllExt(host, level)
	if err != nil {
		log.Errorln(err)
		return
	}
	for i := range shares {
		var sb strings.Builder
		appendNetShare(&sb, rpcconLsat, &shares[i], level, resolveSids)
		lines = append(lines, sb.String())
	}
	return
}

// getShareInfoFormatted retrieves info for a single named share at the given
// info level and returns it as a formatted block. Supported levels are 0, 1, 2,
// 501 and 502.
func getShareInfoFormatted(rpccon *mssrvs.RPCCon, rpcconLsat *mslsad.RPCCon, host, share string, level int, resolveSids bool) (out string, err error) {
	var ns *mssrvs.NetShare
	ns, err = rpccon.NetShareGetInfoExt(host, share, level)
	if err != nil {
		log.Errorln(err)
		return
	}
	if ns == nil {
		return
	}
	var sb strings.Builder
	appendNetShare(&sb, rpcconLsat, ns, level, resolveSids)
	out = sb.String()
	return
}

func getSrvsSessions(rpccon *mssrvs.RPCCon, level int) (sessions []string, err error) {
	var result *mssrvs.SessionEnumStruct
	result, err = rpccon.NetSessionEnum("", "", level)
	if err != nil {
		log.Errorln(err)
		return
	}
	switch result.Level {
	case 0:
		sic := result.Level0
		for i := 0; i < int(sic.EntriesRead); i++ {
			si := sic.Buffer[i]
			sessions = append(sessions, fmt.Sprintf("host: %s\n", si.Cname))
		}
	case 10:
		sic := result.Level10
		for i := 0; i < int(sic.EntriesRead); i++ {
			si := sic.Buffer[i]
			sessions = append(sessions, fmt.Sprintf("host: %s, user: %s, active: %6d, idle: %6d\n", si.Cname, si.Username, si.Time, si.IdleTime))
		}
	case 502:
		sic := result.Level502
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
	var result *mssrvs.ServerInfoUnion
	result, err = rpccon.NetServerGetInfo("", level)
	if err != nil {
		log.Errorln(err)
		return
	}
	switch result.Level {
	case 100:
		si := result.Level100
		info = append(info, fmt.Sprintf("Server Name: %s\n", si.Name))
	case 101:
		si := result.Level101
		info = append(info, fmt.Sprintf("Version Major: %d\n", si.VersionMajor))
		info = append(info, fmt.Sprintf("Version Minor: %d\n", si.VersionMinor))
		info = append(info, fmt.Sprintf("Server Name: %s\n", si.Name))
		info = append(info, fmt.Sprintf("Server Comment: %s\n", si.Comment))
	case 102:
		si := result.Level102
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

func validateSrvsActions(args *userArgs) error {
	return exactlyOneAction(
		args.enumSessions,
		args.enumShares,
		args.getShareInfo,
		args.setShareInfo,
		args.enumDisks,
		args.getServerInfo,
		args.getFileSecurity,
	)
}

func handleSrvs(args *userArgs) (err error) {
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
	}
	if args.enumShares {
		if !isFlagSet("level") {
			args.level = 1
		} else {
			switch args.level {
			case 1, 501, 502:
			default:
				fmt.Println("Invalid level for srvs --enum-shares (supported: 1, 501, 502)")
				return
			}
		}
	}
	if args.getShareInfo {
		if args.share == "" {
			fmt.Println("Must specify a --share for srvs --get-share-info")
			return
		}
		if !isFlagSet("level") {
			args.level = 2
		} else {
			switch args.level {
			case 0, 1, 2, 501, 502:
			default:
				fmt.Println("Invalid level for srvs --get-share-info (supported: 0, 1, 2, 501, 502)")
				return
			}
		}
	}
	if args.setShareInfo {
		if args.share == "" {
			fmt.Println("Must specify a --share for srvs --set-share-info")
			return
		}
		nset := 0
		if isFlagSet("comment") {
			nset++
		}
		if isFlagSet("share-flags") {
			nset++
		}
		if nset != 1 {
			fmt.Println("Must specify exactly one of --comment or --share-flags for srvs --set-share-info")
			return
		}
	}
	if args.getFileSecurity {
		if args.share == "" {
			fmt.Println("Must specify a --share to retrieve file security info")
			return
		}
		// An empty --path (like "\", "/" or "\\") resolves to the share root;
		// normalizeSharePath handles that below.
	}

	// Make the connection!
	err = makeConnection(&args.connArgs)
	if err != nil {
		log.Errorln(err)
		return
	}
	if args.opts == nil || args.opts.c == nil {
		err = fmt.Errorf("failed to establish connection to server")
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
	transport, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		log.Errorln(err)
		return
	}

	bind, err := dcerpc.Bind(transport, mssrvs.MSRPCUuidSrvSvc, mssrvs.MSRPCSrvSvcMajorVersion, mssrvs.MSRPCSrvSvcMinorVersion, dcerpc.MSRPCUuidNdr)
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
		transport2, err2 := smbtransport.NewSMBTransport(f2)
		if err != nil {
			err = err2
			log.Errorln(err)
			return
		}
		var bind2 *dcerpc.ServiceBind
		bind2, err = dcerpc.Bind(transport2, mslsad.MSRPCUuidLsaRpc, mslsad.MSRPCLsaRpcMajorVersion, mslsad.MSRPCLsaRpcMinorVersion, dcerpc.MSRPCUuidNdr)
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
		var lines []string
		lines, err = getSharesFormatted(rpccon, rpcconLsat, "", args.level, args.resolveSids)
		if err != nil {
			log.Errorln(err)
			return
		}
		for _, item := range lines {
			fmt.Println(item)
		}
		return
	} else if args.getShareInfo {
		var out string
		out, err = getShareInfoFormatted(rpccon, rpcconLsat, "", args.share, args.level, args.resolveSids)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println(out)
		return
	} else if args.setShareInfo {
		if isFlagSet("comment") {
			err = rpccon.NetShareSetInfoComment("", args.share, args.comment)
		} else {
			err = rpccon.NetShareSetInfoFlags("", args.share, uint32(args.shareFlags))
		}
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Printf("Successfully updated share %s\n", args.share)
		return
	} else if args.enumDisks {
		var disks []string
		disks, err = rpccon.NetServerDiskEnum("")
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Server disks:")
		for _, d := range disks {
			fmt.Println(d)
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
		// MS-SRVS expects a backslash-rooted path; the share root is "\".
		queryPath := "\\" + normalizeSharePath(args.filePath)

		var sd *msdtyp.SecurityDescriptor
		var names []string
		sd, names, err = getFileSecurity(rpccon, rpcconLsat, args.share, queryPath, args.resolveSids)
		if err != nil {
			log.Errorln(err)
			return
		}

		fmt.Printf("Security information for share: %s, file: %s\n", args.share, queryPath)
		if sd == nil {
			fmt.Println("No security descriptor returned")
			return
		}
		var sb strings.Builder
		appendSecurityDescriptor(&sb, sd, names, args.resolveSids, nil)
		fmt.Println(sb.String())
	}
	return
}

// normalizeSharePath cleans a user-supplied path into a path relative to a
// share's root: forward slashes are converted to backslashes, a leading
// drive-letter prefix such as "C:" is dropped, and surrounding backslashes are
// trimmed. The empty string denotes the share root, so inputs of "", "\", "/"
// and "\\" all collapse to root. Callers add whatever leading separator their
// backend expects: MS-SRVS NetGetFileSecurity wants a leading "\" for the root,
// while a direct SMB2 open wants an empty name (a leading "\" is rejected with
// INVALID_PARAMETER and a "/" with OBJECT_NAME_INVALID).
func normalizeSharePath(path string) string {
	path = strings.ReplaceAll(path, "/", "\\")
	if i := strings.Index(path, ":"); i != -1 {
		path = path[i+1:]
	}
	return strings.Trim(path, "\\")
}

func getFileSecurity(rpccon *mssrvs.RPCCon, rpcconLsat *mslsad.RPCCon, share, path string, resolveSids bool) (sd *msdtyp.SecurityDescriptor, names []string, err error) {
	sd, err = rpccon.NetGetFileSecurity(share, path)
	if err != nil {
		log.Errorln(err)
		return
	}
	if resolveSids && sd != nil {
		names = resolveSidStrings(rpcconLsat, collectSidsFromSD(sd))
	}
	return
}

// collectSidsFromSD returns the SIDs referenced by sd in the canonical order
// owner, group, DACL entries then SACL entries — the same order in which
// appendSecurityDescriptor consumes resolved names.
func collectSidsFromSD(sd *msdtyp.SecurityDescriptor) (sids []string) {
	if sd == nil {
		return
	}
	if sd.OwnerSid != nil {
		sids = append(sids, sd.OwnerSid.ToString())
	}
	if sd.GroupSid != nil {
		sids = append(sids, sd.GroupSid.ToString())
	}
	if sd.Dacl != nil {
		for _, item := range sd.Dacl.Permissions().Entries {
			sids = append(sids, item.Sid)
		}
	}
	if sd.Sacl != nil {
		for _, item := range sd.Sacl.Permissions().Entries {
			sids = append(sids, item.Sid)
		}
	}
	return
}

// resolveSidStrings translates a list of SID strings to names via MS-LSAT.
// On any failure it logs and returns whatever was resolved (possibly nil).
func resolveSidStrings(rpcconLsat *mslsad.RPCCon, sids []string) (names []string) {
	if rpcconLsat == nil || len(sids) == 0 {
		return
	}
	res, err := rpcconLsat.LsarLookupSids2(1, sids)
	if err != nil {
		log.Errorln(err)
		return
	}
	for _, item := range res.TranslatedNames {
		if item.Use == mslsad.SidTypeUnknown {
			names = append(names, "<unknown>")
		} else if item.DomainIndex != -1 {
			names = append(names, fmt.Sprintf("%s\\%s", res.ReferencedDomains[item.DomainIndex].Name, item.Name))
		} else {
			names = append(names, item.Name)
		}
	}
	return
}

// appendSecurityDescriptor writes a human-readable representation of sd to sb.
// When resolveSids is set, names must hold the resolved names for the SIDs
// returned by collectSidsFromSD(sd), in the same order; they are consumed as
// the owner, group, DACL and SACL entries are printed. objRights, when non-nil,
// decodes the object-specific access mask bits (e.g. SERVICE_* / SC_MANAGER_*)
// that msdtyp does not name on its own; pass nil to show only the standard
// rights.
func appendSecurityDescriptor(sb *strings.Builder, sd *msdtyp.SecurityDescriptor, names []string, resolveSids bool, objRights func(uint32) []string) {
	if sd == nil {
		return
	}
	if sd.OwnerSid != nil {
		fmt.Fprintf(sb, "OwnerSid: %s", sd.OwnerSid.ToString())
		if resolveSids && len(names) > 0 {
			fmt.Fprintf(sb, "(%s)", names[0])
			names = names[1:]
		}
		sb.WriteRune('\n')
	}
	if sd.GroupSid != nil {
		fmt.Fprintf(sb, "GroupSid: %s", sd.GroupSid.ToString())
		if resolveSids && len(names) > 0 {
			fmt.Fprintf(sb, "(%s)", names[0])
			names = names[1:]
		}
		sb.WriteRune('\n')
	}
	if sd.Dacl != nil {
		fmt.Fprintln(sb, "DACL entries:")
		names = appendAceEntries(sb, sd.Dacl.ACLS, names, resolveSids, objRights)
	}
	if sd.Sacl != nil {
		fmt.Fprintln(sb, "SACL entries:")
		names = appendAceEntries(sb, sd.Sacl.ACLS, names, resolveSids, objRights)
	}
}

// appendAceEntries writes the ACE entries of an ACL to sb, consuming one
// resolved name per entry when resolveSids is set. When objRights is non-nil it
// is applied to each ACE's raw access mask and the resulting object-specific
// right names are shown ahead of the standard rights. Returns the unconsumed
// tail of names.
func appendAceEntries(sb *strings.Builder, aces []msdtyp.ACE, names []string, resolveSids bool, objRights func(uint32) []string) []string {
	for _, ace := range aces {
		item := ace.Permissions()
		fmt.Fprintf(sb, "AceType: %s\nAceFlags: %s\nSid: %s\n", item.AceType, item.AceFlagStrings, item.Sid)
		if resolveSids && len(names) > 0 {
			fmt.Fprintf(sb, "Name: %s\n", names[0])
			names = names[1:]
		}
		permissions := item.Permissions
		if objRights != nil {
			permissions = append(objRights(ace.Mask), permissions...)
		}
		sb.WriteString("Permissions: ")
		sb.WriteString(strings.Join(permissions, ","))
		sb.WriteString("\n\n")
	}
	return names
}
