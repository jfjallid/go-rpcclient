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
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb"
)

var helpSmbOptions = `
    Usage: ` + os.Args[0] + ` smb [options] <action>
    ` + helpConnectionOptions + `
    Action:
          --get-file-security  Get security descriptor for a file/folder by opening it directly over SMB

    SMB options:
          --share <string>     Name of the share containing the file (e.g. C$)
          --path  <string>     Path to file or folder to query.
                               Omitted, "\", "/" or "" resolve to the share root
          --sacl               Also request the SACL (requires SeSecurityPrivilege)
`

func validateSmbActions(args *userArgs) error {
	return exactlyOneAction(
		args.getFileSecurity,
	)
}

func handleSmb(args *userArgs) (err error) {
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

	// Unlike the other modules this one performs no DCE/RPC bind for its own
	// action; it talks to the SMB layer directly. An LSARPC bind is only needed
	// to translate SIDs when --resolve-sids is set.
	var rpcconLsat *mslsad.RPCCon
	if args.resolveSids {
		ipcShare := "IPC$"
		err = conn.TreeConnect(ipcShare)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer conn.TreeDisconnect(ipcShare)
		var f *smb.File
		f, err = conn.OpenFile(ipcShare, mslsad.MSRPCLsaRpcPipe)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer f.CloseFile()
		transport, err2 := smbtransport.NewSMBTransport(f)
		if err2 != nil {
			err = err2
			log.Errorln(err)
			return
		}
		var bind *dcerpc.ServiceBind
		bind, err = dcerpc.Bind(transport, mslsad.MSRPCUuidLsaRpc, mslsad.MSRPCLsaRpcMajorVersion, mslsad.MSRPCLsaRpcMinorVersion, dcerpc.MSRPCUuidNdr)
		if err != nil {
			log.Errorln("Failed to bind to LSARPC service")
			log.Errorln(err)
			return
		}
		rpcconLsat = mslsad.NewRPCCon(bind)
	}

	if args.getFileSecurity {
		additionalInfo := smb.OwnerSecurityInformation | smb.GroupSecurityInformation | smb.DACLSecurityInformation
		if args.sacl {
			additionalInfo |= smb.SACLSecurityInformation
		}

		// A direct SMB2 open wants the share root as an empty name (a leading
		// "\" is rejected with INVALID_PARAMETER, a "/" with OBJECT_NAME_INVALID),
		// so the normalized relative path is sent as-is.
		queryPath := normalizeSharePath(args.filePath)

		var sd *msdtyp.SecurityDescriptor
		var names []string
		sd, names, err = getFileSecuritySMB(conn, rpcconLsat, args.share, queryPath, additionalInfo, args.resolveSids)
		if err != nil {
			log.Errorln(err)
			return
		}

		fmt.Printf("Security information for share: %s, file: \\%s\n", args.share, queryPath)
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

// getFileSecuritySMB reads the security descriptor of a file or folder by
// opening it directly over SMB2 (READ_CONTROL access) and issuing a QUERY_INFO
// request, rather than going through the MS-SRVS NetrpGetFileSecurity RPC like
// getFileSecurity does. additionalInfo selects the components to request, e.g.
// OwnerSecurityInformation|GroupSecurityInformation|DACLSecurityInformation. The
// returned descriptor flows through the same appendSecurityDescriptor pipeline
// as the srvs variant. OpenFileReadAttributes connects the target share's tree
// on demand; it is torn down when the caller closes the connection.
func getFileSecuritySMB(conn *smb.Connection, rpcconLsat *mslsad.RPCCon, share, path string, additionalInfo uint32, resolveSids bool) (sd *msdtyp.SecurityDescriptor, names []string, err error) {
	f, err := conn.OpenFileReadAttributes(share, path)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer f.CloseFile()
	sd, err = f.QueryInfoSecurityRaw(additionalInfo, 0)
	if err != nil {
		log.Errorln(err)
		return
	}
	if resolveSids && sd != nil {
		names = resolveSidStrings(rpcconLsat, collectSidsFromSD(sd))
	}
	return
}
