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

	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/mssrvs"
)

var helpSrvsOptions = `
    Usage: ` + os.Args[0] + ` --srvs [options] <action>
    ` + helpConnectionOptions + `
    Action:
          --enum-sessions      List sessions (supported levels 0, 10, 502. Default 10)
          --enum-shares        List SMB Shares
          --get-info           Get Server info (supported levels 100,101,102. Default 101. 102 requires admin privileges)

    SRVS options:
          --level <int>        Level of information to return
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
	}
	return
}
