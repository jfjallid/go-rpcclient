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

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mswkst"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
)

var helpWkstOptions = `
    Usage: ` + os.Args[0] + ` wkst [options] <action>
    ` + helpConnectionOptions + `
    Action:
          --enum-sessions      List logged in users (Required admin privileges) (default level: 1)

    WKST options:
          --level <int>        Level of information to return
`

func getWkstSessions(rpccon *mswkst.RPCCon, level int) (sessions []string, err error) {
	var res *mswkst.WkstaUserEnum
	res, err = rpccon.EnumWkstLoggedOnUsers(level)
	if err != nil {
		log.Errorln(err)
		return
	}

	switch level {
	case 0:
		info := res.Level0
		for i := 0; i < int(info.EntriesRead); i++ {
			sessions = append(sessions, fmt.Sprintf("Username: %s\n", info.Buffer[i].Username))
		}
	case 1:
		info := res.Level1
		for i := 0; i < int(info.EntriesRead); i++ {
			sessions = append(sessions, fmt.Sprintf("Username: %s, LogonDomain: %s, OtherDomains: %s, LogonServer: %s\n", info.Buffer[i].Username, info.Buffer[i].LogonDomain, info.Buffer[i].OtherDomains, info.Buffer[i].LogonServer))
		}
	}
	return
}

func validateWkstActions(args *userArgs) error {
	return exactlyOneAction(
		args.enumSessions,
	)
}

func handleWkst(args *userArgs) (err error) {
	if args.enumSessions {
		if !isFlagSet("level") {
			args.level = 1
		} else {
			if (args.level > 1) || (args.level < 0) {
				fmt.Println("Invalid level for --enum-sessions. Only Level 0 and 1 supported")
				return
			}
		}
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
	f, err := conn.OpenFile(share, mswkst.MSRPCWksSvcPipe)
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
	bind, err := dcerpc.Bind(transport, mswkst.MSRPCUuidWksSvc, mswkst.MSRPCWksSvcMajorVersion, mswkst.MSRPCWksSvcMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		log.Errorln("Failed to bind to service")
		log.Errorln(err)
		return
	}

	rpccon := mswkst.NewRPCCon(bind)
	fmt.Println("Successfully performed Bind to Wkst service")

	if args.enumSessions {
		var sessions []string
		sessions, err = getWkstSessions(rpccon, args.level)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Logged in users:")
		for _, item := range sessions {
			fmt.Print(item)
		}
	}
	return
}
