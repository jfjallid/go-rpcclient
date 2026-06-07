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
	"maps"
	"strconv"
	"strings"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mslsad"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/golog"
)

const (
	SrvsEnumSessions    = "srvsenumsessions"
	SrvsEnumShares      = "srvsenumshares"
	SrvsGetShareInfo    = "srvsgetshareinfo"
	SrvsSetShareInfo    = "srvssetshareinfo"
	SrvsEnumDisks       = "srvsenumdisks"
	SrvsGetInfo         = "srvsgetinfo"
	SrvsGetFileSecurity = "srvsgetfilesecurity"
)

var srvsUsageKeys = []string{
	SrvsEnumSessions,
	SrvsEnumShares,
	SrvsGetShareInfo,
	SrvsSetShareInfo,
	SrvsEnumDisks,
	SrvsGetInfo,
	SrvsGetFileSecurity,
}
var srvsUsageMap = map[string]string{
	SrvsEnumSessions:    SrvsEnumSessions + " [level]",
	SrvsEnumShares:      SrvsEnumShares + " [level]",
	SrvsGetShareInfo:    SrvsGetShareInfo + " <share> [level]",
	SrvsSetShareInfo:    SrvsSetShareInfo + " <share> <field> <value>",
	SrvsEnumDisks:       SrvsEnumDisks,
	SrvsGetInfo:         SrvsGetInfo + " [level]",
	SrvsGetFileSecurity: SrvsGetFileSecurity + " <share> [path]",
}

var srvsDescriptionMap = map[string]string{
	SrvsEnumSessions:    "List network sessions (supported levels 0, 10, 502. Default 10)",
	SrvsEnumShares:      "List SMB Shares (supported levels 1, 501, 502. Default 1)",
	SrvsGetShareInfo:    "Get info for a single share (supported levels 0, 1, 2, 501, 502. Default 2)",
	SrvsSetShareInfo:    "Modify a share. <field> is 'comment' or 'flags'",
	SrvsEnumDisks:       "List disk drives on the server",
	SrvsGetInfo:         "Get Server info (supported levels 100,101,102. Default 101. 102 requires admin privileges)",
	SrvsGetFileSecurity: "Get security descriptor for file/folder on specified share",
}

func printSrvsHelp(self *shell) {
	self.showCustomHelpFunc(40, "MS-SRVS", srvsUsageKeys)
}

func init() {
	maps.Copy(usageMap, srvsUsageMap)
	maps.Copy(descriptionMap, srvsDescriptionMap)
	allKeys = append(allKeys, srvsUsageKeys...)
	golog.Set("github.com/jfjallid/go-smb/dcerpc/mssrvs", "mssrvs", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	handlers[SrvsGetInfo] = getServerInfoFunc
	handlers[SrvsEnumSessions] = getNetSessionsFunc
	handlers[SrvsEnumShares] = listSharesFunc
	handlers[SrvsGetShareInfo] = getShareInfoFunc
	handlers[SrvsSetShareInfo] = setShareInfoFunc
	handlers[SrvsEnumDisks] = enumDisksFunc
	handlers[SrvsGetFileSecurity] = getFileSecurityFunc
	helpFunctions[1] = printSrvsHelp
}

func (self *shell) getSrvsHandle() (rpccon *mssrvs.RPCCon, err error) {

	val, found := self.binds["srvs"]
	if !found {
		var f *smb.File
		f, err = self.options.c.OpenFile(self.share, mssrvs.MSRPCSrvSvcPipe)
		if err != nil {
			if err == smb.StatusMap[smb.StatusObjectNameNotFound] {
				err = fmt.Errorf("Named pipe not available. Is the service running?")
			}
			return
		}
		self.files = append(self.files, f)
		transport, err2 := smbtransport.NewSMBTransport(f)
		if err2 != nil {
			err = err2
			self.println(err)
			return
		}
		var bind *dcerpc.ServiceBind
		bind, err = dcerpc.Bind(transport, mssrvs.MSRPCUuidSrvSvc, mssrvs.MSRPCSrvSvcMajorVersion, mssrvs.MSRPCSrvSvcMinorVersion, dcerpc.MSRPCUuidNdr)
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

func listSharesFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SrvsEnumShares]
	args := argArr.([]string)
	level := 1
	if len(args) > 0 {
		val, err := strconv.ParseInt(args[0], 10, 32)
		if err != nil {
			self.println("Error parsing level")
			self.println(usage)
			return
		} else if (val != 1) && (val != 501) && (val != 502) {
			self.println("Must specify a valid level (1, 501 or 502)")
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
	var rpcconLsat *mslsad.RPCCon
	if self.resolveSids {
		rpcconLsat, err = self.getLsadHandle()
		if err != nil {
			self.println(err)
			return
		}
	}

	lines, err := getSharesFormatted(rpccon, rpcconLsat, "", level, self.resolveSids)
	if err != nil {
		self.println(err)
		return
	}
	for _, item := range lines {
		self.println(item)
	}
}

func getShareInfoFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SrvsGetShareInfo]
	args := argArr.([]string)
	if len(args) < 1 {
		self.println(usage)
		return
	}
	share := args[0]
	level := 2
	if len(args) > 1 {
		val, err := strconv.ParseInt(args[1], 10, 32)
		if err != nil {
			self.println("Error parsing level")
			self.println(usage)
			return
		}
		switch val {
		case 0, 1, 2, 501, 502:
		default:
			self.println("Must specify a valid level (0, 1, 2, 501 or 502)")
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
	var rpcconLsat *mslsad.RPCCon
	if self.resolveSids {
		rpcconLsat, err = self.getLsadHandle()
		if err != nil {
			self.println(err)
			return
		}
	}

	out, err := getShareInfoFormatted(rpccon, rpcconLsat, "", share, level, self.resolveSids)
	if err != nil {
		self.println(err)
		return
	}
	self.println(out)
}

func setShareInfoFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SrvsSetShareInfo]
	args := argArr.([]string)
	if len(args) < 3 {
		self.println(usage)
		return
	}
	share := args[0]
	field := strings.ToLower(args[1])
	value := strings.Join(args[2:], " ")

	rpccon, err := self.getSrvsHandle()
	if err != nil {
		self.println(err)
		return
	}

	switch field {
	case "comment":
		err = rpccon.NetShareSetInfoComment("", share, value)
	case "flags":
		val, perr := parseNumericArg(value, uint32(0))
		if perr != nil {
			self.printf("Failed to parse flags value: %s\n", perr)
			self.println(usage)
			return
		}
		err = rpccon.NetShareSetInfoFlags("", share, val.(uint32))
	default:
		self.printf("Unknown field %q. Supported fields: comment, flags\n", field)
		self.println(usage)
		return
	}
	if err != nil {
		self.println(err)
		return
	}
	self.printf("Successfully updated share %s\n", share)
}

func enumDisksFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	rpccon, err := self.getSrvsHandle()
	if err != nil {
		self.println(err)
		return
	}
	disks, err := rpccon.NetServerDiskEnum("")
	if err != nil {
		self.println(err)
		return
	}
	self.println("Server disks:")
	for _, d := range disks {
		self.println(d)
	}
}

func getServerInfoFunc(self *shell, argArr interface{}) {
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

func getNetSessionsFunc(self *shell, argArr interface{}) {
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

func getFileSecurityFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SrvsGetFileSecurity]
	args := argArr.([]string)
	if len(args) < 1 {
		self.println(usage)
		return
	}
	share := args[0]
	// An omitted path (or "\", "/", "") resolves to the share root. MS-SRVS
	// expects a backslash-rooted path, so the root is "\".
	queryPath := "\\" + normalizeSharePath(strings.Join(args[1:], " "))

	rpccon, err := self.getSrvsHandle()
	if err != nil {
		self.println(err)
		return
	}
	var rpcconLsat *mslsad.RPCCon
	if self.resolveSids {
		rpcconLsat, err = self.getLsadHandle()
		if err != nil {
			self.println(err)
			return
		}
	}
	sd, names, err := getFileSecurity(rpccon, rpcconLsat, share, queryPath, self.resolveSids)
	if err != nil {
		self.println(err)
		return
	}

	self.printf("Security information for share: %s, file: %s\n", share, queryPath)
	if sd == nil {
		self.println("No security descriptor returned")
		return
	}
	var sb strings.Builder
	appendSecurityDescriptor(&sb, sd, names, self.resolveSids, nil)
	self.println(sb.String())
}
