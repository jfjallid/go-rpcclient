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

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/mslsad"
	"github.com/jfjallid/go-smb/smb/dcerpc/mssrvs"
	"github.com/jfjallid/golog"
)

const (
	SrvsEnumSessions    = "srvsenumsessions"
	SrvsEnumShares      = "srvsenumshares"
	SrvsGetInfo         = "srvsgetinfo"
	SrvsGetFileSecurity = "srvsgetfilesecurity"
)

var srvsUsageKeys = []string{
	SrvsEnumSessions,
	SrvsEnumShares,
	SrvsGetInfo,
	SrvsGetFileSecurity,
}
var srvsUsageMap = map[string]string{
	SrvsEnumSessions:    SrvsEnumSessions + " [level]",
	SrvsEnumShares:      SrvsEnumShares,
	SrvsGetInfo:         SrvsGetInfo + " [level]",
	SrvsGetFileSecurity: SrvsGetFileSecurity + " <share> <path>",
}

var srvsDescriptionMap = map[string]string{
	SrvsEnumSessions:    "List network sessions (supported levels 0, 10, 502. Default 10)",
	SrvsEnumShares:      "List SMB Shares",
	SrvsGetInfo:         "Get Server info (supported levels 100,101,102. Default 101. 102 requires admin privileges)",
	SrvsGetFileSecurity: "Get security descriptor for file/folder on specified share",
}

func printSrvsHelp(self *shell) {
	self.showCustomHelpFunc(34, "MS-SRVS", srvsUsageKeys)
}

func init() {
	maps.Copy(usageMap, srvsUsageMap)
	maps.Copy(descriptionMap, srvsDescriptionMap)
	allKeys = append(allKeys, srvsUsageKeys...)
	golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mssrvs", "mssrvs", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	handlers[SrvsGetInfo] = getServerInfoFunc
	handlers[SrvsEnumSessions] = getNetSessionsFunc
	handlers[SrvsEnumShares] = listSharesFunc
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

func listSharesFunc(self *shell, args interface{}) {
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
	share := ""
	path := ""

	if len(args) < 2 {
		self.println(usage)
		return
	} else {
		share = args[0]
		path = strings.Join(args[1:], " ")
	}
	//TODO Maybe do some basic validation on the arguments?
	if strings.Contains(path, ":") {
		// Remove drive prefix
		path = strings.SplitN(path, ":", 2)[1]
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
	sd, names, err := getFileSecurity(rpccon, rpcconLsat, share, path, self.resolveSids)
	if err != nil {
		self.println(err)
		return
	}

	self.printf("Security information for share: %s, file: %s\n", share, path)
	var sb strings.Builder
	if sd.OwnerSid != nil {
		fmt.Fprintf(&sb, "OwnerSid: %s", sd.OwnerSid.ToString())
		if self.resolveSids && len(names) > 0 {
			fmt.Fprintf(&sb, "(%s)", names[0])
		}
		sb.WriteRune('\n')
		names = names[1:]
	}
	if sd.GroupSid != nil {
		fmt.Fprintf(&sb, "GroupSid: %s", sd.GroupSid.ToString())
		if self.resolveSids && len(names) > 0 {
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
			if self.resolveSids && len(names) > 0 {
				fmt.Fprintf(&sb, "Name: %s\n", names[0])
				names = names[1:]
			}
			fmt.Fprintf(&sb, "Permissions: ")
			permissions := ""
			for _, perm := range item.Permissions {
				permissions = fmt.Sprintf("%s,%s", permissions, perm)
			}
			sb.WriteString(strings.TrimPrefix(permissions, ","))
			sb.WriteString("\n")
		}
	}
	if sd.Sacl != nil {
		fmt.Fprintln(&sb, "SACL entries:")
		saclPermissions := sd.Sacl.Permissions()
		for _, item := range saclPermissions.Entries {
			fmt.Fprintf(&sb, "AceType: %s\nAceFlags: %s\nSid: %s\n", item.AceType, item.AceFlagStrings, item.Sid)
			fmt.Fprintf(&sb, "Permissions: ")
			permissions := ""
			for _, perm := range item.Permissions {
				permissions = fmt.Sprintf("%s,%s", permissions, perm)
			}
			sb.WriteString(strings.TrimPrefix(permissions, ","))
			sb.WriteString("\n")
		}
	}
	self.println(sb.String())

}
