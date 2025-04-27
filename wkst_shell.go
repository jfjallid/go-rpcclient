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

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/mswkst"
	"github.com/jfjallid/golog"
)

const (
	WkstEnumSessions = "wkstenumsessions"
)

var wkstUsageKeys = []string{
	WkstEnumSessions,
}
var wkstUsageMap = map[string]string{
	WkstEnumSessions: WkstEnumSessions + " [level]",
}

var wkstDescriptionMap = map[string]string{
	WkstEnumSessions: "List logged in users (Required admin privileges) (supported levels 0, 1. Default level: 1)",
}

func printWkstHelp(self *shell) {
	self.showCustomHelpFunc(30, "MS-WKST", wkstUsageKeys)
}

func init() {
	maps.Copy(usageMap, wkstUsageMap)
	maps.Copy(descriptionMap, wkstDescriptionMap)
	allKeys = append(allKeys, wkstUsageKeys...)
	golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mswkst", "mswkst", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	handlers[WkstEnumSessions] = getSessionsFunc
	helpFunctions[2] = printWkstHelp
}

func (self *shell) getWkstHandle() (rpccon *mswkst.RPCCon, err error) {
	val, found := self.binds["wkst"]
	if !found {
		var f *smb.File
		f, err = self.options.c.OpenFile(self.share, mswkst.MSRPCWksSvcPipe)
		if err != nil {
			if err == smb.StatusMap[smb.StatusObjectNameNotFound] {
				err = fmt.Errorf("Named pipe not available. Is the service runnng?")
			}
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

func getSessionsFunc(self *shell, argArr interface{}) {
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
