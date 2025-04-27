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
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/mslsad"
	"github.com/jfjallid/golog"
)

const (
	LsadEnumAccounts  = "lsaenumaccounts"
	LsadEnumAccRights = "lsaenumaccrights"
	LsadAddRights     = "lsaaddrights"
	LsadDelRights     = "lsadelrights"
	LsadGetDominfo    = "lsagetdominfo"
	LsadPurgeRights   = "lsapurgerights"
)

var lsadUsageKeys = []string{
	LsadEnumAccounts,
	LsadEnumAccRights,
	LsadAddRights,
	LsadDelRights,
	LsadGetDominfo,
	LsadPurgeRights,
}
var lsadUsageMap = map[string]string{
	LsadEnumAccounts:  LsadEnumAccounts,
	LsadEnumAccRights: LsadEnumAccRights + " <SID>",
	LsadAddRights:     LsadAddRights + " <SID> <rights...>",
	LsadDelRights:     LsadDelRights + " <SID> <rights...>",
	LsadGetDominfo:    LsadGetDominfo,
	LsadPurgeRights:   LsadPurgeRights + " <SID>",
}

var lsadDescriptionMap = map[string]string{
	LsadEnumAccounts:  "List LSA accounts",
	LsadEnumAccRights: "List LSA rights assigned to account specified by SID",
	LsadAddRights:     "Add list of LSA rights to account specified by SID",
	LsadDelRights:     "Remove list of LSA rights from account specified by SID",
	LsadGetDominfo:    "Get primary domain name and domain SID",
	LsadPurgeRights:   "Removes all LSA rights for the specified SID",
}

func printLsadHelp(self *shell) {
	self.showCustomHelpFunc(30, "MS-LSAD", lsadUsageKeys)
}

func init() {
	maps.Copy(usageMap, lsadUsageMap)
	maps.Copy(descriptionMap, lsadDescriptionMap)
	allKeys = append(allKeys, lsadUsageKeys...)
	golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/mslsad", "mslsad", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	handlers[LsadEnumAccounts] = getLSAAccount
	handlers[LsadEnumAccRights] = getLSAAccountRights
	handlers[LsadAddRights] = addLSAAccountRights
	handlers[LsadDelRights] = removeLSAAccountRights
	handlers[LsadPurgeRights] = purgeLSAAccountRights
	handlers[LsadGetDominfo] = getLSAPrimaryDomainInfo
	helpFunctions[3] = printLsadHelp
}

func (self *shell) getLsadHandle() (rpccon *mslsad.RPCCon, err error) {
	val, found := self.binds["lsad"]
	if !found {
		var f *smb.File
		f, err = self.options.c.OpenFile(self.share, mslsad.MSRPCLsaRpcPipe)
		if err != nil {
			if err == smb.StatusMap[smb.StatusObjectNameNotFound] {
				err = fmt.Errorf("Named pipe not available. Is the service running?")
			}
			return
		}
		self.files = append(self.files, f)
		var bind *dcerpc.ServiceBind
		bind, err = dcerpc.Bind(f, mslsad.MSRPCUuidLsaRpc, mslsad.MSRPCLsaRpcMajorVersion, mslsad.MSRPCLsaRpcMinorVersion, dcerpc.MSRPCUuidNdr)
		if err != nil {
			self.println("Failed to bind to service")
			return
		}
		rpccon = mslsad.NewRPCCon(bind)
		self.binds["lsad"] = rpccon
	} else {
		rpccon = val.(*mslsad.RPCCon)
	}
	return
}

func getLSAAccount(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}

	rpccon, err := self.getLsadHandle()
	if err != nil {
		self.println(err)
		return
	}

	accounts, err := getLSAAccounts(rpccon)
	if err != nil {
		self.println(err)
		return
	}
	for _, item := range accounts {
		self.println(item)
	}
}

func getLSAAccountRights(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[LsadEnumAccRights]

	args := argArr.([]string)
	sidStr := ""
	if len(args) < 1 {
		self.println(usage)
		return
	} else {
		sid, err := msdtyp.ConvertStrToSID(args[0])
		if err != nil {
			self.println("Error parsing SID")
			self.println(usage)
			return
		}
		sidStr = sid.ToString()
	}

	rpccon, err := self.getLsadHandle()
	if err != nil {
		self.println(err)
		return
	}

	rights, err := rpccon.ListAccountRights(sidStr)
	if err != nil {
		self.println(err)
		return
	}
	for _, right := range rights {
		self.println(right)
	}
}

func addLSAAccountRights(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[LsadAddRights]

	args := argArr.([]string)
	sidStr := ""
	var rights []string
	if len(args) < 2 {
		self.println(usage)
		return
	} else {
		sid, err := msdtyp.ConvertStrToSID(args[0])
		if err != nil {
			self.println("Error parsing SID")
			self.println(usage)
			return
		}
		sidStr = sid.ToString()
		rights = append(rights, args[1:]...)
		// sanity check
		for _, item := range rights {
			if strings.Contains(item, ",") {
				self.println("List of rights should be separated by spaces")
				self.println(usage)
				return
			}
		}
	}

	rpccon, err := self.getLsadHandle()
	if err != nil {
		self.println(err)
		return
	}

	err = rpccon.AddAccountRights(sidStr, rights)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Rights added!")
}

func removeLSAAccountRights(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[LsadDelRights]

	args := argArr.([]string)
	sidStr := ""
	var rights []string
	if len(args) < 2 {
		self.println(usage)
		return
	} else {
		sid, err := msdtyp.ConvertStrToSID(args[0])
		if err != nil {
			self.println("Error parsing SID")
			self.println(usage)
			return
		}
		sidStr = sid.ToString()
		rights = append(rights, args[1:]...)
		// sanity check
		for _, item := range rights {
			if strings.Contains(item, ",") {
				self.println("List of rights should be separated by spaces")
				self.println(usage)
				return
			}
		}
	}

	rpccon, err := self.getLsadHandle()
	if err != nil {
		self.println(err)
		return
	}

	err = rpccon.RemoveAccountRights(sidStr, rights, false)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Rights removed!")
}

func purgeLSAAccountRights(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[LsadPurgeRights]

	args := argArr.([]string)
	sidStr := ""
	if len(args) < 1 {
		self.println(usage)
		return
	} else {
		sid, err := msdtyp.ConvertStrToSID(args[0])
		if err != nil {
			self.println("Error parsing SID")
			self.println(usage)
			return
		}
		sidStr = sid.ToString()
	}

	rpccon, err := self.getLsadHandle()
	if err != nil {
		self.println(err)
		return
	}

	err = rpccon.RemoveAccountRights(sidStr, nil, true)
	if err != nil {
		self.println(err)
		return
	}
	self.println("all rights removed!")
}

func getLSAPrimaryDomainInfo(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}

	rpccon, err := self.getLsadHandle()
	if err != nil {
		self.println(err)
		return
	}

	domInfo, err := rpccon.GetPrimaryDomainInfo()
	if err != nil {
		self.println(err)
		return
	}
	self.printf("Domain: %s, SID: %s\n", domInfo.Name, domInfo.Sid.ToString())
}
