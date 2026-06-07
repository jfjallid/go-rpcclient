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
	"maps"
	"strings"

	"github.com/jfjallid/go-smb/dcerpc/mslsad"
	"github.com/jfjallid/go-smb/smb"
)

const (
	SmbGetFileSecurity = "smbgetfilesecurity"
)

var smbUsageKeys = []string{
	SmbGetFileSecurity,
}

var smbUsageMap = map[string]string{
	SmbGetFileSecurity: SmbGetFileSecurity + " <share> [path] [sacl]",
}

var smbDescriptionMap = map[string]string{
	SmbGetFileSecurity: "Get security descriptor for file/folder by opening it directly over SMB. Append 'sacl' to also request the SACL",
}

func printSmbHelp(self *shell) {
	self.showCustomHelpFunc(40, "MS-SMB", smbUsageKeys)
}

func init() {
	maps.Copy(usageMap, smbUsageMap)
	maps.Copy(descriptionMap, smbDescriptionMap)
	allKeys = append(allKeys, smbUsageKeys...)
	handlers[SmbGetFileSecurity] = smbGetFileSecurityFunc
	helpFunctions[7] = printSmbHelp
}

func smbGetFileSecurityFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[SmbGetFileSecurity]
	args := argArr.([]string)
	if len(args) < 1 {
		self.println(usage)
		return
	}
	share := args[0]
	rest := args[1:]
	// An optional trailing "sacl" token requests the SACL. Require at least one
	// other token so a lone "sacl" is still treated as the path argument.
	sacl := false
	if len(rest) > 1 && strings.ToLower(rest[len(rest)-1]) == "sacl" {
		sacl = true
		rest = rest[:len(rest)-1]
	}
	// An omitted path (or "\", "/", "") resolves to the share root, which over a
	// direct SMB2 open is the empty name; send the normalized relative path.
	queryPath := normalizeSharePath(strings.Join(rest, " "))

	var rpcconLsat *mslsad.RPCCon
	if self.resolveSids {
		var err error
		rpcconLsat, err = self.getLsadHandle()
		if err != nil {
			self.println(err)
			return
		}
	}

	additionalInfo := smb.OwnerSecurityInformation | smb.GroupSecurityInformation | smb.DACLSecurityInformation
	if sacl {
		additionalInfo |= smb.SACLSecurityInformation
	}

	sd, names, err := getFileSecuritySMB(self.options.c, rpcconLsat, share, queryPath, additionalInfo, self.resolveSids)
	if err != nil {
		self.println(err)
		return
	}

	self.printf("Security information for share: %s, file: \\%s\n", share, queryPath)
	if sd == nil {
		self.println("No security descriptor returned")
		return
	}
	var sb strings.Builder
	appendSecurityDescriptor(&sb, sd, names, self.resolveSids, nil)
	self.println(sb.String())
}
