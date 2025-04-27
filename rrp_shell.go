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
	"encoding/hex"
	"fmt"
	"maps"
	"strconv"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/msrrp"
	"github.com/jfjallid/golog"
)

const (
	RegGetValue         = "reggetvalue"
	RegSetValue         = "regsetvalue"
	RegDeleteValue      = "regdelvalue"
	RegEnumKeys         = "regenumkeys"
	RegEnumValues       = "regenumvalues"
	RegCreateKey        = "regcreatekey"
	RegDeleteKey        = "regdelkey"
	RegGetKeyInfo       = "reggetkeyinfo"
	RegGetKeySecurity   = "reggetkeysecurity"
	RegSaveKey          = "regsavekey"
	ToggleBackupResPriv = "togglebackuprestorepriv"
)

var rrpUsageKeys = []string{
	RegGetValue,
	RegSetValue,
	RegDeleteValue,
	RegEnumKeys,
	RegEnumValues,
	RegCreateKey,
	RegDeleteKey,
	RegGetKeyInfo,
	RegGetKeySecurity,
	RegSaveKey,
	ToggleBackupResPriv,
}

var rrpUsageMap = map[string]string{
	RegGetValue:         RegGetValue + " <key> [name]",
	RegSetValue:         RegSetValue + " <key> [name] ",
	RegDeleteValue:      RegDeleteValue + " <key> [name]",
	RegEnumKeys:         RegEnumKeys + " <key>",
	RegEnumValues:       RegEnumValues + " <key>",
	RegCreateKey:        RegCreateKey + " <key>",
	RegDeleteKey:        RegDeleteKey + " <key>",
	RegGetKeyInfo:       RegGetKeyInfo + " <key>",
	RegGetKeySecurity:   RegGetKeySecurity + " <key>",
	RegSaveKey:          RegSaveKey + " <key> <dst path>",
	ToggleBackupResPriv: ToggleBackupResPriv,
}

var rrpDescriptionMap = map[string]string{
	RegGetValue:         "Retrieve registry value",
	RegSetValue:         "Set or create registry value",
	RegDeleteValue:      "Delete registry value",
	RegEnumKeys:         "List subkey names",
	RegEnumValues:       "List value names for registry key",
	RegCreateKey:        "Create registry key. Use quotes if there are spaces",
	RegDeleteKey:        "Delete registry key. Use quotes if there are spaces",
	RegGetKeyInfo:       "Retrieve key info. Use quotes if there are spaces",
	RegGetKeySecurity:   "Retrieve key security information",
	RegSaveKey:          "Save registry key and subkeys to disk",
	ToggleBackupResPriv: "Use SeBackup/RestorePrivilege for supported operations",
}

func rrpCleanup(self *shell) {
	if len(self.regHiveHandles) > 0 {
		rpccon, err := self.getRrpHandle()
		if err == nil {
			for i, hKey := range self.regHiveHandles {
				rpccon.CloseKeyHandle(hKey)
				delete(self.regHiveHandles, i)
			}
		}
	}
}

func printRrpHelp(self *shell) {
	self.showCustomHelpFunc(30, "MS-RRP", rrpUsageKeys)
}

func init() {
	maps.Copy(usageMap, rrpUsageMap)
	maps.Copy(descriptionMap, rrpDescriptionMap)
	allKeys = append(allKeys, rrpUsageKeys...)
	cleanupCallbacks = append(cleanupCallbacks, rrpCleanup)
	golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/msrrp", "msrrp", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	handlers[RegGetValue] = regGetValueFunc
	handlers[RegSetValue] = regSetValueFunc
	handlers[RegDeleteValue] = regDeleteValueFunc
	handlers[RegEnumKeys] = regEnumKeysFunc
	handlers[RegEnumValues] = regEnumValuesFunc
	handlers[RegCreateKey] = regCreateKeyFunc
	handlers[RegDeleteKey] = regDeleteKeyFunc
	handlers[RegGetKeyInfo] = regGetKeyInfoFunc
	handlers[RegGetKeySecurity] = regGetKeySecurityInfoFunc
	handlers[RegSaveKey] = regSaveKeyFunc
	handlers[ToggleBackupResPriv] = toggleBackupRestorePrivilege
	helpFunctions[5] = printRrpHelp
}

func (self *shell) getRrpHandle() (rpccon *msrrp.RPCCon, err error) {
	val, found := self.binds["rrp"]
	if !found {
		var f *smb.File
		f, err = self.options.c.OpenFile(self.share, msrrp.MSRRPPipe)
		if err != nil {
			if err == smb.StatusMap[smb.StatusObjectNameNotFound] {
				err = fmt.Errorf("Named pipe not available. Is the service running?")
			}
			return
		}
		self.files = append(self.files, f)
		var bind *dcerpc.ServiceBind
		bind, err = dcerpc.Bind(f, msrrp.MSRRPUuid, msrrp.MSRRPMajorVersion, msrrp.MSRRPMinorVersion, dcerpc.MSRPCUuidNdr)
		if err != nil {
			self.println("Failed to bind to service")
			return
		}
		rpccon = msrrp.NewRPCCon(bind)
		self.binds["rrp"] = rpccon
	} else {
		rpccon = val.(*msrrp.RPCCon)
	}
	return
}

func (self *shell) getHiveHandle(hive byte) (hKeyBase []byte, err error) {
	var rpccon *msrrp.RPCCon
	var found bool
	rpccon, err = self.getRrpHandle()
	if err != nil {
		self.println(err)
		return
	}
	hKeyBase, found = self.regHiveHandles[hive]
	if !found {
		hKeyBase, err = rpccon.OpenBaseKey(hive)
		if err != nil {
			return
		}
		self.regHiveHandles[hive] = hKeyBase
	}
	return
}

func toggleBackupRestorePrivilege(self *shell, argArr interface{}) {
	if (self.regOpenCreateKeyOptions & msrrp.RegOptionBackupRestore) == msrrp.RegOptionBackupRestore {
		self.regOpenCreateKeyOptions ^= msrrp.RegOptionBackupRestore
		self.println("SeBackupPrivilege turned off")
	} else {
		self.regOpenCreateKeyOptions |= msrrp.RegOptionBackupRestore
		self.println("SeBackupPrivilege turned on")
	}
	return
}

func regGetValueFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[RegGetValue]
	var name string
	rpccon, err := self.getRrpHandle()
	if err != nil {
		self.println(err)
		return
	}
	if rpccon != nil {
	}
	args := argArr.([]string)
	numArgs := len(args)
	if numArgs < 1 {
		self.println(usage)
		return
	} else if numArgs > 1 {
		name = args[1]
	}
	var hive byte
	var hKeyBase []byte
	var regKeyPath, hiveStr string
	hive, hiveStr, regKeyPath, err = parseRegKeyPath(args[0])
	if err != nil {
		self.println(err)
		return
	}
	hKeyBase, err = self.getHiveHandle(hive)
	if err != nil {
		self.println(err)
		return
	}

	if self.verbose {
		self.printf("Getting reg value (%s) from key %s\\%s\n", name, hiveStr, regKeyPath)
	}
	var result any
	var dataType uint32
	result, dataType, err = getKeyValue(rpccon, hKeyBase, regKeyPath, name, self.regOpenCreateKeyOptions)
	if err != nil {
		self.println(err)
		return
	}
	switch dataType {
	case msrrp.RegSz:
		self.printf("REG_SZ: %s\n", result)
	case msrrp.RegDword:
		self.printf("REG_DWORD: %d\n", result)
	case msrrp.RegDwordBigEndian:
		self.printf("REG_DWORD_BigEndian: %d\n", result)
	case msrrp.RegQword:
		self.printf("REG_QWORD: %d\n", result)
	case msrrp.RegBinary:
		self.printf("REG_Binary: %x\n", result)
	case msrrp.RegExpandSz:
		self.printf("REG_ExpandSz: %s\n", result)
	case msrrp.RegMultiSz:
		var arr []string
		arr = result.([]string)
		self.println("REG_MultiSz:")
		for _, s := range arr {
			self.println(s)
		}
	default:
		self.printf("Unknown: %v\n", result)
	}
}

func regSetValueFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[RegSetValue]
	var name string
	rpccon, err := self.getRrpHandle()
	if err != nil {
		self.println(err)
		return
	}
	if rpccon != nil {
	}
	args := argArr.([]string)
	numArgs := len(args)
	if numArgs < 1 {
		self.println(usage)
		return
	} else if numArgs > 1 {
		name = args[1]
	}
	var hive byte
	var hKeyBase []byte
	var regKeyPath, hiveStr string
	hive, hiveStr, regKeyPath, err = parseRegKeyPath(args[0])
	if err != nil {
		self.println(err)
		return
	}
	hKeyBase, err = self.getHiveHandle(hive)
	if err != nil {
		self.println(err)
		return
	}
	input, err := self.getInput("Available types: SZ (string), DW (32bit), DWBE (32bit-be), QW (64bit), BIN (hex)", "Enter new value: <Type> <Value>: ")
	if err != nil {
		self.printf("Error getting user input: %s\n", err)
		return
	}
	parts := parseArgs(input)
	if len(parts) < 2 {
		self.println("Must provide both type and value")
		self.println(usage)
		return
	}
	var dataType uint32
	var dataValue any
	switch strings.ToUpper(parts[0]) {
	case "SZ":
		dataType = msrrp.RegSz
		dataValue = parts[1]
	case "DW":
		var val uint64
		dataType = msrrp.RegDword
		if strings.HasPrefix(parts[1], "0x") {
			val, err = strconv.ParseUint(parts[1][2:], 16, 32)
		} else {
			val, err = strconv.ParseUint(parts[1], 10, 32)
		}
		if err != nil {
			self.println(err)
			return
		}
		dataValue = uint32(val)
	case "DWBE":
		var val uint64
		dataType = msrrp.RegDwordBigEndian
		if strings.HasPrefix(parts[1], "0x") {
			val, err = strconv.ParseUint(parts[1][2:], 16, 32)
		} else {
			val, err = strconv.ParseUint(parts[1], 10, 32)
		}
		if err != nil {
			self.println(err)
			return
		}
		dataValue = uint32(val)
	case "QW":
		dataType = msrrp.RegQword
		if strings.HasPrefix(parts[1], "0x") {
			dataValue, err = strconv.ParseUint(parts[1][2:], 16, 64)
		} else {
			dataValue, err = strconv.ParseUint(parts[1], 10, 64)
		}
		if err != nil {
			self.println(err)
			return
		}
	case "BIN":
		dataType = msrrp.RegBinary
		value := strings.TrimPrefix(parts[1], "0x")
		self.printf("Trying to convert hex string (%s) to binary\n", value)
		dataValue, err = hex.DecodeString(value)
		if err != nil {
			self.println("Invalid hex string for binary value")
			return
		}
	}

	if self.verbose {
		self.printf("Setting reg value (%s) for key %s\\%s\n", name, hiveStr, regKeyPath)
	}
	err = setKeyValue(rpccon, hKeyBase, regKeyPath, name, dataValue, dataType, self.regOpenCreateKeyOptions)
	if err != nil {
		self.println(err)
		return
	}
}

func regDeleteValueFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[RegDeleteValue]
	var name string
	rpccon, err := self.getRrpHandle()
	if err != nil {
		self.println(err)
		return
	}
	args := argArr.([]string)
	numArgs := len(args)
	if numArgs < 1 {
		self.println(usage)
		return
	} else if numArgs > 1 {
		name = args[1]
	}
	var hive byte
	var hKeyBase []byte
	var regKeyPath, hiveStr string
	hive, hiveStr, regKeyPath, err = parseRegKeyPath(args[0])
	if err != nil {
		self.println(err)
		return
	}
	hKeyBase, err = self.getHiveHandle(hive)
	if err != nil {
		self.println(err)
		return
	}
	if self.verbose {
		self.printf("Deleting reg value (%s) for key %s\\%s\n", name, hiveStr, regKeyPath)
	}
	err = deleteKeyValue(rpccon, hKeyBase, regKeyPath, name, self.regOpenCreateKeyOptions)
	if err != nil {
		self.println(err)
		return
	}
}

func regEnumKeysFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[RegEnumKeys]
	rpccon, err := self.getRrpHandle()
	if err != nil {
		self.println(err)
		return
	}
	args := argArr.([]string)
	numArgs := len(args)
	if numArgs < 1 {
		self.println(usage)
		return
	}
	var hive byte
	var hKeyBase []byte
	var hiveStr, regKeyPath string
	hive, hiveStr, regKeyPath, err = parseRegKeyPath(args[0])
	if err != nil {
		self.println(err)
		return
	}
	hKeyBase, err = self.getHiveHandle(hive)
	if err != nil {
		self.println(err)
		return
	}

	var keys []string
	keys, err = rpccon.GetSubKeyNames(hKeyBase, regKeyPath)
	if err != nil {
		self.println(err)
		return
	}
	self.printf("Sub keys of (%s\\%s):\n", hiveStr, regKeyPath)
	for _, name := range keys {
		self.printf("%s\\%s\\%s\n", hiveStr, regKeyPath, name)
	}
}

func regEnumValuesFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[RegEnumValues]
	rpccon, err := self.getRrpHandle()
	if err != nil {
		self.println(err)
		return
	}
	args := argArr.([]string)
	numArgs := len(args)
	if numArgs < 1 {
		self.println(usage)
		return
	}
	var hive byte
	var hKeyBase []byte
	var hiveStr, regKeyPath string
	hive, hiveStr, regKeyPath, err = parseRegKeyPath(args[0])
	if err != nil {
		self.println(err)
		return
	}
	hKeyBase, err = self.getHiveHandle(hive)
	if err != nil {
		self.println(err)
		return
	}
	var items []msrrp.ValueInfo
	items, err = getKeyValues(rpccon, hKeyBase, regKeyPath, self.regOpenCreateKeyOptions)
	if err != nil {
		self.println(err)
		return
	}
	self.printf("Value names of key (%s\\%s):\n", hiveStr, regKeyPath)
	for _, item := range items {
		if item.Name == "" {
			item.Name = "(Default)"
		}
		self.printf("%q (type %s)\n", item.Name, item.TypeName)
	}
}

func regCreateKeyFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[RegCreateKey]
	rpccon, err := self.getRrpHandle()
	if err != nil {
		self.println(err)
		return
	}
	args := argArr.([]string)
	numArgs := len(args)
	if numArgs < 1 {
		self.println(usage)
		return
	}
	var hive byte
	var hKeyBase []byte
	var regKeyPath, hiveStr string
	var disposition uint32
	hive, hiveStr, regKeyPath, err = parseRegKeyPath(args[0])
	if err != nil {
		self.println(err)
		return
	}
	if regKeyPath == "" {
		self.println("Must specify a key to create and not just a Registry Hive")
		self.println(usage)
		return
	}
	hKeyBase, err = self.getHiveHandle(hive)
	if err != nil {
		self.println(err)
		return
	}

	if self.verbose {
		self.printf("Creating reg key %s\\%s\n", hiveStr, regKeyPath)
	}
	disposition, err = createKey(rpccon, hKeyBase, regKeyPath, self.regOpenCreateKeyOptions)
	if err != nil {
		self.println(err)
		return
	}
	if disposition == msrrp.RegCreatedNewKey {
		self.println("Successfully created registry key")
	} else {
		self.println("Registry key already exists!")
	}
}

func regDeleteKeyFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[RegDeleteKey]
	rpccon, err := self.getRrpHandle()
	if err != nil {
		self.println(err)
		return
	}
	args := argArr.([]string)
	numArgs := len(args)
	if numArgs < 1 {
		self.println(usage)
		return
	}
	var hive byte
	var hKeyBase []byte
	var regKeyPath, hiveStr string
	hive, hiveStr, regKeyPath, err = parseRegKeyPath(args[0])
	if err != nil {
		self.println(err)
		return
	}
	hKeyBase, err = self.getHiveHandle(hive)
	if err != nil {
		self.println(err)
		return
	}
	if self.verbose {
		self.printf("Deleting reg key %s\\%s\n", hiveStr, regKeyPath)
	}
	err = deleteKey(rpccon, hKeyBase, regKeyPath, self.regOpenCreateKeyOptions)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Successfully deleted registry key")

}

func regGetKeyInfoFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[RegGetKeyInfo]
	rpccon, err := self.getRrpHandle()
	if err != nil {
		self.println(err)
		return
	}
	args := argArr.([]string)
	numArgs := len(args)
	if numArgs < 1 {
		self.println(usage)
		return
	}
	var hive byte
	var hKeyBase []byte
	var hiveStr, regKeyPath string
	hive, hiveStr, regKeyPath, err = parseRegKeyPath(args[0])
	if err != nil {
		self.println(err)
		return
	}
	hKeyBase, err = self.getHiveHandle(hive)
	if err != nil {
		self.println(err)
		return
	}
	if self.verbose {
		self.printf("Getting key info for %s\\%s\n", hiveStr, regKeyPath)
	}
	var keyInfo *msrrp.KeyInfo
	keyInfo, err = getKeyInfo(rpccon, hKeyBase, regKeyPath, self.regOpenCreateKeyOptions)
	if err != nil {
		self.println(err)
		return
	}
	self.printf("Key info:\nName: %s\\%s\nClass: %s\nSubKeys: %d\nValues: %d\n", hiveStr, regKeyPath, keyInfo.ClassName, keyInfo.SubKeys, keyInfo.Values)
}

func regGetKeySecurityInfoFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[RegGetKeySecurity]
	rpccon, err := self.getRrpHandle()
	if err != nil {
		self.println(err)
		return
	}
	args := argArr.([]string)
	numArgs := len(args)
	if numArgs < 1 {
		self.println(usage)
		return
	}
	var hive byte
	var hKeyBase []byte
	var hiveStr, regKeyPath string
	hive, hiveStr, regKeyPath, err = parseRegKeyPath(args[0])
	if err != nil {
		self.println(err)
		return
	}
	hKeyBase, err = self.getHiveHandle(hive)
	if err != nil {
		self.println(err)
		return
	}
	if self.verbose {
		self.printf("Getting key security info for %s\\%s\n", hiveStr, regKeyPath)
	}
	var sd *msdtyp.SecurityDescriptor
	sd, err = getKeySecurityInfo(rpccon, hKeyBase, regKeyPath, self.regOpenCreateKeyOptions)
	if err != nil {
		self.println(err)
		return
	}
	self.printf("Key security information for: %s\\%s\n", hiveStr, regKeyPath)
	if sd.OwnerSid != nil {
		self.printf("OwnerSid: %s\n", sd.OwnerSid.ToString())
	}
	if sd.GroupSid != nil {
		self.printf("GroupSid: %s\n", sd.GroupSid.ToString())
	}
	if sd.Dacl != nil {
		self.println("DACL entries:")
		daclPermissions := sd.Dacl.Permissions()
		for _, item := range daclPermissions.Entries {
			self.printf("AceType: %s\nAceFlags: %s\nSid: %s\n", item.AceType, item.AceFlagStrings, item.Sid)
			self.printf("Permissions: ")
			permissions := ""
			for _, perm := range item.Permissions {
				permissions = fmt.Sprintf("%s,%s", permissions, perm)
			}
			self.println(strings.TrimPrefix(permissions, ","))
			self.println()
		}
	}
	if sd.Sacl != nil {
		self.println("SACL entries:")
		saclPermissions := sd.Sacl.Permissions()
		for _, item := range saclPermissions.Entries {
			self.printf("AceType: %s\nAceFlags: %s\nSid: %s\n", item.AceType, item.AceFlagStrings, item.Sid)
			self.printf("Permissions: ")
			permissions := ""
			for _, perm := range item.Permissions {
				permissions = fmt.Sprintf("%s,%s", permissions, perm)
			}
			self.println(strings.TrimPrefix(permissions, ","))
			self.println()
		}
	}
}

func regSaveKeyFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[RegSaveKey]
	rpccon, err := self.getRrpHandle()
	if err != nil {
		self.println(err)
		return
	}
	args := argArr.([]string)
	numArgs := len(args)
	if numArgs < 1 {
		self.println(usage)
		return
	}
	var hive byte
	var hKeyBase []byte
	var regKeyPath, hiveStr string
	hive, hiveStr, regKeyPath, err = parseRegKeyPath(args[0])
	if err != nil {
		self.println(err)
		return
	}
	hKeyBase, err = self.getHiveHandle(hive)
	if err != nil {
		self.println(err)
		return
	}
	var remotePath, ownerSid string
	remotePath, err = self.getInput("Enter remote absolute path to save key", "path: ")
	if err != nil {
		self.printf("Error getting user input: %s\n", err)
		return
	}
	if remotePath == "" {
		self.println("No path provided. Using a default path")
	}

	ownerSid, err = self.getInput("", "Enter SID of principal to own the reg file: ")
	if err != nil {
		self.printf("Error getting user input: %s\n", err)
		return
	}
	if ownerSid == "" {
		self.println("Empty SID, using a default ACL")
	} else {
		_, err = msdtyp.ConvertStrToSID(ownerSid)
		if err != nil {
			self.println("Invalid SID, using a default ACL")
			return
		}
	}

	acl := ""
	if ownerSid != "" {
		acl = fmt.Sprintf("with ACL restricting access to SID: %s", ownerSid)
	} else {
		acl = "with a default ACL"
	}
	if self.verbose {
		self.printf("Saving reg key (%s\\%s) to path (%s) %s\n", hiveStr, regKeyPath, remotePath, acl)
	}
	var path string
	path, err = saveRegKey(rpccon, hKeyBase, regKeyPath, remotePath, ownerSid, self.regOpenCreateKeyOptions)
	if err != nil {
		self.println(err)
		return
	}
	self.printf("Successfully dumped registry key to disk %q %s\n", path, acl)
}
