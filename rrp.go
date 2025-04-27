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
	"math/rand"
	"os"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/msrrp"
)

var helpRRPOptions = `
    Usage: ` + os.Args[0] + ` --rrp [options] <action>
    ` + helpConnectionOptions + `
    Action:
          --get-value        Retrive registry value --name for --key
          --set-value        Set or create registry value --name for --key
          --delete-value     Delete registry value --name for --key
          --enum-keys        List subkey names for --key
          --enum-values      List value names for --key
          --create-key       Create new registry key specified with --key
          --delete-key       Delete registry key specified with --key
          --get-key-info     Retrieve key info
          --get-key-security Retrieve key security information
          --save-key         Save registry key and subkeys to disk

    RRP options:
          --name <string>        Name of registry key value. Skip to target default value
          --key <path>           Registry path to key beginning with Hive
                                 e.g., "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
          --remote-path <path>   Absolute path on target where to store saved registry key.
                                 If no filename is provided at the end, a random name will be used
          --owner-sid <SID>      SID of security principal that should own the registry key dump
          --string-val <string>  Used with --set-value
          --dword-val <uint32>   Used with --set-value
          --qword-val <uint64>   Used with --set-value
          --binary-val <hex>     Used with --set-value. Hex string without leading 0x
          --use-debug-privilege  Indicate that SeBackupPrivilege is held.
                                 Required to retrieve SACL entries with --get-key-security
`

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func getRandString(n int) string {
	arr := make([]rune, n)
	for i := range arr {
		arr[i] = letters[rand.Intn(len(letters))]
	}
	return string(arr)
}

func parseRegKeyPath(key string) (hive byte, hiveStr, regKeyPath string, err error) {
	// Determine base registry hive
	var pathStr string
	hiveStr, pathStr, _ = strings.Cut(key, "\\")
	hiveStr = strings.ToUpper(hiveStr)
	switch hiveStr {
	case "HKLM":
		hive = msrrp.HKEYLocalMachine
	case "HKCU":
		hive = msrrp.HKEYCurrentUser
	case "HKCR":
		hive = msrrp.HKEYClassesRoot
	case "HKU":
		hive = msrrp.HKEYUsers
	case "HKCC":
		hive = msrrp.HKEYCurrentConfig
	default:
		err = fmt.Errorf("Unknown registry hive %s", hiveStr)
		return
	}
	regKeyPath = strings.TrimSuffix(pathStr, "\\")
	return
}

func getKeyValue(rpccon *msrrp.RPCCon, hKeyBase []byte, regKeyPath, valueName string, keyOptions uint32) (result any, dataType uint32, err error) {
	var hKey []byte
	if regKeyPath != "" {
		hKey, err = rpccon.OpenSubKeyExt(hKeyBase, regKeyPath, keyOptions, 0)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer rpccon.CloseKeyHandle(hKey)
	} else {
		hKey = hKeyBase
	}
	result, dataType, err = rpccon.QueryValueExt(hKey, valueName)
	if err != nil {
		log.Errorln(err)
	}
	return
}

func setKeyValue(rpccon *msrrp.RPCCon, hKeyBase []byte, regKeyPath, valueName string, dataValue any, dataType, keyOptions uint32) (err error) {
	var hKey []byte
	if regKeyPath != "" {
		hKey, err = rpccon.OpenSubKeyExt(hKeyBase, regKeyPath, dataType, 0)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer rpccon.CloseKeyHandle(hKey)
	} else {
		hKey = hKeyBase
	}
	err = rpccon.SetValue(hKey, valueName, dataValue, dataType)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func deleteKeyValue(rpccon *msrrp.RPCCon, hKeyBase []byte, regKeyPath, valueName string, keyOptions uint32) (err error) {
	var hKey []byte
	if regKeyPath != "" {
		hKey, err = rpccon.OpenSubKeyExt(hKeyBase, regKeyPath, keyOptions, 0)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer rpccon.CloseKeyHandle(hKey)
	} else {
		hKey = hKeyBase
	}
	err = rpccon.DeleteValue(hKey, valueName)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func getKeyValues(rpccon *msrrp.RPCCon, hKeyBase []byte, regKeyPath string, keyOptions uint32) (items []msrrp.ValueInfo, err error) {
	var hKey []byte
	if regKeyPath != "" {
		hKey, err = rpccon.OpenSubKeyExt(hKeyBase, regKeyPath, keyOptions, 0)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer rpccon.CloseKeyHandle(hKey)
	} else {
		hKey = hKeyBase
	}
	items, err = rpccon.GetKeyValues(hKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func createKey(rpccon *msrrp.RPCCon, hKeyBase []byte, regKeyPath string, keyOptions uint32) (disposition uint32, err error) {
	var hKey, hSubKey []byte
	parts := strings.Split(regKeyPath, "\\")
	targetKey := parts[len(parts)-1]
	parentKey := strings.Join(parts[:len(parts)-1], "\\")
	if parentKey != "" {
		hKey, err = rpccon.OpenSubKeyExt(hKeyBase, parentKey, keyOptions, 0)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer rpccon.CloseKeyHandle(hKey)
	} else {
		hKey = hKeyBase
	}
	// Use a default DACL
	hSubKey, disposition, err = rpccon.CreateKey(hKey, targetKey, "", keyOptions, 0, nil)
	if err != nil {
		log.Errorln(err)
		return
	}
	rpccon.CloseKeyHandle(hSubKey)
	return
}

func deleteKey(rpccon *msrrp.RPCCon, hKeyBase []byte, regKeyPath string, keyOptions uint32) (err error) {
	var hKey []byte
	parts := strings.Split(regKeyPath, "\\")
	targetKey := parts[len(parts)-1]
	parentKey := strings.Join(parts[:len(parts)-1], "\\")
	if parentKey != "" {
		hKey, err = rpccon.OpenSubKeyExt(hKeyBase, parentKey, keyOptions, 0)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer rpccon.CloseKeyHandle(hKey)
	} else {
		hKey = hKeyBase
	}
	err = rpccon.DeleteKey(hKey, targetKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func getKeyInfo(rpccon *msrrp.RPCCon, hKeyBase []byte, regKeyPath string, keyOptions uint32) (keyInfo *msrrp.KeyInfo, err error) {
	var hKey []byte
	if regKeyPath != "" {
		hKey, err = rpccon.OpenSubKeyExt(hKeyBase, regKeyPath, keyOptions, 0)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer rpccon.CloseKeyHandle(hKey)
	} else {
		hKey = hKeyBase
	}
	keyInfo, err = rpccon.QueryKeyInfo(hKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func getKeySecurityInfo(rpccon *msrrp.RPCCon, hKeyBase []byte, regKeyPath string, keyOptions uint32) (sd *msdtyp.SecurityDescriptor, err error) {
	var hKey []byte
	var securityInformation uint32 = msrrp.OwnerSecurityInformation | msrrp.GroupSecurityInformation | msrrp.DACLSecurityInformation
	if keyOptions&msrrp.RegOptionBackupRestore == msrrp.RegOptionBackupRestore {
		securityInformation |= msrrp.SACLSecurityInformation
	}
	if regKeyPath != "" {
		hKey, err = rpccon.OpenSubKeyExt(hKeyBase, regKeyPath, keyOptions, 0)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer rpccon.CloseKeyHandle(hKey)
	} else {
		hKey = hKeyBase
	}
	sd, err = rpccon.GetKeySecurityExt(hKey, securityInformation)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func saveRegKey(rpccon *msrrp.RPCCon, hKeyBase []byte, regKeyPath, remotePath, ownerSid string, keyOptions uint32) (path string, err error) {
	var hKey []byte
	if regKeyPath != "" {
		hKey, err = rpccon.OpenSubKeyExt(hKeyBase, regKeyPath, keyOptions, 0)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer rpccon.CloseKeyHandle(hKey)
	} else {
		hKey = hKeyBase
	}
	remotePath = strings.ReplaceAll(remotePath, "/", "\\")
	parts := strings.Split(regKeyPath, "\\")
	numParts := len(parts)
	keyName := ""
	if numParts > 1 {
		keyName = parts[numParts-1]
	} else {
		keyName = getRandString(7)
	}
	if remotePath == "" {
		path = fmt.Sprintf("c:\\windows\\temp\\%s", keyName)
	} else {
		parts = strings.Split(remotePath, "\\")
		numParts = len(parts)
		if numParts > 1 {
			if strings.HasSuffix(remotePath, "\\") {
				path = remotePath + keyName
			} else {
				path = strings.TrimSuffix(remotePath, "\\")
			}
		} else {
			path = fmt.Sprintf("c:\\windows\\temp\\%s", keyName)
		}
	}
	// Check if destination file contains a file extension
	if !strings.Contains(path, ".") {
		path += ".dmp"
	}
	err = rpccon.RegSaveKey(hKey, path, ownerSid)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func handleRrp(args *userArgs) (err error) {
	var hive byte
	var hiveStr string
	var regKeyPath string
	var dataType uint32
	var dataValue any
	var openCreateKeyOptions uint32
	numActions := 0
	if args.getKeyValue {
		numActions++
	}
	if args.setKeyValue {
		numActions++
	}
	if args.deleteValue {
		numActions++
	}
	if args.deleteKey {
		numActions++
	}
	if args.createKey {
		numActions++
	}
	if args.saveKey {
		if args.remotePath == "" {
			fmt.Println("Must specify --remote-path to save the registry key to")
			flags.Usage()
			return
		}
		numActions++
	}
	if args.enumKeys {
		numActions++
	}
	if args.enumValues {
		numActions++
	}
	if args.getKeyInfo {
		numActions++
	}
	if args.getKeySecurity {
		numActions++
	}
	if args.setKeySecurity {
		numActions++
	}
	if numActions != 1 {
		fmt.Println("Must specify ONE action. No more, no less")
		flags.Usage()
		return
	}
	if args.key == "" {
		fmt.Println("Must specify a registry key path")
		flags.Usage()
		return
	}
	if args.setKeyValue {
		numValues := 0
		if isFlagSet("string-val") {
			dataType = msrrp.RegSz
			dataValue = args.stringValue
			numValues++
		}
		if isFlagSet("dword-val") {
			dataType = msrrp.RegDword
			dataValue = uint32(args.dwordValue)
			numValues++
		}
		if isFlagSet("qword-val") {
			dataType = msrrp.RegQword
			dataValue = args.qwordValue
			numValues++
		}
		if isFlagSet("binary-val") {
			dataType = msrrp.RegBinary
			dataValue = args.binaryValue
			numValues++
		}
		if numValues != 1 {
			fmt.Println("Specify only one type of value when setting a registry key")
			flags.Usage()
			return
		}
	}
	if args.debugPrivilege {
		openCreateKeyOptions = msrrp.RegOptionBackupRestore
	}

	// Determine base registry hive
	hive, hiveStr, regKeyPath, err = parseRegKeyPath(args.key)
	if err != nil {
		log.Errorln(err)
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
	f, err := conn.OpenFile(share, msrrp.MSRRPPipe)
	if err != nil {
		if err == smb.StatusMap[smb.StatusObjectNameNotFound] {
			err = fmt.Errorf("RemoteRegistry is currently not running")
		}
		log.Errorln(err)
		return
	}
	defer f.CloseFile()

	bind, err := dcerpc.Bind(f, msrrp.MSRRPUuid, msrrp.MSRRPMajorVersion, msrrp.MSRRPMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		log.Errorln("Failed to bind to service")
		log.Errorln(err)
		return
	}

	rpccon := msrrp.NewRPCCon(bind)
	fmt.Println("Successfully performed Bind to RRP service")

	hKeyBase, err := rpccon.OpenBaseKey(hive)
	if err != nil {
		log.Errorln(err)
		return
	}
	if args.getKeyValue {
		fmt.Printf("Querying value for key: %q and value: %q\n", args.key, args.name)
		var result any
		result, dataType, err = getKeyValue(rpccon, hKeyBase, regKeyPath, args.name, openCreateKeyOptions)
		switch dataType {
		case msrrp.RegSz:
			fmt.Printf("REG_SZ: %s\n", result)
		case msrrp.RegDword:
			fmt.Printf("REG_DWORD: %d\n", result)
		case msrrp.RegDwordBigEndian:
			fmt.Printf("REG_DWORD_BigEndian: %d\n", result)
		case msrrp.RegQword:
			fmt.Printf("REG_QWORD: %d\n", result)
		case msrrp.RegBinary:
			fmt.Printf("REG_Binary: %x\n", result)
		default:
			fmt.Printf("Unknown: %v\n", result)
		}
		return
	} else if args.setKeyValue {
		err = setKeyValue(rpccon, hKeyBase, regKeyPath, args.name, dataValue, dataType, openCreateKeyOptions)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Successfully set value for registry key")
		return
	} else if args.deleteValue {
		err = deleteKeyValue(rpccon, hKeyBase, regKeyPath, args.name, openCreateKeyOptions)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Successfully deleted value for registry key")
		return
	} else if args.deleteKey {
		err = deleteKey(rpccon, hKeyBase, regKeyPath, openCreateKeyOptions)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Successfully deleted registry key")
		return
	} else if args.createKey {
		var disp uint32
		disp, err = createKey(rpccon, hKeyBase, regKeyPath, openCreateKeyOptions)
		if err != nil {
			log.Errorln(err)
			return
		}
		if disp == msrrp.RegCreatedNewKey {
			fmt.Println("Successfully created registry key")
		} else {
			fmt.Println("Registry key already exists!")
		}
		return
	} else if args.saveKey {
		var path string
		path, err = saveRegKey(rpccon, hKeyBase, regKeyPath, args.remotePath, args.ownerSid.s, openCreateKeyOptions)
		if err != nil {
			log.Errorln(err)
			return
		}
		acl := ""
		if args.ownerSid.s != "" {
			acl = fmt.Sprintf("with ACL restricting access to SID: %s", args.ownerSid.s)
		} else {
			acl = "with a default ACL"
		}
		fmt.Printf("Successfully dumped registry key to %q %s\n", path, acl)
		return
	} else if args.enumKeys {
		var keys []string
		keys, err = rpccon.GetSubKeyNames(hKeyBase, regKeyPath)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Printf("Sub keys of (%s\\%s):\n", hiveStr, regKeyPath)
		for _, name := range keys {
			fmt.Printf("%s\\%s\\%s\n", hiveStr, regKeyPath, name)
		}
		return
	} else if args.enumValues {
		var items []msrrp.ValueInfo
		items, err = getKeyValues(rpccon, hKeyBase, regKeyPath, openCreateKeyOptions)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Printf("Value names of key (%s\\%s):\n", hiveStr, regKeyPath)
		for _, item := range items {
			fmt.Printf("%q (type %s)\n", item.Name, item.TypeName)
		}
		return
	} else if args.getKeyInfo {
		var keyInfo *msrrp.KeyInfo
		keyInfo, err = getKeyInfo(rpccon, hKeyBase, regKeyPath, openCreateKeyOptions)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Printf("Key info:\nName: %s\\%s\nClass: %s\nSubKeys: %d\nValues: %d\n", hiveStr, regKeyPath, keyInfo.ClassName, keyInfo.SubKeys, keyInfo.Values)
		return
	} else if args.getKeySecurity {
		var sd *msdtyp.SecurityDescriptor
		sd, err = getKeySecurityInfo(rpccon, hKeyBase, regKeyPath, openCreateKeyOptions)
		fmt.Printf("Key security information for: %s\\%s\n", hiveStr, regKeyPath)
		if sd.OwnerSid != nil {
			fmt.Printf("OwnerSid: %s\n", sd.OwnerSid.ToString())
		}
		if sd.GroupSid != nil {
			fmt.Printf("GroupSid: %s\n", sd.GroupSid.ToString())
		}
		if sd.Dacl != nil {
			fmt.Println("DACL entries:")
			daclPermissions := sd.Dacl.Permissions()
			for _, item := range daclPermissions.Entries {
				fmt.Printf("AceType: %s\nAceFlags: %s\nSid: %s\n", item.AceType, item.AceFlagStrings, item.Sid)
				fmt.Printf("Permissions: ")
				permissions := ""
				for _, perm := range item.Permissions {
					permissions = fmt.Sprintf("%s,%s", permissions, perm)
				}
				fmt.Println(strings.TrimPrefix(permissions, ","))
				fmt.Println()
			}
		}
		if sd.Sacl != nil {
			fmt.Println("SACL entries:")
			saclPermissions := sd.Sacl.Permissions()
			for _, item := range saclPermissions.Entries {
				fmt.Printf("AceType: %s\nAceFlags: %s\nSid: %s\n", item.AceType, item.AceFlagStrings, item.Sid)
				fmt.Printf("Permissions: ")
				permissions := ""
				for _, perm := range item.Permissions {
					permissions = fmt.Sprintf("%s,%s", permissions, perm)
				}
				fmt.Println(strings.TrimPrefix(permissions, ","))
				fmt.Println()
			}
		}
		return
	}
	return
}
