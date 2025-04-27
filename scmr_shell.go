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

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/msscmr"
	"github.com/jfjallid/golog"
)

const (
	ScmrEnumServices    = "scmrenumservices"
	ScmrEnumSvcConfigs  = "scmrenumserviceconfigs"
	ScmrGetSvcConfig    = "scmrgetserviceconfig"
	ScmrGetSvcStatus    = "scmrgetservicestatus"
	ScmrChangeSvcConfig = "scmrchangeserviceconfig"
	ScmrStartService    = "scmrstartservice"
	ScmrControlService  = "scmrcontrolservice"
	ScmrCreateService   = "scmrcreateservice"
	ScmrDeleteService   = "scmrdeleteservice"
	ScmrEnableService   = "scmrenableservice"
)

var scmrUsageKeys = []string{
	ScmrEnumServices,
	ScmrEnumSvcConfigs,
	ScmrGetSvcConfig,
	ScmrGetSvcStatus,
	ScmrChangeSvcConfig,
	ScmrStartService,
	ScmrControlService,
	ScmrCreateService,
	ScmrDeleteService,
	ScmrEnableService,
}

var scmrUsageMap = map[string]string{
	ScmrEnumServices:    ScmrEnumServices,
	ScmrEnumSvcConfigs:  ScmrEnumSvcConfigs,
	ScmrGetSvcConfig:    ScmrGetSvcConfig + " <name>",
	ScmrGetSvcStatus:    ScmrGetSvcStatus + " <name>",
	ScmrChangeSvcConfig: ScmrChangeSvcConfig + " <name>",
	ScmrStartService:    ScmrStartService + " <name>",
	ScmrControlService:  ScmrControlService + " <name>",
	ScmrCreateService:   ScmrCreateService + " <name>",
	ScmrDeleteService:   ScmrDeleteService + " <name>",
	ScmrEnableService:   ScmrEnableService + " <name>",
}

var scmrDescriptionMap = map[string]string{
	ScmrEnumServices:    "List services of specified type and states",
	ScmrEnumSvcConfigs:  "List configs of services of specified type and states",
	ScmrGetSvcConfig:    "Retrieve service config",
	ScmrGetSvcStatus:    "Check status of service",
	ScmrChangeSvcConfig: "Change config of a service",
	ScmrStartService:    "Start a service",
	ScmrControlService:  "Change state of service",
	ScmrCreateService:   "Create new service",
	ScmrDeleteService:   "Delete service",
	ScmrEnableService:   "Enable service (change start type)",
}

func printScmrHelp(self *shell) {
	self.showCustomHelpFunc(30, "MS-SCMR", scmrUsageKeys)
}

func init() {
	maps.Copy(usageMap, scmrUsageMap)
	maps.Copy(descriptionMap, scmrDescriptionMap)
	allKeys = append(allKeys, scmrUsageKeys...)
	golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/msscmr", "msscmr", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	handlers[ScmrEnumServices] = scmrEnumServicesFunc
	handlers[ScmrEnumSvcConfigs] = scmrEnumServiceConfigsFunc
	handlers[ScmrGetSvcConfig] = scmrGetServiceConfigFunc
	handlers[ScmrGetSvcStatus] = scmrGetServiceStatusFunc
	handlers[ScmrChangeSvcConfig] = scmrChangeServiceConfigFunc
	handlers[ScmrStartService] = scmrStartServiceFunc
	handlers[ScmrControlService] = scmrControlServiceFunc
	handlers[ScmrCreateService] = scmrCreateServiceFunc
	handlers[ScmrDeleteService] = scmrDeleteServiceFunc
	handlers[ScmrEnableService] = scmrEnableServiceFunc
	helpFunctions[6] = printScmrHelp
}

func (self *shell) getScmrHandle() (rpccon *msscmr.RPCCon, err error) {
	val, found := self.binds["scmr"]
	if !found {
		var f *smb.File
		f, err = self.options.c.OpenFile(self.share, msscmr.MSRPCSvcCtlPipe)
		if err != nil {
			if err == smb.StatusMap[smb.StatusObjectNameNotFound] {
				err = fmt.Errorf("Named pipe not available. Is the service running?")
			}
			return
		}
		self.files = append(self.files, f)
		var bind *dcerpc.ServiceBind
		bind, err = dcerpc.Bind(f, msscmr.MSRPCUuidSvcCtl, msscmr.MSRPCSvcCtlMajorVersion, msscmr.MSRPCSvcCtlMinorVersion, dcerpc.MSRPCUuidNdr)
		if err != nil {
			self.println("Failed to bind to service")
			return
		}
		rpccon = msscmr.NewRPCCon(bind)
		self.binds["scmr"] = rpccon
	} else {
		rpccon = val.(*msscmr.RPCCon)
	}
	return
}

func scmrEnumServicesFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[ScmrEnumServices]
	rpccon, err := self.getScmrHandle()
	if err != nil {
		self.println(err)
		return
	}
	var svcStateStr, svcTypeStr string
	args := argArr.([]string)
	numArgs := len(args)
	if numArgs > 1 {
		svcStateStr = args[0]
		svcTypeStr = args[1]
		return
	} else if numArgs == 1 {
		svcStateStr = args[0]
	}
	var serviceState uint32
	var serviceType uint32
	var val any
	if svcStateStr != "" {
		val, err = parseNumericArg(svcStateStr, serviceState)
		if err != nil {
			self.println(err)
			self.println(usage)
			return
		}
		serviceState = val.(uint32)
	} else {
		serviceState = 0x3
	}
	if svcTypeStr != "" {
		val, err = parseNumericArg(svcTypeStr, serviceType)
		if err != nil {
			self.println(err)
			self.println(usage)
			return
		}
		serviceType = val.(uint32)
	} else {
		serviceType = 0x30
	}

	var services []msscmr.EnumServiceStatusW
	services, err = rpccon.EnumServicesStatus(serviceType, serviceState)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Services:")
	for _, item := range services {
		self.printf("Service: %s\n Dislay Name: %s\n Status: %s\n", item.ServiceName, item.DisplayName, msscmr.ServiceStatusMap[item.ServiceStatus.CurrentState])
	}
	return
}

func scmrEnumServiceConfigsFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[ScmrEnumSvcConfigs]
	rpccon, err := self.getScmrHandle()
	if err != nil {
		self.println(err)
		return
	}
	var svcStateStr, svcTypeStr string
	args := argArr.([]string)
	numArgs := len(args)
	if numArgs > 1 {
		svcStateStr = args[0]
		svcTypeStr = args[1]
		return
	} else if numArgs == 1 {
		svcStateStr = args[0]
	}
	var serviceState uint32
	var serviceType uint32
	var val any
	if svcStateStr != "" {
		val, err = parseNumericArg(svcStateStr, serviceState)
		if err != nil {
			self.println(err)
			self.println(usage)
			return
		}
		serviceState = val.(uint32)
	} else {
		serviceState = 0x3
	}
	if svcTypeStr != "" {
		val, err = parseNumericArg(svcTypeStr, serviceType)
		if err != nil {
			self.println(err)
			self.println(usage)
			return
		}
		serviceType = val.(uint32)
	} else {
		serviceType = 0x30
	}

	var services []msscmr.EnumServiceStatusW
	services, err = rpccon.EnumServicesStatus(serviceType, serviceState)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Services:")
	for _, item := range services {
		config, err := rpccon.GetServiceConfig(item.ServiceName)
		if err != nil {
			self.println(err)
			continue
		}
		self.printf("DISPLAY_NAME       : %s\n", config.DisplayName)
		self.printf("SERVICE_NAME       : %s\n", item.ServiceName)
		self.printf("TYPE               : %s\n", config.ServiceType)
		self.printf("START_TYPE         : %s\n", config.StartType)
		self.printf("ERROR_CONTROL      : %s\n", config.ErrorControl)
		self.printf("BINARY_PATH_NAME   : %s\n", config.BinaryPathName)
		self.printf("LOAD_ORDER_GROUP   : %s\n", config.LoadOrderGroup)
		self.printf("TAG                : %d\n", config.TagId)
		self.printf("DEPENDENCIES       : %s\n", config.Dependencies)
		self.printf("SERVICE_START_NAME : %s\n", config.ServiceStartName)
		self.println()
	}
}

func scmrGetServiceConfigFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[ScmrGetSvcConfig]
	var name string
	rpccon, err := self.getScmrHandle()
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
	name = args[0]
	var config msscmr.ServiceConfig
	config, err = rpccon.GetServiceConfig(name)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Service config:")
	self.printf("DISPLAY_NAME       : %s\n", config.DisplayName)
	self.printf("SERVICE_NAME       : %s\n", name)
	self.printf("TYPE               : %s\n", config.ServiceType)
	self.printf("START_TYPE         : %s\n", config.StartType)
	self.printf("ERROR_CONTROL      : %s\n", config.ErrorControl)
	self.printf("BINARY_PATH_NAME   : %s\n", config.BinaryPathName)
	self.printf("LOAD_ORDER_GROUP   : %s\n", config.LoadOrderGroup)
	self.printf("TAG                : %d\n", config.TagId)
	self.printf("DEPENDENCIES       : %s\n", config.Dependencies)
	self.printf("SERVICE_START_NAME : %s\n", config.ServiceStartName)
	self.println()
	return
}

func scmrGetServiceStatusFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[ScmrGetSvcConfig]
	var name string
	rpccon, err := self.getScmrHandle()
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
	name = args[0]
	status, err := rpccon.GetServiceStatus(name)
	if err != nil {
		self.println(err)
		return
	}
	self.printf("Service Status of (%s): %v\n", name, msscmr.ServiceStatusMap[status])
}

func scmrChangeServiceConfigFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[ScmrChangeSvcConfig]
	var name string
	rpccon, err := self.getScmrHandle()
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
	name = args[0]
	var svcType, svcStartType, svcErrorControl uint32
	var val any
	var itemsChanged []string
	self.println("To skip changing a specific setting, leave value empty")
	svcExePath, err := self.getInput("", "New service binPath: ")
	if err != nil {
		self.printf("Error getting path to service binary: %s\n", err)
		return
	}
	if svcExePath != "" {
		itemsChanged = append(itemsChanged, fmt.Sprintf("binPath: %s", svcExePath))
	}
	svcTypeStr, err := self.getInput("kernel_driver: 0x1, file_system_driver: 0x2, win32_own_service: 0x10, win32_share_process: 0x20", "New service type: ")
	if err != nil {
		self.printf("Error getting service type: %s\n", err)
		return
	}
	if svcTypeStr == "" {
		svcType = msscmr.ServiceNoChange
	} else {
		val, err = parseNumericArg(svcTypeStr, svcType)
		if err != nil {
			self.println(err)
			return
		}
		svcType = val.(uint32)
		itemsChanged = append(itemsChanged, fmt.Sprintf("service type: 0x%x", svcType))
	}
	svcStartTypeStr, err := self.getInput("BootStart: 0x0, SystemStart: 0x1, AutoStart: 0x2, DemandStart: 0x3, Disabled: 0x4", "New start type: ")
	if err != nil {
		self.printf("Error getting service start type: %s\n", err)
		return
	}
	if svcStartTypeStr == "" {
		svcStartType = msscmr.ServiceNoChange
	} else {
		val, err = parseNumericArg(svcStartTypeStr, svcStartType)
		if err != nil {
			self.println(err)
			return
		}
		svcStartType = val.(uint32)
		itemsChanged = append(itemsChanged, fmt.Sprintf("service start type: 0x%x", svcStartType))
	}

	svcErrorCtlStr, err := self.getInput("Ignore: 0x, Normal: 0x1, Severe: 0x2, Critical: 0x3", "New error control: ")
	if err != nil {
		self.printf("Error getting service error control: %s\n", err)
		return
	}
	if svcErrorCtlStr == "" {
		svcErrorControl = msscmr.ServiceNoChange
	} else {
		val, err = parseNumericArg(svcErrorCtlStr, svcErrorControl)
		if err != nil {
			self.println(err)
			return
		}
		svcErrorControl = val.(uint32)
		itemsChanged = append(itemsChanged, fmt.Sprintf("error control: 0x%x", svcErrorControl))
	}
	svcDisplayName, err := self.getInput("", "New display name: ")
	if err != nil {
		self.printf("Error getting service display name: %s\n", err)
		return
	}
	if svcDisplayName != "" {
		itemsChanged = append(itemsChanged, fmt.Sprintf("display name: %s", svcDisplayName))
	}
	svcStartName, err := self.getInput("", "New Service start name: ")
	if err != nil {
		self.printf("Error getting service start name: %s\n", err)
		return
	}
	if svcStartName != "" {
		itemsChanged = append(itemsChanged, fmt.Sprintf("start name: %s", svcStartName))
		self.println("Make sure to also provide the user password if applicable")
	}
	svcUserPass, err := self.getInput("Leave empty to keep existing password", "New service account password: ")
	if err != nil {
		self.printf("Error getting service account password: %s\n", err)
		return
	}
	if svcUserPass != "" {
		itemsChanged = append(itemsChanged, "service user pass: *******")
	}

	if len(itemsChanged) == 0 {
		self.println("Must change some part of the service config")
		self.println(usage)
		return
	}
	if self.verbose {
		self.printf("Trying to change config for %s\n", name)
		for _, item := range itemsChanged {
			self.println(item)
		}
	}
	err = rpccon.ChangeServiceConfig(name, svcType, svcStartType, svcErrorControl, svcExePath, svcStartName, svcUserPass, svcDisplayName, "", "", 0)
	if err != nil {
		self.println(err)
		return
	}
	if err != nil {
		self.println(err)
		return
	}

	self.println("Successfully modified the service!")
}

func scmrStartServiceFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[ScmrStartService]
	var name string
	rpccon, err := self.getScmrHandle()
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
	name = args[0]
	arguments := args[1:]
	err = rpccon.StartService(name, arguments)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Service started!")
}

func scmrControlServiceFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[ScmrGetSvcConfig]
	var name string
	rpccon, err := self.getScmrHandle()
	if err != nil {
		self.println(err)
		return
	}
	args := argArr.([]string)
	numArgs := len(args)
	if numArgs < 2 {
		self.println(usage)
		return
	}
	name = args[0]
	var action uint32
	var verb string
	switch strings.ToLower(args[1]) {
	case "stop":
		action = msscmr.ServiceControlStop
		verb = "stopped"
	case "pause":
		action = msscmr.ServiceControlPause
		verb = "paused"
	case "continue":
		action = msscmr.ServiceControlContinue
		verb = "resumed"
	}
	if self.verbose {
		self.printf("Trying to (%s) service %s\n", args[1], name)
	}
	err = rpccon.ControlService(name, action)
	if err != nil {
		self.println(err)
		return
	}
	self.printf("Successfully %s %s\n", verb, name)
}

func scmrCreateServiceFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[ScmrCreateService]
	var name string
	rpccon, err := self.getScmrHandle()
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
	name = args[0]
	if self.verbose {
		self.printf("Trying to create service with a name of %s\n", name)
	}
	var svcType, svcStartType, svcErrorControl uint32
	var val any
	svcExePath, err := self.getInput("", "Service binPath: ")
	if err != nil {
		self.printf("Error getting path to service binary: %s\n", err)
		return
	}
	if svcExePath == "" {
		self.println("Cannot create a service without a path to a service binary")
		return
	}
	svcTypeStr, err := self.getInput("kernel_driver: 0x1, file_system_driver: 0x2, win32_own_service: 0x10, win32_share_process: 0x20", "Service type (default 0x30): ")
	if err != nil {
		self.printf("Error getting service type: %s\n", err)
		return
	}
	if svcTypeStr == "" {
		svcType = 0x30
	} else {
		val, err = parseNumericArg(svcTypeStr, svcType)
		if err != nil {
			self.println(err)
			return
		}
		svcType = val.(uint32)
	}
	svcStartTypeStr, err := self.getInput("BootStart: 0x0, SystemStart: 0x1, AutoStart: 0x2, DemandStart: 0x3, Disabled: 0x4", "Service start type (default 0x3): ")
	if err != nil {
		self.printf("Error getting service start type: %s\n", err)
		return
	}
	if svcStartTypeStr == "" {
		svcStartType = 0x3
	} else {
		val, err = parseNumericArg(svcStartTypeStr, svcStartType)
		if err != nil {
			self.println(err)
			return
		}
		svcStartType = val.(uint32)
	}

	svcErrorCtlStr, err := self.getInput("Ignore: 0x, Normal: 0x1, Severe: 0x2, Critical: 0x3", "Service error control (default 0x1): ")
	if err != nil {
		self.printf("Error getting service error control: %s\n", err)
		return
	}
	if svcErrorCtlStr == "" {
		svcErrorControl = 0x1
	} else {
		val, err = parseNumericArg(svcErrorCtlStr, svcErrorControl)
		if err != nil {
			self.println(err)
			return
		}
		svcErrorControl = val.(uint32)
	}
	svcDisplayName, err := self.getInput("", "Service display name: ")
	if err != nil {
		self.printf("Error getting service display name: %s\n", err)
		return
	}
	if svcDisplayName == "" {
		svcDisplayName = name
	}
	svcStartName, err := self.getInput("", "Service start name (default LocalSystem): ")
	if err != nil {
		self.printf("Error getting service start name: %s\n", err)
		return
	}
	if svcStartName == "" {
		svcStartName = "LocalSystem"
	}
	svcUserPass, err := self.getInput("Leave empty to keep existing password", "Service account password: ")
	if err != nil {
		self.printf("Error getting service account password: %s\n", err)
		return
	}

	if self.verbose {
		self.printf("Trying to create a service with name: %q, type: 0x%x, startType: 0x%x, errorCtl: 0x%x, startName: %q, displayName: %q, and a binPath: %s\n")
	}
	err = rpccon.CreateService(name, svcType, svcStartType, svcErrorControl, svcExePath, svcStartName, svcUserPass, svcDisplayName, false)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Successfully created the service")
}

func scmrDeleteServiceFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[ScmrDeleteService]
	var name string
	rpccon, err := self.getScmrHandle()
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
	name = args[0]
	err = rpccon.DeleteService(name)
	if err != nil {
		self.println(err)
		return
	}
	self.printf("Successfully deleted the service %s\n", name)
}

func scmrEnableServiceFunc(self *shell, argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	usage := "Usage: " + usageMap[ScmrEnableService]
	var name string
	rpccon, err := self.getScmrHandle()
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
	name = args[0]
	err = rpccon.ChangeServiceConfig(name, msscmr.ServiceNoChange, msscmr.ServiceDemandStart, msscmr.ServiceNoChange, "", "", "", "", "", "", 0)
	if err != nil {
		self.println(err)
		return
	}
	self.println("Service enabled!")
}
