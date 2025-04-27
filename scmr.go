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
	"strings"

	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/msscmr"
)

const validServiceTypes uint64 = 0x1 | 0x2 | 0x10 | 0x20

var helpScmrOptions = `
    Usage: ` + os.Args[0] + ` --scmr [options] <action>
    ` + helpConnectionOptions + `
    Action:
          --enum-services         List services of specified type and states
          --enum-service-configs  List configs of services of specified type and states
          --get-service-config    Retrieve service config
          --get-service-status    Check status of service
          --change-service-config Change config of a service
          --start-service         Start a service specified by --name with --args
          --control-service       Change state of service
          --create-service        Create new service (default type: 0x10, startType: 0x3,
                                  error: 0x0, startName: LocalSystem, displayName: service name)
          --delete-service        Delete service

    SCMR options:
          --service-type <int>    Type of service. One or a combination of:
                                  kernel_driver: 0x1, file_system_driver: 0x2
                                  win32_own_process: 0x10, win32_share_process: 0x20
          --service-status <int>  Service state. (default 0x3) Active 0x1, Inactive 0x2, All 0x3
          --name <string>         Name of service to query, change, create or delete
          --args <Strings>        Comma-separated list of start arguments for service
          --action <action>       Service control action (stop, pause, continue)
          --start-type: <int>     Service start type: BootStart 0x0, SystemStart 0x1,
                                  AutoStart 0x2, DemandStart 0x3, Disabled 0x4
          --start-name <string>   Username to run service as. (default LocalSystem)
          --start-pass <string>   Password of user specified by --start-name
          --display-name <string> Service display name
          --error-control <int>   Service error control (default 0x1: ErrorNormal)
          --exe-path <string>     Absolute path to service binary
`

func handleScmr(args *userArgs) (err error) {
	numActions := 0
	if args.enumServices {
		numActions++
	}
	if args.enumServiceConfigs {
		numActions++
	}
	if args.getServiceConfig {
		numActions++
	}
	if args.getServiceStatus {
		numActions++
	}
	if args.changeServiceConfig {
		numActions++
	}
	if args.startService {
		numActions++
	}
	if args.controlService {
		action := strings.ToLower(args.serviceAction)
		if (action != "stop") && (action != "pause") && (action != "continue") {
			fmt.Println("Must specify a valid control action. (stop, pause, continue)")
			flags.Usage()
			return
		}
		numActions++
	}
	if args.createService {
		numActions++
	}
	if args.deleteService {
		numActions++
	}
	if numActions != 1 {
		fmt.Println("Must specify ONE action. No more, no less")
		flags.Usage()
		return
	}
	if args.enumServiceConfigs || args.enumServices {
		if (args.serviceState < 1) || (args.serviceState > 3) {
			fmt.Println("Invalid --service-state for --enum-services.")
			flags.Usage()
			return
		}
		if args.serviceType & ^validServiceTypes != 0 {
			fmt.Println("Invalid --service-type for --enum-services.")
			flags.Usage()
			return
		}
	}
	if args.getServiceConfig || args.startService {
		if args.name == "" {
			fmt.Println("Must specify a service name")
			flags.Usage()
			return
		}
	}
	if args.changeServiceConfig {
		if !isFlagSet("service-type") && !isFlagSet("start-type") && !isFlagSet("start-name") && !isFlagSet("start-pass") && !isFlagSet("error-control") && !isFlagSet("exe-path") {
			fmt.Println("Must specify some part of the config to change for the service")
			flags.Usage()
			return
		}
		if !isFlagSet("service-type") {
			args.serviceType = uint64(msscmr.ServiceNoChange)
		} else if args.serviceType & ^validServiceTypes != 0 {
			fmt.Println("Invalid --service-type")
			flags.Usage()
			return
		}
		if !isFlagSet("start-type") {
			args.serviceStartType = uint64(msscmr.ServiceNoChange)
		} else if args.serviceStartType > 0x4 {
			fmt.Println("Invalid --start-type")
			flags.Usage()
			return
		}
		if !isFlagSet("error-control") {
			args.serviceErrorControl = uint64(msscmr.ServiceNoChange)
		} else if args.serviceErrorControl > 0x3 {
			fmt.Println("Invalid --error-control")
			flags.Usage()
			return
		}
	}
	if args.createService {
		if !isFlagSet("service-type") {
			args.serviceType = uint64(msscmr.ServiceWin32OwnProcess)
		} else if args.serviceType & ^validServiceTypes != 0 {
			fmt.Println("Invalid --service-type")
			flags.Usage()
			return
		}
		if !isFlagSet("start-type") {
			args.serviceStartType = uint64(msscmr.ServiceDemandStart)
		} else if args.serviceStartType > 0x4 {
			fmt.Println("Invalid --start-type")
			flags.Usage()
			return
		}
		if !isFlagSet("error-control") {
			args.serviceErrorControl = uint64(msscmr.ServiceErrorIgnore)
		} else if args.serviceErrorControl > 0x3 {
			fmt.Println("Invalid --error-control")
			flags.Usage()
			return
		}
		if args.exePath == "" {
			fmt.Println("--exe-path cannot be empty when creating a service")
			flags.Usage()
			return
		}
		if args.startName == "" {
			args.startName = "LocalSystem"
		}
		if !isFlagSet("display-name") {
			args.displayName = args.name
		}
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
	f, err := conn.OpenFile(share, msscmr.MSRPCSvcCtlPipe)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer f.CloseFile()

	bind, err := dcerpc.Bind(f, msscmr.MSRPCUuidSvcCtl, msscmr.MSRPCSvcCtlMajorVersion, msscmr.MSRPCSvcCtlMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		log.Errorln("Failed to bind to service")
		log.Errorln(err)
		return
	}

	rpccon := msscmr.NewRPCCon(bind)
	fmt.Println("Successfully performed Bind to Scmr service")

	if args.enumServices || args.enumServiceConfigs {
		var services []msscmr.EnumServiceStatusW
		services, err = rpccon.EnumServicesStatus(uint32(args.serviceType), uint32(args.serviceState))
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Services:")
		for _, item := range services {
			if args.enumServices {
				fmt.Printf("Service: %s\n Dislay Name: %s\n Status: %s\n", item.ServiceName, item.DisplayName, msscmr.ServiceStatusMap[item.ServiceStatus.CurrentState])
			} else {
				config, err := rpccon.GetServiceConfig(item.ServiceName)
				if err != nil {
					log.Errorln(err)
					continue
				}
				fmt.Printf("DISPLAY_NAME       : %s\n", config.DisplayName)
				fmt.Printf("SERVICE_NAME       : %s\n", item.ServiceName)
				fmt.Printf("TYPE               : %s\n", config.ServiceType)
				fmt.Printf("START_TYPE         : %s\n", config.StartType)
				fmt.Printf("ERROR_CONTROL      : %s\n", config.ErrorControl)
				fmt.Printf("BINARY_PATH_NAME   : %s\n", config.BinaryPathName)
				fmt.Printf("LOAD_ORDER_GROUP   : %s\n", config.LoadOrderGroup)
				fmt.Printf("TAG                : %d\n", config.TagId)
				fmt.Printf("DEPENDENCIES       : %s\n", config.Dependencies)
				fmt.Printf("SERVICE_START_NAME : %s\n", config.ServiceStartName)
				fmt.Println()
			}
		}
		return
	} else if args.getServiceConfig {
		var config msscmr.ServiceConfig
		config, err = rpccon.GetServiceConfig(args.name)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Service config:")
		fmt.Printf("DISPLAY_NAME       : %s\n", config.DisplayName)
		fmt.Printf("SERVICE_NAME       : %s\n", args.name)
		fmt.Printf("TYPE               : %s\n", config.ServiceType)
		fmt.Printf("START_TYPE         : %s\n", config.StartType)
		fmt.Printf("ERROR_CONTROL      : %s\n", config.ErrorControl)
		fmt.Printf("BINARY_PATH_NAME   : %s\n", config.BinaryPathName)
		fmt.Printf("LOAD_ORDER_GROUP   : %s\n", config.LoadOrderGroup)
		fmt.Printf("TAG                : %d\n", config.TagId)
		fmt.Printf("DEPENDENCIES       : %s\n", config.Dependencies)
		fmt.Printf("SERVICE_START_NAME : %s\n", config.ServiceStartName)
		fmt.Println()
		return
	} else if args.getServiceStatus {
		var status uint32
		status, err = rpccon.GetServiceStatus(args.name)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Printf("Service Status of (%s): %v\n", args.name, msscmr.ServiceStatusMap[status])
	} else if args.startService {
		err = rpccon.StartService(args.name, args.arguments)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Service started!")
		return
	} else if args.controlService {
		var action uint32
		switch strings.ToLower(args.serviceAction) {
		case "stop":
			action = msscmr.ServiceControlStop
		case "pause":
			action = msscmr.ServiceControlPause
		case "continue":
			action = msscmr.ServiceControlContinue
		}
		fmt.Printf("Trying to (%s) service %s\n", args.serviceAction, args.name)
		err = rpccon.ControlService(args.name, action)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Printf("Successfully performed action (%s)\n", args.serviceAction)
	} else if args.changeServiceConfig {
		fmt.Printf("Trying to change config of service (%s)\n", args.name)
		err = rpccon.ChangeServiceConfig(args.name, uint32(args.serviceType), uint32(args.serviceStartType), uint32(args.serviceErrorControl), args.exePath, args.startName, args.userPassword, args.displayName, "", "", 0)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Successfully changed service config")
		return
	} else if args.createService {
		fmt.Printf("Trying to create service with a name of %s\n", args.name)
		err = rpccon.CreateService(args.name, uint32(args.serviceType), uint32(args.serviceStartType), uint32(args.serviceErrorControl), args.exePath, args.startName, args.userPassword, args.displayName, false)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Successfully created the service")
		return
	} else if args.deleteService {
		err = rpccon.DeleteService(args.name)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Printf("Successfully deleted the service %s\n", args.name)
		return
	}
	return
}
