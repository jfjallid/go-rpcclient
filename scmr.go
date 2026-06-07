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

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mslsad"
	"github.com/jfjallid/go-smb/dcerpc/msscmr"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb"
)

const validServiceTypes uint64 = 0x1 | 0x2 | 0x10 | 0x20

// scmSecurityTarget is the sentinel name that makes --get-service-security /
// scmrgetservicesecurity read the SCM database's own security descriptor instead
// of an individual service's. It mirrors the "SCMANAGER" pseudo-name used by
// sc.exe (e.g. "sc sdshow SCMANAGER").
const scmSecurityTarget = "scmanager"

var helpScmrOptions = `
    Usage: ` + os.Args[0] + ` scmr [options] <action>
    ` + helpConnectionOptions + `
    Action:
          --enum-services           List services of specified type and states
          --enum-service-configs    List configs of services of specified type and states
          --get-service-config      Retrieve service config
          --get-service-config2     Retrieve service config2
          --get-service-status      Check status of service
          --change-service-config   Change config of a service
          --start-service           Start a service specified by --name with --args
          --control-service         Change state of service
          --create-service          Create new service (default type: 0x10, startType: 0x3,
                                    error: 0x0, startName: LocalSystem, displayName: service name)
          --delete-service          Delete service
          --get-service-security    Retrieve the security descriptor of a service.
                                    Use --name SCMANAGER to read the SCM database's
                                    own security descriptor

    SCMR options:
          --service-type <int>      Type of service. One or a combination of:
                                    kernel_driver: 0x1, file_system_driver: 0x2
                                    win32_own_process: 0x10, win32_share_process: 0x20
          --service-status <int>    Service state. (default 0x3) Active 0x1, Inactive 0x2, All 0x3
          --name <string>           Name of service to query, change, create or delete
          --args <Strings>          Comma-separated list of start arguments for service
          --action <action>         Service control action (stop, pause, continue)
          --start-type: <int>       Service start type: BootStart 0x0, SystemStart 0x1,
                                    AutoStart 0x2, DemandStart 0x3, Disabled 0x4
          --start-name <string>     Username to run service as. (default LocalSystem)
          --start-pass <string>     Password of user specified by --start-name
          --display-name <string>   Service display name
          --error-control <int>     Service error control (default 0x1: ErrorNormal)
          --exe-path <string>       Absolute path to service binary
          --dependencies <string>   List of dependencies <Svc1>/<Svc2>/... LoadOrderingGroups are prefixed by +
          --load-order-group <str>  Service LoadOrderGroup
          --info-level <int>        Level of service config to retrieve
          --description <string>    Service description
          --failure-actions <items> Comma-separated list of failure actions "<type> <delay>,..."
          --failure-actions-flag    Enable failure actions for non-crash errors
          --delayed-autostart       Enable delayed autostart
          --sid-type <int>          ?
          --required-privileges     Comma-separated list of required privileges
          --pre-shutdown <int>      Pre-shutdown timeout
          --preferred-node <int>    Preferred NUMA Node for service
          --preferred-node-delete   Clear preferred NUMA node info?
          --reset-period <int>      Time until failure count resets to 0. Only used together with --failure-actions
          --reboot-msg <msg>        Message broadcasted to users upon system reboot
          --failure-command <cmd>   Command to execute upon service failure if a failure action is set
          --start                   Start a service after creating it (default false)
          --sacl                    Also retrieve the SACL with --get-service-security
                                    (requires SeSecurityPrivilege)
`

func validateScmrActions(args *userArgs) error {
	return exactlyOneAction(
		args.enumServices,
		args.enumServiceConfigs,
		args.getServiceConfig,
		args.getServiceConfig2,
		args.getServiceStatus,
		args.changeServiceConfig,
		args.startService,
		args.controlService,
		args.createService,
		args.deleteService,
		args.getServiceSecurity,
	)
}

func handleScmr(args *userArgs) (err error) {
	if args.controlService {
		action := strings.ToLower(args.serviceAction)
		if (action != "stop") && (action != "pause") && (action != "continue") {
			fmt.Println("Must specify a valid control action. (stop, pause, continue)")
			flags.Usage()
			return
		}
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
	if args.getServiceConfig || args.startService || args.getServiceSecurity {
		if args.name == "" {
			fmt.Println("Must specify a service name")
			flags.Usage()
			return
		}
	}
	if args.changeServiceConfig {
		if !isFlagSet("service-type") &&
			!isFlagSet("start-type") &&
			!isFlagSet("start-name") &&
			!isFlagSet("start-pass") &&
			!isFlagSet("error-control") &&
			!isFlagSet("exe-path") &&
			!isFlagSet("dependencies") &&
			!isFlagSet("load-order-group") &&
			!isFlagSet("description") &&
			!isFlagSet("failure-actions") &&
			!isFlagSet("reset-period") &&
			!isFlagSet("reboot-msg") &&
			!isFlagSet("failure-command") &&
			!isFlagSet("failure-actions-flag") &&
			!isFlagSet("delayed-autostart") &&
			!isFlagSet("sid-type") &&
			!isFlagSet("required-privileges") &&
			!isFlagSet("pre-shutdown") &&
			!isFlagSet("preferred-node") &&
			!isFlagSet("preferred-node-delete") {
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
	f, err := conn.OpenFile(share, msscmr.MSRPCSvcCtlPipe)
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

	bind, err := dcerpc.Bind(transport, msscmr.MSRPCUuidSvcCtl, msscmr.MSRPCSvcCtlMajorVersion, msscmr.MSRPCSvcCtlMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		log.Errorln("Failed to bind to service")
		log.Errorln(err)
		return
	}

	rpccon := msscmr.NewRPCCon(bind)
	fmt.Println("Successfully performed Bind to Scmr service")

	var rpcconLsat *mslsad.RPCCon
	if args.getServiceSecurity && args.resolveSids {
		var f2 *smb.File
		f2, err = conn.OpenFile(share, mslsad.MSRPCLsaRpcPipe)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer f2.CloseFile()
		var transport2 *smbtransport.SMBTransport
		transport2, err = smbtransport.NewSMBTransport(f2)
		if err != nil {
			log.Errorln(err)
			return
		}
		var bind2 *dcerpc.ServiceBind
		bind2, err = dcerpc.Bind(transport2, mslsad.MSRPCUuidLsaRpc, mslsad.MSRPCLsaRpcMajorVersion, mslsad.MSRPCLsaRpcMinorVersion, dcerpc.MSRPCUuidNdr)
		if err != nil {
			log.Errorln("Failed to bind to LSARPC service")
			log.Errorln(err)
			return
		}
		rpcconLsat = mslsad.NewRPCCon(bind2)
	}

	if args.enumServices || args.enumServiceConfigs {
		var services []msscmr.EnumServiceStatusW
		services, err = rpccon.EnumServicesStatus(uint32(args.serviceType), uint32(args.serviceState))
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Printf("Found %d services:\n", len(services))
		for _, item := range services {
			if args.enumServices {
				fmt.Printf("Service: %s\n Display Name: %s\n Status: %s\n", item.ServiceName, item.DisplayName, msscmr.ServiceStatusMap[item.ServiceStatus.CurrentState])
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
	} else if args.getServiceConfig2 {
		if !isFlagSet("info-level") {
			log.Noticeln("No --info-level set so using a default of 1")
			args.infoLevel = 1
		}
		switch args.infoLevel {
		case uint64(msscmr.ServiceConfigDescription):
			var description string
			description, err = rpccon.GetServiceDescription(args.name)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Printf("SERVICE_NAME        : %s\n", args.name)
			fmt.Printf("SERVICE_DESCRIPTION : %s\n", description)
		case uint64(msscmr.ServiceConfigFailure_actions):
			var result *msscmr.ServiceFailureActions
			result, err = rpccon.GetServiceFailureActions(args.name)
			if err != nil {
				log.Errorln(err)
				return
			}
			command := ""
			rebootMsg := ""
			if result.Command != nil {
				command = *result.Command
			}
			if result.RebootMsg != nil {
				rebootMsg = *result.RebootMsg
			}
			fmt.Printf("SERVICE_NAME            : %s\n", args.name)
			fmt.Println("SERVICE_FAILURE_ACTIONS :")
			fmt.Printf("Command: %s\n", command)
			fmt.Printf("Reboot Msg: %s\n", rebootMsg)
			fmt.Printf("Reset Period: %ds\n", result.ResetPeriod)
			for i, action := range result.Actions {
				fmt.Printf("Action %d: Type: %s, Delay: %dms\n", i, msscmr.ScFailureActionMap[action.Type], action.Delay)
			}
		case uint64(msscmr.ServiceConfigDelayed_auto_start_info):
			var result bool
			result, err = rpccon.GetServiceDelayedAutoStartInfo(args.name)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Printf("SERVICE_NAME                   : %s\n", args.name)
			fmt.Printf("SERVICE_DELAYED_AUTOSTART_INFO : %v\n", result)
		case uint64(msscmr.ServiceConfigFailure_actions_flag):
			var result bool
			result, err = rpccon.GetServiceFailureActionsFlag(args.name)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Printf("SERVICE_NAME                 : %s\n", args.name)
			fmt.Printf("SERVICE_FAILURE_ACTIONS_FLAG : %v\n", result)
		case uint64(msscmr.ServiceConfigService_sid_info):
			var result uint32
			result, err = rpccon.GetServiceSIDInfo(args.name)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Printf("SERVICE_NAME     : %s\n", args.name)
			fmt.Printf("SERVICE_SID_INFO : %d\n", result)
		case uint64(msscmr.ServiceConfigRequired_privileges_info):
			var result []string
			result, err = rpccon.GetServiceRequiredPrivileges(args.name)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Printf("SERVICE_NAME                : %s\n", args.name)
			fmt.Printf("SERVICE_REQUIRED_PRIVILEGES :\n")
			for i, priv := range result {
				fmt.Printf("Privilege %d: %s\n", i, priv)
			}
		case uint64(msscmr.ServiceConfigPreshutdown_info):
			var result uint32
			result, err = rpccon.GetServicePreshutdownInfo(args.name)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Printf("SERVICE_NAME             : %s\n", args.name)
			fmt.Printf("SERVICE_PRESHUTDOWN_INFO : %d\n", result)
		case uint64(msscmr.ServiceConfigPreferred_node):
			var result *msscmr.ServicePreferredNodeInfo
			result, err = rpccon.GetServicePreferredNode(args.name)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Printf("SERVICE_NAME           : %s\n", args.name)
			fmt.Printf("SERVICE_PREFERRED_NODE : preferred_node: %d, delete: %v\n", result.PreferredNode, result.Delete)
		default:
			fmt.Printf("Invalid --info-level for --get-service-config2: %d\n", args.infoLevel)
		}
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
		var exePath, displayName, serviceStartName *string
		var loadOrderGroup *string
		// Default each numeric field to the MS-SCMR "no change" sentinel so that
		// touching one part of the config (e.g. only --exe-path) does not silently
		// reset the others to their flag defaults. Mirrors the interactive shell.
		svcType := msscmr.ServiceNoChange
		svcStartType := msscmr.ServiceNoChange
		svcErrorControl := msscmr.ServiceNoChange
		standardChange := false
		if isFlagSet("service-type") {
			standardChange = true
			svcType = uint32(args.serviceType)
		}
		if isFlagSet("start-type") {
			standardChange = true
			svcStartType = uint32(args.serviceStartType)
		}
		if isFlagSet("start-name") {
			standardChange = true
			serviceStartName = &args.startName
		}
		if isFlagSet("start-pass") {
			standardChange = true
		}
		if isFlagSet("error-control") {
			standardChange = true
			svcErrorControl = uint32(args.serviceErrorControl)
		}
		if isFlagSet("exe-path") {
			standardChange = true
			exePath = &args.exePath
		}
		if isFlagSet("dependencies") {
			standardChange = true
		}
		if isFlagSet("load-order-group") {
			standardChange = true
			loadOrderGroup = &args.loadOrderGroup
		}
		if isFlagSet("display-name") {
			standardChange = true
			displayName = &args.displayName
		}
		fmt.Printf("Trying to change config of service (%s)\n", args.name)
		if standardChange {
			err = rpccon.ChangeServiceConfig(args.name, svcType, svcStartType, svcErrorControl, exePath, serviceStartName, args.userPassword, displayName, loadOrderGroup, args.dependencies, 0)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Successfully changed the service config")
		}

		if isFlagSet("description") {
			err = rpccon.SetServiceDescription(args.name, args.serviceDescription)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Successfully changed the service description")
		}
		if isFlagSet("failure-actions") || isFlagSet("reset-period") || isFlagSet("reboot-msg") || isFlagSet("failure-command") {
			//TODO Improve logic?

			//TODO Figure out no-change values if any?
			fa := msscmr.ServiceFailureActions{}
			if isFlagSet("reset-period") {
				fa.ResetPeriod = uint32(args.resetPeriod)
			}
			if isFlagSet("reboot-msg") {
				fa.RebootMsg = &args.rebootMsg
			}
			if isFlagSet("failure-command") {
				fa.Command = &args.failureCommand
			}
			if isFlagSet("failure-actions") {
				fa.Actions = args.serviceFailActions
			}
			err = rpccon.SetServiceFailureActions(args.name, &fa)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Successfully changed the service failure actions")
		}
		if isFlagSet("failure-actions-flag") {
			err = rpccon.SetServiceFailureActionsFlag(args.name, args.serviceFailureActionsFlag)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Successfully changed the service failure actions flag")
		}
		if isFlagSet("delayed-autostart") {
			err = rpccon.SetServiceDelayedAutoStartInfo(args.name, args.delayedAutoStart)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Successfully changed the service's delayed autostart setting")
		}
		if isFlagSet("sid-type") {
			err = rpccon.SetServiceSIDInfo(args.name, uint32(args.sidType))
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Successfully changed the service SID Info")
		}
		if isFlagSet("required-privileges") {
			err = rpccon.SetServiceRequiredPrivileges(args.name, args.requiredPrivileges)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Successfully changed the service's required privileges")
		}
		if isFlagSet("pre-shutdown") {
			err = rpccon.SetServicePreshutdownInfo(args.name, uint32(args.preShutdownTimeout))
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Successfully changed the service pre-shutdown timeout")
		}
		if isFlagSet("preferred-node") {
			err = rpccon.SetServicePreferredNode(args.name, &msscmr.ServicePreferredNodeInfo{PreferredNode: uint16(args.preferredNode)})
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Successfully changed the service's preferred NUMA node")
		}
		if isFlagSet("preferred-node-delete") {
			err = rpccon.SetServicePreferredNode(args.name, &msscmr.ServicePreferredNodeInfo{Delete: args.preferredNodeDelete})
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Successfully cleared the service's preferred NUMA node")
		}

		fmt.Println("Successfully changed service config")
		return
	} else if args.createService {
		statusMsg := "Trying to create"
		if args.createAndStart {
			statusMsg += " and start"
		}
		statusMsg += " service with a name of " + args.name
		fmt.Println(statusMsg)
		err = rpccon.CreateService(args.name, uint32(args.serviceType), uint32(args.serviceStartType), uint32(args.serviceErrorControl), args.exePath, args.startName, args.userPassword, args.displayName, false)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Successfully created the service")
		if args.createAndStart {
			err = rpccon.StartService(args.name, nil)
			if err != nil {
				log.Errorln(err)
				return
			}
			fmt.Println("Service started!")
		}
		return
	} else if args.deleteService {
		err = rpccon.DeleteService(args.name)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Printf("Successfully deleted the service %s\n", args.name)
		return
	} else if args.getServiceSecurity {
		var sd *msdtyp.SecurityDescriptor
		var names []string
		sd, names, err = getServiceSecurity(rpccon, rpcconLsat, args.name, args.sacl, args.resolveSids)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Printf("Security information for %s\n", scmrSecurityLabel(args.name))
		if sd == nil {
			fmt.Println("No security descriptor returned")
			return
		}
		var sb strings.Builder
		appendSecurityDescriptor(&sb, sd, names, args.resolveSids, scmrObjectRights(args.name))
		fmt.Println(sb.String())
		return
	}
	return
}

// getServiceSecurity reads the security descriptor of a service via
// RQueryServiceObjectSecurity. When name matches the scmSecurityTarget sentinel
// it reads the SCM database's own security descriptor instead. The SACL is only
// requested when includeSacl is set as it requires SeSecurityPrivilege on the
// target. When resolveSids is set the referenced SIDs are translated to names
// via MS-LSAT.
func getServiceSecurity(rpccon *msscmr.RPCCon, rpcconLsat *mslsad.RPCCon, name string, includeSacl, resolveSids bool) (sd *msdtyp.SecurityDescriptor, names []string, err error) {
	var securityInformation uint32 = msscmr.OwnerSecurityInformation | msscmr.GroupSecurityInformation | msscmr.DaclSecurityInformation
	if includeSacl {
		securityInformation |= msscmr.SaclSecurityInformation
	}
	if strings.EqualFold(name, scmSecurityTarget) {
		sd, err = rpccon.GetSCManagerSecurity(securityInformation)
	} else {
		sd, err = rpccon.GetServiceSecurity(name, securityInformation)
	}
	if err != nil {
		log.Errorln(err)
		return
	}
	if resolveSids && sd != nil {
		names = resolveSidStrings(rpcconLsat, collectSidsFromSD(sd))
	}
	return
}

// scmrSecurityLabel returns a human-readable label for the target of a
// --get-service-security query, used in the printed header.
func scmrSecurityLabel(name string) string {
	if strings.EqualFold(name, scmSecurityTarget) {
		return "the Service Control Manager database"
	}
	return "service: " + name
}

// namedRight pairs an access-mask bit with its name. The order is the bit order
// in which the rights are listed.
type namedRight struct {
	mask uint32
	name string
}

// scmManagerAccessRights are the SCM-database object-specific access rights
// (MS-SCMR 3.1.4). They share the low mask bits with serviceAccessRights but
// have different meanings, which is why decoding must know the target type.
var scmManagerAccessRights = []namedRight{
	{msscmr.SCManagerConnect, "SC_MANAGER_CONNECT"},
	{msscmr.SCManagerCreateService, "SC_MANAGER_CREATE_SERVICE"},
	{msscmr.SCManagerEnumerateService, "SC_MANAGER_ENUMERATE_SERVICE"},
	{msscmr.SCManagerLock, "SC_MANAGER_LOCK"},
	{msscmr.SCManagerQueryLockStatus, "SC_MANAGER_QUERY_LOCK_STATUS"},
	{msscmr.SCManagerModifyBootConfig, "SC_MANAGER_MODIFY_BOOT_CONFIG"},
}

// serviceAccessRights are the per-service object-specific access rights
// (MS-SCMR 3.1.4).
var serviceAccessRights = []namedRight{
	{msscmr.ServiceQueryConfig, "SERVICE_QUERY_CONFIG"},
	{msscmr.ServiceChangeConfig, "SERVICE_CHANGE_CONFIG"},
	{msscmr.ServiceQueryStatus, "SERVICE_QUERY_STATUS"},
	{msscmr.ServiceEnumerateDependents, "SERVICE_ENUMERATE_DEPENDENTS"},
	{msscmr.ServiceStart, "SERVICE_START"},
	{msscmr.ServiceStop, "SERVICE_STOP"},
	{msscmr.ServicePauseContinue, "SERVICE_PAUSE_CONTINUE"},
	{msscmr.ServiceInterrogate, "SERVICE_INTERROGATE"},
	{msscmr.ServiceUserDefinedControl, "SERVICE_USER_DEFINED_CONTROL"},
	{msscmr.ServiceSetStatus, "SERVICE_SET_STATUS"},
}

// scmrObjectRights returns a decoder for the object-specific (low 16-bit) access
// mask bits of either the SCM database or an individual service, selected by
// whether name is the scmSecurityTarget sentinel. The standard rights
// (READ_CONTROL, DELETE, ...) are decoded separately by msdtyp, so this only
// adds the SC_MANAGER_* / SERVICE_* names msdtyp omits.
func scmrObjectRights(name string) func(uint32) []string {
	rights := serviceAccessRights
	if strings.EqualFold(name, scmSecurityTarget) {
		rights = scmManagerAccessRights
	}
	return func(mask uint32) []string {
		var out []string
		for _, r := range rights {
			if mask&r.mask != 0 {
				out = append(out, r.name)
			}
		}
		return out
	}
}
