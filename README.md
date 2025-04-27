# go-rpcclient

## Description
Package go-rpcclient is a tool built to interact with RPC services over SMB
named pipes using the [go-smb](https://github.com/jfjallid/go-smb) library.

## Usage
```
Usage: ./go-rpcclient <service> [options]

<service>:
      --lsad                Interact with the Local Security Authority
      --samr                Interact with the Security Account Manager
      --wkst                Interact with the Workstation Service
      --srvs                Interact with the Server Service
      --scmr                Interact with the Service Control Manager
      --rrp                 Interact with the Remote Registry
  -i, --interactive         Launch interactive mode
  
General options:
      --host <ip/hostname>  Hostname or ip address of remote server. Must be hostname when using Kerberos
  -P, --port [port]         SMB Port (default 445)
  -d, --domain [name/fqdn]  Domain name to use for login
  -u, --user   [string]     Username. Not required for Kerberos auth
  -p, --pass   [string]     Password. Prompted if not specified
  -n, --no-pass             Disable password prompt and send no credentials
      --hash   [hex]        Hex encoded NT Hash for user password
      --local               Authenticate as a local user instead of domain user
      --null                Attempt null session authentication
  -k, --kerberos            Use Kerberos authentication. (KRB5CCNAME will be checked on Linux)
      --dc-ip     [ip]      Optionally specify ip of KDC when using Kerberos authentication
      --target-ip [ip]      Optionally specify ip of target when using Kerberos authentication
      --aes-key   [hex]     Use a hex encoded AES128/256 key for Kerberos authentication
  -t, --timeout   [int]     Dial timeout in seconds (default 5)
      --relay               Start an SMB listener that will relay incoming
                            NTLM authentications to the remote server and
                            use that connection. NOTE that this forces SMB 2.1
                            without encryption.
      --relay-port [port]   Listening port for relay (default 445)
      --socks-host [target] Establish connection via a SOCKS5 proxy server
      --socks-port [port]   SOCKS5 proxy port (default 1080)
      --noenc               Disable smb encryption
      --smb2                Force smb 2.1
      --debug               Enable debug logging
      --verbose             Enable verbose logging
  -v, --version             Show version
```

### WKST specific usage
```
Usage: ./go-rpcclient --wkst [options] <action>
...
Action:
      --enum-sessions      List logged in users (Required admin privileges) (default level: 1)

WKST options:
      --level <int>        Level of information to return
```

### SRVS specific usage
```
Usage: ./go-rpcclient --srvs [options] <action>
...
Action:
      --enum-sessions      List sessions (supported levels 0, 10, 502. Default 10)
      --enum-shares        List SMB Shares
      --get-info           Get Server info (supported levels 100,101,102. Default 101. 102 requires admin privileges)

SRVS options:
      --level <int>        Level of information to return
```

### LSAD specific usage
```
Usage: ./go-rpcclient --lsad [options] <action>
...
Action:
      --enum-accounts       List LSA accounts
      --enum-rights         List LSA rights assigned to account specified by --sid
      --add                 Add LSA rights specified by --rights to account specified by --sid
      --remove              Remove LSA rights specified by --rights from account specified by --sid
      --getinfo             Get primary domain name and domain SID
      --purge               Removes all rights for the specified --sid

LSA options:
      --sid    <SID>        Target SID of format "S-1-5-...-...-..."
      --rights <list>       Comma-separated list of rights. E.g., "SeDebugPrivilege,SeLoadDriverPrivilege"
      --system              Target system rights instead of user rights(privileges) when listing and adding rights (default false)
```

### SAMR specific usage
```
Usage: ./go-rpcclient --samr [options] <action>
...
Action:
      --enum-domains       List SAMR Domains
      --enum-users         List users (--local-domain or --netbios to specify a different domain)
      --list-groups        List domain groups (or aliases with --alias)
      --list-admins        List members of local administrators group
      --list-members       List members of group or alias
      --add-member         Add member to group (use --rid) or alias (use --sid)
      --remove-member      Remove member from group (use --user-rid) or alias (use --sid)
      --create-user        Create local user
      --create-computer    Create a machine account in AD domain (no SPN is added)
      --translate-sid      Convert SID to name of principal
      --lookup-sid         Translate --rid in --local-domain to a SID
      --lookup-rids        Translate --rids to names in domain specified by --local-domain
      --lookup-names       Translate --names to rids in domain specified by --local-domain
      --lookup-domain      Lookup domain SID for --local-domain
      --change-password    Change password of user. Leave current password empty to supply NT Hash instead
      --reset-password     Reset/force change password of user
      --make-admin         Add user to local administrators group
      --delete-user        Delete local user specified by --user-rid
      --query-user         Query local user specified by --user-rid or --name

SAMR options:
      --sid      <SID>      Target SID of format "S-1-5-...
      --rid      <RID>      Target RID
      --user-rid <RID>      Only used when removing local user from a group
      --rids     <LIST>     Comma-separated list of RIDs to lookup in specified domain
      --local-domain <name> Samr domain name to target. Typically "Builtin" or NetBios name of machine
                            Changes the domain for the action from the default for most actions
      --name <string>       Username of local account to create or query
      --names <LIST>        Comma-separated list of samAccountNames to lookup in specified domain
      --user-pass <string>  Password for --create-user or current password for --change-password.
                            Mutually exclusive with --old-hash
      --netbios <string>    NetBios computername
      --alias               Use the "alias" version of add/remove/list member commands
      --limit <int>         Indication of how many users return max
      --old-hash <hex>      Current NT Hash which is used with --change-password
      --new-pass <string>   New password for --change-password. Skip parameter to trigger prompt.
```

### SCMR specific usage
```
Usage: ./go-rpcclient --scmr [options] <action>
...
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
```

### RRP specific usage
```
Usage: ./go-rpcclient --rrp [options] <action>
...
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
```

## Examples

### List local admins
```
./go-rpcclient --samr --host 127.0.0.1 --local --user administrator --pass SuperSecretPass1 --list-admins
```

### Add domain user as local admin
```
./go-rpcclient --samr --host 127.0.0.1 --local --user administrator --pass SuperSecretPass1 --make-admin --sid <SID>
```

### Change user password
This can be used to change a user's password with knowledge of the current password:
```
./go-rpcclient --samr --host 127.0.0.1 --local --user test --change-password --name <samAccountName> --user-pass <current pw> --new-pass <new pw>
```

If the password has expired and must be changed, we can attempt null authentication:
```
./go-rpcclient --samr --host 127.0.0.1 --null --change-password --name <samAccountName> --user-pass <current pw> --new-pass <new pw>
```

It is also possible to update a user's password with knowledge of the current NT Hash:
```
./go-rpcclient --samr --host 127.0.0.1 --domain test.local --user test --change-password --name <samAccountName> --old-hash <NT hash> --new-pass <new pw>
```

Skipping the parameters `--old-hash`, `--user-pass` and `--new-pass` will trigger prompts to enter the credentials.

### Reset user password
This can be used to reset a user's password using force-change-password rights:
```
./go-rpcclient --samr --host 127.0.0.1 --local --user administrator --pass SuperSecretPass1 --reset-password --sid <SID> --new-pass <new pw>
```

### List logged on users
```
./go-rpcclient --wkst --host 127.0.0.1 --local --user administrator --pass SuperSecretPass1 --enum-sessions
```

### Launch go-rpcclient in interactive mode
Tab completion is currently only supported on Linux and interactive mode on
Windows is a bit experimental.

```
./go-rpcclient -i --host 127.0.0.1 --local --user administrator --pass SuperSecretPass1
```

Using null authentication:
```
./go-rpcclient -i --host 127.0.0.1 --null
```

We can also start interactive mode and choose authentication later
```
./go-rpcclient -i --host 127.0.0.1
```
