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
	"github.com/jfjallid/go-smb/smb/dcerpc/mslsad"
)

var helpLsadOptions = `
    Usage: ` + os.Args[0] + ` --lsad [options] <action>
    ` + helpConnectionOptions + `
    Action:
          --enum-accounts       List LSA accounts
          --enum-rights         List LSA rights assigned to account specified by --sid
          --add                 Add LSA rights specified by --rights to account specified by --sid
          --remove              Remove LSA rights specified by --rights from account specified by --sid
          --getinfo             Get primary domain name and domain SID
          --purge               Removes all rights for the specified --sid
          --lookup-sids         Attempts to translate the sids specified by --sids to names
          --lookup-names        Attempts to translate the sids specified by --names to sids
          --whoami              Get the identity of the authenticated user

    LSA options:
          --sid    <SID>        Target SID of format "S-1-5-...-...-..."
          --level  <num>        LookupLevel for --lookup-sids (default 1, LookupWksta)
          --sids   <list>       Comma-separated list of SIDs to lookup of format "S-1-5-...-...-..."
          --names  <list>       Comma-separated list of names to lookup
          --rights <list>       Comma-separated list of rights. E.g., "SeDebugPrivilege,SeLoadDriverPrivilege"
          --system              Target system rights instead of user rights(privileges) when listing and adding rights (default false)
`

func getLSAAccounts(rpccon *mslsad.RPCCon) (accounts []string, err error) {
	sids, err := rpccon.ListAccounts()
	if err != nil {
		return
	}
	for _, sid := range sids {
		accounts = append(accounts, sid.ToString())
	}
	return
}

func handleLsaRpc(args *userArgs) (err error) {
	numActions := 0
	if args.enumAccounts {
		numActions++
	}
	if args.enumRights {
		numActions++
	}
	if args.addRights {
		numActions++
	}
	if args.removeRights {
		numActions++
	}
	if args.purgeRights {
		numActions++
	}
	if args.getDomainInfo {
		numActions++
	}
	if args.getUserName {
		numActions++
	}
	if args.lookupSids {
		numActions++
	}
	if args.lookupNames {
		numActions++
	}
	if numActions != 1 {
		fmt.Println("Must specify ONE action. No more, no less")
		flags.Usage()
		return
	}

	if (args.addRights || args.removeRights || args.enumRights || args.purgeRights) && (args.sid.v == nil) {
		fmt.Println("Must specify --sid argument to list, add, remove or purge rights")
		flags.Usage()
		return
	}

	if (args.addRights || args.removeRights) && (len(args.rights) == 0) {
		fmt.Println("Must specify --rights argument to add or remove rights")
		flags.Usage()
		return
	}

	if args.lookupSids && (len(args.sids) == 0) {
		fmt.Println("Must specify --sids argument to lookup sids")
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
	f, err := conn.OpenFile(share, mslsad.MSRPCLsaRpcPipe)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer f.CloseFile()

	bind, err := dcerpc.Bind(f, mslsad.MSRPCUuidLsaRpc, mslsad.MSRPCLsaRpcMajorVersion, mslsad.MSRPCLsaRpcMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		log.Errorln("Failed to bind to service")
		log.Errorln(err)
		return
	}

	rpccon := mslsad.NewRPCCon(bind)
	fmt.Println("Successfully performed Bind to LsaRpc service")

	if args.getUserName {
		var username, domain string
		username, domain, err = rpccon.LsarGetUserName()
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Printf("Username: %s, Domain: %s\n", username, domain)
	} else if args.lookupSids {
		var res mslsad.SidTranslations
		fmt.Println("Translating SIDs to names")
		res, err = rpccon.LsarLookupSids2(mslsad.LsapLookupLevel(args.level), args.sids.GetStrings())
		if err != nil {
			log.Errorln(err)
			return
		}
		if len(res.TranslatedNames) == 0 {
			fmt.Printf("Failed to translate names and got a return code of: 0x%08x\n", res.ReturnCode)
		} else {
			for i, item := range res.TranslatedNames {
				referencedDomain := "<Unknown>"
				domainSid := "<Unknown>"
				if item.DomainIndex >= 0 {
					referencedDomain = res.ReferencedDomains[item.DomainIndex].Name
					domainSid = res.ReferencedDomains[item.DomainIndex].Sid
				}
				fmt.Printf("Sid: %s\nSidType: %s\nName: %s\nDomain: %s\nDomainSid: %s\n\n", args.sids[i].String(), mslsad.SidNameUseMap[item.Use], item.Name, referencedDomain, domainSid)
			}
		}
	} else if args.lookupNames {
		var res mslsad.NameTranslations
		fmt.Println("Translating names to SIDs")
		res, err = rpccon.LsarLookupNames3(mslsad.LsapLookupLevel(args.level), args.names)
		if err != nil {
			log.Errorln(err)
			return
		}
		if len(res.TranslatedSids) == 0 {
			fmt.Printf("Failed to translate Sids and got a return code of: 0x%08x\n", res.ReturnCode)
		} else {
			for i, item := range res.TranslatedSids {
				referencedDomain := "<Unknown>"
				domainSid := "<Unknown>"
				if item.DomainIndex >= 0 {
					referencedDomain = res.ReferencedDomains[item.DomainIndex].Name
					domainSid = res.ReferencedDomains[item.DomainIndex].Sid
				}
				fmt.Printf("Name: %s\nSidType: %s\nSid: %s\nDomain: %s\nDomainSid: %s\n\n", args.names[i], mslsad.SidNameUseMap[item.Use], item.Sid, referencedDomain, domainSid)
			}
		}
	} else if args.enumAccounts {
		fmt.Println("Enumerating LSA accounts")
		sids, err2 := getLSAAccounts(rpccon)
		if err2 != nil {
			err = err2
			log.Errorln(err)
			return
		}
		var names []string
		var sb strings.Builder
		if args.resolveSids {
			// Attempt to lookup all the Sids
			res, err := rpccon.LsarLookupSids2(1, sids)
			if err != nil {
				log.Errorln(err)
			} else {
				for _, item := range res.TranslatedNames {
					if item.Use == mslsad.SidTypeUnknown {
						names = append(names, "<unknown>")
					} else {
						if item.DomainIndex != -1 {
							names = append(names, fmt.Sprintf("%s\\%s", res.ReferencedDomains[item.DomainIndex].Name, item.Name))
						} else {
							names = append(names, item.Name)
						}
					}
				}
			}
		}
		for i, sid := range sids {
			fmt.Fprintf(&sb, "Account SID: %s", sid)
			if len(names) > 0 {
				fmt.Fprintf(&sb, ", Name: %s", names[i])
			}
			fmt.Fprintf(&sb, "\n")
		}
		fmt.Println(sb.String())
	} else if args.getDomainInfo {
		fmt.Println("Getting Domain Info")
		domInfo, err2 := rpccon.GetPrimaryDomainInfo()
		if err2 != nil {
			err = err2
			log.Errorln(err)
			return
		}
		fmt.Printf("Domain: %s, SID: %s\n", domInfo.Name, domInfo.Sid.ToString())
	} else if args.enumRights {
		if args.systemRights {
			fmt.Printf("Enumerating system rights for SID: %s\n", args.sid.s)
			rights, err2 := rpccon.GetSystemAccessAccount(args.sid.s)
			if err2 != nil {
				err = err2
				log.Errorln(err)
				return
			}
			fmt.Printf("Found %d rights:\n", len(rights))
			for _, item := range rights {
				fmt.Printf("%s\n", item)
			}
		} else {
			fmt.Printf("Enumerating user rights for SID: %s\n", args.sid.s)
			rights, err2 := rpccon.ListAccountRights(args.sid.s)
			if err2 != nil {
				err = err2
				log.Errorln(err)
				return
			}
			fmt.Printf("Found %d rights:\n", len(rights))
			for _, item := range rights {
				fmt.Printf("%s\n", item)
			}
		}
	} else if args.addRights {
		if args.systemRights {
			err = rpccon.SetSystemAccessAccount(args.sid.s, args.rights)
		} else {
			err = rpccon.AddAccountRights(args.sid.s, args.rights)
		}
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Rights added!")
	} else if args.removeRights {
		err = rpccon.RemoveAccountRights(args.sid.s, args.rights, false)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Rights removed!")
	} else if args.purgeRights {
		if args.systemRights {
			err = rpccon.SetSystemAccessAccount(args.sid.s, nil)
		} else {
			err = rpccon.RemoveAccountRights(args.sid.s, nil, true)
		}
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Rights removed!")
	}
	return
}
