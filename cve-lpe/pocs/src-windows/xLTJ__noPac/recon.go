package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/mandiant/gopacket/pkg/flags"
	"github.com/mandiant/gopacket/pkg/ldap"
)

func ReconLDAP(ldapClient *ldap.Client, opts *flags.Options) {
	// get base DN
	baseDN, err := ldapClient.GetDefaultNamingContext()
	if err != nil {
		log.Fatalf("[-] Failed to get base DN: %v", err)
	}

	// LDAP search for Machine Account Quota
	machineAccountQuota, err = getMaq(ldapClient, baseDN)
	if err != nil {
		log.Fatalf("[-] Failed query for Machine Account Quota: %v", err)
	}
	fmt.Printf("[*] ms-DS-MachineAccountQuota = %d\n", machineAccountQuota)

	// if no DcHost is given, try and find one
	if opts.DcHost == "" {
		fmt.Println("[*] No DC-host given, finding DC-host...")

		dcHost, err := getDomainController(ldapClient, baseDN)
		if err != nil {
			log.Fatalf("[-] Failed to query for domain controllers: %v", err)
		}

		opts.DcHost = dcHost
		fmt.Printf("[+] Successfully found DC-host: %s\n", opts.DcHost)
	}
}

func getMaq(ldapClient *ldap.Client, baseDN string) (int, error) {
	// LDAP search at BASE scope. looking for ms-DS-MachineAccountQuota attribute to find the machine account quota
	maqResult, err := ldapClient.SearchBase(baseDN, "(objectClass=*)", []string{"ms-DS-MachineAccountQuota"})
	if err != nil {
		return 0, fmt.Errorf("error searching for ms-DS-MachineAccountQuota: %s", err)
	}

	// extract and convert. only one entry will be returned from the search so just grab that
	maqString := maqResult.Entries[0].GetAttributeValue("ms-DS-MachineAccountQuota")
	maq, err := strconv.Atoi(maqString)
	if err != nil {
		return 0, fmt.Errorf("error converting to int: %s", err)
	}

	return maq, err
}

func getDomainController(ldapClient *ldap.Client, baseDN string) (string, error) {
	dcResult, err := ldapClient.Search(
		baseDN,
		"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
		[]string{"sAMAccountName"},
	)
	if err != nil {
		return "", fmt.Errorf("error searching for DC's: %s", err)
	}

	if len(dcResult.Entries) == 0 {
		return "", fmt.Errorf("no domain controller found")
	}

	// grab the first one and remove $
	dcHost := dcResult.Entries[0].GetAttributeValue("sAMAccountName")
	return strings.TrimSuffix(dcHost, "$"), err
}
