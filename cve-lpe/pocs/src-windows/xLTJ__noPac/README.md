# About

NoPac exploit, exploiting some old vulnerabilities CVE-2021-42278 and CVE-2021-42287 to impersonate a domain admin from a standard user.

No more annoying dependencies, just a single binary holy shit i love Go, Python could NEVER.

The -shell flag just spawns impacket-smbexec. You can also just use the ccache file for the impersonated account anyway.

Made this primarely to test out the new Go implementation of Impacket (gopacket) and its pretty cool honestly, and one step towards never having to touch python ever which is always nice.

Also there is no cleanup, I might add that later idk.

# Usage
```
Usage: ./nopac [options] target

Target:
  [[domain/]username[:password]@]<targetName or address>

Authentication:
  -aesKey string
        AES key to use for Kerberos Authentication (128 or 256 bits)
  -hashes string
        NTLM hashes, format is LMHASH:NTHASH
  -k    Use Kerberos authentication
  -keytab string
        Read keys for SPN from keytab file
  -no-pass
        don't ask for password (useful for -k)

Connection:
  -6    Connect via IPv6
  -dc-host string
        Hostname of the domain controller
  -dc-ip string
        IP Address of the domain controller
  -port int
        Destination port to connect to SMB Server
  -proxy string
        SOCKS5 proxy URL (e.g. socks5h://127.0.0.1:1080). Routes TCP through the proxy. UDP features are disabled. If unset, ALL_PROXY env is consulted.
  -target-ip string
        IP Address of the target machine

Tool Specific:
  -impersonate string
        User to impersonate
  -new-name string
        New username
  -new-pass string
        New password
  -shell
        Launch shell at the end
  -use-ldap
        Use LDAP instead of LDAPS

Miscellaneous:
  -debug
        Turn DEBUG output ON
  -inputfile string
        input file with list of entries
  -outputfile string
        base output filename
  -ts
        Adds timestamp to every logging output

```
