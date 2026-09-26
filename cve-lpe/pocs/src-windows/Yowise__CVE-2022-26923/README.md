# CVE-2022-26923

As described by [Tenable](https://www.tenable.com/cve/CVE-2022-26923/plugins): Active Directory Domain Services Elevation of Privilege Vulnerability

**CVSS v3**

Base score: 8.8

Vector: CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

Severity: High



## Summary:

CVE-2022-26923 exploits a vulnerability in Microsoft Active Directory Certificate Services (AD CS) to elevate privileges. 

Certificate Templates: AD CS offers two default templates for certificate requests: User and Machine.

User Template Limitation: The User template is not vulnerable because it embeds the user's UPN in the SAN, which is unique and cannot be easily modified.

Machine Template Vulnerability: The Machine template uses the DNS Name for identification. By modifying the DNS Name of a newly enrolled host to match a Domain Controller, an attacker can obtain a certificate that allows impersonation of the Domain Controller.

Privilege Escalation: This impersonation can be used to elevate privileges and gain control over the Active Directory domain.






## A little story about ADCS and certificates:


Microsoft defines **Active Directory Certificate Services** (AD CS) as, "...the _server role_ that allows
you to build a _public key infrastructure_ (PKI) and provide public key cryptography, digital
certificates, and digital signature capabilities for your organization." 

A certificate is an X.509-formatted digitally signed document used for encryption, message
signing, and/or authentication. A certificate typically has various fields, including some of the
following:
1. Subject - The owner of the certificate.
2. Public Key - Associates the Subject with a private key stored separately.
3. NotBefore and NotAfter dates - Define the duration that the certificate is valid.
4. Serial Number - An identifier for the certificate assigned by the CA.
5. Issuer - Identifies who issued the certificate (commonly a CA).
6. SubjectAlternativeName - Defines one or more alternate names that the Subject may go
by.
7. Basic Constraints - Identifies if the certificate is a CA or an end entity, and if there are any
constraints when using the certificate.
8. Extended Key Usages (EKUs) - Object identifiers (OIDs) that describe how the certificate
will be used. Also known as Enhanced Key Usage in Microsoft parlance. Common EKU
OIDs include:

**- Code Signing (OID 1.3.6.1.5.5.7.3.3) - The certificate is for signing executable code.**
   
**- Encrypting File System (OID 1.3.6.1.4.1.311.10.3.4) - The certificate is for
encrypting file systems.**

**- Secure Email (1.3.6.1.5.5.7.3.4) - The certificate is for encrypting email.**

**- Client Authentication (OID 1.3.6.1.5.5.7.3.2) - The certificate is for authentication
to another server (e.g., to AD).**

**- Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2) - The certificate is for use in smart
card authentication.**

**- Server Authentication (OID 1.3.6.1.5.5.7.3.1) - The certificate is for identifying
servers (e.g., HTTPS certificates).**


10. Signature Algorithm - Specifies the algorithm used to sign the certificate.
11. Signature - The signature of the certificates body made using the issuer’s (e.g., a CA’s)
private key.

Source:  [specterops' whitepaper](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)


Digital certificates can be used to encrypt and digitally sign electronic documents and messages as well as for authentication of computer, user, or device accounts on a network. For example, digital certificates are used to provide:

🔐**Confidentiality** through encryption.

🔏**Integrity** through digital signatures.

🖇️**Authentication** by associating certificate keys with the computer, user, or device accounts on a computer network.


Source: [Microsoft Learning](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview)


AD CS is a Microsoft technology that provides a centralized infrastructure for managing digital certificates. It offers several key benefits:

- Identity Binding: AD CS binds identities (users, computers, services) to private keys, ensuring secure authentication and access control.

- Certificate Management: It efficiently manages the distribution, enrollment, and revocation of certificates.

- Integration with Active Directory: Leverages existing identity information in AD for seamless certificate registration and management.

- Group Policy Configuration: Allows for fine-grained control of certificate issuance and usage based on roles or attributes.

- Supports Various Applications: AD CS supports a wide range of applications, including S/MIME, wireless networks, VPN, IPsec, EFS, smart cards, SSL/TLS, and digital signatures.
 

In essence, AD CS provides a secure and efficient way to manage digital certificates, enhancing the overall security of an organization's IT infrastructure.



