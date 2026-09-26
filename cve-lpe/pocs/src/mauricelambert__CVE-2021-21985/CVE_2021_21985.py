#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" This script check the CVE-2021-21985 vulnerability and patch. """

###################
#    This script check the CVE-2021-21985 vulnerability and patch.
#    Copyright (C) 2021  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

print(
    """
CVE_2021_21985  Copyright (C) 2021  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
)

from ssl import SSLContext, create_default_context, CERT_NONE
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from json.decoder import JSONDecodeError
from json import loads, dumps
from sys import argv, exit


def create_ssl_context() -> SSLContext:

    """Create a SSLContext without hostname check and certification."""

    context = create_default_context()
    context.check_hostname = False
    context.verify_mode = CERT_NONE
    return context


if len(argv) == 1:
    print(
        "USAGE: CVE_2021_21985.py <IP or hostname server 1> <IP or hostname server 2> <IP or hostname server ...>"
    )
    exit(1)

targets = argv[1:]
print("Start scan...")
data = dumps(
    {
        "methodInput": [
            {"type": "ClusterComputeResource", "value": None, "serverGuid": None}
        ]
    }
).encode()
headers = {
    "User-Agent": "Mozilla/5.0 (compatible; vCenter)",
    "Content-Type": "application/json",
}

for target in targets:
    # print(f"Scan {target}")
    try:
        response = urlopen(
            Request(
                f"https://{target}/ui/h5-vsan/rest/proxy/service/com.vmware.vsan.client.services.capability.VsanCapabilityProvider/getClusterCapabilityData",
                data=data,
                headers=headers,
            ),
            context=create_ssl_context(),
        )
    except HTTPError as e:
        response = e
    except URLError as e:
        print(f"ERROR on {target}: reason: {e.reason}")
        continue

    # print(f"Status code: {response.status}")

    if response.status == 200:
        try:
            content = loads(response.read())
        except JSONDecodeError:
            print(f"ERROR on {target}: content response is not JSON.")
            continue
        else:
            if "result" in content.keys():
                print(f" [-] {target} is vulnerable")
            elif "error" in content.keys():
                print(
                    f" [!] {target} is probably vulnerable (get a JSON response error)"
                )

    elif response.status == 401:
        print(f" [+] {target} is patched")
        # breakpoint()

    elif response.status == 503:
        print(f" [!] {target} is probably not vulnerable (get a HTTP error code 503)")

    elif response.status == 404:
        print(
            f" [!] {target} is probably not vulnerable (vulnerable ressource is not available)"
        )

    else:
        print(
            f' [!] {target} return a HTTP error code "{response.status} {response.reason}" (Not Implemented)'
        )

print("End.")
