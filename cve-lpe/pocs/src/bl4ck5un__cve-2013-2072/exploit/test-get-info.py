#!/usr/bin/python
import sys
sys.path.append("/usr/lib/python2.7/site-packages/")
from xen.lowlevel import xc
from xen.xend import XendDomain
import pprint as pp

def dump(obj):
	pp.pprint(obj)
	print "\n"

xendDomainObj = XendDomain.instance()
domInfo = xendDomainObj.domain_lookup_nr(0)
print "===domInfo==="
dump(domInfo)

cpus = domInfo.getCpus()
print "===cpus==="
dump(cpus)

vms = xendDomainObj.get_all_vms()
print "==all vms=="
dump(vms)

print "==dom0.info=="
dom0 = vms[0]
dump(dom0.info)

print "==dom0.info['vcpus_params']=="
dom0 = vms[0]
dump(dom0.info['vcpus_params'])

xcobj = xc.xc()
print "===xeninfo==="
dump(xcobj.xeninfo())

print "===domain_getinfo==="
dump(xcobj.domain_getinfo())

print "===vcpu_getinfo==="
dump(xcobj.vcpu_getinfo(0))

exit(0)
print "===physinfo==="
dump(xcobj.physinfo())
print "===topologyinfo==="
dump(xcobj.topologyinfo())
print "===cpupool_getinfo==="
dump(xcobj.cpupool_getinfo())
print "===numainfo==="
dump(xcobj.numainfo())


