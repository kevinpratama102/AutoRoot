# Class: XendDomain.py.XendDomain
def domain_pincpu(self, domid, vcpu, cpumap):
    """Set which cpus vcpu can use
    @param domid: Domain ID or Name
    @type domid: int or string.
    @param vcpu: vcpu to pin to
    @type vcpu: int
    @param cpumap:  string repr of usable cpus
    @type cpumap: string
    @rtype: 0
    """
    dominfo = self.domain_lookup_nr(domid)
    if not dominfo:
        raise XendInvalidDomain(str(domid))

    # if vcpu is keyword 'all', apply the cpumap to all vcpus
    if str(vcpu).lower() == "all":
        vcpus = range(0, int(dominfo.getVCpuCount()))
    else:
        vcpus = [ int(vcpu) ]
   
    # set the same cpumask for all vcpus
    rc = 0
    cpus = dominfo.getCpus()
    cpumap = map(int, cpumap.split(",")) # str -> int
    # (*) cpumap is a list of int, each one for a usable cpu
    for v in vcpus:
        try:
            if dominfo._stateGet() in (DOM_STATE_RUNNING, DOM_STATE_PAUSED):
                rc = xc.vcpu_setaffinity(dominfo.getDomid(), v, cpumap) # target
            cpus[v] = cpumap
        except Exception, ex:
            log.exception(ex)
            raise XendError("Cannot pin vcpu: %d to cpu: %s - %s" % \
                            (v, cpumap, str(ex)))
    dominfo.setCpus(cpus)
    self.managed_config_save(dominfo)

    return rc