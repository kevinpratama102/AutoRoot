# XenDomainInfo.py.XenDomainInfo
def _setCPUAffinity(self):
    """ Repin domain vcpus if a restricted cpus list is provided.
        Returns the choosen node number.
    """

    def has_cpus():
        if self.info['cpus'] is not None:
            for c in self.info['cpus']:
                if c:
                    return True
        return False

    def has_cpumap():
        if self.info.has_key('vcpus_params'):
            for k, v in self.info['vcpus_params'].items():
                if k.startswith('cpumap'):
                    return True
        return False

    index = 0
    if has_cpumap():
        for v in range(0, self.info['VCPUs_max']):
            if self.info['vcpus_params'].has_key('cpumap%i' % v):
                cpumask = map(int, self.info['vcpus_params']['cpumap%i' % v].split(','))
                xc.vcpu_setaffinity(self.domid, v, cpumask)
    elif has_cpus():
        for v in range(0, self.info['VCPUs_max']):
            if self.info['cpus'][v]:
                xc.vcpu_setaffinity(self.domid, v, self.info['cpus'][v])
    else:
        def find_relaxed_node(node_list):
            import sys
            nr_nodes = info['max_node_index'] + 1
            if node_list is None:
                node_list = range(0, nr_nodes)
            nodeload = [0]
            nodeload = nodeload * nr_nodes
            from xen.xend import XendDomain
            doms = XendDomain.instance().list('all')
            for dom in filter (lambda d: d.domid != self.domid, doms):
                cpuinfo = dom.getVCPUInfo()
                for vcpu in sxp.children(cpuinfo, 'vcpu'):
                    if sxp.child_value(vcpu, 'online') == 0: continue
                    cpumap = list(sxp.child_value(vcpu,'cpumap'))
                    for i in range(0, nr_nodes):
                        node_cpumask = node_to_cpu[i]
                        for j in node_cpumask:
                            if j in cpumap:
                                nodeload[i] += 1
                                break
            for i in range(0, nr_nodes):
                if len(node_to_cpu[i]) == 0:
                    nodeload[i] += 8
                else:
                    nodeload[i] = int(nodeload[i] * 16 / len(node_to_cpu[i]))
                    if i not in node_list:
                        nodeload[i] += 8
            return map(lambda x: x[0], sorted(enumerate(nodeload), key=lambda x:x[1]))

        info = xc.numainfo()
        if info['max_node_index'] > 0 and  XendCPUPool.number_of_pools() < 2:
            node_memory_list = info['node_memfree']
            node_to_cpu = []
            for i in range(0, info['max_node_index'] + 1):
                node_to_cpu.append([])
            for cpu, node in enumerate(xc.topologyinfo()['cpu_to_node']):
                node_to_cpu[node].append(cpu)
            needmem = self.image.getRequiredAvailableMemory(self.info['memory_dynamic_max']) / 1024
            candidate_node_list = []
            for i in range(0, info['max_node_index'] + 1):
                if node_memory_list[i] >= needmem and len(node_to_cpu[i]) > 0:
                    candidate_node_list.append(i)
            best_node = find_relaxed_node(candidate_node_list)[0]
            cpumask = node_to_cpu[best_node]
            best_nodes = find_relaxed_node(filter(lambda x: x != best_node, range(0,info['max_node_index']+1)))
            for node_idx in best_nodes:
                if len(cpumask) >= self.info['VCPUs_max']:
                    break
                cpumask = cpumask + node_to_cpu[node_idx]
                log.debug("allocating additional NUMA node %d", node_idx)
            for v in range(0, self.info['VCPUs_max']):
                xc.vcpu_setaffinity(self.domid, v, cpumask)
    return index