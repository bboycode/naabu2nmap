package cmd

type PortSummary struct {
	Hosts             int
	DistinctPorts     int
	OpenHostPortPairs int
	HostsByPort       map[int]int
}

func SummarizeTargets(targets map[string]*target, useHost bool) PortSummary {
	portsByHost := make(map[string]map[int]struct{})

	for _, target := range targets {
		hostName := scanTargetName(target, useHost)
		if hostName == "" {
			continue
		}
		if portsByHost[hostName] == nil {
			portsByHost[hostName] = make(map[int]struct{})
		}
		for _, ports := range target.ports {
			for port := range ports {
				portsByHost[hostName][port] = struct{}{}
			}
		}
	}

	summary := PortSummary{
		Hosts:       len(portsByHost),
		HostsByPort: make(map[int]int),
	}
	for _, ports := range portsByHost {
		for port := range ports {
			summary.HostsByPort[port]++
			summary.OpenHostPortPairs++
		}
	}
	summary.DistinctPorts = len(summary.HostsByPort)
	return summary
}
