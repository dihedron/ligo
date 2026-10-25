package flows

import (
	"slices"
	"strings"
)

// LigoFlow returns the flow to ligo's workload API, from
// service.workload_advertise (ADR-16).
func LigoFlow(destination string, port int, serverName string) Flow {
	return Flow{
		Name:        "ligo-workload-api",
		Purpose:     "DISCOVERY",
		Protocol:    "TCP",
		Destination: destination,
		Ports:       []Port{{Low: port, High: port}},
		TLS:         true,
		ServerName:  serverName,
	}
}

// Effective computes the flows a workload needs (ADR-16 rule 4, §3.6): the
// target's, the platform's, the secret store's and ligo's, in that order,
// each group by name. An empty storeName leaves out the secret store, as in
// the catalog.
func Effective(targetName string, target []Flow, platformName string, platform []Flow, storeName string, store []Flow, ligo Flow) []Flow {
	var out []Flow
	add := func(declaredBy string, group []Flow) {
		group = slices.Clone(group)
		slices.SortFunc(group, func(a, b Flow) int { return strings.Compare(a.Name, b.Name) })
		for _, f := range group {
			f.DeclaredBy = declaredBy
			out = append(out, f)
		}
	}
	add("target:"+targetName, target)
	add("platform:"+platformName, platform)
	if storeName != "" {
		add("secret-store:"+storeName, store)
	}
	add("ligo", []Flow{ligo})
	return out
}
