package netpol

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"text/template"
)

const (
	NFTABLES_FILE       = "/tmp/kube-router.nft"
	NFTABLES_TABLE_NAME = "kube-router"
	KUBE_BRIDGE_IF      = "kube-bridge"
	NFTABLES_TEMPLATE   = `
	delete table {{.TableName}}
	create table {{.TableName}}

	table {{.TableName}} {

		{{range $key, $value := .Sets}}
			set {{$key}} {
                type ipv4_addr
				flags constant, interval
				{{ $length := len $value }}{{ if gt $length 2 }}
                elements = { {{$value}} }
				{{end}}
        	}
		{{end}}

		set pod_cidr {
			type ipv4_addr
			flags constant, interval

			elements = { {{podCIDR}} }
		}

		chain egress {
			type filter hook prerouting priority -120; policy accept
			{{template "accept" .}}

			{{range .EgressPods}}
				ip saddr {{.IP}} jump {{.Namespace}}-{{.Name}}-egress-fw
			{{end}}
			{{if defaultDeny}}ip saddr @pod_cidr {{template "drop"}}{{end}}
		}

		chain ingress-forward {
			type filter hook forward priority 0; policy accept
			{{template "accept" .}}
			ip daddr @pod_cidr ip daddr != {{genIPSetFromPods .AllPods}} nftrace set 1 reject with icmp type host-unreachable
			meta mark 32760 {{template "reject"}}

			{{range .IngressPods}}
				ip daddr {{.IP}} jump {{.Namespace}}-{{.Name}}-ingress-fw
			{{end}}
			{{if defaultDeny}}ip daddr @pod_cidr {{template "reject"}}{{end}}
		}

		chain ingress-output {
			type filter hook output priority 0; policy accept
			{{template "accept" .}}
			ip daddr @pod_cidr ip daddr != {{genIPSetFromPods .AllPods}} nftrace set 1 reject with icmp type host-unreachable
			meta mark 32760 {{template "reject"}}

			{{range .IngressPods}}
				ip daddr {{.IP}} jump {{.Namespace}}-{{.Name}}-ingress-fw
			{{end}}
			{{if defaultDeny}}ip daddr @pod_cidr {{template "reject"}}{{end}}
		}

		{{$policies := .Policies}}
		{{range .IngressPods}}
		chain {{.Namespace}}-{{.Name}}-ingress-fw {
			ct state established,related accept
			ct state invalid {{template "drop"}}
			{{with $pod := .}}
			{{range $policies}}
				{{if .Matches $pod}}jump {{.Namespace}}-{{.Name}}-netpol-ingress{{end}}{{end}}
			{{end}}
			{{template "reject"}}
		}
		{{end}}
		{{range .EgressPods}}
		chain {{.Namespace}}-{{.Name}}-egress-fw {
			ct state established,related accept
			ct state invalid {{template "drop"}}
			{{with $pod := .}}
			{{range $policies}}
				{{if .Matches $pod}}jump {{.Namespace}}-{{.Name}}-netpol-egress{{end}}{{end}}
			{{end}}
			{{template "markforreject"}}
		}
		{{end}}

		{{range .Policies}}
			{{template "policy" .}}
		{{end}}
	}

	{{define "policy"}}
	{{if .TargetPods}}
	{{with $p := .}}
		chain {{.Namespace}}-{{.Name}}-netpol-ingress {
		{{range .IngressRules}}
			{{with $r := .}}
			{{if .MatchAllPorts}}
				ip daddr {{genIPSetFromPods $p.TargetPods}}{{if not $r.MatchAllSource}}{{genIPSetFromIngressRule $r}}{{end}} accept
			{{else}}
				{{range .Ports}}
					ip daddr {{genIPSetFromPods $p.TargetPods}}{{if not $r.MatchAllSource}}{{genIPSetFromIngressRule $r}}{{end}} {{template "port" .}} accept
				{{end}}
			{{end}}
			{{end}}
		{{end}}
		}
		chain {{.Namespace}}-{{.Name}}-netpol-egress {
		{{range .EgressRules}}
			{{with $r := .}}
			{{if .MatchAllPorts}}
				ip saddr {{genIPSetFromPods $p.TargetPods}}{{if not $r.MatchAllDestinations}}{{genIPSetFromEgressRule $r}}{{end}} accept
			{{else}}
				{{range .Ports}}
					ip saddr {{genIPSetFromPods $p.TargetPods}}{{if not $r.MatchAllDestinations}}{{genIPSetFromEgressRule $r}}{{end}} {{template "port" .}} accept
				{{end}}
			{{end}}
			{{end}}
		{{end}}
		}
	{{end}}
	{{end}}
	{{end}}

	{{define "port"}}{{$proto := toLower .Protocol}}{{if .Port}}{{ $proto }} dport {{.Port}}{{else}}ip protocol {{ $proto }}{{end}}{{end}}
	{{define "accept"}}
		ip protocol icmp accept
		{{if .LocalIp4}}ip saddr { {{range .LocalIp4}}{{.}},{{end}} } accept{{end}}
	{{end}}
	{{define "markforreject"}}nftrace set 1 mark set 32760{{end}}
	{{define "reject"}}nftrace set 1 reject{{end}}
	{{define "drop"}}nftrace set 1 drop{{end}}

`
)

var sets map[string]string

type NFTablesInfo struct {
	AllPods     map[string]PodInfo
	IngressPods map[string]PodInfo
	EgressPods  map[string]PodInfo
	Policies    []NetworkPolicyInfo
	LocalIp4    []string
	LocalIp6    []string
	TableName   string
	Sets        map[string]string
}

type NFTables struct {
	template *template.Template
	dead     bool
}

func NewNFTablesHandler(podCIDR string, defaultDeny bool) (*NFTables, error) {
	t, err := template.New("table").Funcs(template.FuncMap{
		"toLower":                 strings.ToLower,
		"genIPSetFromIngressRule": genIPSetFromIngressRule,
		"genIPSetFromEgressRule":  genIPSetFromEgressRule,
		"genIPSetFromPods":        genIPSetFromPods,
		"defaultDeny": func() bool {
			return defaultDeny
		},
		"podCIDR": func() string {
			return podCIDR
		},
	}).Parse(NFTABLES_TEMPLATE)
	if err != nil {
		return nil, err
	}

	nft := &NFTables{
		template: t,
		dead:     false,
	}

	return nft, nil
}

func (nft *NFTables) Init() {
	//TODO: Check for nftables binary in path, perhaps kernel version?

	nft.execNftablesCmd("create", "table", NFTABLES_TABLE_NAME)
}

func (nft *NFTables) Sync(networkPoliciesInfo *[]NetworkPolicyInfo, allPods, ingressPods, egressPods *map[string]PodInfo) error {
	if nft.dead {
		return errors.New("Cannot sync nftables with a killed NFTable handler")
	}

	glog.V(2).Infof("Flushing nftables configuration to file: %s", NFTABLES_FILE)

	ip4, ip6, err := getLocalAddrs()
	if err != nil {
		return err
	}

	file, _ := ioutil.TempFile("/tmp", "kube-router-")
	defer func() {
		file.Close()
		os.Remove(file.Name())
	}()
	writer := bufio.NewWriter(file)
	sets = make(map[string]string)

	//yuk pre-gen sets
	genIPSetFromPods(*allPods)
	for _, pol := range *networkPoliciesInfo {
		genIPSetFromPods(pol.TargetPods)
		for _, e := range pol.EgressRules {
			genIPSetFromEgressRule(e)
		}
		for _, i := range pol.IngressRules {
			genIPSetFromIngressRule(i)
		}
	}

	err = nft.Generate(writer, &NFTablesInfo{
		AllPods:     *allPods,
		IngressPods: *ingressPods,
		EgressPods:  *egressPods,
		Policies:    *networkPoliciesInfo,
		LocalIp4:    *ip4,
		LocalIp6:    *ip6,
		TableName:   NFTABLES_TABLE_NAME,
		Sets:        sets,
	})
	if err != nil {
		return err
	}
	err = writer.Flush()
	if err != nil {
		return err
	}
	err = file.Sync()
	if err != nil {
		return err
	}
	err = file.Close()
	if err != nil {
		return err
	}
	err = os.Rename(file.Name(), NFTABLES_FILE)
	if err != nil {
		return err
	}

	return nft.execNftablesCmd("-f", NFTABLES_FILE)
}

func (nft *NFTables) Generate(writer *bufio.Writer, info *NFTablesInfo) error {
	return nft.template.Execute(writer, info)
}

func (nft *NFTables) execNftablesCmd(args ...string) error {
	cmd := exec.Command("nft", args...)
	glog.V(2).Infof("Execute nftables command: %s", strings.Join(args, " "))
	return cmd.Run()
}

func (nft *NFTables) Cleanup() {
	nft.Shutdown()
	os.Remove(NFTABLES_FILE)
	nft.execNftablesCmd("delete", "table", NFTABLES_TABLE_NAME)
}

func (nft *NFTables) Shutdown() {
	nft.dead = true
}

func getLocalAddrs() (*[]string, *[]string, error) {
	ifaces, err := net.InterfaceByName(KUBE_BRIDGE_IF)
	if err != nil {
		return nil, nil, err
	}
	addrs, err := ifaces.Addrs()
	if err != nil {
		return nil, nil, err
	}

	ip4 := make([]string, 0)
	ip6 := make([]string, 0)
	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPAddr:
			if v.IP.To4() != nil {
				ip4 = append(ip4, v.IP.String())
			} else {
				ip6 = append(ip6, v.IP.String())
			}
		case *net.IPNet:
			if v.IP.To4() != nil {
				ip4 = append(ip4, v.IP.String())
			} else {
				ip6 = append(ip6, v.IP.String())
			}
		}
	}

	return &ip4, &ip6, nil
}

func genIPSetFromPods(pods map[string]PodInfo) string {
	var ips []string

	for _, p := range pods {
		if len(p.IP) > 1 {
			ips = append(ips, p.IP)
		}
	}

	if len(ips) > 0 {
		return "@" + getOrCreateSet(ips)
	} else {
		return "{}"
	}
}

func genIPSetFromIngressRule(rule IngressRule) string {
	var (
		positive []string
		negative []string
	)

	for _, p := range rule.SrcPods {
		positive = append(positive, p.IP)
	}
	for _, b := range rule.SrcIPBlocks {
		positive = append(positive, b.CIDR)
		negative = append(negative, b.Except...)
	}

	return genIpSet(getOrCreateSet(positive), getOrCreateSet(negative), "saddr")
}

func genIPSetFromEgressRule(rule EgressRule) string {
	var (
		positive []string
		negative []string
	)

	for _, p := range rule.DstPods {
		positive = append(positive, p.IP)
	}
	for _, b := range rule.DstIPBlocks {
		positive = append(positive, b.CIDR)
		negative = append(negative, b.Except...)
	}

	return genIpSet(getOrCreateSet(positive), getOrCreateSet(negative), "daddr")
}

func getOrCreateSet(unfiltered []string) string {
	nets := make([]string, 0)
	for _, ip := range unfiltered {
		if len(ip) > 1 {
			if addr := net.ParseIP(ip); addr != nil { // if this is a plain address (non-cidr notation, add /32)
				ip = ip + "/32"
			}
			nets = append(nets, ip)
		}
	}
	merged, err := MergeCIDRs(nets)
	if err != nil {
		// the thing is: "getOrCreateSet" is not really allowed to fail, so if merge fails, just log it and use the unmerged list
		glog.Errorf("merging of cidrs failed for set: %v", nets, err)
	} else {
		nets = merged
	}
	sort.Strings(nets)
	ipStr := strings.Join(nets, ",")
	digest := sha256.Sum256([]byte(ipStr))
	setName := fmt.Sprintf("set_%x", digest)
	if _, ok := sets[setName]; !ok {
		sets[setName] = ipStr
	}
	return setName
}

func genIpSet(positive string, negative string, matches string) string {
	var builder strings.Builder

	if len(positive) > 0 {
		builder.WriteString(" ip ")
		builder.WriteString(matches)
		builder.WriteString(" @")
		builder.WriteString(positive)
	}
	if len(negative) > 0 {
		builder.WriteString(" ip ")
		builder.WriteString(matches)
		builder.WriteString(" != ")
		builder.WriteString("@")
		builder.WriteString(negative)
	}

	return builder.String()
}

/*
	The following code is a hard vendoring of go-cidrman, because dep management
	in this fork is difficult.

	Attribution: https://github.com/EvilSuperstars/go-cidrman
*/

type ipNets []*net.IPNet

func (nets ipNets) toCIDRs() []string {
	var cidrs []string
	for _, net := range nets {
		cidrs = append(cidrs, net.String())
	}

	return cidrs
}

// MergeIPNets accepts a list of IP networks and merges them into the smallest possible list of IPNets.
// It merges adjacent subnets where possible, those contained within others and removes any duplicates.
func MergeIPNets(nets []*net.IPNet) ([]*net.IPNet, error) {
	if nets == nil {
		return nil, nil
	}
	if len(nets) == 0 {
		return make([]*net.IPNet, 0), nil
	}

	// Split into IPv4 and IPv6 lists.
	// Merge the list separately and then combine.
	var block4s cidrBlock4s
	for _, net := range nets {
		ip4 := net.IP.To4()
		if ip4 != nil {
			block4s = append(block4s, newBlock4(ip4, net.Mask))
		} else {
			return nil, errors.New("Not implemented")
		}
	}

	merged, err := merge4(block4s)
	if err != nil {
		return nil, err
	}

	return merged, nil
}

// MergeCIDRs accepts a list of CIDR blocks and merges them into the smallest possible list of CIDRs.
func MergeCIDRs(cidrs []string) ([]string, error) {
	if cidrs == nil {
		return nil, nil
	}
	if len(cidrs) == 0 {
		return make([]string, 0), nil
	}

	var networks []*net.IPNet
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		networks = append(networks, network)
	}
	mergedNets, err := MergeIPNets(networks)
	if err != nil {
		return nil, err
	}

	return ipNets(mergedNets).toCIDRs(), nil
}

// ipv4ToUInt32 converts an IPv4 address to an unsigned 32-bit integer.
func ipv4ToUInt32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip)
}

// uint32ToIPV4 converts an unsigned 32-bit integer to an IPv4 address.
func uint32ToIPV4(addr uint32) net.IP {
	ip := make([]byte, net.IPv4len)
	binary.BigEndian.PutUint32(ip, addr)
	return ip
}

// The following functions are inspired by http://www.cs.colostate.edu/~somlo/iprange.c.

// setBit sets the specified bit in an address to 0 or 1.
func setBit(addr uint32, bit uint, val uint) uint32 {
	if bit < 0 {
		panic("negative bit index")
	}

	if val == 0 {
		return addr & ^(1 << (32 - bit))
	} else if val == 1 {
		return addr | (1 << (32 - bit))
	} else {
		panic("set bit is not 0 or 1")
	}
}

// netmask returns the netmask for the specified prefix.
func netmask(prefix uint) uint32 {
	if prefix == 0 {
		return 0
	}
	return ^uint32((1 << (32 - prefix)) - 1)
}

// broadcast4 returns the broadcast address for the given address and prefix.
func broadcast4(addr uint32, prefix uint) uint32 {
	return addr | ^netmask(prefix)
}

// network4 returns the network address for the given address and prefix.
func network4(addr uint32, prefix uint) uint32 {
	return addr & netmask(prefix)
}

// splitRange4 recursively computes the CIDR blocks to cover the range lo to hi.
func splitRange4(addr uint32, prefix uint, lo, hi uint32, cidrs *[]*net.IPNet) error {
	if prefix > 32 {
		return fmt.Errorf("Invalid mask size: %d", prefix)
	}

	bc := broadcast4(addr, prefix)
	if (lo < addr) || (hi > bc) {
		return fmt.Errorf("%d, %d out of range for network %d/%d, broadcast %d", lo, hi, addr, prefix, bc)
	}

	if (lo == addr) && (hi == bc) {
		cidr := net.IPNet{IP: uint32ToIPV4(addr), Mask: net.CIDRMask(int(prefix), 8*net.IPv4len)}
		*cidrs = append(*cidrs, &cidr)
		return nil
	}

	prefix++
	lowerHalf := addr
	upperHalf := setBit(addr, prefix, 1)
	if hi < upperHalf {
		return splitRange4(lowerHalf, prefix, lo, hi, cidrs)
	} else if lo >= upperHalf {
		return splitRange4(upperHalf, prefix, lo, hi, cidrs)
	} else {
		err := splitRange4(lowerHalf, prefix, lo, broadcast4(lowerHalf, prefix), cidrs)
		if err != nil {
			return err
		}
		return splitRange4(upperHalf, prefix, upperHalf, hi, cidrs)
	}
}

// IPv4 CIDR block.

type cidrBlock4 struct {
	first uint32
	last  uint32
}

type cidrBlock4s []*cidrBlock4

// newBlock4 returns a new IPv4 CIDR block.
func newBlock4(ip net.IP, mask net.IPMask) *cidrBlock4 {
	var block cidrBlock4

	block.first = ipv4ToUInt32(ip)
	prefix, _ := mask.Size()
	block.last = broadcast4(block.first, uint(prefix))

	return &block
}

// Sort interface.

func (c cidrBlock4s) Len() int {
	return len(c)
}

func (c cidrBlock4s) Less(i, j int) bool {
	lhs := c[i]
	rhs := c[j]

	// By last IP in the range.
	if lhs.last < rhs.last {
		return true
	} else if lhs.last > rhs.last {
		return false
	}

	// Then by first IP in the range.
	if lhs.first < rhs.first {
		return true
	} else if lhs.first > rhs.first {
		return false
	}

	return false
}

func (c cidrBlock4s) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

// merge4 accepts a list of IPv4 networks and merges them into the smallest possible list of IPNets.
// It merges adjacent subnets where possible, those contained within others and removes any duplicates.
func merge4(blocks cidrBlock4s) ([]*net.IPNet, error) {
	sort.Sort(blocks)

	// Coalesce overlapping blocks.
	for i := len(blocks) - 1; i > 0; i-- {
		if blocks[i].first <= blocks[i-1].last+1 {
			blocks[i-1].last = blocks[i].last
			if blocks[i].first < blocks[i-1].first {
				blocks[i-1].first = blocks[i].first
			}
			blocks[i] = nil
		}
	}

	var merged []*net.IPNet
	for _, block := range blocks {
		if block == nil {
			continue
		}

		if err := splitRange4(0, 0, block.first, block.last, &merged); err != nil {
			return nil, err
		}
	}

	return merged, nil
}
