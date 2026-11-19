package telemetry

import (
	"cmp"
	"net"
	"slices"

	"github.com/satchel/satchel/pkg/xrpc"
)

// NetIface 描述单测可注入的网络接口快照。
type NetIface struct {
	Name  string
	Flags net.Flags
	Addrs []net.Addr
}

// ListNICs 枚举本机 UP 且非 loopback 的网卡及其可绑定单播 IPv4/IPv6 地址。
func ListNICs() ([]xrpc.NICInfo, error) {
	return ListNICsWith(defaultListIfaces)
}

// ListNICsWith 使用可注入的接口枚举器提取可绑定地址并按网卡名与地址排序。
func ListNICsWith(listFn func() ([]NetIface, error)) ([]xrpc.NICInfo, error) {
	if listFn == nil {
		listFn = defaultListIfaces
	}
	ifaces, err := listFn()
	if err != nil {
		return nil, err
	}
	out := make([]xrpc.NICInfo, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs := filterNICAddrs(iface.Addrs)
		if len(addrs) == 0 {
			continue
		}
		slices.SortFunc(addrs, func(a, b xrpc.NICAddr) int {
			if c := cmp.Compare(a.Family, b.Family); c != 0 {
				return c
			}
			return cmp.Compare(a.IP, b.IP)
		})
		out = append(out, xrpc.NICInfo{Name: iface.Name, Addrs: addrs})
	}
	slices.SortFunc(out, func(a, b xrpc.NICInfo) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}

func defaultListIfaces() ([]NetIface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]NetIface, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		out = append(out, NetIface{Name: iface.Name, Flags: iface.Flags, Addrs: addrs})
	}
	return out, nil
}

func filterNICAddrs(addrs []net.Addr) []xrpc.NICAddr {
	out := make([]xrpc.NICAddr, 0, len(addrs))
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil {
			continue
		}
		ip := ipnet.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			continue
		}
		family := "v6"
		if ip.To4() != nil {
			family = "v4"
		}
		out = append(out, xrpc.NICAddr{
			IP:     ip.String(),
			Family: family,
			CIDR:   ipnet.String(),
			Scope:  addrScope(ip),
		})
	}
	return out
}

// addrScope 将地址归类为 ula (fc00::/7)、private (RFC1918 + CGNAT 100.64.0.0/10) 或 global。
func addrScope(ip net.IP) string {
	if ip.To4() == nil && len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc {
		return "ula"
	}
	if ip.IsPrivate() {
		return "private"
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1]&0xc0 == 64 {
		return "private"
	}
	return "global"
}
