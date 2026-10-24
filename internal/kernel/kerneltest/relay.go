package kerneltest

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"testing"
)

// Relay 挡在服务端的一个入站前面：客户端连 Relay，Relay 再连服务端，并记下自己连服务端用的本地地址。
// 服务端看到的对端就是这些地址，用来核对 tracker 列出的对端（agent-kernel「按凭据识别连接」）。
// TCP 每条连接一个上游连接；UDP 每个客户端地址一个上游 socket。
//
// TCP 的转发假定上面跑的是 VLESS：从请求头的命令字节认出这条连接装的是 TCP（1）还是 UDP（2，xudp 用的是 3），
// 记在 Network 里，用来核对清单里每条连接的对端与网络类型对得上。请求头是版本 1 字节、UUID 16 字节、
// 附加信息的长度 1 字节、附加信息、命令 1 字节（sing-vmess vless.EncodeRequest）。
type Relay struct {
	Port int

	mu    sync.Mutex
	peers map[string]string // 连服务端用的本地地址 → 网络类型（认不出时为空）
}

// StartRelay 在 127.0.0.1 上起一个转发，network 是 "tcp" 或 "udp"，转到本机的 target 端口。测试结束时关掉。
func StartRelay(t testing.TB, network string, target int) *Relay {
	t.Helper()
	r := &Relay{peers: map[string]string{}}
	addr := fmt.Sprintf("127.0.0.1:%d", target)
	switch network {
	case "tcp":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		r.Port = ln.Addr().(*net.TCPAddr).Port
		t.Cleanup(func() { ln.Close() })
		go r.serveTCP(ln, addr)
	case "udp":
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		r.Port = pc.LocalAddr().(*net.UDPAddr).Port
		t.Cleanup(func() { pc.Close() })
		go r.serveUDP(pc, addr)
	default:
		t.Fatalf("不认识的网络 %q", network)
	}
	return r
}

// Peers 返回这个转发连服务端用过的本地地址，排好序。
func (r *Relay) Peers() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.peers))
	for addr := range r.peers {
		out = append(out, addr)
	}
	sort.Strings(out)
	return out
}

// Network 返回经 addr 这条上游连接的是 TCP 还是 UDP（"tcp" / "udp"），认不出时为空。
func (r *Relay) Network(addr string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.peers[addr]
}

func (r *Relay) record(addr net.Addr, network string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers[addr.String()] = network
}

func (r *Relay) serveTCP(ln net.Listener, target string) {
	for {
		down, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer down.Close()
			up, err := net.Dial("tcp", target)
			if err != nil {
				return
			}
			defer up.Close()
			// 先记下再开始转发：服务端要等客户端的请求头到了才登记连接。
			br := bufio.NewReader(down)
			head, err := br.Peek(18)
			if err != nil {
				return
			}
			network := ""
			if head, err = br.Peek(18 + int(head[17]) + 1); err == nil {
				switch head[len(head)-1] {
				case 1:
					network = "tcp"
				case 2, 3:
					network = "udp"
				}
			}
			r.record(up.LocalAddr(), network)
			go func() {
				io.Copy(up, br)
				up.(*net.TCPConn).CloseWrite()
			}()
			io.Copy(down, up)
		}()
	}
}

func (r *Relay) serveUDP(pc net.PacketConn, target string) {
	ups := map[string]net.Conn{}
	defer func() {
		for _, up := range ups {
			up.Close()
		}
	}()
	buf := make([]byte, 64<<10)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		up := ups[from.String()]
		if up == nil {
			if up, err = net.Dial("udp", target); err != nil {
				continue
			}
			ups[from.String()] = up
			r.record(up.LocalAddr(), "")
			go func() {
				b := make([]byte, 64<<10)
				for {
					n, err := up.Read(b)
					if err != nil {
						return
					}
					pc.WriteTo(b[:n], from)
				}
			}()
		}
		up.Write(buf[:n])
	}
}
