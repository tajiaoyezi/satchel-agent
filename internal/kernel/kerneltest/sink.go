package kerneltest

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Meter 是一个只增不减的字节计数器，测吞吐时在时间窗两端各读一次。
type Meter struct{ n atomic.Int64 }

func (m *Meter) Add(n int) { m.n.Add(int64(n)) }

// Bytes 返回累计字节数。
func (m *Meter) Bytes() int64 { return m.n.Load() }

// Mbps 量一个时间窗内的吞吐（兆比特每秒）。
func (m *Meter) Mbps(window time.Duration) float64 {
	start, t0 := m.Bytes(), time.Now()
	time.Sleep(window)
	return float64(m.Bytes()-start) * 8 / time.Since(t0).Seconds() / 1e6
}

// UDPPayload 是收发流量的服务下发 UDP 时每个数据报的大小。
const UDPPayload = 1200

// Sink 是收发流量的服务：同一个端口上一个 TCP 服务与一个 UDP 服务。
//
// TCP：连上后先发一行命令。
//   - "D <bps> <bytes>"：按 bps（0 表示不控速）下发 bytes 个字节（0 表示一直发到连接断开），发完关闭；
//   - "U <id>"：一直接收到 EOF，字节数记在 Upload(id) 上；
//   - "H <id>"：先发 "hello" 再半关闭，之后和 "U <id>" 一样接收（测半关闭有没有被当成整条关闭）；
//   - "E"：回显。
//
// UDP：每个数据报以命令开头。
//   - "D <bps> <durationMs>"：按 bps 向来源地址发 UDPPayload 大小的数据报，持续 durationMs 毫秒；
//   - "E ..."：原样回发。
type Sink struct {
	Port int

	ln   net.Listener
	pc   net.PacketConn
	mu   sync.Mutex
	up   map[string]*Meter
	done chan struct{}
}

// StartSink 在 127.0.0.1 上起一个收发流量的服务，测试结束时关掉。
func StartSink(t testing.TB) *Sink {
	t.Helper()
	port := FreePort(t)
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	s := &Sink{Port: port, ln: ln, pc: pc, up: map[string]*Meter{}, done: make(chan struct{})}
	go s.serveTCP()
	go s.serveUDP()
	t.Cleanup(s.Close)
	return s
}

// Close 关掉服务。
func (s *Sink) Close() {
	select {
	case <-s.done:
		return
	default:
		close(s.done)
	}
	s.ln.Close()
	s.pc.Close()
}

// Upload 返回 "U <id>" 连接的接收计数。
func (s *Sink) Upload(id string) *Meter {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.up[id]
	if m == nil {
		m = &Meter{}
		s.up[id] = m
	}
	return m
}

func (s *Sink) serveTCP() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleTCP(conn)
	}
}

func (s *Sink) handleTCP(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	f := strings.Fields(line)
	if len(f) == 0 {
		return
	}
	switch f[0] {
	case "D":
		if len(f) != 3 {
			return
		}
		bps, _ := strconv.ParseInt(f[1], 10, 64)
		total, _ := strconv.ParseInt(f[2], 10, 64)
		pacedWrite(conn, bps, total, s.done)
	case "H":
		if len(f) != 2 {
			return
		}
		conn.Write([]byte("hello"))
		conn.(*net.TCPConn).CloseWrite()
		fallthrough
	case "U":
		if len(f) != 2 {
			return
		}
		m := s.Upload(f[1])
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Read(buf)
			m.Add(n)
			if err != nil {
				return
			}
		}
	case "E":
		io.Copy(conn, r)
	}
}

// pacedWrite 按 bps 写 total 个字节（total 为 0 时一直写到出错），bps 为 0 时不控速。
func pacedWrite(w io.Writer, bps, total int64, done <-chan struct{}) {
	chunk := make([]byte, 16<<10)
	start := time.Now()
	var sent int64
	for total == 0 || sent < total {
		select {
		case <-done:
			return
		default:
		}
		n := int64(len(chunk))
		if total > 0 && total-sent < n {
			n = total - sent
		}
		if _, err := w.Write(chunk[:n]); err != nil {
			return
		}
		sent += n
		if bps > 0 {
			if ahead := time.Duration(float64(sent*8)/float64(bps)*float64(time.Second)) - time.Since(start); ahead > 0 {
				time.Sleep(ahead)
			}
		}
	}
}

func (s *Sink) serveUDP() {
	buf := make([]byte, 64<<10)
	for {
		n, addr, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		f := strings.Fields(string(buf[:min(n, 64)]))
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "D":
			if len(f) < 3 {
				continue
			}
			bps, _ := strconv.ParseInt(f[1], 10, 64)
			ms, _ := strconv.ParseInt(f[2], 10, 64)
			go s.udpDownload(addr, bps, time.Duration(ms)*time.Millisecond)
		case "E":
			s.pc.WriteTo(buf[:n], addr)
		}
	}
}

func (s *Sink) udpDownload(addr net.Addr, bps int64, d time.Duration) {
	payload := make([]byte, UDPPayload)
	start := time.Now()
	var sent int64
	for time.Since(start) < d {
		select {
		case <-s.done:
			return
		default:
		}
		if _, err := s.pc.WriteTo(payload, addr); err != nil {
			return
		}
		sent += UDPPayload
		if bps <= 0 {
			continue
		}
		if ahead := time.Duration(float64(sent*8)/float64(bps)*float64(time.Second)) - time.Since(start); ahead > 0 {
			time.Sleep(ahead)
		}
	}
}

// FreePort 找一个 TCP 与 UDP 在 127.0.0.1 上都空着的端口。
func FreePort(t testing.TB) int {
	t.Helper()
	for i := 0; i < 50; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		ln.Close()
		if err == nil {
			pc.Close()
			return port
		}
	}
	t.Fatal("找不到 TCP 与 UDP 都空着的端口")
	return 0
}
