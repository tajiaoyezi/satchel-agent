package tracker

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// 包装层是证伪的核心（design 第 3 条）：sing 的拷贝（common/bufio）只在包装层实现了它的计数接口、声明自己可以被替换、
// 或暴露了底层 socket / 等待读的接口时才会拆掉包装层走快路径。所以这里只实现最普通的读写、地址与关闭方法，
// MUST NOT 实现 ReadCounter / WriteCounter、ReaderWithUpstream、common.WithUpstream、ReadWaiter / ReadWaitCreator、syscall.Conn 等，
// 拷贝就只能逐次调用这里的 Read / Write，限速与计数不会被绕开。代价是 splice、批量读这些快路径用不上。
//
// 另外转发几个不涉及搬数据的方法，sing 找它们时只沿 Upstream() 往里拆，包装层不实现 Upstream()，不转发就找不到：
//   - 握手结果的回报（HandshakeSuccess、HandshakeFailure、ConnHandshakeSuccess、PacketConnHandshakeSuccess、
//     NeedHandshakeForWrite）：不转发的话入站收不到「出站已连上」的回报，有的协议会一直等；
//   - 缓冲区的预留量（FrontHeadroom、RearHeadroom、ReaderOverhead、ReaderMTU、WriterMTU）：拷贝按它们分配缓冲区，
//     不转发的话缓冲区前面没给包头留地方（xudp 往前写包头时越界 panic）；
//   - TCP 的半关闭（CloseWrite）：sing-box 拷完一个方向后对这一侧调 CloseWrite，包装层不实现的话它就整条关掉，
//     目标先发完、客户端还要接着上传时就断了。

// tcpConn 包装入站这一侧的 TCP 连接：Read 是客户端发上来的（上行），Write 是回给客户端的（下行），都先取额度再记数。
type tcpConn struct {
	inner   net.Conn
	bucket  *bucket // nil 表示认不出凭据，不限速
	counter *counter
	release func()
	ctx     context.Context
	cancel  context.CancelFunc
	once    sync.Once
}

func (c *tcpConn) Read(p []byte) (int, error) {
	if c.bucket != nil {
		if max := c.bucket.chunk(); max > 0 && len(p) > max {
			p = p[:max] // 限速时一次只读一小块，免得先欠下一大笔额度
		}
	}
	n, err := c.inner.Read(p)
	if n > 0 {
		c.counter.up.Add(int64(n))
		if c.bucket != nil {
			if werr := c.bucket.take(c.ctx, n); werr != nil && err == nil {
				err = net.ErrClosed
			}
		}
	}
	return n, err
}

func (c *tcpConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := len(p)
		if c.bucket != nil {
			if max := c.bucket.chunk(); max > 0 && chunk > max {
				chunk = max
			}
			if err := c.bucket.take(c.ctx, chunk); err != nil {
				return written, net.ErrClosed
			}
		}
		n, err := c.inner.Write(p[:chunk])
		written += n
		c.counter.down.Add(int64(n))
		if err != nil {
			return written, err
		}
		p = p[n:]
	}
	return written, nil
}

func (c *tcpConn) Close() error {
	var err error
	c.once.Do(func() {
		c.cancel()
		err = c.inner.Close()
		c.release()
	})
	return err
}

// CloseWrite 转发半关闭。内层不支持半关闭时整条关掉，和 sing-box 对这种连接的做法一样，免得客户端一直等不到 EOF。
func (c *tcpConn) CloseWrite() error {
	inner, _ := N.UnwrapCountWriter(c.inner, nil)
	if wc, ok := N.UnwrapWriter(inner).(N.WriteCloser); ok {
		return wc.CloseWrite()
	}
	return c.Close()
}

func (c *tcpConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *tcpConn) RemoteAddr() net.Addr               { return c.inner.RemoteAddr() }
func (c *tcpConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *tcpConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *tcpConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

func (c *tcpConn) HandshakeSuccess() error          { return N.ReportHandshakeSuccess(c.inner) }
func (c *tcpConn) HandshakeFailure(err error) error { return N.ReportHandshakeFailure(c.inner, err) }
func (c *tcpConn) ConnHandshakeSuccess(conn net.Conn) error {
	return N.ReportConnHandshakeSuccess(c.inner, conn)
}
func (c *tcpConn) NeedHandshakeForWrite() bool { return N.NeedHandshakeForWrite(c.inner) }

func (c *tcpConn) FrontHeadroom() int  { return N.CalculateFrontHeadroom(c.inner) }
func (c *tcpConn) RearHeadroom() int   { return N.CalculateRearHeadroom(c.inner) }
func (c *tcpConn) ReaderOverhead() int { return N.CalculateReaderOverhead(c.inner) }
func (c *tcpConn) ReaderMTU() int      { return N.CalculateMTU(c.inner, nil) }
func (c *tcpConn) WriterMTU() int      { return N.CalculateMTU(nil, c.inner) }

// packetConn 包装入站这一侧的 UDP 流：ReadPacket 是客户端发上来的（上行），WritePacket 是回给客户端的（下行）。
// 字节数按负载（应用层）算。
type packetConn struct {
	inner   N.PacketConn
	bucket  *bucket
	counter *counter
	release func()
	ctx     context.Context
	cancel  context.CancelFunc
	once    sync.Once
}

func (c *packetConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := c.inner.ReadPacket(buffer)
	if err != nil {
		return destination, err
	}
	n := buffer.Len()
	c.counter.up.Add(int64(n))
	if c.bucket != nil {
		if werr := c.bucket.take(c.ctx, n); werr != nil {
			return destination, net.ErrClosed
		}
	}
	return destination, nil
}

func (c *packetConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	n := buffer.Len()
	if c.bucket != nil {
		if err := c.bucket.take(c.ctx, n); err != nil {
			buffer.Release() // WritePacket 拿走了 buffer 的所有权，出错也要放回去
			return net.ErrClosed
		}
	}
	if err := c.inner.WritePacket(buffer, destination); err != nil {
		return err
	}
	c.counter.down.Add(int64(n))
	return nil
}

func (c *packetConn) Close() error {
	var err error
	c.once.Do(func() {
		c.cancel()
		err = c.inner.Close()
		c.release()
	})
	return err
}

func (c *packetConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *packetConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *packetConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *packetConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

func (c *packetConn) HandshakeSuccess() error          { return N.ReportHandshakeSuccess(c.inner) }
func (c *packetConn) HandshakeFailure(err error) error { return N.ReportHandshakeFailure(c.inner, err) }
func (c *packetConn) PacketConnHandshakeSuccess(conn net.PacketConn) error {
	return N.ReportPacketConnHandshakeSuccess(c.inner, conn)
}

func (c *packetConn) FrontHeadroom() int  { return N.CalculateFrontHeadroom(c.inner) }
func (c *packetConn) RearHeadroom() int   { return N.CalculateRearHeadroom(c.inner) }
func (c *packetConn) ReaderOverhead() int { return N.CalculateReaderOverhead(c.inner) }
func (c *packetConn) ReaderMTU() int      { return N.CalculateMTU(c.inner, nil) }
func (c *packetConn) WriterMTU() int      { return N.CalculateMTU(nil, c.inner) }
