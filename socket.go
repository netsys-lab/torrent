package torrent

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/anacrolix/torrent/scion_torrent"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"

	"github.com/anacrolix/missinggo"
	"github.com/anacrolix/missinggo/perf"
	"github.com/pkg/errors"
	"golang.org/x/net/proxy"
)

type dialer interface {
	dial(_ context.Context, addr net.Addr) (net.Conn, error)
}

type socket interface {
	net.Listener
	dialer
}

func getProxyDialer(proxyURL string) (proxy.Dialer, error) {
	fixedURL, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	return proxy.FromURL(fixedURL, proxy.Direct)
}

func listen(n network, cfg *ClientConfig, f firewallCallback) (socket, error) {
	portStr := strconv.FormatInt(int64(cfg.ListenPort), 10)
	switch {
	case n.Tcp:
		return listenTcp(n.String(), net.JoinHostPort(cfg.ListenHost(n.String()), portStr), cfg.ProxyURL)
	case n.Udp:
		return listenUtp(n.String(), net.JoinHostPort(cfg.ListenHost(n.String()), portStr), cfg.ProxyURL, f)
	case n.Scion:
		return listenScion(cfg.PublicScionAddr)
	default:
		panic(n)
	}
}

type scionSocket struct {
	local *snet.Addr
	q     quic.Listener
}

func (s *scionSocket) Accept() (net.Conn, error) {
	x, err := s.q.Accept()
	if err != nil {
		return nil, err
	}
	conn, err := x.AcceptStream()
	if err != nil {
		return nil, err
	}
	return &squicStreamWrapper{
		conn,
		x.LocalAddr,
		x.RemoteAddr,
	}, nil
}

func (s *scionSocket) Close() error {
	return s.q.Close()
}

func (s *scionSocket) Addr() net.Addr {
	return s.q.Addr()
}

type squicStreamWrapper struct {
	quic.Stream
	local, remote func() net.Addr
}

func (w *squicStreamWrapper) LocalAddr() net.Addr {
	return w.local()
}
func (w *squicStreamWrapper) RemoteAddr() net.Addr {
	return w.remote()
}

func (s *scionSocket) dial(ctx context.Context, addr net.Addr) (net.Conn, error) {
	if err := scion_torrent.InitScion(s.local.IA); err != nil {
		return nil, err
	}
	if err := scion_torrent.InitSQUICCerts(); err != nil {
		return nil, err
	}
	snetAddr, ok := addr.(*snet.Addr)
	if !ok {
		return nil, errors.New("Invalid scion addr")
	}
	str := snetAddr.String()
	front := str[:strings.LastIndex(str, ":")]
	newAddr, err := snet.AddrFromString(front)
	if err != nil {
		return nil, err
	}
	sess, err := squic.DialSCION(nil, newAddr, snetAddr, &quic.Config{
		KeepAlive: true,
	})
	if err != nil {
		return nil, err
	}
	conn, err := sess.OpenStreamSync()
	if err != nil {
		return nil, err
	}
	return &squicStreamWrapper{
		conn,
		sess.LocalAddr,
		sess.RemoteAddr,
	}, nil
}

func listenScion(address *snet.Addr) (s socket, err error) {
	if err := scion_torrent.InitScion(address.IA); err != nil {
		return nil, err
	}
	if err := scion_torrent.InitSQUICCerts(); err != nil {
		return nil, err
	}
	conn, err := squic.ListenSCION(nil, address, &quic.Config{KeepAlive: true})
	if err != nil {
		return nil, err
	}
	scionSocket := &scionSocket{}
	scionSocket.q = conn
	scionSocket.local = address
	return scionSocket, nil
}

func listenTcp(network, address, proxyURL string) (s socket, err error) {
	l, err := net.Listen(network, address)
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			l.Close()
		}
	}()

	// If we don't need the proxy - then we should return default net.Dialer,
	// otherwise, let's try to parse the proxyURL and return proxy.Dialer
	if len(proxyURL) != 0 {
		// TODO: The error should be propagated, as proxy may be in use for
		// security or privacy reasons. Also just pass proxy.Dialer in from
		// the Config.
		if dialer, err := getProxyDialer(proxyURL); err == nil {
			return tcpSocket{l, func(ctx context.Context, addr string) (conn net.Conn, err error) {
				defer perf.ScopeTimerErr(&err)()
				return dialer.Dial(network, addr)
			}}, nil
		}
	}
	dialer := net.Dialer{}
	return tcpSocket{l, func(ctx context.Context, addr string) (conn net.Conn, err error) {
		defer perf.ScopeTimerErr(&err)()
		return dialer.DialContext(ctx, network, addr)
	}}, nil
}

type tcpSocket struct {
	net.Listener
	d func(ctx context.Context, addr string) (net.Conn, error)
}

func (me tcpSocket) dial(ctx context.Context, addr net.Addr) (net.Conn, error) {
	return me.d(ctx, addr.String())
}

func listenAll(networks []network, config *ClientConfig, f firewallCallback) ([]socket, error) {
	fmt.Printf("ListenAll: %v", networks)
	if len(networks) == 0 {
		return nil, nil
	}
	for {
		ss, retry, err := listenAllRetry(networks, config, f)
		if !retry {
			return ss, err
		}
	}
}

type networkAndHost struct {
	Network network
	Host    string
}

func listenAllRetry(nahs []network, cfg *ClientConfig, f firewallCallback) (ss []socket, retry bool, err error) {
	ss = make([]socket, 1, len(nahs))
	ss[0], err = listen(nahs[0], cfg, f)
	if err != nil {
		return nil, false, errors.Wrap(err, "first listen")
	}
	defer func() {
		if err != nil || retry {
			for _, s := range ss {
				s.Close()
			}
			ss = nil
		}
	}()
	for _, nah := range nahs[1:] {
		s, err := listen(nah, cfg, f)
		if err != nil {
			return ss,
				missinggo.IsAddrInUse(err) && cfg.ListenPort == 0,
				errors.Wrap(err, "subsequent listen")
		}
		ss = append(ss, s)
	}
	return
}

type firewallCallback func(net.Addr) bool

func listenUtp(network, addr, proxyURL string, fc firewallCallback) (s socket, err error) {
	us, err := NewUtpSocket(network, addr, fc)
	if err != nil {
		return
	}

	// If we don't need the proxy - then we should return default net.Dialer,
	// otherwise, let's try to parse the proxyURL and return proxy.Dialer
	if len(proxyURL) != 0 {
		if dialer, err := getProxyDialer(proxyURL); err == nil {
			return utpSocketSocket{us, network, dialer}, nil
		}
	}

	return utpSocketSocket{us, network, nil}, nil
}

type utpSocketSocket struct {
	utpSocket
	network string
	d       proxy.Dialer
}

func (me utpSocketSocket) dial(ctx context.Context, addr net.Addr) (conn net.Conn, err error) {
	defer perf.ScopeTimerErr(&err)()
	if me.d != nil {
		return me.d.Dial(me.network, addr.String())
	}

	return me.utpSocket.DialContext(ctx, me.network, addr.String())
}
