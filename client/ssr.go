package client

import (
	"errors"
	"fmt"
	shadowsocksr "github.com/ouqiang/shadowsocksR"
	"github.com/ouqiang/shadowsocksR/obfs"
	"github.com/ouqiang/shadowsocksR/protocol"
	"github.com/ouqiang/shadowsocksR/ssr"
	cipher "github.com/ouqiang/shadowsocksR/streamCipher"
	"github.com/ouqiang/shadowsocksR/tools/socks"
	"golang.org/x/net/proxy"
	"net"
	"net/url"
)

// SSR struct.
type SSR struct {
	dialer proxy.Dialer
	addr   string

	EncryptMethod   string
	EncryptPassword string
	Obfs            string
	ObfsParam       string
	ObfsData        interface{}
	Protocol        string
	ProtocolParam   string
	ProtocolData    interface{}
}

// NewSSR returns a shadowsocksr proxy, ssr://method:pass@host:port/query
func NewSSR(s string, d proxy.Dialer) (*SSR, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("parse err: %w", err)
	}

	addr := u.Host
	method := u.User.Username()
	pass, _ := u.User.Password()
	p := &SSR{
		dialer:          d,
		addr:            addr,
		EncryptMethod:   method,
		EncryptPassword: pass,
	}

	query := u.Query()
	p.Protocol = query.Get("protocol")
	p.ProtocolParam = query.Get("protocol_param")
	p.Obfs = query.Get("obfs")
	p.ObfsParam = query.Get("obfs_param")

	p.ProtocolData = new(protocol.AuthData)

	return p, nil
}

// Addr returns forwarder's address
func (s *SSR) Addr() string {
	return s.addr
}

// Dial connects to the address addr on the network net via the proxy.
func (s *SSR) Dial(network, addr string) (net.Conn, error) {
	target := socks.ParseAddr(addr)
	if target == nil {
		return nil, errors.New("[ssr] unable to parse address: " + addr)
	}

	ciph, err := cipher.NewStreamCipher(s.EncryptMethod, s.EncryptPassword)
	if err != nil {
		return nil, err
	}

	if network == "" {
		network = "tcp"
	}

	c, err := s.dialer.Dial(network, s.addr)
	if err != nil {
		return nil, fmt.Errorf("[ssr] dial to %s error: %w", s.addr, err)
	}

	ssrconn := shadowsocksr.NewSSTCPConn(c, ciph)
	if ssrconn.Conn == nil || ssrconn.RemoteAddr() == nil {
		return nil, errors.New("[ssr] nil connection")
	}

	// should initialize obfs/protocol now
	tcpAddr := ssrconn.RemoteAddr().(*net.TCPAddr)
	port := tcpAddr.Port

	ssrconn.IObfs = obfs.NewObfs(s.Obfs)
	if ssrconn.IObfs == nil {
		return nil, errors.New("[ssr] unsupported obfs type: " + s.Obfs)
	}

	obfsServerInfo := &ssr.ServerInfo{
		Host:   tcpAddr.IP.String(),
		Port:   uint16(port),
		TcpMss: 1460,
		Param:  s.ObfsParam,
	}
	ssrconn.IObfs.SetServerInfo(obfsServerInfo)

	ssrconn.IProtocol = protocol.NewProtocol(s.Protocol)
	if ssrconn.IProtocol == nil {
		return nil, errors.New("[ssr] unsupported protocol type: " + s.Protocol)
	}

	protocolServerInfo := &ssr.ServerInfo{
		Host:   tcpAddr.IP.String(),
		Port:   uint16(port),
		TcpMss: 1460,
		Param:  s.ProtocolParam,
	}
	ssrconn.IProtocol.SetServerInfo(protocolServerInfo)

	if s.ObfsData == nil {
		s.ObfsData = ssrconn.IObfs.GetData()
	}
	ssrconn.IObfs.SetData(s.ObfsData)

	if s.ProtocolData == nil {
		s.ProtocolData = ssrconn.IProtocol.GetData()
	}
	ssrconn.IProtocol.SetData(s.ProtocolData)
	if _, err := ssrconn.Write(target); err != nil {
		_ = ssrconn.Close()
		return nil, err
	}
	return ssrconn, err
}
