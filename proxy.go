package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Connect ...
func Connect(src io.ReadWriteCloser, gateway *Endpoint) {
	defer func() {
		if p := recover(); p != nil {
			log.Println("panic on connecting:", p)
		}
	}()
	defer src.Close()
	ep, err := accept(src)
	if err != nil {
		log.Println(err)
		return
	}
	// log.Println("accepted endpoint", ep.String())

	// connect
	if gateway == nil {
		gateway = &NoneEndpoint
	}

	dst, er := connect(&ep, gateway)
	if er != nil {
		log.Println(er)
		return
	}
	defer dst.Close()

	if ep.req != nil && ep.req.Method != "CONNECT" {
		if err = ep.req.Write(dst); err != nil {
			return
		}
	}

	// relay
	go func() {
		defer dst.Close()
		defer src.Close()
		io.CopyBuffer(src, dst, make([]byte, 8*1024))
	}()
	io.CopyBuffer(dst, src, make([]byte, 1024))
}

// Endpoint ...
type Endpoint struct {
	Schema string
	Host   string
	Port   int
	req    *http.Request
}

// NoneEndpoint ...
var NoneEndpoint = Endpoint{Schema: "none", Host: "", Port: 0}

// ParseEndpoint ...
func ParseEndpoint(str string) (ep *Endpoint) {
	tmp := strings.Split(str, "://")
	schema := tmp[0]
	host := ""
	port := 0
	if len(tmp) == 2 {
		tmp = strings.Split(tmp[1], ":")
		host = tmp[0]
		if len(tmp) == 2 {
			if p, err := strconv.Atoi(tmp[1]); err == nil {
				port = p
			} else {
				return nil
			}
		}
	}
	if len(schema) == 0 {
		schema = "none"
	}
	ep = new(Endpoint)
	ep.Schema, ep.Host, ep.Port = schema, host, port
	return ep
}

// Address ...
func (ep *Endpoint) Address() string {
	return fmt.Sprintf("%s:%d", ep.Host, ep.Port)
}

// String ...
func (ep *Endpoint) String() string {
	if ep.Schema == "none" {
		return "none://"
	}
	return fmt.Sprint(ep.Schema, "://", ep.Host, ":", ep.Port)
}

func accept(conn io.ReadWriteCloser) (ep Endpoint, err error) {
	buf, n := make([]byte, 128), 0
	if n, err = conn.Read(buf); err != nil {
		return ep, err
	}
	if n <= 0 {
		return ep, errors.New("request is empty")
	}
	// log.Println("receive:", buf[:n])

	if buf[0] == 0x04 {
		// socks4
		return acceptSOCKS4(conn, buf[:n])
	} else if buf[0] == 0x05 {
		// socks5
		return acceptSOCKS5(conn, buf[:n])
	} else if buf[0] > 0x40 && buf[0] < 0x5B {
		// http
		return acceptHTTP(conn, buf[:n])
	} else {
		return ep, errors.New("first byte invalid: " + string(buf[0]))
	}
}

func connect(ep *Endpoint, gateway *Endpoint) (conn net.Conn, err error) {
	switch gateway.Schema {
	case "socks5", "socks":
		return connectSOCK5(ep, gateway)
	case "socks4":
		return connectSOCK4(ep, gateway)
	case "http":
		return connectHTTP(ep, gateway)
	case "none":
		return connectTCP(ep)
	default:
		return nil, errors.New("schema invalid of gateway Endpoint")
	}
}

func connectTCP(ep *Endpoint) (conn net.Conn, err error) {
	return net.DialTimeout("tcp", ep.Address(), time.Second*10)
}

// socks4:
// |VER{1}4|ATYP{1}1|DST.PORT{2}|DST.ADDR{4}|USERID{}|END{1}0|[?(Socks4a)DST.ADDR=0,0,0,1?DST.HOST{}|END{1}0]
// |REP{1}0|PROTOCOL{1}90|DST.PORT{2}|DST.ADDR{4}|
func acceptSOCKS4(conn io.ReadWriter, buf []byte) (ep Endpoint, err error) {
	n := len(buf)
	port := int(buf[2])<<8 + int(buf[3])
	// host (Socks4a)
	var host string
	if buf[4] == 0 && buf[5] == 0 && buf[6] == 0 && buf[7] > 0 {
		//skip USERID
		index := 8
		for ; index < n && buf[index] != 0; index++ {
		}
		index++
		for i := index; i < n; i++ {
			if buf[i] == 0 {
				host = string(buf[index:i])
				break
			}
		}
	} else {
		host = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
	}
	if _, err := conn.Write([]byte{0, 90, buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]}); err != nil {
		return ep, err
	}
	ep.Schema, ep.Host, ep.Port = "tcp", host, port
	return ep, nil
}

func connectSOCK4(ep *Endpoint, gateway *Endpoint) (conn net.Conn, err error) {
	if conn, err = connectTCP(gateway); err != nil {
		return nil, err
	}
	buf := make([]byte, 128)
	copy(buf[:4], []byte{4, 1, byte(ep.Port >> 8), byte(ep.Port & 0xFF)})
	buf[8] = 0
	n := 9
	ip := net.ParseIP(ep.Host)
	if ip != nil {
		if ip = ip.To4(); ip == nil {
			return nil, errors.New("ipv6 not supported")
		}
		copy(buf[4:8], ip)
	} else {
		copy(buf[4:8], []byte{0, 0, 0, 1})
		hosts := []byte(ep.Host)
		nhost := len(hosts)
		copy(buf[9:9+nhost], hosts)
		buf[9+nhost] = 0
		n += nhost + 1
	}
	if _, err = conn.Write(buf[:n]); err != nil {
		return nil, err
	}
	if n, err = conn.Read(buf); err != nil {
		return nil, err
	}
	if n < 8 || buf[0] != 0 {
		return nil, errors.New("connect to socks4 gateway failed")
	}
	return conn, nil
}

// socks5:
// |VER{1}5|NMETHODS{1}|METHODS{NMETHODS}|
// |VER{1}5|METHOD{1}|
// |VER{1}5|CMD{1}[1(TCP)|3(UDP)]|RSV{1}0|ATYP{1}[1(IPv4)/3(HOST)/4(IPv6)]|[DST.ADDR{4}/DST.NHOST{1}|DST.HOST{DST.NHOST}]|DST.PORT{2}|
// |VER{1}5|REP{1}0|RSV{1}0|ATYP{1}1|BND.ADDR{4}|BIND.PORT{2}| : 5, 0, 0, 1, 0, 0, 0, 0, 0, 0
func acceptSOCKS5(conn io.ReadWriter, buf []byte) (ep Endpoint, err error) {
	n := len(buf)
	var hasAnonymousMethod bool
	nMethods := int(buf[1])
	for i := 2; i < nMethods+2 && i < n; i++ {
		if buf[i] == 0 {
			hasAnonymousMethod = true
			break
		}
	}
	if !hasAnonymousMethod {
		// other methods not supported
		conn.Write([]byte{5, 0xFF})
		return ep, errors.New("method not supported")
	}
	if _, err = conn.Write([]byte{5, 0}); err != nil {
		return ep, err
	}
	buf = make([]byte, 128)
	if n, err = conn.Read(buf); err != nil {
		return ep, err
	}
	var (
		host     string
		port     int
		response []byte
	)
	switch buf[3] {
	case 1: //ipv4
		host = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		port = int(buf[8])<<8 + int(buf[9])
		response = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0} // success
	case 3: //host
		nHost := buf[4]
		host = string(buf[5 : 5+nHost])
		port = int(buf[5+nHost])<<8 + int(buf[5+nHost+1])
		response = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0} // success
	case 4: //ipv6 not supported
		fallthrough
	default: //address type not supported
		conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return ep, errors.New("address type not supported")
	}
	if _, err = conn.Write(response); err != nil {
		return ep, err
	}
	ep.Schema, ep.Host, ep.Port = "tcp", host, port
	return ep, nil
}

func connectSOCK5(ep *Endpoint, gateway *Endpoint) (conn net.Conn, err error) {
	if conn, err = connectTCP(gateway); err != nil {
		return nil, err
	}
	if _, err = conn.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	buf := make([]byte, 128)
	n := 0
	if n, err = conn.Read(buf); err != nil {
		return nil, err
	}
	if n < 2 || buf[1] != 0 {
		return nil, errors.New("invalid response from socks5 gateway")
	}
	copy(buf[:3], []byte{5, 1, 0})
	port := []byte{byte(ep.Port >> 8), byte(ep.Port & 0xFF)}
	ip := net.ParseIP(ep.Host)
	if ip != nil {
		if ip = ip.To4(); ip == nil {
			return nil, errors.New("ipv6 not supported")
		}
		buf[3] = 1 // ipv4
		copy(buf[4:8], ip)
		copy(buf[8:10], port)
		n = 10
	} else {
		nhost := len(ep.Host)
		buf[3] = 3 // host
		buf[4] = byte(nhost)
		copy(buf[5:5+nhost], []byte(ep.Host))
		copy(buf[5+nhost:5+nhost+2], port)
		n = 5 + nhost + 2
	}
	if _, err = conn.Write(buf[:n]); err != nil {
		return nil, err
	}
	if n, err = conn.Read(buf); err != nil {
		return nil, err
	}
	if n < 10 || buf[1] != 0 {
		return nil, errors.New("connect to socks5 gateway failed")
	}
	return conn, nil
}

func acceptHTTP(conn io.ReadWriter, buf []byte) (ep Endpoint, err error) {
	bufReader := bufio.NewReader(io.MultiReader(bytes.NewReader(buf), conn))
	var req *http.Request
	if req, err = http.ReadRequest(bufReader); err != nil {
		return ep, err
	}
	// log.Println(req.Method, req.RequestURI)
	if req.Method == "CONNECT" {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n"))
	}
	host, port := "", 0
	if strings.Index(req.Host, ":") > 0 {
		arr := strings.Split(req.Host, ":")
		host = arr[0]
		if port, err = strconv.Atoi(arr[1]); err != nil {
			return ep, err
		}
	} else {
		host = req.Host
		port = 80
	}
	ep.Schema, ep.Host, ep.Port, ep.req = "tcp", host, port, req
	return ep, nil
}

func connectHTTP(ep *Endpoint, gateway *Endpoint) (conn net.Conn, err error) {
	if conn, err = connectTCP(gateway); err != nil {
		return nil, err
	}
	req := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n", ep.Host, ep.Port, ep.Host)
	if _, err = conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	if res, err := http.ReadResponse(bufio.NewReader(conn), nil); err != nil || res.StatusCode != 200 {
		if err == nil {
			err = fmt.Errorf("connect to remote %s failed", ep.String())
		}
		return nil, err
	}
	return conn, nil
}
