package main

import (
	"crypto/sha512"
	"flag"
	"io"
	"log"
	"net"

	proxy "github.com/loye/go-qproxy"
)

func main() {
	local := flag.String("local", ":1443", "proxy listen address")
	gatewayStr := flag.String("gateway", "", "remote proxy address")
	password := flag.String("password", "", "password")
	flag.Parse()

	gateway := proxy.ParseEndpoint(*gatewayStr)

	var seed *[64]byte
	if len(*password) > 0 {
		seedArray := sha512.Sum512([]byte(*password))
		seed = &seedArray
	}
	if err := start(*local, gateway, seed); err != nil {
		log.Fatalln(err)
	}
}

func start(local string, gateway *proxy.Endpoint, seed *[64]byte) (err error) {
	ln, err := net.Listen("tcp", local)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Println("start listening ...")
	log.Println("local addr\t:", ln.Addr())
	if gateway != nil {
		log.Println("gateway\t:", gateway)
	}

	for {
		conn, e := ln.Accept()
		if e != nil {
			log.Println(e)
			continue
		}
		src := conn.(io.ReadWriteCloser)
		if seed != nil {
			src = proxy.NewEncrypter(conn, seed)
		}
		go proxy.Connect(src, gateway)
	}
}
