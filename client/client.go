package main

import (
	"crypto/sha512"
	"flag"
	"io"
	"log"
	"net"
	"time"

	proxy "github.com/loye/go-qproxy"
)

func main() {
	local := flag.String("local", ":2080", "proxy listen address")
	remote := flag.String("remote", "127.0.0.1:1443", "remote proxy address")
	password := flag.String("password", "12345678", "password")
	flag.Parse()
	encryptionSeed := sha512.Sum512([]byte(*password))
	log.Println("Start listening...")
	log.Println("address      :", *local)
	log.Println("remote proxy :", *remote)
	log.Println("password     :", *password)

	err := listen(*local, *remote, &encryptionSeed)
	if err != nil {
		log.Fatalln(err)
	}
}

func listen(localAddr string, remoteAddr string, seed *[64]byte) error {
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		rw, e := ln.Accept()
		if e != nil {
			log.Println("accept local connection failed:", e)
			continue
		}
		go forward(rw, remoteAddr, seed)
	}
}

func forward(rw io.ReadWriteCloser, remoteAddr string, seed *[64]byte) {
	defer rw.Close()
	conn, err := net.DialTimeout("tcp", remoteAddr, time.Second*10)
	if err != nil {
		log.Println("dial to remote failed:", err)
		return
	}
	enc := proxy.NewEncrypter(conn, seed)
	defer enc.Close()

	// relay
	go func() {
		defer enc.Close()
		defer rw.Close()
		io.CopyBuffer(rw, enc, make([]byte, 8*1024))
	}()
	io.CopyBuffer(enc, rw, make([]byte, 1024))
}
