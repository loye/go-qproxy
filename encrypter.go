package proxy

import "io"

// Encrypter for Write with decrypt and Read with encrypt
type Encrypter struct {
	rw          io.ReadWriteCloser
	seed        *[64]byte
	readOffset  int
	writeOffset int
}

// NewEncrypter used to create new instance of Encrypter
func NewEncrypter(rw io.ReadWriteCloser, seed *[64]byte) *Encrypter {
	return &Encrypter{rw, seed, 0, 0}
}

// decrypt
func (enc *Encrypter) Read(p []byte) (n int, err error) {
	n, err = enc.rw.Read(p)
	if n > 0 {
		offset := enc.readOffset
		seed := *&enc.seed
		var step byte
		for i, l, os := 0, len(p), offset&63; i < l; i, os = i+1, os+1 {
			if os&8 == 0 {
				step = byte(os&7 - 8)
			} else {
				step = byte(os&7 + 1)
			}
			p[i] = (^p[i] - step*seed[os&63]) & 255
		}
		enc.readOffset += n
	}
	return
}

// encrypt
func (enc *Encrypter) Write(p []byte) (n int, err error) {
	offset := enc.writeOffset
	seed := *&enc.seed
	var step byte
	for i, l, os := 0, len(p), offset&63; i < l; i, os = i+1, os+1 {
		if os&8 == 0 {
			step = byte(os&7 - 8)
		} else {
			step = byte(os&7 + 1)
		}
		p[i] = ^((p[i] + step*seed[os&63]) & 255)
	}
	n, err = enc.rw.Write(p)
	enc.writeOffset += n
	return
}

// Close the rw
func (enc *Encrypter) Close() error {
	return enc.rw.Close()
}
