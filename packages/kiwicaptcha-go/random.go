package kiwicaptcha

import "crypto/rand"

// randomRead fills the buffer from the system entropy source.
func randomRead(buf []byte) (int, error) {
	return rand.Read(buf)
}
