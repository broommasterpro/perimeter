package mux

import (
	"bytes"
	"testing"
)

func FuzzFrameDecoder(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 1, 0, 0, 0, 1, 'a'})
	f.Add([]byte{2, 0, 0, 0, 1, 255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		frame, err := ReadFrame(bytes.NewReader(data))
		if err != nil {
			return
		}
		if len(frame.Payload) > MaxPayload {
			t.Fatal("oversized allocation")
		}
		var encoded bytes.Buffer
		if err := WriteFrame(&encoded, frame); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded.Bytes(), data[:encoded.Len()]) {
			t.Fatal("roundtrip mismatch")
		}
	})
}
