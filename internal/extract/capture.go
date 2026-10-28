package extract

import (
	"unicode/utf8"
)

// Capture keeps at most Head leading and Tail trailing bytes of everything written to it, so an
// instruction placed at the end of a huge message is still seen. A nil *Capture discards writes.
type Capture struct {
	Head, Tail int
	head       []byte
	ring       []byte
	ringPos    int
	total      int64
}

func (c *Capture) AddByte(b byte) {
	if c == nil {
		return
	}
	c.total++
	if len(c.head) < c.Head {
		c.head = append(c.head, b)
		return
	}
	if c.Tail <= 0 {
		return
	}
	if len(c.ring) < c.Tail {
		c.ring = append(c.ring, b)
		return
	}
	c.ring[c.ringPos] = b
	c.ringPos = (c.ringPos + 1) % c.Tail
}

func (c *Capture) Add(p []byte) {
	for _, b := range p {
		c.AddByte(b)
	}
}

// Truncated reports whether bytes were dropped between head and tail.
func (c *Capture) Truncated() bool {
	return c != nil && c.total > int64(len(c.head)+len(c.ring))
}

func (c *Capture) Len() int64 {
	if c == nil {
		return 0
	}
	return c.total
}

// String returns head [+ marker + tail], cut on rune boundaries.
func (c *Capture) String() string {
	if c == nil {
		return ""
	}
	if !c.Truncated() {
		return string(c.head) + string(c.ordered())
	}
	return trimTail(c.head) + "\n[...]\n" + trimHead(c.ordered())
}

func (c *Capture) ordered() []byte {
	if len(c.ring) < c.Tail {
		return c.ring
	}
	out := make([]byte, 0, len(c.ring))
	out = append(out, c.ring[c.ringPos:]...)
	return append(out, c.ring[:c.ringPos]...)
}

// trimTail drops an incomplete UTF-8 sequence at the end of b.
func trimTail(b []byte) string {
	for i := 0; i < utf8.UTFMax && len(b) > 0; i++ {
		if utf8.Valid(b) {
			break
		}
		b = b[:len(b)-1]
	}
	return string(b)
}

// trimHead drops continuation bytes at the start of b.
func trimHead(b []byte) string {
	for i := 0; i < utf8.UTFMax && len(b) > 0 && !utf8.RuneStart(b[0]); i++ {
		b = b[1:]
	}
	return string(b)
}
