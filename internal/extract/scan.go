package extract

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// PathElem is one step from the document root: an object key or an array index.
type PathElem struct {
	Key   string
	Index int
	IsIdx bool
}

// visitor receives string values and container ends. StringStart returns where to write the
// decoded bytes of that string, or nil to discard them; memory therefore stays bounded by what
// visitors choose to keep, never by the size of the document.
type visitor interface {
	StringStart(path []PathElem) *Capture
	End(path []PathElem)
}

const (
	maxDepth  = 128
	maxKeyLen = 256
)

var errSyntax = errors.New("invalid JSON")
var errDuplicateKey = errors.New("duplicate protocol field")

// A fixed bitset rejects ambiguous protocol fields without retaining arbitrary client keys.
// Decode escapes and fold case before checking, just as when building the extraction path.
var protocolFieldBits = func() map[string]uint64 {
	fields := strings.Fields("model messages contents input prompt suffix instruction instructions system systeminstruction system_instruction role content parts text type output query documents image_url input_audio file image source inlinedata inline_data filedata file_data audio file_id functionresponse function_response")
	bits := make(map[string]uint64, len(fields))
	for i, field := range fields {
		bits[field] = uint64(1) << i
	}
	return bits
}()

// foldKey matches encoding/json's Unicode simple folding, then lowers the representative so
// ASCII protocol paths remain readable. ToLower alone misses aliases such as long s (U+017F).
func foldKey(key string) string {
	return strings.Map(func(r rune) rune {
		if r < utf8.RuneSelf {
			return unicode.ToLower(r)
		}
		for {
			next := unicode.SimpleFold(r)
			if next <= r {
				return unicode.ToLower(next)
			}
			r = next
		}
	}, key)
}

// scan walks one JSON value from r, folding keys like New API's Go decoder.
func scan(r io.Reader, v visitor) error {
	s := &scanner{r: bufio.NewReaderSize(r, 64<<10), v: v}
	s.skipWS()
	if err := s.value(); err != nil {
		return err
	}
	s.skipWS()
	if _, err := s.r.ReadByte(); err != io.EOF {
		return fmt.Errorf("%w: trailing data", errSyntax)
	}
	return nil
}

type scanner struct {
	r    *bufio.Reader
	v    visitor
	path []PathElem
	err  error
}

func (s *scanner) next() byte {
	b, err := s.r.ReadByte()
	if err != nil {
		if s.err == nil {
			if err == io.EOF {
				err = fmt.Errorf("%w: unexpected end", errSyntax)
			}
			s.err = err
		}
		return 0
	}
	return b
}

func (s *scanner) peek() byte {
	b, err := s.r.Peek(1)
	if err != nil {
		return 0
	}
	return b[0]
}

func (s *scanner) skipWS() {
	for {
		switch s.peek() {
		case ' ', '\t', '\n', '\r':
			s.r.ReadByte()
		default:
			return
		}
	}
}

func (s *scanner) value() error {
	if len(s.path) > maxDepth {
		return fmt.Errorf("%w: nesting deeper than %d", errSyntax, maxDepth)
	}
	switch c := s.peek(); {
	case c == '{':
		s.next()
		return s.object()
	case c == '[':
		s.next()
		return s.array()
	case c == '"':
		s.next()
		return s.str(s.v.StringStart(s.path))
	case c == '-' || (c >= '0' && c <= '9'):
		return s.number()
	case c == 't':
		return s.literal("true")
	case c == 'f':
		return s.literal("false")
	case c == 'n':
		return s.literal("null")
	default:
		if s.err != nil {
			return s.err
		}
		return fmt.Errorf("%w: unexpected %q", errSyntax, c)
	}
}

func (s *scanner) object() error {
	var seen uint64
	s.skipWS()
	if s.peek() == '}' {
		s.next()
		s.v.End(s.path)
		return nil
	}
	for {
		s.skipWS()
		if s.next() != '"' {
			return s.fail("expected object key")
		}
		key := &Capture{Head: maxKeyLen}
		if err := s.str(key); err != nil {
			return err
		}
		if key.Truncated() {
			return s.fail("object key too long")
		}
		name := foldKey(key.String())
		bit := protocolFieldBits[name]
		if seen&bit != 0 {
			return errDuplicateKey
		}
		seen |= bit
		s.skipWS()
		if s.next() != ':' {
			return s.fail("expected ':'")
		}
		s.skipWS()
		s.path = append(s.path, PathElem{Key: name})
		if err := s.value(); err != nil {
			return err
		}
		s.path = s.path[:len(s.path)-1]
		s.skipWS()
		switch s.next() {
		case ',':
		case '}':
			s.v.End(s.path)
			return nil
		default:
			return s.fail("expected ',' or '}'")
		}
	}
}

func (s *scanner) array() error {
	s.skipWS()
	if s.peek() == ']' {
		s.next()
		s.v.End(s.path)
		return nil
	}
	for i := 0; ; i++ {
		s.skipWS()
		s.path = append(s.path, PathElem{Index: i, IsIdx: true})
		if err := s.value(); err != nil {
			return err
		}
		s.path = s.path[:len(s.path)-1]
		s.skipWS()
		switch s.next() {
		case ',':
		case ']':
			s.v.End(s.path)
			return nil
		default:
			return s.fail("expected ',' or ']'")
		}
	}
}

// str decodes a string body (opening quote already consumed) into c (nil discards).
func (s *scanner) str(c *Capture) error {
	var buf [utf8.UTFMax]byte
	for {
		b := s.next()
		if s.err != nil {
			return s.err
		}
		switch {
		case b == '"':
			return nil
		case b < 0x20:
			return s.fail("control character in string")
		case b != '\\':
			c.AddByte(b)
			continue
		}
		switch e := s.next(); e {
		case '"', '\\', '/':
			c.AddByte(e)
		case 'b':
			c.AddByte('\b')
		case 'f':
			c.AddByte('\f')
		case 'n':
			c.AddByte('\n')
		case 'r':
			c.AddByte('\r')
		case 't':
			c.AddByte('\t')
		case 'u':
			r, err := s.hex4()
			if err != nil {
				return err
			}
			if utf16.IsSurrogate(r) {
				// A high surrogate must be followed by \uDC00–\uDFFF; anything else decodes to U+FFFD,
				// as encoding/json does.
				if s.peek() == '\\' {
					s.next()
					if s.next() != 'u' {
						return s.fail("bad escape")
					}
					r2, err := s.hex4()
					if err != nil {
						return err
					}
					if dec := utf16.DecodeRune(r, r2); dec != utf8.RuneError {
						r = dec
					} else {
						n := utf8.EncodeRune(buf[:], utf8.RuneError)
						c.Add(buf[:n])
						r = r2
						if utf16.IsSurrogate(r) {
							r = utf8.RuneError
						}
					}
				} else {
					r = utf8.RuneError
				}
			}
			n := utf8.EncodeRune(buf[:], r)
			c.Add(buf[:n])
		default:
			return s.fail("bad escape")
		}
	}
}

func (s *scanner) hex4() (rune, error) {
	var r rune
	for i := 0; i < 4; i++ {
		b := s.next()
		switch {
		case b >= '0' && b <= '9':
			r = r<<4 | rune(b-'0')
		case b >= 'a' && b <= 'f':
			r = r<<4 | rune(b-'a'+10)
		case b >= 'A' && b <= 'F':
			r = r<<4 | rune(b-'A'+10)
		default:
			return 0, s.fail("bad \\u escape")
		}
	}
	return r, nil
}

func (s *scanner) number() error {
	n := 0
	for {
		switch c := s.peek(); {
		case c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E' || (c >= '0' && c <= '9'):
			s.next()
			n++
			if n > 64 {
				return s.fail("number too long")
			}
		default:
			return nil
		}
	}
}

func (s *scanner) literal(lit string) error {
	for i := 0; i < len(lit); i++ {
		if s.next() != lit[i] {
			return s.fail("bad literal")
		}
	}
	return nil
}

func (s *scanner) fail(msg string) error {
	if s.err != nil {
		return s.err
	}
	return fmt.Errorf("%w: %s", errSyntax, msg)
}
