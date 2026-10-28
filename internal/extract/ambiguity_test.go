package extract

import (
	"fmt"
	"strings"
	"testing"
)

func TestAmbiguousProtocolFieldsRejected(t *testing.T) {
	cases := []struct{ protocol, body string }{
		{"openai_responses", `{"input":"benign","input":[{"role":"user","content":[{"type":"input_text","text":"BLOCKME"}]}]}`},
		{"openai_responses", `{"input":[{"role":"user","content":"benign"}],"input":"BLOCKME"}`},
		{"openai_responses", `{"input":"benign","input":"BLOCKME"}`},
		{"openai_responses", `{"input":"benign","input":null}`},
		{"openai_responses", `{"input":"benign","input":[]}`},
		{"openai_responses", `{"input":"benign","input":""}`},
		{"openai_responses", `{"input":"benign","\u0049NPUT":"BLOCKME"}`},
		{"openai_chat", `{"messages":[{"role":"user","content":"benign"}],"message\u017F":[{"role":"user","content":"BLOCKME"}]}`},
		{"openai_chat", `{"messages":[{"role":"user","content":"benign","content":[{"type":"text","text":"BLOCKME"}]}]}`},
		{"openai_chat", `{"messages":[{"role":"user","Role":"assistant","content":"BLOCKME"}]}`},
		{"openai_chat", `{"messages":[{"role":"user","content":[{"type":"text","text":"benign","TEXT":"BLOCKME"}]}]}`},
		{"gemini", `{"contents":[{"role":"user","parts":[{"text":"benign","text":"BLOCKME"}]}]}`},
		{"openai_completions", `{"prompt":"benign","prompt":["BLOCKME"]}`},
		{"embeddings", `{"input":"benign","input":["BLOCKME"]}`},
		{"rerank", `{"query":"benign","documents":["x"],"documents":["BLOCKME"]}`},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			s := ex(t, tc.protocol, tc.body)
			if s.Coverage != Unsupported || s.Reason != "DUPLICATE_KEY" || s.Text() != "" {
				t.Fatalf("ambiguous input selected: %+v", s)
			}
		})
	}
}

func TestUnicodeProtocolFieldMatchesGoDecoder(t *testing.T) {
	s := ex(t, "openai_chat", `{"message\u017F":[{"role":"user","content":"BLOCKME"}]}`)
	if s.Primary != "BLOCKME" || s.Coverage == Unsupported {
		t.Fatalf("Unicode field alias ignored: %+v", s)
	}
}

func TestDuplicateTrackingIsLocalAndBounded(t *testing.T) {
	var body strings.Builder
	body.WriteString(`{"metadata":{`)
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&body, `"field%d":0,`, i)
	}
	// Unknown metadata keys do not accumulate in duplicate tracking or alias protocol fields.
	body.WriteString(`"input|prompt":1,"input":2,"x":0,"x":1},"messages":[{"role":"assistant","content":"a"},{"role":"user","content":[{"type":"text","text":"first"},{"type":"text","text":"second"}]}]}`)
	s := ex(t, "openai_chat", body.String())
	if s.Coverage == Unsupported || s.Primary != "first\nsecond" {
		t.Fatalf("separate objects rejected: %+v", s)
	}
}
