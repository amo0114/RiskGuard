// Package extract selects, with bounded memory, the parts of a model request that the content
// classifier looks at: the latest user turn (primary) plus system/instructions (context). Tool
// results, earlier turns and media are never sent; their presence makes coverage partial.
package extract

import (
	"compress/gzip"
	"errors"
	"io"
	"strings"
)

type Coverage string

const (
	FullSelected Coverage = "full_selected_inputs"
	Partial      Coverage = "partial_context"
	Unsupported  Coverage = "unsupported"
)

type Budget struct {
	Primary int // bytes of the latest user turn (head + tail)
	// Context is the head of system/instructions sent along. W05: agent system prompts ("You are
	// Claude Code...") alone make Qwen3Guard answer Controversial/Jailbreak, so the default is 0
	// and their presence is recorded as SYSTEM_NOT_INSPECTED instead.
	Context int
}

type Selection struct {
	Primary        string
	Context        string
	Coverage       Coverage
	Reason         string // set when Coverage is Unsupported or Partial
	InspectedChars int
	UserTurns      int
	HasMedia       bool
	HasToolResults bool
	HasSystem      bool // system/instructions present but not (fully) selected
	Truncated      bool // any selected text was cut to its budget
	// PrimaryTruncated: the latest user text itself was cut. Truncated alone cannot tell, since
	// the system context budget can also truncate.
	PrimaryTruncated bool
	Model            string // top-level "model" (first 64 bytes), for audit grouping only
}

// Text is what the classifier receives.
func (s Selection) Text() string {
	if s.Context == "" {
		return s.Primary
	}
	if s.Primary == "" {
		return s.Context
	}
	return s.Context + "\n\n" + s.Primary
}

var ErrUnsupportedEncoding = errors.New("unsupported content encoding")

// Extract parses body for protocol. contentEncoding is the request Content-Encoding header;
// gzip is decoded (bounded by maxDecoded), anything else other than identity is unsupported.
func Extract(protocol, contentType, contentEncoding string, body io.Reader, b Budget, maxDecoded int64) Selection {
	if ct := strings.ToLower(contentType); ct != "" && !strings.Contains(ct, "json") {
		return Selection{Coverage: Unsupported, Reason: "NON_JSON_BODY"}
	}
	switch strings.ToLower(strings.TrimSpace(contentEncoding)) {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(body)
		if err != nil {
			return Selection{Coverage: Unsupported, Reason: "BAD_ENCODING"}
		}
		defer zr.Close()
		body = &capped{r: zr, left: maxDecoded}
	default:
		return Selection{Coverage: Unsupported, Reason: "UNSUPPORTED_ENCODING"}
	}

	v := newTurns(protocol, b)
	if v == nil {
		return Selection{Coverage: Unsupported, Reason: "UNKNOWN_PROTOCOL"}
	}
	if err := scan(body, v); err != nil {
		if errors.Is(err, errDuplicateKey) {
			return Selection{Coverage: Unsupported, Reason: "DUPLICATE_KEY"}
		}
		if errors.Is(err, errDecodedTooLarge) {
			return Selection{Coverage: Unsupported, Reason: "DECODED_TOO_LARGE"}
		}
		return Selection{Coverage: Unsupported, Reason: "PARSE_FAILED"}
	}
	return v.selection()
}

var errDecodedTooLarge = errors.New("decoded body too large")

type capped struct {
	r    io.Reader
	left int64
}

func (c *capped) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, errDecodedTooLarge
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

type kind int

const (
	kIgnore kind = iota
	kRole
	kText       // user/system/assistant text of the current turn (role decides)
	kPartType   // type of a content part / input item
	kMedia      // any string under an image/audio/file part
	kTool       // tool output text (not selected)
	kSystem     // top-level system/instructions text
	kDirectUser // top-level prompt/input that is itself the user turn
)

// layout maps a path to a kind for one protocol. turnDepth is the depth of a turn object
// (e.g. messages[i] is depth 2).
type layout struct {
	turnList  string
	turnDepth int
	classify  func(p []PathElem) kind
	// mediaGap: a request carrying only media (no text) is a coverage gap, not "no input".
	mediaGap bool
}

func key(p []PathElem, i int) string {
	if i < len(p) && !p[i].IsIdx {
		return p[i].Key
	}
	return ""
}

func idx(p []PathElem, i int) bool { return i < len(p) && p[i].IsIdx }

var mediaKeys = map[string]bool{
	"image_url": true, "input_audio": true, "file": true, "image": true, "source": true,
	"inlinedata": true, "inline_data": true, "filedata": true, "file_data": true, "audio": true,
}

var mediaTypes = map[string]bool{
	"image_url": true, "input_audio": true, "file": true, "image": true, "input_image": true,
	"input_file": true, "document": true, "audio": true,
}

var toolTypes = map[string]bool{
	"tool_result": true, "function_call_output": true, "custom_tool_call_output": true,
	"mcp_tool_result": true, "web_search_tool_result": true,
}

// messagesLayout covers OpenAI chat (incl. /pg) and Claude messages:
// messages[i].{role,content}, content as string or parts[j].{type,text,...}.
func messagesLayout(withSystem bool) layout {
	return layout{turnList: "messages", turnDepth: 2, classify: func(p []PathElem) kind {
		if withSystem && key(p, 0) == "system" {
			if len(p) == 1 || (idx(p, 1) && key(p, 2) == "text" && len(p) == 3) {
				return kSystem
			}
			return kIgnore
		}
		if key(p, 0) != "messages" || !idx(p, 1) {
			return kIgnore
		}
		switch {
		case len(p) == 3 && key(p, 2) == "role":
			return kRole
		case len(p) == 3 && key(p, 2) == "content":
			return kText
		case len(p) == 5 && key(p, 2) == "content" && idx(p, 3) && key(p, 4) == "text":
			return kText
		case len(p) == 5 && key(p, 2) == "content" && idx(p, 3) && key(p, 4) == "type":
			return kPartType
		case len(p) >= 5 && key(p, 2) == "content" && idx(p, 3) && mediaKeys[key(p, 4)]:
			return kMedia
		case len(p) >= 5 && key(p, 2) == "content" && idx(p, 3) && key(p, 4) == "content":
			return kTool // Claude tool_result body
		}
		return kIgnore
	}}
}

// responsesLayout: instructions; input as string or items[i].{role,type,content,output}.
var responsesLayout = layout{turnList: "input", turnDepth: 2, classify: func(p []PathElem) kind {
	switch {
	case len(p) == 1 && key(p, 0) == "instructions":
		return kSystem
	case len(p) == 1 && key(p, 0) == "input":
		return kDirectUser
	case key(p, 0) != "input" || !idx(p, 1):
		return kIgnore
	case len(p) == 3 && key(p, 2) == "role":
		return kRole
	case len(p) == 3 && key(p, 2) == "type":
		return kPartType
	case len(p) == 3 && key(p, 2) == "content":
		return kText
	case len(p) == 3 && key(p, 2) == "output":
		return kTool
	case len(p) == 5 && key(p, 2) == "content" && idx(p, 3) && key(p, 4) == "text":
		return kText
	case len(p) == 5 && key(p, 2) == "content" && idx(p, 3) && key(p, 4) == "type":
		return kPartType
	case len(p) >= 5 && key(p, 2) == "content" && idx(p, 3) && (mediaKeys[key(p, 4)] || key(p, 4) == "file_id"):
		return kMedia
	}
	return kIgnore
}}

// geminiLayout: contents[i].{role,parts[j].text|inlineData|functionResponse}, systemInstruction.
var geminiLayout = layout{turnList: "contents", turnDepth: 2, classify: func(p []PathElem) kind {
	if k := key(p, 0); k == "systeminstruction" || k == "system_instruction" {
		if len(p) == 4 && key(p, 1) == "parts" && idx(p, 2) && key(p, 3) == "text" {
			return kSystem
		}
		return kIgnore
	}
	if key(p, 0) != "contents" || !idx(p, 1) {
		return kIgnore
	}
	switch {
	case len(p) == 3 && key(p, 2) == "role":
		return kRole
	case len(p) == 5 && key(p, 2) == "parts" && idx(p, 3) && key(p, 4) == "text":
		return kText
	case len(p) >= 5 && key(p, 2) == "parts" && idx(p, 3) && mediaKeys[key(p, 4)]:
		return kMedia
	case len(p) >= 5 && key(p, 2) == "parts" && idx(p, 3) && (key(p, 4) == "functionresponse" || key(p, 4) == "function_response"):
		return kTool
	}
	return kIgnore
}}

// directLayout: the listed top-level fields (string or array of strings) are one user turn.
func directLayout(fields ...string) layout {
	set := map[string]bool{}
	for _, f := range fields {
		set[f] = true
	}
	return layout{classify: func(p []PathElem) kind {
		if len(p) == 0 || !set[key(p, 0)] {
			return kIgnore
		}
		if len(p) == 1 || (len(p) == 2 && idx(p, 1)) || (len(p) == 3 && idx(p, 1) && key(p, 2) == "text") {
			return kDirectUser
		}
		return kIgnore
	}}
}

// anyStringLayout: request schemas we do not model field-by-field (search/fetch tools); every
// string leaf is treated as user input.
// promptLayout covers media generation requests (images, speech, video, Midjourney, Suno): the
// text prompt is reviewed; reference images, masks or audio are not.
var promptFields = map[string]bool{"prompt": true, "input": true, "gpt_description_prompt": true, "negative_prompt": true}

var generationMediaKeys = map[string]bool{
	"image": true, "images": true, "image_url": true, "base64": true, "base64array": true, "mask": true,
	"input_reference": true, "init_image": true, "image_tail": true, "first_frame_image": true,
	"last_frame_image": true, "reference_images": true, "file": true, "video": true, "audio": true,
}

var promptLayout = layout{mediaGap: true, classify: func(p []PathElem) kind {
	switch k := key(p, 0); {
	case promptFields[k] && (len(p) == 1 || (len(p) == 2 && idx(p, 1))):
		return kDirectUser
	case generationMediaKeys[k]:
		return kMedia
	}
	return kIgnore
}}

var anyStringLayout = layout{classify: func(p []PathElem) kind {
	if len(p) > 0 && (key(p, 0) == "model" || key(p, len(p)-1) == "model") {
		return kIgnore
	}
	return kDirectUser
}}

func layoutFor(protocol string) (layout, bool) {
	switch protocol {
	case "openai_chat":
		return messagesLayout(false), true
	case "claude_messages":
		return messagesLayout(true), true
	case "openai_responses":
		return responsesLayout, true
	case "gemini":
		return geminiLayout, true
	case "openai_completions":
		return directLayout("prompt", "suffix"), true
	case "embeddings", "moderations":
		return directLayout("input"), true
	case "rerank":
		return directLayout("query", "documents"), true
	case "openai_edits":
		return directLayout("instruction", "input"), true
	case "tool_special":
		return anyStringLayout, true
	case "image_generation", "audio_speech", "video_generation", "midjourney", "suno":
		return promptLayout, true
	}
	return layout{}, false
}

// turns accumulates the current turn and keeps the latest user turn.
type turns struct {
	l layout
	b Budget

	role, partType *Capture
	text           *Capture // current turn text
	turnMedia      bool
	turnTool       bool
	turnHasItem    bool

	lastUser   *Capture
	direct     *Capture
	system     *Capture
	model      *Capture
	userTurns  int
	media      bool
	toolOutput bool
}

func newTurns(protocol string, b Budget) *turns {
	l, ok := layoutFor(protocol)
	if !ok {
		return nil
	}
	t := &turns{l: l, b: b}
	t.resetTurn()
	return t
}

func (t *turns) newText() *Capture {
	return &Capture{Head: t.b.Primary / 2, Tail: t.b.Primary - t.b.Primary/2}
}

func (t *turns) resetTurn() {
	t.role = &Capture{Head: 32}
	t.partType = &Capture{Head: 64}
	t.text = t.newText()
	t.turnMedia, t.turnTool, t.turnHasItem = false, false, false
}

func (t *turns) StringStart(p []PathElem) *Capture {
	if len(p) == 1 && key(p, 0) == "model" {
		t.model = &Capture{Head: 64}
		return t.model
	}
	switch t.l.classify(p) {
	case kRole:
		t.role = &Capture{Head: 32}
		return t.role
	case kText:
		t.turnHasItem = true
		if t.text.Len() > 0 {
			t.text.AddByte('\n')
		}
		return t.text
	case kPartType:
		t.partType = &Capture{Head: 64}
		return t.partType
	case kMedia:
		t.turnMedia = true
		if t.l.turnList == "" {
			t.media = true // no turns to end: record it directly
		}
	case kTool:
		t.turnTool = true
	case kSystem:
		if t.system == nil {
			t.system = &Capture{Head: t.b.Context}
		} else if t.system.Len() > 0 {
			t.system.AddByte('\n')
		}
		return t.system
	case kDirectUser:
		if t.direct == nil {
			t.direct = t.newText()
		} else if t.direct.Len() > 0 {
			t.direct.AddByte('\n')
		}
		return t.direct
	}
	return nil
}

func (t *turns) End(p []PathElem) {
	if t.l.turnList == "" || len(p) < 1 || key(p, 0) != t.l.turnList {
		return
	}
	// end of a content part / item-level type: classify by its declared type
	if pt := strings.ToLower(t.partType.String()); pt != "" && (len(p) == t.l.turnDepth+2 || len(p) == t.l.turnDepth) {
		if mediaTypes[pt] {
			t.turnMedia = true
		}
		if toolTypes[pt] {
			t.turnTool = true
		}
		t.partType = &Capture{Head: 64}
	}
	if len(p) != t.l.turnDepth {
		return
	}
	role := strings.ToLower(strings.TrimSpace(t.role.String()))
	t.media = t.media || t.turnMedia
	t.toolOutput = t.toolOutput || t.turnTool
	switch {
	case role == "user" || (role == "" && t.l.turnList == "contents"):
		if t.turnHasItem && t.text.Len() > 0 {
			t.lastUser = t.text
			t.userTurns++
		}
	case role == "tool" || role == "function":
		t.toolOutput = true
	case role == "system" || role == "developer":
		if t.text.Len() > 0 {
			if t.system == nil {
				t.system = &Capture{Head: t.b.Context}
			} else {
				t.system.AddByte('\n')
			}
			t.system.Add([]byte(t.text.String()))
		}
	}
	t.resetTurn()
}

func (t *turns) selection() Selection {
	s := Selection{HasMedia: t.media, HasToolResults: t.toolOutput, UserTurns: t.userTurns}
	if t.model != nil && !t.model.Truncated() {
		s.Model = t.model.String()
	}
	user := t.lastUser
	if t.direct != nil && t.direct.Len() > 0 {
		user = t.direct // a top-level input string replaces item turns (Responses "input": "...")
		s.UserTurns++
	}
	if user != nil {
		s.Primary = user.String()
		s.Truncated = user.Truncated()
		s.PrimaryTruncated = s.Truncated
	}
	if t.system != nil && t.system.Len() > 0 {
		if t.b.Context == 0 {
			s.HasSystem = true
		} else {
			s.Context = t.system.String()
			s.Truncated = s.Truncated || t.system.Truncated()
		}
	}
	s.InspectedChars = len([]rune(s.Text()))
	switch {
	case s.Primary == "" && s.Context == "" && s.HasMedia && t.l.mediaGap:
		s.Coverage, s.Reason = Unsupported, "MEDIA_ONLY"
	case s.Primary == "" && s.Context == "":
		s.Coverage, s.Reason = Unsupported, "NO_INSPECTABLE_INPUT"
	case s.Primary == "":
		// only system text: the user's own request is not visible (e.g. only tool results)
		s.Coverage, s.Reason = Partial, "NO_USER_TEXT"
	case s.Truncated:
		s.Coverage, s.Reason = Partial, "TRUNCATED"
	case s.HasMedia:
		s.Coverage, s.Reason = Partial, "MEDIA_NOT_INSPECTED"
	case s.HasToolResults || s.UserTurns > 1:
		s.Coverage, s.Reason = Partial, "HISTORY_NOT_INSPECTED"
	case s.HasSystem:
		s.Coverage, s.Reason = Partial, "SYSTEM_NOT_INSPECTED"
	default:
		s.Coverage = FullSelected
	}
	return s
}
