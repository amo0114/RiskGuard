package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"
)

// canFakeReply lists protocols whose clients expect generated text, so a block reply can look
// like a normal answer. Media generation, moderation, tool and vector endpoints keep the errors:
// a text "answer" there would break the client or hide the rejection.
func canFakeReply(protocol string) bool {
	switch protocol {
	case "openai_chat", "claude_messages", "openai_responses", "gemini", "openai_completions", "openai_edits":
		return true
	}
	return false
}

// replyBag deals reply indexes in shuffled rounds: no reply repeats within a round, and a round
// never opens with the reply that closed the previous one.
type replyBag struct {
	mu    sync.Mutex
	order []int
	prev  int // last dealt index + 1; 0 before the first deal
}

func (b *replyBag) next(n int) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.order) == 0 {
		b.order = rand.Perm(n)
		if n > 1 && b.order[0] == b.prev-1 {
			b.order[0], b.order[1] = b.order[1], b.order[0]
		}
	}
	v := b.order[0]
	b.order, b.prev = b.order[1:], v+1
	return v
}

// writeBlockReply answers a content rejection as a normal 200 answer whose text is the configured
// block reply, so clients display it instead of an error; streaming requests get the protocol's
// own event stream, one line per chunk. protocol must pass canFakeReply; false means nothing was
// written. X-Risk-Code still marks the response.
func writeBlockReply(r *http.Request, w http.ResponseWriter, protocol string, body io.Reader, text, code, trace string) bool {
	var req struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if json.NewDecoder(body).Decode(&req) != nil {
		return false
	}
	stream := req.Stream
	if protocol == "gemini" {
		// Gemini carries model and streaming in the path: /v1beta/models/{model}:streamGenerateContent
		req.Model = modelOf("", r.URL.Path)
		stream = strings.Contains(r.URL.Path, ":streamGenerateContent")
	}
	sse := stream && (protocol != "gemini" || r.URL.Query().Get("alt") == "sse")
	w.Header().Set("X-Risk-Code", code)
	if sse {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(http.StatusOK)

	ctx, created := r.Context(), time.Now().Unix()
	switch protocol {
	case "openai_chat":
		id := "chatcmpl-" + trace
		if !stream {
			writeJSON(w, map[string]any{
				"id": id, "object": "chat.completion", "created": created, "model": req.Model,
				"choices": []any{map[string]any{"index": 0, "finish_reason": "stop",
					"message": map[string]any{"role": "assistant", "content": text}}},
				"usage": map[string]int{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
			})
			return true
		}
		chunk := func(delta map[string]any, finish any) map[string]any {
			return map[string]any{"id": id, "object": "chat.completion.chunk", "created": created, "model": req.Model,
				"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}}}
		}
		writeSSE(w, "", chunk(map[string]any{"role": "assistant", "content": ""}, nil))
		streamLines(ctx, w, text, func(line string) { writeSSE(w, "", chunk(map[string]any{"content": line}, nil)) })
		writeSSE(w, "", chunk(map[string]any{}, "stop"))
		fmt.Fprint(w, "data: [DONE]\n\n")

	case "claude_messages":
		id, usage := "msg_"+trace, map[string]int{"input_tokens": 0, "output_tokens": 0}
		if !stream {
			writeJSON(w, map[string]any{
				"id": id, "type": "message", "role": "assistant", "model": req.Model,
				"content":     []any{map[string]any{"type": "text", "text": text}},
				"stop_reason": "end_turn", "stop_sequence": nil, "usage": usage,
			})
			return true
		}
		writeSSE(w, "message_start", map[string]any{"type": "message_start", "message": map[string]any{
			"id": id, "type": "message", "role": "assistant", "model": req.Model, "content": []any{},
			"stop_reason": nil, "stop_sequence": nil, "usage": usage}})
		writeSSE(w, "content_block_start", map[string]any{"type": "content_block_start", "index": 0,
			"content_block": map[string]any{"type": "text", "text": ""}})
		streamLines(ctx, w, text, func(line string) {
			writeSSE(w, "content_block_delta", map[string]any{"type": "content_block_delta", "index": 0,
				"delta": map[string]any{"type": "text_delta", "text": line}})
		})
		writeSSE(w, "content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
		writeSSE(w, "message_delta", map[string]any{"type": "message_delta",
			"delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil}, "usage": map[string]int{"output_tokens": 0}})
		writeSSE(w, "message_stop", map[string]any{"type": "message_stop"})

	case "openai_responses":
		writeResponses(ctx, w, stream, req.Model, text, trace, created)

	case "gemini":
		chunk := func(t string, finish bool) map[string]any {
			c := map[string]any{"index": 0, "content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": t}}}}
			if finish {
				c["finishReason"] = "STOP"
			}
			return map[string]any{"candidates": []any{c}, "modelVersion": req.Model,
				"usageMetadata": map[string]int{"promptTokenCount": 0, "candidatesTokenCount": 0, "totalTokenCount": 0}}
		}
		switch {
		case !stream:
			writeJSON(w, chunk(text, true))
		case sse:
			streamLines(ctx, w, text, func(line string) { writeSSE(w, "", chunk(line, false)) })
			writeSSE(w, "", chunk("", true))
		default: // streamGenerateContent without alt=sse is one JSON array, written element by element
			fmt.Fprint(w, "[")
			first := true
			streamLines(ctx, w, text, func(line string) {
				if !first {
					fmt.Fprint(w, ",\n")
				}
				first = false
				b, _ := json.Marshal(chunk(line, false))
				w.Write(b)
			})
			fmt.Fprint(w, ",\n")
			b, _ := json.Marshal(chunk("", true))
			w.Write(b)
			fmt.Fprint(w, "]")
		}

	case "openai_completions":
		id := "cmpl-" + trace
		choice := func(t string, finish any) map[string]any {
			return map[string]any{"text": t, "index": 0, "logprobs": nil, "finish_reason": finish}
		}
		if !stream {
			writeJSON(w, map[string]any{"id": id, "object": "text_completion", "created": created, "model": req.Model,
				"choices": []any{choice(text, "stop")},
				"usage":   map[string]int{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}})
			return true
		}
		chunk := func(t string, finish any) map[string]any {
			return map[string]any{"id": id, "object": "text_completion", "created": created, "model": req.Model,
				"choices": []any{choice(t, finish)}}
		}
		streamLines(ctx, w, text, func(line string) { writeSSE(w, "", chunk(line, nil)) })
		writeSSE(w, "", chunk("", "stop"))
		fmt.Fprint(w, "data: [DONE]\n\n")

	case "openai_edits": // legacy, never streamed
		writeJSON(w, map[string]any{"object": "edit", "created": created,
			"choices": []any{map[string]any{"text": text, "index": 0}},
			"usage":   map[string]int{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}})
	}
	return true
}

// writeResponses is the OpenAI Responses shape (Codex): one assistant message with one
// output_text part. The stream follows the event order clients wait for, ending in
// response.completed.
func writeResponses(ctx context.Context, w http.ResponseWriter, stream bool, model, text, trace string, created int64) {
	respID, msgID := "resp_"+trace, "msg_"+trace
	part := func(t string) map[string]any {
		return map[string]any{"type": "output_text", "text": t, "annotations": []any{}}
	}
	item := func(status string, content []any) map[string]any {
		return map[string]any{"type": "message", "id": msgID, "status": status, "role": "assistant", "content": content}
	}
	response := func(status string, output []any) map[string]any {
		r := map[string]any{"id": respID, "object": "response", "created_at": created, "status": status,
			"model": model, "output": output}
		if status == "completed" {
			r["usage"] = map[string]int{"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
		}
		return r
	}
	done := item("completed", []any{part(text)})
	if !stream {
		writeJSON(w, response("completed", []any{done}))
		return
	}
	seq := 0
	event := func(typ string, fields map[string]any) {
		fields["type"], fields["sequence_number"] = typ, seq
		seq++
		writeSSE(w, typ, fields)
	}
	at := func(m map[string]any) map[string]any {
		m["item_id"], m["output_index"], m["content_index"] = msgID, 0, 0
		return m
	}
	event("response.created", map[string]any{"response": response("in_progress", []any{})})
	event("response.in_progress", map[string]any{"response": response("in_progress", []any{})})
	event("response.output_item.added", map[string]any{"output_index": 0, "item": item("in_progress", []any{})})
	event("response.content_part.added", at(map[string]any{"part": part("")}))
	streamLines(ctx, w, text, func(line string) { event("response.output_text.delta", at(map[string]any{"delta": line})) })
	event("response.output_text.done", at(map[string]any{"text": text}))
	event("response.content_part.done", at(map[string]any{"part": part(text)}))
	event("response.output_item.done", map[string]any{"output_index": 0, "item": done})
	event("response.completed", map[string]any{"response": response("completed", []any{done})})
}

func writeJSON(w io.Writer, v any) { _ = json.NewEncoder(w).Encode(v) }

// replyLineDelay paces a streamed block reply one line at a time, so chat clients draw the art
// the way they draw model output instead of showing it in one jump (~1s for a 20-line image).
var replyLineDelay = 50 * time.Millisecond

// streamLines emits text line by line (newlines kept), flushing each one. A client that goes
// away stops the pacing; the caller still writes the closing events, which then just fail.
func streamLines(ctx context.Context, w http.ResponseWriter, text string, emit func(string)) {
	rc := http.NewResponseController(w)
	_ = rc.Flush()
	for i, line := range strings.SplitAfter(text, "\n") {
		if line == "" {
			continue
		}
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(replyLineDelay):
			}
		}
		emit(line)
		_ = rc.Flush()
	}
}

func writeSSE(w io.Writer, event string, v any) {
	b, _ := json.Marshal(v)
	if event != "" {
		fmt.Fprintf(w, "event: %s\n", event)
	}
	fmt.Fprintf(w, "data: %s\n\n", b)
}
