// Package routes classifies an inbound request against the New API v1.0.0-rc.46 route table
// (docs/ops/01-port-and-route-map.md, G0 01-route-matrix.md R01–R30).
//
// Classification uses r.URL.Path (the decoded path) because that is what gin matches on: a request
// for /v1/chat%2Fcompletions reaches the same handler as /v1/chat/completions.
package routes

import (
	"net/http"
	"path"
	"strings"
)

type Class string

const (
	AdminPassthrough   Class = "admin_passthrough"
	ModelText          Class = "model_text"
	ModelUninspectable Class = "model_uninspectable"
	ReadPassthrough    Class = "read_passthrough"
	Unknown            Class = "unknown"
)

// Result is safe to log: Template never contains IDs, model names or query strings.
type Result struct {
	Class    Class
	Protocol string
	Template string
}

func Classify(r *http.Request) Result {
	p := r.URL.Path
	m := r.Method

	// Anything gin would not match literally (//, /./, /../, trailing slash redirect targets) is not
	// trusted to land on a known handler; in rc.46 it falls through to NoRoute -> pluginDispatcher.
	if p == "" || p[0] != '/' || (p != "/" && path.Clean(p) != p) {
		return Result{Unknown, "", "<non-canonical>"}
	}

	if isWebSocketUpgrade(r) {
		switch {
		case m == http.MethodGet && p == "/v1/responses":
			return Result{ModelUninspectable, "openai_responses_ws", p}
		case m == http.MethodGet && p == "/v1/realtime":
			return Result{ModelUninspectable, "openai_realtime_ws", p}
		}
		return Result{Unknown, "websocket", "<upgrade>"}
	}

	read := m == http.MethodGet || m == http.MethodHead
	// Generation endpoints review their JSON prompt; multipart uploads (image edits, audio files,
	// video references) carry the request in parts the extractor does not read.
	gen := func(protocol, tpl string) Result {
		if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/") {
			return Result{ModelUninspectable, protocol, tpl}
		}
		return Result{ModelText, protocol, tpl}
	}

	switch {
	case p == "/api" || strings.HasPrefix(p, "/api/"):
		// Console/management API: authorised by New API sessions/access tokens, not classified.
		return Result{AdminPassthrough, "", "/api/*"}

	case p == "/pg/chat/completions":
		if m == http.MethodPost {
			return Result{ModelText, "openai_chat", p} // UserAuth (session) model execution
		}

	case strings.HasPrefix(p, "/v1beta/models/"), strings.HasPrefix(p, "/v1/models/"):
		tpl := p[:strings.Index(p[1:], "/")+1] + "/models/*"
		if read {
			return Result{ReadPassthrough, "", tpl}
		}
		if m == http.MethodPost {
			return Result{ModelText, "gemini", tpl}
		}

	case p == "/v1/models" || p == "/v1beta/models":
		if read {
			return Result{ReadPassthrough, "", p}
		}

	case strings.HasPrefix(p, "/v1/"):
		return classifyV1(m, read, p, gen)

	case strings.HasPrefix(p, "/mj/") || strings.Contains(p, "/mj/"):
		if read {
			return Result{ReadPassthrough, "", "/mj/*"}
		}
		return gen("midjourney", "/mj/*")

	case strings.HasPrefix(p, "/suno/"):
		if read {
			return Result{ReadPassthrough, "", "/suno/*"}
		}
		return gen("suno", "/suno/*")
	}

	// Remaining reads are the console SPA and static assets. Remaining writes can only be served by
	// NoRoute -> pluginDispatcher (runtime JS plugins), i.e. unregistered execution candidates.
	if read {
		return Result{AdminPassthrough, "", "<web>"}
	}
	return Result{Unknown, "", "<unregistered>"}
}

func classifyV1(m string, read bool, p string, gen func(protocol, tpl string) Result) Result {
	post := m == http.MethodPost
	switch {
	case post && p == "/v1/chat/completions":
		return Result{ModelText, "openai_chat", p}
	case post && p == "/v1/completions":
		return Result{ModelText, "openai_completions", p}
	case post && p == "/v1/messages":
		return Result{ModelText, "claude_messages", p}
	case post && (p == "/v1/responses" || p == "/v1/responses/compact"):
		return Result{ModelText, "openai_responses", p}
	case post && (p == "/v1/alpha/search" || p == "/v1/tools/search" || p == "/v1/tools/fetch"):
		return Result{ModelText, "tool_special", p}
	case post && p == "/v1/embeddings":
		return Result{ModelText, "embeddings", p}
	case post && p == "/v1/rerank":
		return Result{ModelText, "rerank", p}
	case post && p == "/v1/moderations":
		return Result{ModelText, "moderations", p}
	case post && p == "/v1/edits":
		return Result{ModelText, "openai_edits", p}

	case read && strings.HasPrefix(p, "/v1/responses/"):
		return Result{ReadPassthrough, "", "/v1/responses/{id}"}

	case post && p == "/v1/images/generations":
		return gen("image_generation", "/v1/images/*")
	case strings.HasPrefix(p, "/v1/images/"):
		if post {
			return Result{ModelUninspectable, "images", "/v1/images/*"}
		}
	case post && p == "/v1/audio/speech":
		return gen("audio_speech", "/v1/audio/*")
	case strings.HasPrefix(p, "/v1/audio/"):
		if post {
			return Result{ModelUninspectable, "audio", "/v1/audio/*"}
		}
	case p == "/v1/video/generations" || p == "/v1/videos" || strings.HasPrefix(p, "/v1/videos/"):
		if read {
			return Result{ReadPassthrough, "", "/v1/videos/*"}
		}
		if post {
			return gen("video_generation", "/v1/videos/*")
		}

	case strings.HasPrefix(p, "/v1/tasks/"):
		// Generic task plugins: submissions are runtime-registered execution paths; reads include
		// artifact downloads authorised by TokenOrTaskArtifactAccessAuth, passed through untouched.
		if read {
			return Result{ReadPassthrough, "", "/v1/tasks/*"}
		}
		return Result{Unknown, "task_plugin", "/v1/tasks/*"}
	}
	return Result{Unknown, "", "/v1/<unregistered>"}
}

func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), "upgrade") {
				return true
			}
		}
	}
	return false
}
