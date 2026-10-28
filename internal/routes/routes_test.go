package routes

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		method, target string
		upgrade        bool
		want           Class
		proto          string
	}{
		{"POST", "/v1/chat/completions", false, ModelText, "openai_chat"},
		{"POST", "/v1/chat%2Fcompletions", false, ModelText, "openai_chat"}, // gin matches decoded path
		{"POST", "/v1/completions", false, ModelText, "openai_completions"},
		{"POST", "/v1/messages", false, ModelText, "claude_messages"},
		{"POST", "/v1/responses", false, ModelText, "openai_responses"},
		{"POST", "/v1/responses/compact", false, ModelText, "openai_responses"},
		{"GET", "/v1/responses/resp_123", false, ReadPassthrough, ""},
		{"GET", "/v1/responses", true, ModelUninspectable, "openai_responses_ws"},
		{"GET", "/v1/realtime", true, ModelUninspectable, "openai_realtime_ws"},
		{"GET", "/v1/realtime", false, Unknown, ""},
		{"POST", "/v1beta/models/gemini-x:generateContent", false, ModelText, "gemini"},
		{"POST", "/v1beta/models/gemini-x:generateContent/models/gemini-x:streamGenerateContent?key=k", false, ModelText, "gemini"},
		{"POST", "/v1/models/gemini-x:streamGenerateContent", false, ModelText, "gemini"},
		{"GET", "/v1beta/models", false, ReadPassthrough, ""},
		{"GET", "/v1/models", false, ReadPassthrough, ""},
		{"GET", "/v1/models/gpt-x", false, ReadPassthrough, ""},
		{"POST", "/pg/chat/completions", false, ModelText, "openai_chat"},
		{"POST", "/v1/alpha/search", false, ModelText, "tool_special"},
		{"POST", "/v1/tools/fetch", false, ModelText, "tool_special"},
		{"POST", "/v1/embeddings", false, ModelText, "embeddings"},
		{"POST", "/v1/rerank", false, ModelText, "rerank"},
		{"POST", "/v1/images/generations", false, ModelText, "image_generation"},
		{"POST", "/v1/images/edits", false, ModelUninspectable, "images"},
		{"POST", "/v1/audio/speech", false, ModelText, "audio_speech"},
		{"POST", "/v1/audio/transcriptions", false, ModelUninspectable, "audio"},
		{"POST", "/v1/videos", false, ModelText, "video_generation"},
		{"POST", "/v1/video/generations", false, ModelText, "video_generation"},
		{"POST", "/v1/videos/v1/remix", false, ModelText, "video_generation"},
		{"GET", "/v1/videos/task1/content", false, ReadPassthrough, ""},
		{"POST", "/v1/tasks/typesafe", false, Unknown, "task_plugin"},
		{"GET", "/v1/tasks/k/artifacts/a/content", false, ReadPassthrough, ""},
		{"POST", "/mj/submit/imagine", false, ModelText, "midjourney"},
		{"POST", "/fast/mj/submit/imagine", false, ModelText, "midjourney"},
		{"POST", "/suno/submit/music", false, ModelText, "suno"},
		{"POST", "/api/user/login", false, AdminPassthrough, ""},
		{"GET", "/api/status", false, AdminPassthrough, ""},
		{"GET", "/", false, AdminPassthrough, ""},
		{"GET", "/static/js/app.js", false, AdminPassthrough, ""},
		{"POST", "/some/plugin/route", false, Unknown, ""},    // NoRoute -> pluginDispatcher
		{"POST", "/v1/files", false, Unknown, ""},             // RelayNotImplemented / unregistered
		{"POST", "//v1/chat/completions", false, Unknown, ""}, // non-canonical
		{"POST", "/v1/./chat/completions", false, Unknown, ""},
		{"POST", "/v1/chat/completions/", false, Unknown, ""},
		{"GET", "/api/anything", true, Unknown, "websocket"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.target, nil)
		if c.upgrade {
			r.Header.Set("Connection", "keep-alive, Upgrade")
			r.Header.Set("Upgrade", "websocket")
		}
		got := Classify(r)
		if got.Class != c.want || got.Protocol != c.proto {
			t.Errorf("%s %s upgrade=%v: got %s/%q want %s/%q", c.method, c.target, c.upgrade, got.Class, got.Protocol, c.want, c.proto)
		}
	}
}

func TestTemplateNeverLeaksIdentifiers(t *testing.T) {
	for _, target := range []string{
		"/v1beta/models/secret-model:generateContent?key=sk-abc",
		"/v1/responses/resp_secret",
		"/v1/tasks/k/artifacts/secret/content",
		"/some/plugin/secret",
	} {
		r := httptest.NewRequest("POST", target, nil)
		if tpl := Classify(r).Template; containsAny(tpl, "secret", "sk-", "key=") {
			t.Errorf("%s -> template %q leaks identifiers", target, tpl)
		}
	}
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// Generation prompts are reviewed only from JSON; multipart uploads stay a coverage gap.
func TestGenerationMultipartIsUninspectable(t *testing.T) {
	for _, target := range []string{"/v1/images/generations", "/v1/audio/speech", "/v1/videos", "/mj/submit/imagine", "/suno/submit/music"} {
		r := httptest.NewRequest("POST", target, nil)
		r.Header.Set("Content-Type", "multipart/form-data; boundary=x")
		if got := Classify(r); got.Class != ModelUninspectable {
			t.Errorf("%s multipart: %s/%q", target, got.Class, got.Protocol)
		}
	}
}
