package proxy

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// writeError answers in the error shape the calling client already parses: Anthropic for Claude
// Messages, Google for Gemini, MJ's description form, and New API's new_api_error otherwise.
func writeError(w http.ResponseWriter, protocol string, status int, code, msg, trace string) {
	msg += " (request id: " + trace + ")"
	var body any
	switch protocol {
	case "claude_messages":
		body = map[string]any{"type": "error", "error": map[string]any{"type": anthropicType(status), "message": msg}}
	case "gemini":
		body = map[string]any{"error": map[string]any{"code": status, "message": msg, "status": googleStatus(status)}}
	case "midjourney":
		body = map[string]any{"description": msg, "type": "new_api_error", "code": status}
	default:
		body = map[string]any{"error": map[string]any{"message": msg, "type": "new_api_error", "code": code}}
	}
	switch status {
	case http.StatusTooManyRequests:
		w.Header().Set("Retry-After", "60")
	case http.StatusServiceUnavailable:
		w.Header().Set("Retry-After", "10")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Risk-Code", code)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func anthropicType(status int) string {
	switch status {
	case http.StatusForbidden:
		return "permission_error"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return "invalid_request_error"
	}
	return "api_error"
}

func googleStatus(status int) string {
	switch status {
	case http.StatusForbidden:
		return "PERMISSION_DENIED"
	case http.StatusTooManyRequests:
		return "RESOURCE_EXHAUSTED"
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge:
		return "INVALID_ARGUMENT"
	case http.StatusUnprocessableEntity:
		return "FAILED_PRECONDITION"
	case http.StatusServiceUnavailable, http.StatusBadGateway:
		return "UNAVAILABLE"
	}
	return "UNKNOWN_" + strconv.Itoa(status)
}
