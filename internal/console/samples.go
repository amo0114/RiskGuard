package console

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"

	"riskguard/internal/samples"
)

type sessionKey struct{}

func sessionFrom(r *http.Request) session {
	s, _ := r.Context().Value(sessionKey{}).(session)
	return s
}

// require checks the role on the server for every call; hiding buttons is not access control.
func (c *Console) require(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sessionFrom(r).has(role) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": role + " role required"})
			return
		}
		next(w, r)
	}
}

func (c *Console) store() *samples.Store {
	if c.info.Samples == nil {
		return nil
	}
	return c.info.Samples.Store()
}

func (c *Console) sampleStatus(w http.ResponseWriter, _ *http.Request) {
	if c.info.Samples == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "last_error": c.info.SamplesError})
		return
	}
	writeJSON(w, http.StatusOK, c.info.Samples.Status())
}

// sampleList is metadata only, so any session may page through it.
func (c *Console) sampleList(w http.ResponseWriter, r *http.Request) {
	st := c.store()
	if st == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "samples": []any{}})
		return
	}
	q := r.URL.Query()
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	content, _ := strconv.ParseInt(q.Get("content"), 10, 64)
	list, err := st.List(samples.Filter{Queue: q.Get("queue"), Decision: q.Get("decision"), Review: q.Get("review"),
		Content: content, Credential: q.Get("credential"), Group: q.Get("group") == "content", Before: before, Limit: limit})
	if err != nil {
		c.storeFailed(w, "list", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "samples": list})
}

func sampleID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad sample id"})
		return 0, false
	}
	return id, true
}

// sampleDetail returns redacted text. The access is recorded first; if that record cannot be
// written, the text is not shown.
func (c *Console) sampleDetail(w http.ResponseWriter, r *http.Request) {
	st := c.store()
	id, ok := sampleID(w, r)
	if st == nil || !ok {
		if st == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "sampling disabled"})
		}
		return
	}
	if err := st.Audit(sessionFrom(r).actor, "view_content", "sample:"+strconv.FormatInt(id, 10), "ok"); err != nil {
		c.storeFailed(w, "access audit", err)
		return
	}
	d, err := st.Get(id)
	if errors.Is(err, samples.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "sample not found or expired"})
		return
	}
	if err != nil {
		c.storeFailed(w, "detail", err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (c *Console) sampleReview(w http.ResponseWriter, r *http.Request) {
	st := c.store()
	id, ok := sampleID(w, r)
	if st == nil || !ok {
		if st == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "sampling disabled"})
		}
		return
	}
	var in samples.ReviewInput
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	actor, obj := sessionFrom(r).actor, "sample:"+strconv.FormatInt(id, 10)
	rid, err := st.AddReview(id, actor, c.info.PolicyVersion, in)
	result := "ok"
	switch {
	case errors.Is(err, samples.ErrInvalid):
		result = "invalid"
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid review: labeled needs expected_action allow|review|deny; other statuses must not set one"})
	case errors.Is(err, samples.ErrConflict):
		result = "conflict"
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a newer review exists; reload the sample"})
	case errors.Is(err, samples.ErrNotFound):
		result = "not_found"
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "sample not found, expired or without text"})
	case errors.Is(err, samples.ErrFull):
		result = "store_full"
		writeJSON(w, http.StatusInsufficientStorage, map[string]string{"error": "sample store is full; delete samples or free disk space"})
	case err != nil:
		c.storeFailed(w, "review", err)
		return
	default:
		writeJSON(w, http.StatusOK, map[string]int64{"id": rid})
	}
	if err := st.Audit(actor, "review", obj, result); err != nil {
		log.Printf("riskguard: console access audit: %v", err)
	}
}

func (c *Console) sampleDelete(w http.ResponseWriter, r *http.Request) {
	st := c.store()
	id, ok := sampleID(w, r)
	if st == nil || !ok {
		if st == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "sampling disabled"})
		}
		return
	}
	err := st.Delete(id)
	result := "ok"
	switch {
	case errors.Is(err, samples.ErrNotFound):
		result = "not_found"
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "sample not found"})
	case err != nil:
		c.storeFailed(w, "delete", err)
		return
	default:
		writeJSON(w, http.StatusOK, map[string]string{})
	}
	if err := st.Audit(sessionFrom(r).actor, "delete", "sample:"+strconv.FormatInt(id, 10), result); err != nil {
		log.Printf("riskguard: console access audit: %v", err)
	}
}

func (c *Console) storeFailed(w http.ResponseWriter, op string, err error) {
	log.Printf("riskguard: samples %s: %v", op, err)
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sample store unavailable"})
}
