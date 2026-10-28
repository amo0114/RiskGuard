package samples

import (
	"database/sql"
	"fmt"
)

// LabeledText is one stored text whose latest review is "labeled": the human expected action
// and the redacted text the classifier saw. It carries no trace, IP, credential or client.
type LabeledText struct {
	ContentHMAC      string
	Text             string
	Random           bool   // at least one occurrence came from the random baseline
	Protocol         string // of the first occurrence
	Truncated        bool
	RedactionVersion int
	ReviewID         int64
	ReviewPolicy     string // policy version the reviewer labeled under
	ExpectedAction   string
	Category         string
	Reason           string
}

// Labeled returns every text whose latest review is "labeled", plus counts of reviewed texts left
// out by reason (the other review statuses, or text no longer stored).
func (s *Store) Labeled() ([]LabeledText, map[string]int, error) {
	now := s.now().Unix()
	rows, err := s.db.Query(`SELECT r.content_id, r.id, r.created_at, r.status, r.expected_action, r.category, r.policy_version,
		r.reason_nonce, r.reason_ct, c.hmac, c.nonce, c.ciphertext, coalesce(c.redaction_version, 0), coalesce(c.expires_at, 0),
		EXISTS (SELECT 1 FROM occurrences o WHERE o.content_id = r.content_id AND o.base = 1),
		coalesce((SELECT o.protocol FROM occurrences o WHERE o.content_id = r.content_id ORDER BY o.id LIMIT 1), ''),
		coalesce((SELECT max(o.truncated) FROM occurrences o WHERE o.content_id = r.content_id), 0)
		FROM reviews r LEFT JOIN contents c ON c.id = r.content_id
		WHERE r.id = (SELECT max(r2.id) FROM reviews r2 WHERE r2.content_id = r.content_id)
		ORDER BY r.content_id`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out []LabeledText
	skipped := map[string]int{}
	for rows.Next() {
		var t LabeledText
		var contentID, created, exp int64
		var status string
		var hmacV sql.NullString
		var rn, rc, nonce, ct []byte
		if err := rows.Scan(&contentID, &t.ReviewID, &created, &status, &t.ExpectedAction, &t.Category, &t.ReviewPolicy,
			&rn, &rc, &hmacV, &nonce, &ct, &t.RedactionVersion, &exp, &t.Random, &t.Protocol, &t.Truncated); err != nil {
			return nil, nil, err
		}
		switch {
		case status != "labeled":
			skipped[status]++
			continue
		case !hmacV.Valid || exp <= now:
			skipped["text_expired"]++
			continue
		case ct == nil:
			skipped["text_not_stored"]++
			continue
		}
		t.ContentHMAC = hmacV.String
		if t.Text, err = s.open("content|"+t.ContentHMAC, nonce, ct); err != nil {
			return nil, nil, fmt.Errorf("decrypt content %d: %w", contentID, err)
		}
		if rc != nil {
			if t.Reason, err = s.open(fmt.Sprintf("review|%d|%d", contentID, created), rn, rc); err != nil {
				return nil, nil, fmt.Errorf("decrypt review %d: %w", t.ReviewID, err)
			}
		}
		out = append(out, t)
	}
	return out, skipped, rows.Err()
}
