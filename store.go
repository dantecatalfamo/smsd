package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no cgo
)

// Direction uses SignalWire's own values.
type Direction string

const (
	Inbound  Direction = "inbound"
	Outbound Direction = "outbound"
)

// Media is one MMS attachment as SignalWire described it, plus our local copy.
type Media struct {
	URL         string `json:"url"`
	ContentType string `json:"content_type,omitempty"`
	Size        int64  `json:"size,omitempty"`
	File        string `json:"file,omitempty"` // local copy, served at /api/media/{file}
}

// Message mirrors SignalWire's message fields. Pointer fields are ones
// SignalWire may send as null or leave out.
type Message struct {
	ID           int64      `json:"id"`
	SignalWireID string     `json:"signalwire_id"`
	ProjectID    string     `json:"project_id,omitempty"`
	SpaceID      string     `json:"space_id,omitempty"`
	Direction    Direction  `json:"direction"`
	Type         string     `json:"type,omitempty"` // sms or mms
	From         string     `json:"from"`
	To           string     `json:"to"`
	Peer         string     `json:"peer"` // the other party: from if inbound, to if outbound; conversations are keyed on it
	Body         *string    `json:"body"` // null on media-only MMS
	Segments     *int       `json:"segments,omitempty"`
	Media        []Media    `json:"media,omitempty"`
	Status       string     `json:"status"`
	ErrorCode    *string    `json:"error_code,omitempty"`
	ErrorMessage *string    `json:"error_message,omitempty"`
	Timestamp    *time.Time `json:"timestamp,omitempty"` // SignalWire's time for the message
	StatusAt     *time.Time `json:"status_at,omitempty"` // SignalWire's time for the latest status
	CreatedAt    time.Time  `json:"created_at"`          // when smsd stored it

	// Raw is the payload exactly as SignalWire sent it: the inbound webhook
	// body, or the create-message response for outbound messages.
	Raw json.RawMessage `json:"-"`
}

// StatusUpdate is one delivery status callback.
type StatusUpdate struct {
	SignalWireID string
	Status       string
	ErrorCode    *string
	ErrorMessage *string
	At           *time.Time
}

type Conversation struct {
	Peer          string    `json:"peer"`
	LastBody      *string   `json:"last_body"`
	LastDirection Direction `json:"last_direction"`
	LastAt        time.Time `json:"last_at"`
	MessageCount  int       `json:"message_count"`
}

type Store struct{ db *sql.DB }

// migrations[i] takes the schema from version i to i+1; the version is kept
// in SQLite's user_version. To change the schema, append a new entry. Never
// edit one that has shipped. Times are unix milliseconds.
var migrations = []string{
	// 1: initial SWML-era schema
	`
CREATE TABLE messages (
	id            INTEGER PRIMARY KEY,
	signalwire_id TEXT    NOT NULL UNIQUE,
	project_id    TEXT,
	space_id      TEXT,
	direction     TEXT    NOT NULL CHECK (direction IN ('inbound', 'outbound')),
	type          TEXT,
	from_number   TEXT    NOT NULL,
	to_number     TEXT    NOT NULL,
	peer          TEXT    NOT NULL GENERATED ALWAYS AS
		(CASE direction WHEN 'inbound' THEN from_number ELSE to_number END) STORED,
	body          TEXT,
	segments      INTEGER,
	status        TEXT    NOT NULL,
	error_code    TEXT,
	error_message TEXT,
	timestamp     INTEGER,
	status_at     INTEGER,
	created_at    INTEGER NOT NULL,
	raw           TEXT
);
CREATE INDEX messages_peer_id ON messages(peer, id);

CREATE TABLE media (
	message_id   INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
	position     INTEGER NOT NULL,
	url          TEXT    NOT NULL,
	content_type TEXT,
	size         INTEGER,
	file         TEXT,
	PRIMARY KEY (message_id, position)
);

-- Status callbacks that arrived before their message was stored (the callback
-- can beat the Send response). Applied and removed when the message is inserted.
CREATE TABLE pending_status (
	signalwire_id TEXT PRIMARY KEY,
	status        TEXT    NOT NULL,
	error_code    TEXT,
	error_message TEXT,
	status_at     INTEGER,
	received_at   INTEGER NOT NULL
);
`,
}

func openStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: one writer keeps things simple and correct
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// migrate applies any migrations the database hasn't had yet, each in its own
// transaction together with its user_version bump.
func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this smsd supports (%d)", version, len(migrations))
	}
	for v := version; v < len(migrations); v++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", v+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

// Insert stores a message and its media. Duplicate SignalWire IDs (webhook
// retries) are ignored; inserted reports whether a new row was written. If a
// status callback for the message arrived first, it is applied to the row and to m.
func (s *Store) Insert(ctx context.Context, m *Message) (inserted bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var id int64
	var peer string
	err = tx.QueryRowContext(ctx,
		`INSERT INTO messages (signalwire_id, project_id, space_id, direction, type, from_number, to_number,
			body, segments, status, error_code, error_message, timestamp, status_at, created_at, raw)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (signalwire_id) DO NOTHING
		 RETURNING id, peer`,
		m.SignalWireID, nullString(m.ProjectID), nullString(m.SpaceID), m.Direction, nullString(m.Type), m.From, m.To,
		m.Body, m.Segments, m.Status, m.ErrorCode, m.ErrorMessage, toMillis(m.Timestamp), toMillis(m.StatusAt),
		m.CreatedAt.UnixMilli(), nullString(string(m.Raw)),
	).Scan(&id, &peer)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	for i, md := range m.Media {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO media (message_id, position, url, content_type, size, file) VALUES (?, ?, ?, ?, ?, ?)`,
			id, i, md.URL, nullString(md.ContentType), md.Size, nullString(md.File)); err != nil {
			return false, err
		}
	}

	var u StatusUpdate
	var at sql.NullInt64
	err = tx.QueryRowContext(ctx,
		`DELETE FROM pending_status WHERE signalwire_id = ? RETURNING status, error_code, error_message, status_at`,
		m.SignalWireID).Scan(&u.Status, &u.ErrorCode, &u.ErrorMessage, &at)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return false, err
	default:
		u.At = fromMillis(at)
		if _, err := tx.ExecContext(ctx,
			`UPDATE messages SET status = ?, error_code = ?, error_message = ?, status_at = ? WHERE id = ?`,
			u.Status, u.ErrorCode, u.ErrorMessage, toMillis(u.At), id); err != nil {
			return false, err
		}
		m.Status, m.ErrorCode, m.ErrorMessage, m.StatusAt = u.Status, u.ErrorCode, u.ErrorMessage, u.At
	}

	if err := tx.Commit(); err != nil {
		return false, err
	}
	m.ID, m.Peer = id, peer
	return true, nil
}

// UpdateStatus records a delivery status. If the message isn't stored yet,
// the status is parked in pending_status for Insert to pick up.
func (s *Store) UpdateStatus(ctx context.Context, u StatusUpdate) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`UPDATE messages SET status = ?, error_code = ?, error_message = ?, status_at = ? WHERE signalwire_id = ?`,
		u.Status, u.ErrorCode, u.ErrorMessage, toMillis(u.At), u.SignalWireID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		now := time.Now()
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO pending_status (signalwire_id, status, error_code, error_message, status_at, received_at)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT (signalwire_id) DO UPDATE SET status = excluded.status, error_code = excluded.error_code,
				error_message = excluded.error_message, status_at = excluded.status_at, received_at = excluded.received_at`,
			u.SignalWireID, u.Status, u.ErrorCode, u.ErrorMessage, toMillis(u.At), now.UnixMilli()); err != nil {
			return err
		}
		// Callbacks for messages we never stored (e.g. the insert failed) would otherwise pile up.
		if _, err := tx.ExecContext(ctx, `DELETE FROM pending_status WHERE received_at < ?`,
			now.Add(-24*time.Hour).UnixMilli()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetMediaFile records the local copy of one attachment.
func (s *Store) SetMediaFile(ctx context.Context, messageID int64, position int, file string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE media SET file = ? WHERE message_id = ? AND position = ?`,
		file, messageID, position)
	return err
}

func (s *Store) Conversations(ctx context.Context) ([]Conversation, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT m.peer, m.body, m.direction, m.created_at, l.n
		FROM messages m
		JOIN (SELECT peer, MAX(id) AS id, COUNT(*) AS n FROM messages GROUP BY peer) l ON m.id = l.id
		ORDER BY m.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Conversation{}
	for rows.Next() {
		var c Conversation
		var ms int64
		if err := rows.Scan(&c.Peer, &c.LastBody, &c.LastDirection, &ms, &c.MessageCount); err != nil {
			return nil, err
		}
		c.LastAt = time.UnixMilli(ms).UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

// Messages returns a conversation oldest-first. If beforeID > 0, only
// messages older than it are returned (for paging back through history).
func (s *Store) Messages(ctx context.Context, peer string, beforeID int64, limit int) ([]Message, error) {
	if beforeID <= 0 {
		beforeID = 1<<63 - 1
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, signalwire_id, COALESCE(project_id, ''), COALESCE(space_id, ''), direction, COALESCE(type, ''),
			from_number, to_number, peer, body, segments, status, error_code, error_message,
			timestamp, status_at, created_at, raw
		FROM (SELECT * FROM messages WHERE peer = ? AND id < ? ORDER BY id DESC LIMIT ?)
		ORDER BY id ASC`, peer, beforeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Message{}
	byID := map[int64]int{}
	for rows.Next() {
		var m Message
		var ts, statusAt sql.NullInt64
		var created int64
		var raw sql.NullString
		if err := rows.Scan(&m.ID, &m.SignalWireID, &m.ProjectID, &m.SpaceID, &m.Direction, &m.Type,
			&m.From, &m.To, &m.Peer, &m.Body, &m.Segments, &m.Status, &m.ErrorCode, &m.ErrorMessage,
			&ts, &statusAt, &created, &raw); err != nil {
			return nil, err
		}
		m.Timestamp, m.StatusAt = fromMillis(ts), fromMillis(statusAt)
		m.CreatedAt = time.UnixMilli(created).UTC()
		if raw.Valid {
			m.Raw = json.RawMessage(raw.String)
		}
		byID[m.ID] = len(out)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil || len(out) == 0 {
		return out, err
	}

	mrows, err := s.db.QueryContext(ctx, `
		SELECT media.message_id, media.url, COALESCE(media.content_type, ''), COALESCE(media.size, 0), COALESCE(media.file, '')
		FROM media JOIN messages ON messages.id = media.message_id
		WHERE messages.peer = ? AND media.message_id BETWEEN ? AND ?
		ORDER BY media.message_id, media.position`, peer, out[0].ID, out[len(out)-1].ID)
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var id int64
		var md Media
		if err := mrows.Scan(&id, &md.URL, &md.ContentType, &md.Size, &md.File); err != nil {
			return nil, err
		}
		if i, ok := byID[id]; ok {
			out[i].Media = append(out[i].Media, md)
		}
	}
	return out, mrows.Err()
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func toMillis(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UnixMilli()
}

func fromMillis(ms sql.NullInt64) *time.Time {
	if !ms.Valid {
		return nil
	}
	t := time.UnixMilli(ms.Int64).UTC()
	return &t
}
