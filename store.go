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
	ContentType string `json:"content_type,omitempty"` // as SignalWire declared it
	Size        int64  `json:"size,omitempty"`
	File        string `json:"file,omitempty"`        // local copy, served at /api/media/{file}
	ServedType  string `json:"served_type,omitempty"` // Content-Type the local copy is served with
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
	StatusAt     *time.Time `json:"status_at,omitempty"` // SignalWire's time for the current status
	CreatedAt    time.Time  `json:"created_at"`          // when smsd stored it

	// Raw is the payload exactly as SignalWire sent it: the inbound webhook
	// body, or the create-message response for outbound messages.
	Raw json.RawMessage `json:"-"`
}

// StatusEvent is one delivery status callback.
type StatusEvent struct {
	SignalWireID string
	Status       string
	ErrorCode    *string
	ErrorMessage *string
	Segments     *int
	At           *time.Time
	Raw          json.RawMessage
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
	// 1: initial schema
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
	served_type  TEXT,
	PRIMARY KEY (message_id, position)
);
CREATE INDEX media_file ON media(file); -- not unique: a forwarded file appears again

-- Every status callback, as received. A message's status columns are derived
-- from these (see applyStatus), so out-of-order and early callbacks are harmless.
-- Not keyed to messages: a callback can arrive before its message is stored.
CREATE TABLE status_events (
	id            INTEGER PRIMARY KEY,
	signalwire_id TEXT    NOT NULL,
	status        TEXT    NOT NULL,
	error_code    TEXT,
	error_message TEXT,
	segments      INTEGER,
	status_at     INTEGER,
	received_at   INTEGER NOT NULL,
	raw           TEXT    NOT NULL
);
CREATE INDEX status_events_signalwire_id ON status_events(signalwire_id);
`,
}

func openStore(path string) (*Store, error) {
	// _txlock=immediate: every transaction here writes, so take the write lock
	// up front instead of failing to upgrade a read lock under contention.
	db, err := sql.Open("sqlite", "file:"+path+"?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
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

// migrate applies pending migrations one per transaction. The version is read
// inside the (immediate) transaction, so concurrent starts can't both apply one.
func migrate(db *sql.DB) error {
	for {
		done, err := migrateOne(db)
		if done || err != nil {
			return err
		}
	}
}

func migrateOne(db *sql.DB) (done bool, err error) {
	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var v int
	if err := tx.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return false, err
	}
	switch {
	case v > len(migrations):
		return false, fmt.Errorf("database schema version %d is newer than this smsd supports (%d)", v, len(migrations))
	case v == len(migrations):
		return true, nil
	}
	if _, err := tx.Exec(migrations[v]); err != nil {
		return false, fmt.Errorf("migration %d: %w", v+1, err)
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v+1)); err != nil {
		return false, err
	}
	return false, tx.Commit()
}

func (s *Store) Close() error { return s.db.Close() }

// applyStatus sets a message's status columns from its newest status event:
// latest SignalWire timestamp first, then furthest along, then latest arrival.
// Messages without events keep the status they were stored with.
const applyStatus = `
UPDATE messages SET (status, error_code, error_message, status_at, segments) = (
	SELECT e.status, e.error_code, e.error_message, e.status_at, COALESCE(e.segments, messages.segments)
	FROM status_events e
	WHERE e.signalwire_id = messages.signalwire_id
	ORDER BY e.status_at DESC,
		CASE e.status WHEN 'queued' THEN 0 WHEN 'initiated' THEN 1 WHEN 'sent' THEN 2 WHEN 'read' THEN 4 ELSE 3 END DESC,
		e.id DESC
	LIMIT 1)
WHERE signalwire_id = ? AND EXISTS (SELECT 1 FROM status_events WHERE signalwire_id = ?)
RETURNING status, error_code, error_message, status_at, segments`

// Insert stores a message and its media. Duplicate SignalWire IDs (webhook
// retries) are ignored; inserted reports whether a new row was written. Status
// callbacks that arrived first are applied to the row and to m.
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
			`INSERT INTO media (message_id, position, url, content_type, size, file, served_type) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id, i, md.URL, nullString(md.ContentType), md.Size, nullString(md.File), nullString(md.ServedType)); err != nil {
			return false, err
		}
	}

	var at sql.NullInt64
	err = tx.QueryRowContext(ctx, applyStatus, m.SignalWireID, m.SignalWireID).
		Scan(&m.Status, &m.ErrorCode, &m.ErrorMessage, &at, &m.Segments)
	switch {
	case errors.Is(err, sql.ErrNoRows): // no early callbacks
	case err != nil:
		return false, err
	default:
		m.StatusAt = fromMillis(at)
	}

	if err := tx.Commit(); err != nil {
		return false, err
	}
	m.ID, m.Peer = id, peer
	return true, nil
}

// AddStatus records a status callback and re-derives the message's status.
func (s *Store) AddStatus(ctx context.Context, e StatusEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO status_events (signalwire_id, status, error_code, error_message, segments, status_at, received_at, raw)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.SignalWireID, e.Status, e.ErrorCode, e.ErrorMessage, e.Segments, toMillis(e.At),
		time.Now().UnixMilli(), string(e.Raw)); err != nil {
		return err
	}
	// RETURNING rows must be read for the statement to run to completion.
	rows, err := tx.QueryContext(ctx, applyStatus, e.SignalWireID, e.SignalWireID)
	if err != nil {
		return err
	}
	for rows.Next() {
	}
	if err := rows.Close(); err != nil {
		return err
	}
	return tx.Commit()
}

// mediaJob is one attachment that still needs downloading.
type mediaJob struct {
	MessageID int64
	Position  int
	Media
}

// MissingMedia lists attachments of messages stored since the given time
// whose download hasn't succeeded yet.
func (s *Store) MissingMedia(ctx context.Context, since time.Time) ([]mediaJob, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT media.message_id, media.position, media.url, COALESCE(media.content_type, ''), COALESCE(media.size, 0)
		FROM media JOIN messages ON messages.id = media.message_id
		WHERE media.file IS NULL AND messages.created_at >= ?
		ORDER BY media.message_id, media.position`, since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []mediaJob
	for rows.Next() {
		var j mediaJob
		if err := rows.Scan(&j.MessageID, &j.Position, &j.URL, &j.ContentType, &j.Size); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// SetMediaFile records the local copy of one attachment.
func (s *Store) SetMediaFile(ctx context.Context, messageID int64, position int, file, servedType string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE media SET file = ?, served_type = ? WHERE message_id = ? AND position = ?`,
		file, servedType, messageID, position)
	return err
}

// MediaServedType returns the Content-Type for a local media file, or
// sql.ErrNoRows if smsd never wrote a file by that name.
func (s *Store) MediaServedType(ctx context.Context, file string) (string, error) {
	var ct string
	err := s.db.QueryRowContext(ctx, `SELECT served_type FROM media WHERE file = ? LIMIT 1`, file).Scan(&ct)
	return ct, err
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

	// The page's id range also covers other peers' messages; byID keeps only this page's.
	mrows, err := s.db.QueryContext(ctx, `
		SELECT message_id, url, COALESCE(content_type, ''), COALESCE(size, 0), COALESCE(file, ''), COALESCE(served_type, '')
		FROM media WHERE message_id BETWEEN ? AND ?
		ORDER BY message_id, position`, out[0].ID, out[len(out)-1].ID)
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var id int64
		var md Media
		if err := mrows.Scan(&id, &md.URL, &md.ContentType, &md.Size, &md.File, &md.ServedType); err != nil {
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
