package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no cgo
)

type Direction string

const (
	Inbound  Direction = "in"
	Outbound Direction = "out"
)

type Message struct {
	ID         int64     `json:"id"`
	SID        string    `json:"sid,omitempty"`
	Direction  Direction `json:"direction"`
	Peer       string    `json:"peer"` // the other party's number; conversations are keyed on this
	Body       string    `json:"body"`
	Media      []string  `json:"media,omitempty"`       // URLs as SignalWire reported them
	MediaFiles []string  `json:"media_files,omitempty"` // local copies, served at /api/media/{name}
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}

type Conversation struct {
	Peer         string    `json:"peer"`
	LastBody     string    `json:"last_body"`
	LastDir      Direction `json:"last_direction"`
	LastAt       time.Time `json:"last_at"`
	MessageCount int       `json:"message_count"`
}

type Store struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS messages (
	id         INTEGER PRIMARY KEY,
	sid        TEXT UNIQUE,
	direction  TEXT    NOT NULL,
	peer       TEXT    NOT NULL,
	body       TEXT    NOT NULL,
	media      TEXT    NOT NULL DEFAULT '[]',
	media_files TEXT   NOT NULL DEFAULT '[]',
	status     TEXT    NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_peer_id ON messages(peer, id);

-- Status callbacks that arrived before their message was stored (the callback
-- can beat the Send response). Applied and removed when the message is inserted.
CREATE TABLE IF NOT EXISTS pending_status (
	sid        TEXT PRIMARY KEY,
	status     TEXT    NOT NULL,
	updated_at INTEGER NOT NULL
);
`

// migrate brings databases created by older versions up to the current schema.
func migrate(db *sql.DB) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('messages') WHERE name = 'media_files'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		_, err := db.Exec(`ALTER TABLE messages ADD COLUMN media_files TEXT NOT NULL DEFAULT '[]'`)
		return err
	}
	return nil
}

func openStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: one writer keeps things simple and correct
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Insert stores a message. Duplicate SIDs (webhook retries) are ignored;
// inserted reports whether a new row was written. If a status callback for
// the SID arrived first, its status is applied to the row and to m.
func (s *Store) Insert(ctx context.Context, m *Message) (inserted bool, err error) {
	media, _ := json.Marshal(m.Media)
	if m.Media == nil {
		media = []byte("[]")
	}
	var sid any
	if m.SID != "" {
		sid = m.SID
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO messages (sid, direction, peer, body, media, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sid, m.Direction, m.Peer, m.Body, string(media), m.Status, m.CreatedAt.UnixMilli())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}
	id, _ := res.LastInsertId()

	status := m.Status
	if m.SID != "" {
		err := tx.QueryRowContext(ctx, `DELETE FROM pending_status WHERE sid = ? RETURNING status`, m.SID).Scan(&status)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return false, err
		default:
			if _, err := tx.ExecContext(ctx, `UPDATE messages SET status = ? WHERE id = ?`, status, id); err != nil {
				return false, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	m.ID, m.Status = id, status
	return true, nil
}

// UpdateStatus records a delivery status. If the message isn't stored yet,
// the status is parked in pending_status for Insert to pick up.
func (s *Store) UpdateStatus(ctx context.Context, sid, status string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `UPDATE messages SET status = ? WHERE sid = ?`, status, sid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		now := time.Now()
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO pending_status (sid, status, updated_at) VALUES (?, ?, ?)
			 ON CONFLICT(sid) DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at`,
			sid, status, now.UnixMilli()); err != nil {
			return err
		}
		// Callbacks for messages we never stored (e.g. the insert failed) would otherwise pile up.
		if _, err := tx.ExecContext(ctx, `DELETE FROM pending_status WHERE updated_at < ?`,
			now.Add(-24*time.Hour).UnixMilli()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SetMediaFiles(ctx context.Context, id int64, files []string) error {
	b, _ := json.Marshal(files)
	_, err := s.db.ExecContext(ctx, `UPDATE messages SET media_files = ? WHERE id = ?`, string(b), id)
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
		if err := rows.Scan(&c.Peer, &c.LastBody, &c.LastDir, &ms, &c.MessageCount); err != nil {
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
		SELECT id, COALESCE(sid, ''), direction, peer, body, media, media_files, status, created_at
		FROM (SELECT * FROM messages WHERE peer = ? AND id < ? ORDER BY id DESC LIMIT ?)
		ORDER BY id ASC`, peer, beforeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Message{}
	for rows.Next() {
		var m Message
		var media, files string
		var ms int64
		if err := rows.Scan(&m.ID, &m.SID, &m.Direction, &m.Peer, &m.Body, &media, &files, &m.Status, &ms); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(media), &m.Media)
		_ = json.Unmarshal([]byte(files), &m.MediaFiles)
		m.CreatedAt = time.UnixMilli(ms).UTC()
		out = append(out, m)
	}
	return out, rows.Err()
}
