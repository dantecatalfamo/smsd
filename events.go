package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Event kinds sent on the SSE streams. Both carry the whole message.
const (
	eventMessage = "message" // a new message, inbound or outbound; its id is the SSE event id
	eventUpdate  = "update"  // a stored message changed: status callback, or media downloaded
)

type event struct {
	kind string
	msg  Message
}

// subscriber receives events on one of our numbers (or all, if number is
// empty) and with one peer (or all, if peer is empty).
type subscriber struct {
	number, peer string
	ch           chan event
}

func (sub *subscriber) wants(m Message) bool {
	return (sub.number == "" || sub.number == m.Number) && (sub.peer == "" || sub.peer == m.Peer)
}

// subscriberBuffer is how far a stream may fall behind before it is cut off.
// Its client reconnects with Last-Event-ID and catches up from the database.
const subscriberBuffer = 64

// broker fans events out to SSE streams. Publishing never blocks: a
// subscriber that can't keep up is dropped, which ends its stream.
type broker struct {
	mu     sync.Mutex
	subs   map[*subscriber]struct{}
	closed bool
}

func newBroker() *broker { return &broker{subs: map[*subscriber]struct{}{}} }

// subscribe returns nil once the broker is closed.
func (b *broker) subscribe(number, peer string) *subscriber {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	sub := &subscriber{number: number, peer: peer, ch: make(chan event, subscriberBuffer)}
	b.subs[sub] = struct{}{}
	return sub
}

func (b *broker) unsubscribe(sub *subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.drop(sub)
}

// drop closes sub's channel if the broker still has it. b.mu must be held.
func (b *broker) drop(sub *subscriber) {
	if _, ok := b.subs[sub]; ok {
		delete(b.subs, sub)
		close(sub.ch)
	}
}

func (b *broker) publish(kind string, m Message) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for sub := range b.subs {
		if !sub.wants(m) {
			continue
		}
		select {
		case sub.ch <- event{kind, m}:
		default:
			log.Printf("event stream for %q/%q fell behind; dropping it", sub.number, sub.peer)
			b.drop(sub)
		}
	}
}

// close ends every stream and refuses new ones, for shutdown.
func (b *broker) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	for sub := range b.subs {
		b.drop(sub)
	}
}

var heartbeatInterval = 25 * time.Second // var for tests

const replayPage = 500

// eventScope reads the stream's scope from the route: all messages, one of
// our numbers, or one conversation. Empty means "all".
func eventScope(w http.ResponseWriter, r *http.Request) (number, peer string, ok bool) {
	number, peer = r.PathValue("number"), r.PathValue("peer")
	if strings.Contains(r.Pattern, "{number}") && !validAddr(w, number, "number") {
		return "", "", false
	}
	if strings.Contains(r.Pattern, "{peer}") && !validAddr(w, peer, "peer") {
		return "", "", false
	}
	return number, peer, true
}

// handleEvents streams events as server-sent events. With Last-Event-ID,
// messages stored after that id are replayed first.
func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	number, peer, ok := eventScope(w, r)
	if !ok {
		return
	}
	var last int64
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id < 0 {
			writeJSON(w, http.StatusBadRequest, errBody("Last-Event-ID must be a message id"))
			return
		}
		last = id
	}

	// Subscribe before replaying, so nothing stored in between is missed;
	// messages the replay already sent are skipped below.
	sub := s.events.subscribe(number, peer)
	if sub == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody("shutting down"))
		return
	}
	defer s.events.unsubscribe(sub)

	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{}) // the stream outlives the server's WriteTimeout
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // nginx: don't buffer the stream
	w.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(w, ": connected\n\n"); err != nil {
		return
	}

	if last > 0 {
		for {
			msgs, err := s.store.MessagesAfter(r.Context(), number, peer, last, replayPage)
			if err != nil {
				log.Printf("replay events after %d: %v", last, err)
				return // the client reconnects and tries again
			}
			for _, m := range msgs {
				if writeEvent(w, eventMessage, m) != nil {
					return
				}
				last = m.ID
			}
			if len(msgs) < replayPage {
				break
			}
		}
	}
	if rc.Flush() != nil {
		return
	}

	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-sub.ch:
			if !ok {
				return // fell behind or shutting down
			}
			if ev.kind == eventMessage && ev.msg.ID <= last {
				continue // already replayed
			}
			if writeEvent(w, ev.kind, ev.msg) != nil {
				return
			}
		case <-heartbeat.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
		}
		if rc.Flush() != nil {
			return
		}
	}
}

// writeEvent writes one SSE event. Only new messages get an id, so
// Last-Event-ID always names the newest message the client has seen.
func writeEvent(w io.Writer, kind string, m Message) error {
	data, err := json.Marshal(m) // one line: Marshal never emits newlines
	if err != nil {
		return err
	}
	if kind == eventMessage {
		if _, err := fmt.Fprintf(w, "id: %d\n", m.ID); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", kind, data)
	return err
}
