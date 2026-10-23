package activity

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/kirito/git-proxy/internal/store"
)

type Event struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	Username    string     `json:"username"`
	Source      string     `json:"source"`
	Destination string     `json:"destination"`
	Operation   string     `json:"operation"`
	Status      string     `json:"status"`
	Error       string     `json:"error,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	BytesIn     int64      `json:"bytes_in"`
	BytesOut    int64      `json:"bytes_out"`
}

type Hub struct {
	mu          sync.Mutex
	events      []Event
	subscribers map[chan struct{}]struct{}
}

func New() *Hub { return &Hub{subscribers: make(map[chan struct{}]struct{})} }
func (h *Hub) notify() {
	for ch := range h.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
func (h *Hub) Snapshot(userID string, admin bool) []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := make([]Event, 0, len(h.events))
	for i := len(h.events) - 1; i >= 0; i-- {
		e := h.events[i]
		if admin || e.UserID == userID {
			result = append(result, e)
		}
	}
	return result
}
func (h *Hub) Subscribe() (<-chan struct{}, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan struct{}, 1)
	h.subscribers[ch] = struct{}{}
	return ch, func() { h.mu.Lock(); defer h.mu.Unlock(); delete(h.subscribers, ch) }
}
func (h *Hub) Begin(u store.User, m store.Mapping, operation string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	id := hex.EncodeToString(b[:])
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, Event{ID: id, UserID: u.ID, Username: u.Username, Source: m.Source, Destination: fmt.Sprintf("%s@%s:%d/%s", m.RemoteUser, m.Host, m.Port, m.RemotePath), Operation: operation, Status: "active", StartedAt: time.Now().UTC()})
	h.notify()
	return id
}
func (h *Hub) Progress(id string, in, out int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.events {
		if h.events[i].ID == id {
			h.events[i].BytesIn = in
			h.events[i].BytesOut = out
			h.notify()
			return
		}
	}
}
func (h *Hub) Finish(id string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.events {
		if h.events[i].ID == id {
			now := time.Now().UTC()
			h.events[i].FinishedAt = &now
			h.events[i].Status = "completed"
			if err != nil {
				h.events[i].Status = "failed"
				h.events[i].Error = err.Error()
			}
			break
		}
	}
	completed := 0
	for _, e := range h.events {
		if e.Status != "active" {
			completed++
		}
	}
	if completed > 200 {
		keep := h.events[:0]
		for _, e := range h.events {
			if completed > 200 && e.Status != "active" {
				completed--
				continue
			}
			keep = append(keep, e)
		}
		h.events = keep
	}
	h.notify()
}
