package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"goaccord/internal/netsec"
)

type Packet struct {
	Type        string `json:"type"`
	Role        string `json:"role,omitempty"`
	ID          string `json:"id,omitempty"`
	From        string `json:"from,omitempty"`
	To          string `json:"to,omitempty"`
	Body        string `json:"body,omitempty"`
	Compression string `json:"compression,omitempty"`
	USize       int    `json:"usize,omitempty"`
	Group       string `json:"group,omitempty"`
	Channel     string `json:"channel,omitempty"`
	Nonce       string `json:"nonce,omitempty"`
	PubKey      string `json:"pub_key,omitempty"`
	Sig         string `json:"sig,omitempty"`
	CreatedAt   int64  `json:"created_at,omitempty"`
}

type signedAction struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	From        string `json:"from"`
	To          string `json:"to,omitempty"`
	Body        string `json:"body,omitempty"`
	Compression string `json:"compression,omitempty"`
	USize       int    `json:"usize,omitempty"`
	Group       string `json:"group,omitempty"`
	Channel     string `json:"channel,omitempty"`
	CreatedAt   int64  `json:"created_at,omitempty"`
}

type keyFile struct {
	PrivateKey string `json:"private_key"`
}

type Conn struct {
	conn net.Conn
	enc  *json.Encoder
	mu   sync.Mutex
}

func (c *Conn) Send(p Packet) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enc.Encode(p)
}

type netMsg struct {
	pkt Packet
	err error
}

type sessionState struct {
	mu      sync.RWMutex
	conn    net.Conn
	sender  *Conn
	priv    ed25519.PrivateKey
	loginID string
	counter atomic.Uint64
}

func (s *sessionState) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.conn = nil
	s.sender = nil
	s.priv = nil
	s.loginID = ""
}

func (s *sessionState) set(conn net.Conn, sender *Conn, priv ed25519.PrivateKey, loginID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil && s.conn != conn {
		_ = s.conn.Close()
	}
	s.conn = conn
	s.sender = sender
	s.priv = priv
	s.loginID = strings.TrimSpace(loginID)
	s.counter.Store(0)
}

func (s *sessionState) snapshot() (*Conn, ed25519.PrivateKey, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sender, s.priv, s.loginID
}

func (s *sessionState) nextMessageID() string {
	n := s.counter.Add(1)
	s.mu.RLock()
	prefix := s.loginID
	s.mu.RUnlock()
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	if strings.TrimSpace(prefix) == "" {
		prefix = "fyne"
	}
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), n)
}

func loginIDForPubKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		var kf keyFile
		if err := json.Unmarshal(data, &kf); err != nil {
			return nil, err
		}
		raw, err := base64.StdEncoding.DecodeString(kf.PrivateKey)
		if err != nil {
			return nil, err
		}
		if len(raw) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid private key size")
		}
		return ed25519.PrivateKey(raw), nil
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	payload, err := json.MarshalIndent(keyFile{PrivateKey: base64.StdEncoding.EncodeToString(priv)}, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, payload, 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func signAction(priv ed25519.PrivateKey, p Packet) (string, error) {
	msg, err := json.Marshal(signedAction{
		Type:        p.Type,
		ID:          p.ID,
		From:        p.From,
		To:          p.To,
		Body:        p.Body,
		Compression: p.Compression,
		USize:       p.USize,
		Group:       p.Group,
		Channel:     p.Channel,
		CreatedAt:   p.CreatedAt,
	})
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, msg)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func runAuth(addr string, priv ed25519.PrivateKey) (net.Conn, *Conn, <-chan netMsg, string, error) {
	pub := priv.Public().(ed25519.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	conn, err := tls.Dial("tcp", addr, netsec.ClientTLSConfigInsecure())
	if err != nil {
		return nil, nil, nil, "", err
	}
	enc := &Conn{conn: conn, enc: json.NewEncoder(conn)}
	dec := json.NewDecoder(conn)

	if err := enc.Send(Packet{Type: "hello", Role: "user", PubKey: pubB64}); err != nil {
		_ = conn.Close()
		return nil, nil, nil, "", err
	}

	var challenge Packet
	if err := dec.Decode(&challenge); err != nil {
		_ = conn.Close()
		return nil, nil, nil, "", err
	}
	if challenge.Type != "challenge" || strings.TrimSpace(challenge.Nonce) == "" {
		_ = conn.Close()
		return nil, nil, nil, "", fmt.Errorf("invalid challenge")
	}

	loginSig := ed25519.Sign(priv, []byte("login:"+challenge.Nonce))
	if err := enc.Send(Packet{Type: "auth", PubKey: pubB64, Sig: base64.StdEncoding.EncodeToString(loginSig)}); err != nil {
		_ = conn.Close()
		return nil, nil, nil, "", err
	}

	var resp Packet
	if err := dec.Decode(&resp); err != nil {
		_ = conn.Close()
		return nil, nil, nil, "", err
	}
	if resp.Type != "ok" || strings.TrimSpace(resp.ID) == "" {
		_ = conn.Close()
		if resp.Type == "error" {
			return nil, nil, nil, "", fmt.Errorf("auth failed: %s", resp.Body)
		}
		return nil, nil, nil, "", fmt.Errorf("invalid auth response")
	}

	loginID := strings.TrimSpace(resp.ID)
	if expected := loginIDForPubKey(pub); expected != loginID {
		_ = conn.Close()
		return nil, nil, nil, "", fmt.Errorf("login id mismatch")
	}

	events := make(chan netMsg, 64)
	go func() {
		defer close(events)
		for {
			var p Packet
			if err := dec.Decode(&p); err != nil {
				events <- netMsg{err: err}
				return
			}
			events <- netMsg{pkt: p}
		}
	}()

	return conn, enc, events, loginID, nil
}

func main() {
	home, _ := os.UserHomeDir()
	defaultKeyPath := filepath.Join(home, ".goaccord", "ed25519_key.json")

	fy := app.NewWithID("io.goaccord.client.fyne")
	w := fy.NewWindow("goAccord Fyne Client")
	w.Resize(fyne.NewSize(980, 700))

	var logsMu sync.Mutex
	logs := make([]string, 0, 512)
	appendLog := func(line string, logEntry *widget.Entry) {
		logsMu.Lock()
		logs = append(logs, fmt.Sprintf("%s %s", time.Now().Format("15:04:05"), line))
		if len(logs) > 1200 {
			logs = logs[len(logs)-1200:]
		}
		joined := strings.Join(logs, "\n")
		logsMu.Unlock()
		fyne.Do(func() {
			logEntry.SetText(joined)
			logEntry.CursorRow = 1 << 20
			logEntry.CursorColumn = 0
		})
	}

	state := &sessionState{}

	serverEntry := widget.NewEntry()
	serverEntry.SetText("127.0.0.1:9101")
	keyEntry := widget.NewEntry()
	keyEntry.SetText(defaultKeyPath)
	recipientEntry := widget.NewEntry()
	recipientEntry.SetPlaceHolder("recipient login_id")
	messageEntry := widget.NewMultiLineEntry()
	messageEntry.SetMinRowsVisible(3)
	messageEntry.SetPlaceHolder("type direct message")

	logEntry := widget.NewMultiLineEntry()
	logEntry.SetMinRowsVisible(20)
	logEntry.Disable()

	handleEvent := func(p Packet, logEntry *widget.Entry) {
		switch p.Type {
		case "deliver":
			appendLog(fmt.Sprintf("deliver from=%s to=%s body=%s", shortID(p.From), shortID(p.To), p.Body), logEntry)
		case "channel_deliver":
			appendLog(fmt.Sprintf("channel %s/%s from=%s body=%s", p.Group, p.Channel, shortID(p.From), p.Body), logEntry)
		case "error":
			appendLog("server error: "+p.Body, logEntry)
		default:
			raw, _ := json.Marshal(p)
			appendLog("event: "+string(raw), logEntry)
		}
	}

	connectBtn := widget.NewButton("Connect", func() {
		addr := strings.TrimSpace(serverEntry.Text)
		keyPath := strings.TrimSpace(keyEntry.Text)
		if addr == "" || keyPath == "" {
			appendLog("missing server address or key path", logEntry)
			return
		}

		priv, err := loadOrCreateKey(keyPath)
		if err != nil {
			appendLog("key load/create failed: "+err.Error(), logEntry)
			return
		}
		conn, sender, events, loginID, err := runAuth(addr, priv)
		if err != nil {
			appendLog("connect/auth failed: "+err.Error(), logEntry)
			return
		}

		state.set(conn, sender, priv, loginID)
		appendLog("connected login_id="+loginID, logEntry)
		go func() {
			for ev := range events {
				if ev.err != nil {
					appendLog("connection closed: "+ev.err.Error(), logEntry)
					state.close()
					return
				}
				handleEvent(ev.pkt, logEntry)
			}
		}()
	})

	sendBtn := widget.NewButton("Send DM", func() {
		to := strings.TrimSpace(recipientEntry.Text)
		body := strings.TrimSpace(messageEntry.Text)
		if to == "" || body == "" {
			appendLog("recipient and message are required", logEntry)
			return
		}

		sender, priv, from := state.snapshot()
		if sender == nil || len(priv) == 0 || strings.TrimSpace(from) == "" {
			appendLog("not connected", logEntry)
			return
		}

		p := Packet{
			Type:      "send",
			ID:        state.nextMessageID(),
			From:      from,
			To:        to,
			Body:      body,
			CreatedAt: time.Now().UnixMilli(),
		}
		sig, err := signAction(priv, p)
		if err != nil {
			appendLog("sign failed: "+err.Error(), logEntry)
			return
		}
		pub := priv.Public().(ed25519.PublicKey)
		p.PubKey = base64.StdEncoding.EncodeToString(pub)
		p.Sig = sig
		if err := sender.Send(p); err != nil {
			appendLog("send failed: "+err.Error(), logEntry)
			return
		}
		appendLog(fmt.Sprintf("sent to=%s body=%s", shortID(to), body), logEntry)
		messageEntry.SetText("")
	})

	disconnectBtn := widget.NewButton("Disconnect", func() {
		state.close()
		appendLog("disconnected", logEntry)
	})

	top := container.NewGridWithColumns(6,
		widget.NewLabel("Server"), serverEntry,
		widget.NewLabel("Key File"), keyEntry,
		connectBtn, disconnectBtn,
	)
	composer := container.NewBorder(nil, nil, nil, sendBtn,
		container.NewVBox(widget.NewLabel("To"), recipientEntry, widget.NewLabel("Message"), messageEntry),
	)
	content := container.NewBorder(
		container.NewVBox(top),
		container.NewVBox(layout.NewSpacer(), composer),
		nil, nil,
		container.NewVBox(widget.NewLabel("Events"), logEntry),
	)

	w.SetContent(content)
	w.SetCloseIntercept(func() {
		state.close()
		w.Close()
	})
	appendLog("ready", logEntry)
	w.ShowAndRun()
}

func shortID(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}
