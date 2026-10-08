// Package dnscatch runs a tiny UDP DNS server that logs every query it
// receives. It is used to catch blind out-of-band exfiltration that only leaves
// the target over DNS (common with blind XXE/SSRF/RCE).
package dnscatch

import (
	"encoding/binary"
	"net"
	"strings"

	"gocatcher/internal/capture"
	"gocatcher/internal/ui"
)

// Server is a minimal DNS responder.
type Server struct {
	conn  *net.UDPConn
	store *capture.Store
}

// Start binds addr (e.g. "0.0.0.0:5353") and serves until Stop. Queries are
// recorded in store and printed. It answers every A query with 127.0.0.1 so the
// resolver completes and the target keeps talking.
func Start(addr string, store *capture.Store) (*Server, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	s := &Server{conn: conn, store: store}
	go s.loop()
	ui.Info("DNS callback listener on udp://" + addr)
	return s, nil
}

func (s *Server) loop() {
	buf := make([]byte, 512)
	for {
		n, client, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed
		}
		if n < 12 {
			continue
		}
		msg := make([]byte, n)
		copy(msg, buf[:n])
		name := parseQName(msg)
		rec := capture.Record{
			Proto: "dns", Method: "DNS", Host: name, Path: name,
			Remote: client.IP.String(), Token: firstLabel(name),
		}
		s.store.Add(rec)
		ui.Info("DNS query: " + name + " from " + client.IP.String())
		if resp := buildResponse(msg); resp != nil {
			s.conn.WriteToUDP(resp, client)
		}
	}
}

// Stop closes the listener.
func (s *Server) Stop() {
	if s.conn != nil {
		s.conn.Close()
	}
}

// parseQName reads the QNAME from the question section.
func parseQName(msg []byte) string {
	var labels []string
	i := 12
	for i < len(msg) {
		l := int(msg[i])
		if l == 0 {
			break
		}
		i++
		if i+l > len(msg) {
			break
		}
		labels = append(labels, string(msg[i:i+l]))
		i += l
	}
	return strings.Join(labels, ".")
}

func firstLabel(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[:i]
	}
	return name
}

// buildResponse echoes the question and appends a single A record (127.0.0.1).
func buildResponse(q []byte) []byte {
	// Find end of question section (QNAME + QTYPE(2) + QCLASS(2)).
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	i++    // zero label
	i += 4 // qtype + qclass
	if i > len(q) {
		return nil
	}
	resp := make([]byte, i)
	copy(resp, q[:i])
	// Flags: standard query response, recursion available, no error.
	binary.BigEndian.PutUint16(resp[2:], 0x8180)
	binary.BigEndian.PutUint16(resp[6:], 1) // ANCOUNT = 1

	answer := []byte{
		0xc0, 0x0c, // name pointer to offset 12 (the question)
		0x00, 0x01, // type A
		0x00, 0x01, // class IN
		0x00, 0x00, 0x00, 0x3c, // TTL 60
		0x00, 0x04, // RDLENGTH 4
		127, 0, 0, 1, // RDATA 127.0.0.1
	}
	return append(resp, answer...)
}
