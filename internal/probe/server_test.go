package probe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/XRayWatch-Dev/xraywatch-node-agent/internal/ticket"
)

func TestTCPAndUDPBounds(t *testing.T) {
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	verifier, _ := ticket.New(base64.StdEncoding.EncodeToString(pub), "node")
	s, err := Listen("127.0.0.1:0", verifier)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.Serve(ctx)
	defer func() { cancel(); s.Wait() }()
	addr := s.TCP.Addr().String()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("12345678")
	tcpTicket, _ := ticket.Sign(private, ticket.Probe{RunID: "run", NodeID: "node", EndpointID: "endpoint", Protocol: "tcp", PayloadBudget: len(payload), ExpiresAt: time.Now().Add(time.Minute), Nonce: "0123456789abcdef"})
	var ticketHeader, h [4]byte
	binary.BigEndian.PutUint32(ticketHeader[:], uint32(len(tcpTicket)))
	binary.BigEndian.PutUint32(h[:], uint32(len(payload)))
	c.Write(append(append(append(ticketHeader[:], tcpTicket...), h[:]...), payload...))
	got := make([]byte, 4+len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	c.Close()
	u, err := net.Dial("udp", s.UDP.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(time.Second))
	challenge := []byte("0123456789abcdef")
	udpTicket, _ := ticket.Sign(private, ticket.Probe{RunID: "run", NodeID: "node", EndpointID: "endpoint", Protocol: "udp", PayloadBudget: len(challenge), ExpiresAt: time.Now().Add(time.Minute), Nonce: "fedcba9876543210"})
	packet := make([]byte, 2)
	binary.BigEndian.PutUint16(packet, uint16(len(udpTicket)))
	packet = append(append(packet, udpTicket...), challenge...)
	u.Write(packet)
	response := make([]byte, 256)
	n, err := u.Read(response)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(challenge) {
		t.Fatalf("udp response=%d", n)
	}
}

func TestTCPConcurrencyIsBounded(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	verifier, _ := ticket.New(base64.StdEncoding.EncodeToString(pub), "node")
	s, err := Listen("127.0.0.1:0", verifier)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.Serve(ctx)
	defer func() { cancel(); s.Wait() }()

	connections := make([]net.Conn, 0, MaxTCPConnections)
	defer func() {
		for _, conn := range connections {
			_ = conn.Close()
		}
	}()
	for i := 0; i < MaxTCPConnections; i++ {
		conn, dialErr := net.Dial("tcp", s.TCP.Addr().String())
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		connections = append(connections, conn)
	}
	deadline := time.Now().Add(time.Second)
	for len(s.tcpSlots) != MaxTCPConnections && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(s.tcpSlots); got != MaxTCPConnections {
		t.Fatalf("active TCP handlers=%d, want %d", got, MaxTCPConnections)
	}

	extra, err := net.Dial("tcp", s.TCP.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := extra.Read(one[:]); err == nil {
		t.Fatal("connection beyond admission limit remained open")
	}
}
