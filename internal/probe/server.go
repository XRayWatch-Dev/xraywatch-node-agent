package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/XRayWatch-Dev/xraywatch-node-agent/internal/ticket"
)

const (
	MaxPayload        = 256 << 10
	MaxTCPConnections = 64
)

type Server struct {
	Address  string
	TCP      net.Listener
	UDP      net.PacketConn
	WG       sync.WaitGroup
	Tickets  *ticket.Verifier
	Events   chan Event
	tcpSlots chan struct{}
}
type Event struct {
	RunID      string
	EndpointID string
	Protocol   string
	Bytes      int
	ObservedAt time.Time
}

func Listen(address string, tickets *ticket.Verifier) (*Server, error) {
	if tickets == nil {
		return nil, errors.New("probe ticket verifier is required")
	}
	tcp, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenPacket("udp", address)
	if err != nil {
		tcp.Close()
		return nil, err
	}
	return &Server{Address: address, TCP: tcp, UDP: udp, Tickets: tickets, Events: make(chan Event, 256), tcpSlots: make(chan struct{}, MaxTCPConnections)}, nil
}

func (s *Server) Serve(ctx context.Context) {
	s.WG.Add(2)
	go s.serveTCP(ctx)
	go s.serveUDP(ctx)
	go func() { <-ctx.Done(); s.TCP.Close(); s.UDP.Close() }()
}

func (s *Server) Wait() { s.WG.Wait() }

func (s *Server) serveTCP(ctx context.Context) {
	defer s.WG.Done()
	for {
		conn, err := s.TCP.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		select {
		case s.tcpSlots <- struct{}{}:
			go func() {
				defer func() { <-s.tcpSlots }()
				handleTCP(conn, s.Tickets, s.Events)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func handleTCP(conn net.Conn, tickets *ticket.Verifier, events chan<- Event) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return
	}
	ticketLength := binary.BigEndian.Uint32(header[:])
	if ticketLength < 1 || ticketLength > 4096 {
		return
	}
	ticketBytes := make([]byte, ticketLength)
	if _, err := io.ReadFull(conn, ticketBytes); err != nil {
		return
	}
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxPayload {
		return
	}
	probeTicket, err := tickets.Verify(ticketBytes, "tcp", int(n))
	if err != nil {
		return
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return
	}
	_, _ = conn.Write(append(header[:], payload...))
	select {
	case events <- Event{RunID: probeTicket.RunID, EndpointID: probeTicket.EndpointID, Protocol: "tcp", Bytes: int(n), ObservedAt: time.Now().UTC()}:
	default:
	}
}

func (s *Server) serveUDP(ctx context.Context) {
	defer s.WG.Done()
	buf := make([]byte, 4354)
	for {
		n, addr, err := s.UDP.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		// A short datagram is the reachability challenge; responses are always
		// capped and amplification is impossible (response <= request).
		if n < 19 {
			continue
		}
		ticketLength := int(binary.BigEndian.Uint16(buf[:2]))
		if ticketLength < 1 || ticketLength > 4096 || 2+ticketLength >= n {
			continue
		}
		payload := buf[2+ticketLength : n]
		probeTicket, verifyErr := s.Tickets.Verify(buf[2:2+ticketLength], "udp", len(payload))
		if len(payload) < 16 || len(payload) > 256 || verifyErr != nil {
			continue
		}
		_, _ = s.UDP.WriteTo(payload, addr)
		select {
		case s.Events <- Event{RunID: probeTicket.RunID, EndpointID: probeTicket.EndpointID, Protocol: "udp", Bytes: len(payload), ObservedAt: time.Now().UTC()}:
		default:
		}
	}
}

var ErrInvalidPayload = errors.New("invalid probe payload")
