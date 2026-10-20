package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/XRayWatch-Dev/xraywatch-node-agent/internal/control"
	"github.com/XRayWatch-Dev/xraywatch-node-agent/internal/probe"
	"github.com/XRayWatch-Dev/xraywatch-node-agent/internal/state"
	"github.com/XRayWatch-Dev/xraywatch-node-agent/internal/ticket"
)

var version = "dev"

func main() {
	enroll := flag.Bool("enroll", false, "enroll this host using a token read from stdin")
	showVersion := flag.Bool("version", false, "print agent version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	controlURL := mustEnv("XRAYWATCH_CONTROL_URL")
	stateDir := env("XRAYWATCH_STATE_DIR", "/var/lib/xraywatch")
	port, err := strconv.Atoi(env("XRAYWATCH_LISTEN_PORT", "18443"))
	if err != nil || port < 1 || port > 65535 {
		log.Fatal("invalid XRAYWATCH_LISTEN_PORT")
	}
	if *enroll {
		enrollHost(controlURL, stateDir, port)
		return
	}
	identity, err := state.Load(stateDir)
	if err != nil {
		log.Fatalf("load identity: %v; run with --enroll", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	verifier, err := ticket.New(mustEnv("XRAYWATCH_TRUST_KEY"), identity.NodeID)
	if err != nil {
		log.Fatal(err)
	}
	server, err := probe.Listen(fmt.Sprintf(":%d", port), verifier)
	if err != nil {
		log.Fatalf("listen TCP+UDP port %d: %v", port, err)
	}
	server.Serve(ctx)
	go func() {
		for event := range server.Events {
			_ = state.AppendObservation(stateDir, state.Observation{RunID: event.RunID, EndpointID: event.EndpointID, ObservedAt: event.ObservedAt.Format(time.RFC3339Nano), Stages: map[string]any{event.Protocol: map[string]any{"bytes": event.Bytes, "complete": true}}})
		}
	}()
	client := &control.Client{BaseURL: controlURL, NodeID: identity.NodeID, Secret: identity.Secret, Version: version}
	log.Printf("XRayWatch node agent version=%s node_id=%s listen_port=%d", version, identity.NodeID, port)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if err := client.Heartbeat(ctx, port); err != nil && ctx.Err() == nil {
			log.Printf("heartbeat failed: %v", err)
		}
		if items, err := state.ReadObservations(stateDir); err == nil && len(items) > 0 {
			if err := client.Observations(ctx, items); err == nil {
				_ = state.AckObservations(stateDir, len(items))
			} else if ctx.Err() == nil {
				log.Printf("observation delivery failed: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			server.Wait()
			return
		case <-ticker.C:
		}
	}
}

func enrollHost(controlURL, stateDir string, port int) {
	fmt.Fprint(os.Stderr, "Enrollment token: ")
	token, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	nodeID, secret, err := control.Enroll(context.Background(), controlURL, strings.TrimSpace(token), port)
	if err != nil {
		log.Fatal(err)
	}
	if err := state.Save(stateDir, state.Identity{NodeID: nodeID, Secret: secret}); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "XRayWatch node enrolled: %s\n", nodeID)
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
func mustEnv(key string) string {
	value := env(key, "")
	if value == "" {
		log.Fatalf("%s is required", key)
	}
	return value
}
