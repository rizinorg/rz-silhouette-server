package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	capnp "capnproto.org/go/capnp/v3"

	"rz-silhouette-server/servicecapnp"
)

func buildCapnpPingPacket(packed bool) ([]byte, error) {
	msg, seg := capnp.NewSingleSegmentMessage(nil)
	root, err := servicecapnp.NewRootSilRequest(seg)
	if err != nil {
		return nil, err
	}
	if err := root.SetPsk("demo-psk"); err != nil {
		return nil, err
	}
	root.SetVersion(PROTOCOL_VERSION)
	root.SetRoute(servicecapnp.SilRoute_ping)
	if _, err := root.NewPing(); err != nil {
		return nil, err
	}
	if packed {
		return msg.MarshalPacked()
	}
	return msg.Marshal()
}

func TestDecodeCapnpRequestPing(t *testing.T) {
	packet, err := buildCapnpPingPacket(true)
	if err != nil {
		t.Fatal(err)
	}

	req, err := decodeCapnpRequest(packet)
	if err != nil {
		t.Fatal(err)
	}
	if req.Psk != "demo-psk" {
		t.Fatalf("unexpected psk: %q", req.Psk)
	}
	if req.Version != PROTOCOL_VERSION {
		t.Fatalf("unexpected version: %d", req.Version)
	}
	if req.Route != servicecapnp.SilRoute_ping {
		t.Fatalf("unexpected route: %s", req.Route)
	}
}

func TestDecodeCapnpRequestPingUnpacked(t *testing.T) {
	packet, err := buildCapnpPingPacket(false)
	if err != nil {
		t.Fatal(err)
	}

	msg, err := capnp.Unmarshal(packet)
	if err != nil {
		t.Fatal(err)
	}
	root, err := servicecapnp.ReadRootSilRequest(msg)
	if err != nil {
		t.Fatal(err)
	}
	psk, err := root.Psk()
	if err != nil {
		t.Fatal(err)
	}
	if psk != "demo-psk" {
		t.Fatalf("unexpected psk: %q", psk)
	}
	if root.Version() != PROTOCOL_VERSION {
		t.Fatalf("unexpected version: %d", root.Version())
	}
	if root.Route() != servicecapnp.SilRoute_ping {
		t.Fatalf("unexpected route: %s", root.Route())
	}
}

func TestCapnpPingGoldenFixture(t *testing.T) {
	packet, err := buildCapnpPingPacket(true)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join("testdata", "capnp_ping_request.hex"))
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(packet)
	want := strings.TrimSpace(string(body))
	if got != want {
		t.Fatalf("capnp ping fixture drifted\n got: %s\nwant: %s", got, want)
	}
}

func BenchmarkPingCodecCapnpPacked(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		packet, err := buildCapnpPingPacket(true)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := decodeCapnpRequest(packet); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPingCodecCapnpUnpacked(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		packet, err := buildCapnpPingPacket(false)
		if err != nil {
			b.Fatal(err)
		}
		msg, err := capnp.Unmarshal(packet)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := servicecapnp.ReadRootSilRequest(msg); err != nil {
			b.Fatal(err)
		}
	}
}
