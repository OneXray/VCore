package main

import (
	"net"
	"testing"
)

// The external load driver's only local peer is in-memory IPC, not a host server.
func TestSlowReaderPausesEvenInsideARecordRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	r := request{Transport: "tcp", Seconds: 2, BytesPerSecond: 65536, Seed: 7,
		PauseEveryMS: 200, PauseForMS: 50}
	sent := make(chan result, 1)
	go func() { sent <- transfer(server, r, true) }()
	got := transfer(client, r, false)
	written := <-sent
	if got.Error != "" || written.Error != "" || got.Digest != written.Digest {
		t.Fatalf("incorrect transfer: receive=%+v send=%+v", got, written)
	}
	// Each 64 KiB record is sent a second apart. The read waiting for the
	// second record must pause at 200/400/600/800 ms, not only between records.
	if len(got.ReadPauses) < 4 {
		t.Fatalf("blocking read skipped scheduled pauses: %v", got.ReadPauses)
	}
}
