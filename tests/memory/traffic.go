// Bounded, native traffic generator/validator. This is a test origin, never a
// proxy implementation. The origin can run only in a harness-owned Linux guest.
// Only application records count; control connections and SOCKS headers do not.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type request struct {
	Transport      string `json:"transport"`
	Direction      string `json:"direction"`
	Seconds        int    `json:"seconds"`
	BytesPerSecond int64  `json:"bytes_per_second"`
	Seed           uint64 `json:"seed"`
	ExpectedSource string `json:"expected_source,omitempty"`
	TargetHost     string `json:"-"`
	TargetIP       string `json:"-"`
	PauseEveryMS   int    `json:"pause_every_ms,omitempty"`
	PauseForMS     int    `json:"pause_for_ms,omitempty"`
	Probe          bool   `json:"probe,omitempty"`
	InitialHello   bool   `json:"initial_hello,omitempty"`
	Correctness    bool   `json:"correctness,omitempty"`
	ProbeRounds    int    `json:"probe_rounds,omitempty"`
}
type result struct {
	Bytes      int64   `json:"bytes"`
	Packets    int64   `json:"packets"`
	Elapsed    float64 `json:"seconds"`
	Digest     string  `json:"sha256,omitempty"`
	Reordered  int64   `json:"reordered"`
	MaxLateNS  int64   `json:"max_pacing_lag_ns"`
	Windows    []int64 `json:"bytes_per_second"`
	Error      string  `json:"error,omitempty"`
	Missing    []int64 `json:"first_missing_sequences,omitempty"`
	ReadPauses []int64 `json:"read_pauses_ms,omitempty"`
}
type flowResult struct {
	Transport      string `json:"transport"`
	Direction      string `json:"direction"`
	Sent           result `json:"sent"`
	Received       result `json:"received"`
	Error          string `json:"error,omitempty"`
	SourceVerified bool   `json:"source_verified"`
}

type duplexResult struct {
	Up   result `json:"up"`
	Down result `json:"down"`
}

func frameSize(r request) int {
	if r.Probe {
		return 32
	}
	if r.Transport == "udp" {
		return 1200
	}
	return 65536
}
func count(r request) int64 {
	if r.Probe {
		return int64(r.ProbeRounds)
	}
	if r.Correctness && r.Transport == "udp" {
		return int64(r.Seconds) * 20
	}
	return r.BytesPerSecond * int64(r.Seconds) / int64(frameSize(r))
}

func payloadSize(r request, sequence int64) int {
	if r.Correctness && r.Transport == "udp" {
		return []int{64, 512, 1200}[sequence%3]
	}
	return frameSize(r)
}

func totalBytes(r request) int64 {
	if r.Correctness && r.Transport == "udp" {
		packets := count(r)
		total := packets / 3 * 1776
		for index := int64(0); index < packets%3; index++ {
			total += int64(payloadSize(r, index))
		}
		return total
	}
	return count(r) * int64(frameSize(r))
}
func validate(r request) error {
	if (r.Transport != "tcp" && r.Transport != "udp") ||
		(r.Direction != "up" && r.Direction != "down" && r.Direction != "both") || r.Seconds < 1 || r.Seconds > 300 ||
		r.BytesPerSecond < 1 || r.BytesPerSecond > 125000000 || count(r) == 0 {
		return errors.New("invalid bounded workload")
	}
	if r.Probe && (r.ProbeRounds < 1 || r.ProbeRounds > 100 || r.Seconds != (r.ProbeRounds+19)/20) {
		return errors.New("invalid probe count")
	}
	if r.PauseEveryMS != 0 || r.PauseForMS != 0 {
		if r.Transport != "tcp" || r.PauseForMS < 1 || r.PauseEveryMS <= r.PauseForMS || r.PauseEveryMS >= r.Seconds*1000 {
			return errors.New("invalid read-pause schedule")
		}
	}
	return nil
}

func pattern(buf []byte, seq, seed uint64) {
	binary.LittleEndian.PutUint64(buf, seq)
	for i := 8; i < len(buf); i += 8 {
		binary.LittleEndian.PutUint64(buf[i:], seq^seed^uint64(i)*0x9e3779b97f4a7c15)
	}
}
func check(buf []byte, seed uint64) bool {
	seq := binary.LittleEndian.Uint64(buf)
	for i := 8; i < len(buf); i += 8 {
		if binary.LittleEndian.Uint64(buf[i:]) != seq^seed^uint64(i)*0x9e3779b97f4a7c15 {
			return false
		}
	}
	return true
}
func writeAll(conn net.Conn, buf []byte) error {
	for len(buf) > 0 {
		n, err := conn.Write(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
	}
	return nil
}
func pace(deadline time.Time) {
	if delay := time.Until(deadline); delay > 0 {
		time.Sleep(delay)
	}
}

type udpSendJob struct {
	conn  net.Conn
	r     request
	done  chan result
	out   result
	start time.Time
	buf   [1200]byte
}

var udpJobs = make(chan *udpSendJob, 64)
var udpOnce sync.Once
var udpPacingCredit = 16

// A controller selection is made before each flow's first packet, then the
// origin's readiness acknowledgement proves its UDP transport was established.
// The next selection cannot migrate that transport. No test-only core API.
type flowSelection struct {
	Controller string   `json:"controller"`
	Secret     string   `json:"secret"`
	Group      string   `json:"group"`
	Members    []string `json:"members"`
}

var selectionFile string
var slowFlows, pauseEveryMS, pauseForMS int
var probeMode bool
var correctnessMode bool
var probeRounds int

func loadSelection(flows int) (*flowSelection, error) {
	if selectionFile == "" {
		return nil, nil
	}
	file, err := os.Open(selectionFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var selected flowSelection
	decoder := json.NewDecoder(io.LimitReader(file, 8192))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&selected) != nil || len(selected.Members) != flows || selected.Group == "" || selected.Secret == "" {
		return nil, errors.New("invalid flow selection configuration")
	}
	host, _, err := net.SplitHostPort(selected.Controller)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return nil, errors.New("flow selection requires a loopback controller")
	}
	return &selected, nil
}

func (s *flowSelection) choose(index int) error {
	body, _ := json.Marshal(map[string]string{"name": s.Members[index]})
	req, err := http.NewRequest("PUT", "http://"+s.Controller+"/proxies/"+url.PathEscape(s.Group), bytes.NewReader(body))
	if err != nil {
		return errors.New("controller request construction")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.Secret)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Do(req)
	if err != nil {
		return errors.New("controller selection failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1))
	if err != nil || response.StatusCode != 204 || len(data) != 0 {
		return errors.New("controller did not confirm selection")
	}
	return nil
}

// One process-local pacer owns all UDP sends. Per-flow timers otherwise wake
// together and repay arbitrary scheduling delays as bursts into the proxy.
// This queue holds bounded flow jobs, never a growing queue of datagrams.
func udpSender() {
	jobs := make([]*udpSendJob, 0, 64)
	var due time.Time
	index := 0
	for {
		if len(jobs) == 0 {
			jobs = append(jobs, <-udpJobs)
			due = time.Now()
			index = 0
		}
		var rate int64
		for _, job := range jobs {
			rate += job.r.BytesPerSecond
		}
		select {
		case job := <-udpJobs:
			// Round-robin is exact for this driver's equal-rate flows only.
			if len(jobs) == 64 || job.r.BytesPerSecond != jobs[0].r.BytesPerSecond || rate+job.r.BytesPerSecond > 125000000 {
				job.done <- result{Error: "UDP aggregate workload exceeds bound"}
			} else {
				jobs = append(jobs, job)
				rate += job.r.BytesPerSecond
			}
		default:
		}
		period := time.Duration(1200 * int64(time.Second) / rate)
		// At most 16 records of timing credit. Discard excess credit, not
		// payload: all prescribed records still have to arrive within the
		// independently checked 1% timing/goodput bounds to pass.
		if earliest := time.Now().Add(-time.Duration(udpPacingCredit) * period); earliest.After(due) {
			due = earliest
		}
		if delay := time.Until(due); delay > 100*time.Microsecond {
			time.Sleep(delay - 50*time.Microsecond)
		}
		// A single external-driver thread handles the sub-timer-resolution
		// tail. No per-packet lock or one busy-waiting thread per flow.
		for time.Now().Before(due) {
		}
		job := jobs[index]
		now := time.Now()
		if job.start.IsZero() {
			job.start = now
		}
		offset := job.out.Packets * 1200
		nominal := offset/job.r.BytesPerSecond*int64(time.Second) +
			offset%job.r.BytesPerSecond*int64(time.Second)/job.r.BytesPerSecond
		if late := now.Sub(job.start).Nanoseconds() - nominal; late > job.out.MaxLateNS {
			job.out.MaxLateNS = late
		}
		payload := job.buf[:payloadSize(job.r, job.out.Packets)]
		pattern(payload, uint64(job.out.Packets), job.r.Seed)
		n, err := job.conn.Write(payload)
		if err != nil || n != len(payload) {
			job.out.Error = "send failed"
		} else {
			job.out.Packets++
			job.out.Bytes += int64(n)
			window := int(time.Since(job.start) / time.Second)
			if window >= len(job.out.Windows) {
				job.out.Error = "unbounded drain"
			} else {
				job.out.Windows[window] += int64(n)
			}
		}
		if job.out.Error != "" || job.out.Packets == count(job.r) {
			job.out.Elapsed = time.Since(job.start).Seconds()
			job.done <- job.out
			copy(jobs[index:], jobs[index+1:])
			jobs[len(jobs)-1] = nil
			jobs = jobs[:len(jobs)-1]
		} else {
			index++
		}
		if index >= len(jobs) {
			index = 0
		}
		due = due.Add(period)
	}
}

func sendUDP(conn net.Conn, r request) result {
	udpOnce.Do(func() { go udpSender() })
	job := &udpSendJob{conn: conn, r: r, done: make(chan result, 1), out: result{Windows: make([]int64, r.Seconds+3)}}
	conn.SetWriteDeadline(time.Now().Add(time.Duration(r.Seconds+3) * time.Second))
	defer conn.SetWriteDeadline(time.Time{})
	udpJobs <- job
	return <-job.done
}

func transfer(conn net.Conn, r request, send bool) result {
	if send && r.Transport == "udp" && !r.Probe {
		return sendUDP(conn, r)
	}
	size, total := frameSize(r), count(r)
	buf := make([]byte, size)
	bitmap := make([]byte, (total+7)/8)
	digest := sha256.New()
	out := result{Windows: make([]int64, r.Seconds+3)}
	start := time.Now()
	setDeadline := conn.SetReadDeadline
	if send {
		setDeadline = conn.SetWriteDeadline
	}
	setDeadline(start.Add(time.Duration(r.Seconds+3) * time.Second))
	defer setDeadline(time.Time{})
	highest := int64(-1)
	nextPause := start.Add(time.Duration(r.PauseEveryMS) * time.Millisecond)
	for seq := int64(0); seq < total; seq++ {
		actualSize := payloadSize(r, seq)
		if send {
			// Split the division so a 300-second, 1 Gbps run cannot overflow.
			offset := seq * int64(size)
			nanoseconds := offset/r.BytesPerSecond*int64(time.Second) +
				offset%r.BytesPerSecond*int64(time.Second)/r.BytesPerSecond
			due := start.Add(time.Duration(nanoseconds))
			pace(due)
			if late := time.Since(due).Nanoseconds(); late > out.MaxLateNS {
				out.MaxLateNS = late
			}
			pattern(buf[:actualSize], uint64(seq), r.Seed)
			if writeAll(conn, buf[:actualSize]) != nil {
				out.Error = "send failed"
				break
			}
		} else {
			if r.PauseEveryMS > 0 && !time.Now().Before(nextPause) && time.Since(start) < time.Duration(r.Seconds)*time.Second {
				out.ReadPauses = append(out.ReadPauses, time.Since(start).Milliseconds())
				time.Sleep(time.Duration(r.PauseForMS) * time.Millisecond)
				nextPause = nextPause.Add(time.Duration(r.PauseEveryMS) * time.Millisecond)
			}
			var n int
			var err error
			if r.Transport == "tcp" {
				n, err = io.ReadFull(conn, buf)
			} else {
				n, err = conn.Read(buf)
			}
			if err != nil || n < 8 {
				out.Error = "receive incomplete"
				break
			}
			id := binary.LittleEndian.Uint64(buf)
			if id >= uint64(total) || n != payloadSize(r, int64(id)) || !check(buf[:n], r.Seed) {
				out.Error = "payload corruption"
				break
			}
			if r.Transport == "tcp" && id != uint64(seq) {
				out.Error = "TCP sequence mismatch"
				break
			}
			index, bit := id/8, byte(1<<(id%8))
			if bitmap[index]&bit != 0 {
				out.Error = "duplicate datagram"
				break
			}
			bitmap[index] |= bit
			actualSize = n
			if int64(id) < highest {
				out.Reordered++
			} else {
				highest = int64(id)
			}
		}
		if r.Transport == "tcp" {
			digest.Write(buf)
		}
		out.Bytes += int64(actualSize)
		out.Packets++
		window := int(time.Since(start) / time.Second)
		if window >= len(out.Windows) {
			out.Error = "unbounded drain"
			break
		}
		out.Windows[window] += int64(actualSize)
	}
	out.Elapsed = time.Since(start).Seconds()
	if !send && r.Transport == "udp" && out.Packets != total {
		for id := int64(0); id < total && len(out.Missing) < 16; id++ {
			if bitmap[id/8]&(1<<uint(id%8)) == 0 {
				out.Missing = append(out.Missing, id)
			}
		}
	}
	if r.Transport == "tcp" {
		out.Digest = hex.EncodeToString(digest.Sum(nil))
	}
	return out
}

// Two independent payload sequences share one TCP connection. Directional
// deadlines keep a completed sender from clearing the receiver's drain bound.
func transferDuplex(conn net.Conn, r request, client bool) duplexResult {
	up := make(chan result, 1)
	upRequest, downRequest := r, r
	upRequest.Direction, downRequest.Direction = "up", "down"
	downRequest.Seed ^= 0xd6e8feb86659fd93
	go func() { up <- transfer(conn, upRequest, client) }()
	down := transfer(conn, downRequest, !client)
	return duplexResult{Up: <-up, Down: down}
}

// A connected packet adapter for the server; first datagram pins the peer.
// Read uses a one-byte surplus so oversized packets cannot be silently accepted.
type packetConn struct {
	*net.UDPConn
	peer    netip.AddrPort
	scratch [1463]byte
}

func (c *packetConn) Read(buf []byte) (int, error) {
	n, from, err := c.ReadFromUDPAddrPort(c.scratch[:])
	if err != nil {
		return 0, err
	}
	if from != c.peer || n > len(buf) {
		return 0, errors.New("packet source/size")
	}
	return copy(buf, c.scratch[:n]), nil
}
func (c *packetConn) Write(buf []byte) (int, error) { return c.WriteToUDPAddrPort(buf, c.peer) }
func (c *packetConn) RemoteAddr() net.Addr          { return net.UDPAddrFromAddrPort(c.peer) }

func serveFlow(control net.Conn) {
	defer control.Close()
	control.SetDeadline(time.Now().Add(315 * time.Second))
	decoder, encoder := json.NewDecoder(io.LimitReader(control, 8192)), json.NewEncoder(control)
	var r request
	if decoder.Decode(&r) != nil || validate(r) != nil {
		return
	}
	var data net.Conn
	var listener net.Listener
	var udp *net.UDPConn
	var err error
	var port int
	if r.Transport == "tcp" {
		network, bind := "tcp4", "0.0.0.0:0"
		if control.LocalAddr().(*net.TCPAddr).IP.To4() == nil {
			network, bind = "tcp6", "[::]:0"
		}
		listener, err = net.Listen(network, bind)
		if err != nil {
			return
		}
		defer listener.Close()
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
		port = listener.Addr().(*net.TCPAddr).Port
	} else {
		network := "udp4"
		if control.LocalAddr().(*net.TCPAddr).IP.To4() == nil {
			network = "udp6"
		}
		udp, err = net.ListenUDP(network, &net.UDPAddr{})
		if err != nil {
			return
		}
		defer udp.Close()
		port = udp.LocalAddr().(*net.UDPAddr).Port
	}
	if encoder.Encode(map[string]int{"port": port}) != nil {
		return
	}
	if listener != nil {
		data, err = listener.Accept()
		if err != nil {
			return
		}
		defer data.Close()
		if r.InitialHello {
			data.SetReadDeadline(time.Now().Add(10 * time.Second))
			var hello [1]byte
			if _, err := io.ReadFull(data, hello[:]); err != nil || hello[0] != 42 {
				return
			}
			data.SetReadDeadline(time.Time{})
		}
	} else {
		udp.SetReadDeadline(time.Now().Add(10 * time.Second))
		var hello [2]byte
		n, peer, e := udp.ReadFromUDPAddrPort(hello[:])
		if e != nil || n != 1 || hello[0] != 42 {
			return
		}
		data = &packetConn{UDPConn: udp, peer: peer}
	}
	sourceVerified := false
	if r.ExpectedSource != "" {
		source, _, e := net.SplitHostPort(data.RemoteAddr().String())
		sourceVerified = e == nil && net.ParseIP(source).Equal(net.ParseIP(r.ExpectedSource))
		if !sourceVerified {
			encoder.Encode(map[string]bool{"ready": false, "source_verified": false})
			return
		}
	}
	if encoder.Encode(map[string]bool{"ready": true, "source_verified": sourceVerified}) != nil {
		return
	}
	var start string
	if decoder.Decode(&start) != nil || start != "start" {
		return
	}
	if r.Direction == "both" {
		encoder.Encode(transferDuplex(data, r, false))
	} else {
		encoder.Encode(transfer(data, r, r.Direction == "down"))
	}
}

func origin() error {
	if runtime.GOOS != "linux" || os.Getenv("VCORE_ISOLATED_ORIGIN") != "1" {
		return errors.New("origin requires an owned isolated Linux container")
	}
	listener, err := net.Listen("tcp", ":24003")
	if err != nil {
		return err
	}
	defer listener.Close()
	// External origin capacity includes the 64 background flows plus fresh
	// routing witnesses. This does not change any VCore queue or admission.
	slots := make(chan struct{}, 128)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); serveFlow(conn) }()
		default:
			conn.Close()
		}
	}
}

func socksControl(proxy, target string, udp bool) (net.Conn, string, error) {
	conn, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		return nil, "", err
	}
	fail := func() (net.Conn, string, error) { conn.Close(); return nil, "", errors.New("SOCKS setup") }
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if writeAll(conn, []byte{5, 1, 0}) != nil {
		return fail()
	}
	var hello [2]byte
	if _, err = io.ReadFull(conn, hello[:]); err != nil || hello != [2]byte{5, 0} {
		return fail()
	}
	host, portString, err := net.SplitHostPort(target)
	if err != nil {
		return fail()
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		return fail()
	}
	command := byte(1)
	if udp {
		command = 3
	}
	raw := []byte{5, command, 0}
	if address := net.ParseIP(host); address != nil {
		if v4 := address.To4(); v4 != nil {
			raw = append(append(raw, 1), v4...)
		} else {
			raw = append(append(raw, 4), address.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 253 {
			return fail()
		}
		raw = append(raw, 3, byte(len(host)))
		raw = append(raw, host...)
	}
	raw = append(raw, byte(port>>8), byte(port))
	if !udp {
		// Pipeline a nonempty client-first readiness marker. Waiting for the
		// origin before writing would deadlock codecs with a lazy first write.
		raw = append(raw, 42)
	}
	if writeAll(conn, raw) != nil {
		return fail()
	}
	var reply [4]byte
	if _, err = io.ReadFull(conn, reply[:]); err != nil || !bytes.Equal(reply[:3], []byte{5, 0, 0}) {
		return fail()
	}
	length := 0
	switch reply[3] {
	case 1:
		length = 4
	case 4:
		length = 16
	default:
		return fail()
	}
	var bound [18]byte
	if _, err = io.ReadFull(conn, bound[:length+2]); err != nil {
		return fail()
	}
	ip := net.IP(bound[:length])
	relayHost := ip.String()
	if ip.IsUnspecified() {
		relayHost, _, _ = net.SplitHostPort(proxy)
	}
	conn.SetDeadline(time.Time{})
	return conn, net.JoinHostPort(relayHost, strconv.Itoa(int(binary.BigEndian.Uint16(bound[length:length+2])))), nil
}

type socksUDP struct {
	net.Conn
	control     net.Conn
	header      []byte
	expected    []byte
	readBuffer  [1463]byte
	writeBuffer [1463]byte
}

type boundedUDP struct {
	net.Conn
	scratch [1201]byte
}

func (c *boundedUDP) Read(buf []byte) (int, error) {
	n, err := c.Conn.Read(c.scratch[:])
	if err != nil {
		return 0, err
	}
	if n > len(buf) {
		return 0, errors.New("oversized datagram")
	}
	return copy(buf, c.scratch[:n]), nil
}

func (c *socksUDP) Write(buf []byte) (int, error) {
	if len(buf) > 1200 {
		return 0, errors.New("oversized driver payload")
	}
	copy(c.writeBuffer[:], c.header)
	copy(c.writeBuffer[len(c.header):], buf)
	n, err := c.Conn.Write(c.writeBuffer[:len(c.header)+len(buf)])
	if err != nil {
		return 0, err
	}
	if n != len(c.header)+len(buf) {
		return 0, io.ErrShortWrite
	}
	return len(buf), nil
}
func (c *socksUDP) Read(buf []byte) (int, error) {
	n, err := c.Conn.Read(c.readBuffer[:])
	if err != nil {
		return 0, err
	}
	if n < len(c.expected) || n-len(c.expected) > len(buf) || !bytes.Equal(c.readBuffer[:len(c.expected)], c.expected) {
		return 0, errors.New("SOCKS datagram source/size")
	}
	return copy(buf, c.readBuffer[len(c.expected):n]), nil
}
func (c *socksUDP) Close() error { c.control.Close(); return c.Conn.Close() }

func datagramHeader(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid datagram target")
	}
	header := []byte{0, 0, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			header = append(append(header, 1), v4...)
		} else {
			header = append(append(header, 4), ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 253 {
			return nil, errors.New("invalid datagram name")
		}
		header = append(header, 3, byte(len(host)))
		header = append(header, host...)
	}
	return append(header, byte(port>>8), byte(port)), nil
}

func dialData(r request, proxy, target string) (net.Conn, error) {
	if proxy == "" {
		conn, err := net.DialTimeout(r.Transport, target, 5*time.Second)
		if err != nil {
			return nil, err
		}
		if r.Transport == "udp" {
			return &boundedUDP{Conn: conn}, nil
		}
		if r.InitialHello {
			if err := writeAll(conn, []byte{42}); err != nil {
				conn.Close()
				return nil, err
			}
		}
		return conn, nil
	}
	if r.Transport == "tcp" {
		control, _, err := socksControl(proxy, target, false)
		return control, err
	}
	proxyHost, _, _ := net.SplitHostPort(proxy)
	network, wildcard := "udp4", "0.0.0.0"
	if net.ParseIP(proxyHost).To4() == nil {
		network, wildcard = "udp6", "::"
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	// Bind first and authorize the actual local port: VCore deliberately allows
	// only one unresolved port-zero association per source IP/scope.
	association := net.JoinHostPort(wildcard, strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port))
	control, relay, err := socksControl(proxy, association, true)
	if err != nil {
		conn.Close()
		return nil, err
	}
	relayPeer, err := netip.ParseAddrPort(relay)
	if err != nil {
		conn.Close()
		control.Close()
		return nil, err
	}
	header, err := datagramHeader(target)
	if err != nil {
		conn.Close()
		control.Close()
		return nil, err
	}
	_, portString, _ := net.SplitHostPort(target)
	expected, err := datagramHeader(net.JoinHostPort(r.TargetIP, portString))
	if err != nil {
		conn.Close()
		control.Close()
		return nil, err
	}
	return &socksUDP{Conn: &packetConn{UDPConn: conn, peer: relayPeer}, control: control, header: header, expected: expected}, nil
}

func clientFlow(peer, proxy string, r request, ready *sync.WaitGroup, start <-chan struct{}) []flowResult {
	outcome := flowResult{Transport: r.Transport, Direction: r.Direction}
	signaled := false
	defer func() {
		if !signaled {
			ready.Done()
		}
	}()
	fail := func(message string) []flowResult { outcome.Error = message; return []flowResult{outcome} }
	control, err := net.DialTimeout("tcp", peer, 5*time.Second)
	if err != nil {
		return fail("control connect")
	}
	defer control.Close()
	control.SetDeadline(time.Now().Add(time.Duration(r.Seconds+15) * time.Second))
	decoder, encoder := json.NewDecoder(io.LimitReader(control, 65536)), json.NewEncoder(control)
	if encoder.Encode(r) != nil {
		return fail("control request")
	}
	var answer struct {
		Port int `json:"port"`
	}
	if decoder.Decode(&answer) != nil || answer.Port < 1 {
		return fail("data port")
	}
	host, _, _ := net.SplitHostPort(peer)
	r.TargetIP = host
	if r.TargetHost != "" {
		host = r.TargetHost
	}
	data, err := dialData(r, proxy, net.JoinHostPort(host, strconv.Itoa(answer.Port)))
	if err != nil {
		return fail("data connect")
	}
	defer data.Close()
	if r.Transport == "udp" {
		if _, err = data.Write([]byte{42}); err != nil {
			return fail("UDP hello")
		}
	}
	var ack struct {
		Ready          bool `json:"ready"`
		SourceVerified bool `json:"source_verified"`
	}
	if decoder.Decode(&ack) != nil || !ack.Ready {
		return fail("data readiness")
	}
	outcome.SourceVerified = ack.SourceVerified
	if r.ExpectedSource != "" && !ack.SourceVerified {
		return fail("missing origin route witness")
	}
	ready.Done()
	signaled = true
	<-start
	if encoder.Encode("start") != nil {
		return fail("start")
	}
	if r.Direction == "both" {
		local := transferDuplex(data, r, true)
		var remote duplexResult
		if decoder.Decode(&remote) != nil {
			return fail("remote counters")
		}
		return []flowResult{
			checkedFlow("up", r, local.Up, remote.Up, ack.SourceVerified),
			checkedFlow("down", r, remote.Down, local.Down, ack.SourceVerified),
		}
	}
	local := transfer(data, r, r.Direction == "up")
	var remote result
	if decoder.Decode(&remote) != nil {
		return fail("remote counters")
	}
	if r.Direction == "up" {
		outcome.Sent, outcome.Received = local, remote
	} else {
		outcome.Sent, outcome.Received = remote, local
	}
	return []flowResult{checkedFlow(r.Direction, r, outcome.Sent, outcome.Received, ack.SourceVerified)}
}

func checkedFlow(direction string, r request, sent, received result, sourceVerified bool) flowResult {
	outcome := flowResult{Transport: r.Transport, Direction: direction, Sent: sent, Received: received, SourceVerified: sourceVerified}
	expected := totalBytes(r)
	if outcome.Sent.Error != "" || outcome.Received.Error != "" || outcome.Sent.Bytes != expected ||
		outcome.Received.Bytes != expected || outcome.Sent.Digest != outcome.Received.Digest {
		outcome.Error = "incomplete or incorrect payload"
	}
	return outcome
}

func startBarrier(readyFile, startFile string, flows int) error {
	if readyFile == "" && startFile == "" {
		return nil
	}
	if readyFile == "" || startFile == "" {
		return errors.New("both barrier paths are required")
	}
	ready, err := os.OpenFile(readyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	err = json.NewEncoder(ready).Encode(map[string]int{"pid": os.Getpid(), "flows": flows})
	ready.Close()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		start, err := os.Open(startFile)
		if err == nil {
			data, readErr := io.ReadAll(io.LimitReader(start, 16))
			start.Close()
			if readErr != nil {
				return readErr
			}
			if string(data) == "start\n" {
				return nil
			}
			if len(data) > 6 {
				return errors.New("invalid start barrier")
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		time.Sleep(time.Millisecond)
	}
	return errors.New("start barrier timed out")
}

func runClient(peer, proxy, transport, direction string, seconds, flows, mbps int, target, source, readyFile, startFile string) error {
	duplex := direction == "both" && (flows == 1 || probeMode || correctnessMode)
	if (direction != "up" && direction != "down" && direction != "both") || flows < 1 || flows > 64 ||
		(direction == "both" && flows%2 != 0 && !duplex) || mbps < 1 || mbps > 1000 {
		return errors.New("invalid workload")
	}
	if slowFlows < 0 || slowFlows > flows || (slowFlows > 0 && transport != "tcp" && transport != "mixed") {
		return errors.New("invalid slow-flow count")
	}
	peerHost, _, peerErr := net.SplitHostPort(peer)
	peerIP := net.ParseIP(peerHost)
	if peerErr != nil || peerIP == nil {
		return errors.New("literal control peer required")
	}
	r := request{Transport: transport, Direction: "up", Seconds: seconds, BytesPerSecond: int64(mbps) * 125000 / int64(flows), Seed: 20260929}
	if transport == "mixed" {
		if !correctnessMode || flows%2 != 0 {
			return errors.New("mixed transport requires an even fixed-rate workload")
		}
		r.Transport = "tcp"
	}
	if duplex {
		r.BytesPerSecond /= 2
	}
	r.TargetHost, r.ExpectedSource = target, source
	r.InitialHello = transport == "tcp"
	if correctnessMode {
		r.Correctness, r.BytesPerSecond = true, 65536
		if r.Transport == "udp" {
			r.BytesPerSecond = 24000
		}
	}
	if probeMode {
		if correctnessMode {
			return errors.New("probe is not a fixed-rate workload")
		}
		if direction != "both" || seconds != (probeRounds+19)/20 || slowFlows != 0 {
			return errors.New("probe requires a bounded bidirectional handshake check")
		}
		r.Probe, r.ProbeRounds, r.BytesPerSecond = true, probeRounds, 640
	}
	if target != "" && proxy == "" {
		return errors.New("named workload must use the SOCKS5 entrypoint, not host DNS")
	}
	if source != "" && net.ParseIP(source) == nil {
		return errors.New("route witness requires a literal expected origin peer")
	}
	if err := validate(r); err != nil {
		return err
	}
	proxies := strings.Split(proxy, ",")
	endpointCount := 0
	if proxy != "" {
		if len(proxies) != 1 && len(proxies) != flows {
			return errors.New("proxy list needs one endpoint or one per flow")
		}
		seen := make(map[string]bool, len(proxies))
		for _, endpoint := range proxies {
			host, portText, err := net.SplitHostPort(endpoint)
			port, portErr := strconv.Atoi(portText)
			ip := net.ParseIP(host)
			if err != nil || portErr != nil || ip == nil || port < 1 || port > 65535 || seen[endpoint] {
				return errors.New("invalid or repeated proxy endpoint")
			}
			seen[endpoint] = true
		}
		endpointCount = len(proxies)
	}
	var ready sync.WaitGroup
	selection, err := loadSelection(flows)
	if err != nil {
		return err
	}
	ready.Add(flows)
	start := make(chan struct{})
	results := make(chan []flowResult, flows)
	var before, after syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &before)
	for i := 0; i < flows; i++ {
		if selection != nil {
			if err := selection.choose(i); err != nil {
				return err
			}
		}
		flowProxy := proxies[i%len(proxies)]
		current := r
		if correctnessMode {
			current.Correctness = true
			if transport == "mixed" && i >= flows/2 {
				current.Transport = "udp"
			}
			current.InitialHello = current.Transport == "tcp"
			current.BytesPerSecond = 65536
			if current.Transport == "udp" {
				// Pacer units are 1200-byte slots: 20 slots/s, with the
				// actual payload cycling 64/512/1200 without padding.
				current.BytesPerSecond = 24000
			}
		}
		if i < slowFlows {
			current.PauseEveryMS, current.PauseForMS = pauseEveryMS, pauseForMS
			if err := validate(current); err != nil {
				return err
			}
		}
		current.Seed += uint64(i)
		current.Direction = direction
		if direction == "both" && !duplex {
			current.Direction = "up"
			if i >= flows/2 {
				current.Direction = "down"
			}
		}
		flowReady := &ready
		if selection != nil {
			flowReady = new(sync.WaitGroup)
			flowReady.Add(1)
		}
		go func() { results <- clientFlow(peer, flowProxy, current, flowReady, start) }()
		if selection != nil {
			flowReady.Wait()
			ready.Done()
		}
	}
	ready.Wait()
	if err := startBarrier(readyFile, startFile, flows); err != nil {
		return err
	}
	began := time.Now()
	close(start)
	rows := make([]flowResult, 0, flows)
	var received, sent int64
	success := true
	for i := 0; i < flows; i++ {
		for _, row := range <-results {
			rows = append(rows, row)
			received += row.Received.Bytes
			sent += row.Sent.Bytes
			if row.Error != "" {
				success = false
			}
		}
	}
	elapsed := time.Since(began).Seconds()
	window := elapsed
	if window < float64(seconds) {
		window = float64(seconds)
	}
	goodput := float64(received) * 8 / window
	syscall.Getrusage(syscall.RUSAGE_SELF, &after)
	cpu := func(v syscall.Timeval) float64 { return float64(v.Sec) + float64(v.Usec)/1e6 }
	report := map[string]any{"complete": success, "transport": transport, "direction": direction, "flows": rows,
		"data_connection_count":     flows,
		"single_connection_duplex":  duplex && flows == 1,
		"external_start_barrier":    readyFile != "" && startFile != "",
		"udp_pacing_credit_records": udpPacingCredit,
		"proxy_endpoint_count":      endpointCount,
		"slow_flow_count":           slowFlows,
		"pause_every_ms":            pauseEveryMS,
		"pause_for_ms":              pauseForMS,
		"sent_bytes":                sent, "received_bytes": received, "elapsed_seconds": elapsed, "offered_bps": int64(mbps) * 1000000,
		"receiver_goodput_bps": goodput, "nominal_seconds": seconds, "payload_bytes": frameSize(r),
		"cpu_seconds": cpu(after.Utime) + cpu(after.Stime) - cpu(before.Utime) - cpu(before.Stime),
		"rate_pass":   success && goodput >= float64(mbps)*1000000*0.99}
	if selection != nil {
		report["selected_flow_members"] = selection.Members
	}
	if probeMode {
		report["probe"] = true
		report["probe_rounds"] = probeRounds
		report["offered_bps"] = 0
		report["rate_pass"] = false
	}
	if correctnessMode {
		report["correctness"] = true
		report["tcp_bytes_per_second_per_direction"] = 65536
		report["udp_packets_per_second_per_direction"] = 20
		report["udp_payload_cycle"] = []int{64, 512, 1200}
		report["offered_bps"] = 0
		report["rate_pass"] = false
	}
	json.NewEncoder(os.Stdout).Encode(report)
	if !success {
		return errors.New("payload validation failed")
	}
	return nil
}

func main() {
	mode := flag.String("mode", "client", "origin/client")
	peer := flag.String("peer", "", "isolated origin control address")
	proxy := flag.String("proxy", "", "optional SOCKS5 endpoint, or comma-separated endpoint per flow")
	transport := flag.String("transport", "tcp", "tcp/udp")
	direction := flag.String("direction", "up", "up/down/both")
	seconds := flag.Int("seconds", 10, "bounded measurement duration")
	flows := flag.Int("flows", 16, "bounded flow count")
	mbps := flag.Int("mbps", 1000, "aggregate offered application Mbps")
	target := flag.String("target", "", "SOCKS5 destination name, never resolved by driver")
	source := flag.String("expect-source", "", "origin must observe this literal peer IP")
	readyFile := flag.String("ready-file", "", "owned driver readiness file for paired load")
	startFile := flag.String("start-file", "", "owned common release file for paired load")
	flag.IntVar(&udpPacingCredit, "udp-pacing-credit", 16, "bounded scheduling credit, never discarded payload")
	flag.StringVar(&selectionFile, "selection-file", "", "owned per-flow controller selection configuration")
	flag.IntVar(&slowFlows, "slow-flows", 0, "number of TCP flows with slow receivers")
	flag.IntVar(&pauseEveryMS, "pause-every-ms", 10000, "slow receiver pause period")
	flag.IntVar(&pauseForMS, "pause-for-ms", 2000, "slow receiver pause duration")
	flag.BoolVar(&probeMode, "probe", false, "bounded duplex setup probe; never bandwidth evidence")
	flag.IntVar(&probeRounds, "probe-rounds", 1, "1-100 duplex exchanges without reconnecting")
	flag.BoolVar(&correctnessMode, "correctness", false, "64 KiB/s TCP and 20 pps variable-size UDP per direction")
	flag.Parse()
	var err error
	if udpPacingCredit < 0 || udpPacingCredit > 16 {
		err = errors.New("invalid UDP pacing credit")
	} else if *mode == "origin" {
		err = origin()
	} else if *mode == "client" {
		err = runClient(*peer, *proxy, *transport, *direction, *seconds, *flows, *mbps, *target, *source, *readyFile, *startFile)
	} else {
		err = fmt.Errorf("invalid mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
