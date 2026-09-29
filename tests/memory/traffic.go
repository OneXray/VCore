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
	"net/netip"
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
}
type result struct {
	Bytes     int64   `json:"bytes"`
	Packets   int64   `json:"packets"`
	Elapsed   float64 `json:"seconds"`
	Digest    string  `json:"sha256,omitempty"`
	Reordered int64   `json:"reordered"`
	MaxLateNS int64   `json:"max_pacing_lag_ns"`
	Windows   []int64 `json:"bytes_per_second"`
	Error     string  `json:"error,omitempty"`
}
type flowResult struct {
	Direction string `json:"direction"`
	Sent      result `json:"sent"`
	Received  result `json:"received"`
	Error     string `json:"error,omitempty"`
}

func frameSize(r request) int {
	if r.Transport == "udp" {
		return 1200
	}
	return 65536
}
func count(r request) int64 { return r.BytesPerSecond * int64(r.Seconds) / int64(frameSize(r)) }
func validate(r request) error {
	if (r.Transport != "tcp" && r.Transport != "udp") ||
		(r.Direction != "up" && r.Direction != "down") || r.Seconds < 1 || r.Seconds > 300 ||
		r.BytesPerSecond < 1 || r.BytesPerSecond > 125000000 || count(r) == 0 {
		return errors.New("invalid bounded workload")
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
		if earliest := time.Now().Add(-16 * period); earliest.After(due) {
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
		pattern(job.buf[:], uint64(job.out.Packets), job.r.Seed)
		n, err := job.conn.Write(job.buf[:])
		if err != nil || n != len(job.buf) {
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
	conn.SetDeadline(time.Now().Add(time.Duration(r.Seconds+3) * time.Second))
	defer conn.SetDeadline(time.Time{})
	udpJobs <- job
	return <-job.done
}

func transfer(conn net.Conn, r request, send bool) result {
	if send && r.Transport == "udp" {
		return sendUDP(conn, r)
	}
	size, total := frameSize(r), count(r)
	buf := make([]byte, size)
	bitmap := make([]byte, (total+7)/8)
	digest := sha256.New()
	out := result{Windows: make([]int64, r.Seconds+3)}
	start := time.Now()
	conn.SetDeadline(start.Add(time.Duration(r.Seconds+3) * time.Second))
	defer func() { conn.SetDeadline(time.Time{}) }()
	highest := int64(-1)
	for seq := int64(0); seq < total; seq++ {
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
			pattern(buf, uint64(seq), r.Seed)
			if writeAll(conn, buf) != nil {
				out.Error = "send failed"
				break
			}
		} else {
			var n int
			var err error
			if r.Transport == "tcp" {
				n, err = io.ReadFull(conn, buf)
			} else {
				n, err = conn.Read(buf)
			}
			if err != nil || n != size {
				out.Error = "receive incomplete"
				break
			}
			id := binary.LittleEndian.Uint64(buf)
			if id >= uint64(total) || !check(buf, r.Seed) {
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
			if int64(id) < highest {
				out.Reordered++
			} else {
				highest = int64(id)
			}
		}
		if r.Transport == "tcp" {
			digest.Write(buf)
		}
		out.Bytes += int64(size)
		out.Packets++
		window := int(time.Since(start) / time.Second)
		if window >= len(out.Windows) {
			out.Error = "unbounded drain"
			break
		}
		out.Windows[window] += int64(size)
	}
	out.Elapsed = time.Since(start).Seconds()
	if r.Transport == "tcp" {
		out.Digest = hex.EncodeToString(digest.Sum(nil))
	}
	return out
}

// A connected packet adapter for the server; first datagram pins the peer.
// Read uses a one-byte surplus so oversized packets cannot be silently accepted.
type packetConn struct {
	*net.UDPConn
	peer    netip.AddrPort
	scratch [1201]byte
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
		listener, err = net.Listen("tcp4", "0.0.0.0:0")
		if err != nil {
			return
		}
		defer listener.Close()
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
		port = listener.Addr().(*net.TCPAddr).Port
	} else {
		udp, err = net.ListenUDP("udp4", &net.UDPAddr{})
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
	} else {
		udp.SetReadDeadline(time.Now().Add(10 * time.Second))
		var hello [1]byte
		n, peer, e := udp.ReadFromUDPAddrPort(hello[:])
		if e != nil || n != 1 || hello[0] != 42 {
			return
		}
		data = &packetConn{UDPConn: udp, peer: peer}
	}
	if encoder.Encode(map[string]bool{"ready": true}) != nil {
		return
	}
	var start string
	if decoder.Decode(&start) != nil || start != "start" {
		return
	}
	outcome := transfer(data, r, r.Direction == "down")
	encoder.Encode(outcome)
}

func origin() error {
	if runtime.GOOS != "linux" || os.Getenv("VCORE_ISOLATED_ORIGIN") != "1" {
		return errors.New("origin requires an owned isolated Linux container")
	}
	listener, err := net.Listen("tcp4", "0.0.0.0:24003")
	if err != nil {
		return err
	}
	defer listener.Close()
	slots := make(chan struct{}, 64)
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
	conn, err := net.DialTimeout("tcp4", proxy, 5*time.Second)
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
	address := net.ParseIP(host).To4()
	if address == nil {
		return fail()
	}
	command := byte(1)
	if udp {
		command, address, port = 3, net.IPv4zero.To4(), 0
	}
	raw := []byte{5, command, 0, 1}
	raw = append(raw, address...)
	raw = append(raw, byte(port>>8), byte(port))
	if writeAll(conn, raw) != nil {
		return fail()
	}
	var reply [10]byte
	if _, err = io.ReadFull(conn, reply[:]); err != nil || !bytes.Equal(reply[:4], []byte{5, 0, 0, 1}) {
		return fail()
	}
	relayHost := net.IP(reply[4:8]).String()
	if relayHost == "0.0.0.0" {
		relayHost, _, _ = net.SplitHostPort(proxy)
	}
	conn.SetDeadline(time.Time{})
	return conn, net.JoinHostPort(relayHost, strconv.Itoa(int(binary.BigEndian.Uint16(reply[8:])))), nil
}

type socksUDP struct {
	net.Conn
	control net.Conn
	header  []byte
	scratch [1211]byte
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
	copy(c.scratch[:], c.header)
	copy(c.scratch[len(c.header):], buf)
	n, err := c.Conn.Write(c.scratch[:len(c.header)+len(buf)])
	if err != nil {
		return 0, err
	}
	if n != len(c.header)+len(buf) {
		return 0, io.ErrShortWrite
	}
	return len(buf), nil
}
func (c *socksUDP) Read(buf []byte) (int, error) {
	n, err := c.Conn.Read(c.scratch[:])
	if err != nil {
		return 0, err
	}
	if n < len(c.header) || n-len(c.header) > len(buf) || !bytes.Equal(c.scratch[:len(c.header)], c.header) {
		return 0, errors.New("SOCKS datagram source/size")
	}
	return copy(buf, c.scratch[len(c.header):n]), nil
}
func (c *socksUDP) Close() error { c.control.Close(); return c.Conn.Close() }
func dialData(r request, proxy, target string) (net.Conn, error) {
	if proxy == "" {
		conn, err := net.DialTimeout(r.Transport+"4", target, 5*time.Second)
		if err != nil {
			return nil, err
		}
		if r.Transport == "udp" {
			return &boundedUDP{Conn: conn}, nil
		}
		return conn, nil
	}
	control, relay, err := socksControl(proxy, target, r.Transport == "udp")
	if err != nil {
		return nil, err
	}
	if r.Transport == "tcp" {
		return control, nil
	}
	conn, err := net.DialTimeout("udp4", relay, 5*time.Second)
	if err != nil {
		control.Close()
		return nil, err
	}
	host, portString, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portString)
	header := append([]byte{0, 0, 0, 1}, net.ParseIP(host).To4()...)
	header = append(header, byte(port>>8), byte(port))
	return &socksUDP{Conn: conn, control: control, header: header}, nil
}

func clientFlow(peer, proxy string, r request, ready *sync.WaitGroup, start <-chan struct{}) flowResult {
	outcome := flowResult{Direction: r.Direction}
	signaled := false
	defer func() {
		if !signaled {
			ready.Done()
		}
	}()
	fail := func(message string) flowResult { outcome.Error = message; return outcome }
	control, err := net.DialTimeout("tcp4", peer, 5*time.Second)
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
		Ready bool `json:"ready"`
	}
	if decoder.Decode(&ack) != nil || !ack.Ready {
		return fail("data readiness")
	}
	ready.Done()
	signaled = true
	<-start
	if encoder.Encode("start") != nil {
		return fail("start")
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
	expected := count(r) * int64(frameSize(r))
	if outcome.Sent.Error != "" || outcome.Received.Error != "" || outcome.Sent.Bytes != expected ||
		outcome.Received.Bytes != expected || outcome.Sent.Digest != outcome.Received.Digest {
		return fail("incomplete or incorrect payload")
	}
	return outcome
}

func runClient(peer, proxy, transport, direction string, seconds, flows, mbps int) error {
	if (direction != "up" && direction != "down" && direction != "both") || flows < 1 || flows > 64 ||
		(direction == "both" && flows%2 != 0) || mbps < 1 || mbps > 1000 {
		return errors.New("invalid workload")
	}
	r := request{Transport: transport, Direction: "up", Seconds: seconds, BytesPerSecond: int64(mbps) * 125000 / int64(flows), Seed: 20260929}
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
			if err != nil || portErr != nil || net.ParseIP(host).To4() == nil || port < 1 || port > 65535 || seen[endpoint] {
				return errors.New("invalid or repeated proxy endpoint")
			}
			seen[endpoint] = true
		}
		endpointCount = len(proxies)
	}
	var ready sync.WaitGroup
	ready.Add(flows)
	start := make(chan struct{})
	results := make(chan flowResult, flows)
	var before, after syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &before)
	for i := 0; i < flows; i++ {
		flowProxy := proxies[i%len(proxies)]
		current := r
		current.Seed += uint64(i)
		current.Direction = direction
		if direction == "both" {
			current.Direction = "up"
			if i >= flows/2 {
				current.Direction = "down"
			}
		}
		go func() { results <- clientFlow(peer, flowProxy, current, &ready, start) }()
	}
	ready.Wait()
	began := time.Now()
	close(start)
	rows := make([]flowResult, 0, flows)
	var received, sent int64
	success := true
	for i := 0; i < flows; i++ {
		row := <-results
		rows = append(rows, row)
		received += row.Received.Bytes
		sent += row.Sent.Bytes
		if row.Error != "" {
			success = false
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
		"proxy_endpoint_count": endpointCount,
		"sent_bytes":           sent, "received_bytes": received, "elapsed_seconds": elapsed, "offered_bps": int64(mbps) * 1000000,
		"receiver_goodput_bps": goodput, "nominal_seconds": seconds, "payload_bytes": frameSize(r),
		"cpu_seconds": cpu(after.Utime) + cpu(after.Stime) - cpu(before.Utime) - cpu(before.Stime),
		"rate_pass":   success && goodput >= float64(mbps)*1000000*0.99}
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
	flag.Parse()
	var err error
	if *mode == "origin" {
		err = origin()
	} else if *mode == "client" {
		err = runClient(*peer, *proxy, *transport, *direction, *seconds, *flows, *mbps)
	} else {
		err = fmt.Errorf("invalid mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
