// obgp-replay sends a router again the UPDATE messages one neighbor sent it,
// as an MRT recording of that router kept them: a feeder of the lab's router
// replay. It connects to the router as that neighbor, sends the messages as
// fast as the router takes them or at the pace of the recording, answers a
// route refresh with what it sent so far, and keeps what the router sends
// it, whose digest tells whether two routers sent the same.
//
// The lab's controller runs it in a feeder's pod and drives it over HTTP:
// POST /load with the MRT records, POST /start with the time to start and the
// schedule, GET /status for the counts and the digest.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

const (
	mrtBGP4MP     = 16
	mrtMessageAS4 = 4
)

// message is one UPDATE to send: when it was recorded, its bytes with the
// next hop set to the feeder, and the prefixes it announces and withdraws.
type message struct {
	at        float64 // when it was recorded, Unix seconds, whole as MRT keeps them
	data      []byte
	announced []string
	withdrawn []string
	attrs     []bgp.PathAttributeInterface
}

// load reads BGP4MP records with four-byte ASNs and makes each UPDATE one to
// send from the address nexthop.
func load(data []byte, nexthop netip.Addr) ([]message, error) {
	var out []message
	for i := 0; i < len(data); {
		if i+12 > len(data) {
			return nil, errors.New("a record is cut off")
		}
		ts := binary.BigEndian.Uint32(data[i:])
		kind, subtype := binary.BigEndian.Uint16(data[i+4:]), binary.BigEndian.Uint16(data[i+6:])
		length := int(binary.BigEndian.Uint32(data[i+8:]))
		if i+12+length > len(data) {
			return nil, errors.New("a record is cut off")
		}
		body := data[i+12 : i+12+length]
		i += 12 + length
		if kind != mrtBGP4MP {
			continue
		}
		if subtype != mrtMessageAS4 {
			return nil, fmt.Errorf("BGP4MP subtype %d: only messages with four-byte ASNs and without Add-Path replay", subtype)
		}
		if len(body) < 12 {
			return nil, errors.New("a BGP4MP record is too short")
		}
		size := 4
		if binary.BigEndian.Uint16(body[10:]) == 2 {
			size = 16
		}
		raw := body[12+2*size:]
		msg, err := bgp.ParseBGPMessage(raw)
		if err != nil {
			return nil, fmt.Errorf("a recorded message: %w", err)
		}
		update, ok := msg.Body.(*bgp.BGPUpdate)
		if !ok {
			continue
		}
		m, err := own(update, nexthop)
		if err != nil {
			return nil, err
		}
		m.at = float64(ts)
		out = append(out, m)
	}
	return out, nil
}

// own makes an UPDATE one the feeder sends: the next hop its own address.
func own(update *bgp.BGPUpdate, nexthop netip.Addr) (message, error) {
	var m message
	for _, a := range update.PathAttributes {
		if _, ok := a.(*bgp.PathAttributeNextHop); ok {
			nh, err := bgp.NewPathAttributeNextHop(nexthop)
			if err != nil {
				return m, err
			}
			a = nh
		}
		m.attrs = append(m.attrs, a)
	}
	for _, n := range update.NLRI {
		m.announced = append(m.announced, n.NLRI.String())
	}
	for _, n := range update.WithdrawnRoutes {
		m.withdrawn = append(m.withdrawn, n.NLRI.String())
	}
	data, err := bgp.NewBGPUpdateMessage(update.WithdrawnRoutes, m.attrs, update.NLRI).Serialize()
	m.data = data
	return m, err
}

// schedule gives each message its time after the start: none for flood, for
// paced its recorded second after base, the first second any neighbor of the
// router sent in, so that the feeders keep their times to each other. The
// messages of one second are spread evenly over it.
func schedule(msgs []message, paced bool, base float64) []time.Duration {
	out := make([]time.Duration, len(msgs))
	if !paced {
		return out
	}
	for i := 0; i < len(msgs); {
		j := i
		for j < len(msgs) && msgs[j].at == msgs[i].at {
			j++
		}
		for k := i; k < j; k++ {
			out[k] = time.Duration((msgs[i].at - base + float64(k-i)/float64(j-i)) * float64(time.Second))
		}
		i = j
	}
	return out
}

// Feeder is one neighbor of the router under test.
type Feeder struct {
	As       uint32
	ID       netip.Addr
	NextHop  netip.Addr // the feeder's own address
	Hold     uint16
	Messages []message

	mu        sync.Mutex // the state below
	conn      net.Conn
	w         *bufio.Writer
	wmu       sync.Mutex // the session's writing: a message and the state it changes, or a whole refresh, go out at once
	up        bool
	enhanced  bool                // both sides offer Enhanced Route Refresh (RFC 7313)
	stale     map[string]struct{} // routes of the router since its beginning of a refresh, gone at its end unless sent again
	err       error
	sent      map[string][]bgp.PathAttributeInterface // what the router holds from the feeder now
	received  map[string]string                       // what the router sent the feeder: prefix -> its attributes
	lengths   map[string]int                          // and the length of the AS path of each, what timing does not change
	counts    struct{ Sent, Updates, Refreshes int }
	started   time.Time
	done      time.Time
	scheduled bool
}

func (f *Feeder) write(data []byte, flush bool) error {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	return f.writeLocked(data, flush)
}

// writeLocked writes with wmu held.
func (f *Feeder) writeLocked(data []byte, flush bool) error {
	if _, err := f.w.Write(data); err != nil {
		return err
	}
	if flush {
		return f.w.Flush()
	}
	return nil
}

func (f *Feeder) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err == nil && err != nil {
		f.err = err
		log.Printf("feeder: %v", err)
	}
	f.up = false
}

// Session opens the session over conn: OPEN with four-byte ASNs and route
// refresh, KEEPALIVE, then reads what the router sends until the end.
func (f *Feeder) Session(conn net.Conn) error {
	f.conn, f.w = conn, bufio.NewWriterSize(conn, 1<<16)
	as2 := uint16(bgp.AS_TRANS)
	if f.As <= 0xffff {
		as2 = uint16(f.As)
	}
	// As gobgpd offers them to its neighbors. Enhanced Route Refresh is used where the router offers it too.
	caps := []bgp.ParameterCapabilityInterface{bgp.NewCapMultiProtocol(bgp.RF_IPv4_UC), bgp.NewCapRouteRefresh(),
		bgp.NewCapEnhancedRouteRefresh(), bgp.NewCapFourOctetASNumber(f.As)}
	open, err := bgp.NewBGPOpenMessage(as2, f.Hold, f.ID, []bgp.OptionParameterInterface{bgp.NewOptionParameterCapability(caps)})
	if err != nil {
		return err
	}
	data, _ := open.Serialize()
	if err := f.write(data, true); err != nil {
		return err
	}
	r := bufio.NewReaderSize(conn, 1<<16)
	msg, err := read(r)
	if err != nil {
		return fmt.Errorf("no OPEN: %w", err)
	}
	theirs, ok := msg.Body.(*bgp.BGPOpen)
	if !ok {
		return fmt.Errorf("a message of type %d instead of OPEN", msg.Header.Type)
	}
	hold := min(f.Hold, theirs.HoldTime)
	for _, p := range theirs.OptParams {
		if c, ok := p.(*bgp.OptionParameterCapability); ok {
			for _, x := range c.Capability {
				if x.Code() == bgp.BGP_CAP_ENHANCED_ROUTE_REFRESH {
					f.mu.Lock()
					f.enhanced = true
					f.mu.Unlock()
				}
			}
		}
	}
	keepalive, _ := bgp.NewBGPKeepAliveMessage().Serialize()
	if err := f.write(keepalive, true); err != nil {
		return err
	}
	if hold > 0 {
		go func() {
			for range time.Tick(time.Duration(hold) * time.Second / 3) {
				if f.write(keepalive, true) != nil {
					return
				}
			}
		}()
	}
	for {
		msg, err := read(r)
		if err != nil {
			return err
		}
		switch body := msg.Body.(type) {
		case *bgp.BGPKeepAlive:
			f.mu.Lock()
			f.up = true
			f.mu.Unlock()
		case *bgp.BGPUpdate:
			f.receive(body)
		case *bgp.BGPRouteRefresh:
			if err := f.refreshed(body); err != nil {
				return err
			}
		case *bgp.BGPNotification:
			return fmt.Errorf("the router sent a notification, code %d subcode %d", body.ErrorCode, body.ErrorSubcode)
		}
	}
}

func read(r *bufio.Reader) (*bgp.BGPMessage, error) {
	header := make([]byte, bgp.BGP_HEADER_LENGTH)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[16:]))
	if length < bgp.BGP_HEADER_LENGTH {
		return nil, fmt.Errorf("a message of %d bytes", length)
	}
	data := make([]byte, length)
	copy(data, header)
	if _, err := io.ReadFull(r, data[bgp.BGP_HEADER_LENGTH:]); err != nil {
		return nil, err
	}
	return bgp.ParseBGPMessage(data)
}

// receive keeps what the router sent: each prefix with its attributes, in
// the order of their types, or none once withdrawn.
func (f *Feeder) receive(u *bgp.BGPUpdate) {
	var attrs string
	length := 0
	if len(u.NLRI) > 0 {
		parts := make([]string, 0, len(u.PathAttributes))
		for _, a := range u.PathAttributes {
			if a.GetType() == bgp.BGP_ATTR_TYPE_NEXT_HOP {
				continue // the router's own address, a pod's, which differs by run
			}
			if p, ok := a.(*bgp.PathAttributeAsPath); ok {
				for _, seg := range p.Value {
					length += seg.ASLen()
				}
			}
			b, _ := a.Serialize()
			parts = append(parts, hex.EncodeToString(b))
		}
		sort.Strings(parts)
		attrs = strings.Join(parts, ",")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts.Updates++
	for _, n := range u.WithdrawnRoutes {
		delete(f.received, n.NLRI.String())
		delete(f.lengths, n.NLRI.String())
	}
	for _, n := range u.NLRI {
		f.received[n.NLRI.String()] = attrs
		f.lengths[n.NLRI.String()] = length
		delete(f.stale, n.NLRI.String())
	}
}

// refreshed answers a route refresh of the router: a request with every
// route it holds from the feeder, framed by a beginning and an end where
// both offer Enhanced Route Refresh, as gobgpd answers. The router's own
// beginning marks its routes stale, its end removes those it did not send again.
func (f *Feeder) refreshed(rr *bgp.BGPRouteRefresh) error {
	switch rr.Demarcation {
	case bgp.BGP_ROUTE_REFRESH_BEGIN:
		f.mu.Lock()
		f.stale = make(map[string]struct{}, len(f.received))
		for p := range f.received {
			f.stale[p] = struct{}{}
		}
		f.mu.Unlock()
		return nil
	case bgp.BGP_ROUTE_REFRESH_END:
		f.mu.Lock()
		for p := range f.stale {
			delete(f.received, p)
			delete(f.lengths, p)
		}
		f.stale = nil
		f.mu.Unlock()
		return nil
	case bgp.BGP_ROUTE_REFRESH_REQUEST:
		return f.refresh()
	}
	return nil // RFC 7313: other subtypes are ignored
}

// refresh sends again every route the router holds from the feeder, the
// prefixes of equal attributes packed into as few messages as fit, as gobgpd
// packs them. It holds the session's writing throughout: no message of the
// recording passes between, so the router never gets an old route after a newer one.
func (f *Feeder) refresh() error {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	f.mu.Lock()
	f.counts.Refreshes++
	enhanced := f.enhanced
	groups := map[string][]string{}
	attrsOf := map[string][]bgp.PathAttributeInterface{}
	sizeOf := map[string]int{}
	for prefix, attrs := range f.sent {
		key, size := "", 0
		for _, a := range attrs {
			b, _ := a.Serialize()
			key += hex.EncodeToString(b) + ","
			size += len(b)
		}
		groups[key] = append(groups[key], prefix)
		attrsOf[key], sizeOf[key] = attrs, size
	}
	f.mu.Unlock()
	var data [][]byte
	if enhanced {
		b, _ := bgp.NewBGPRouteRefreshMessage(bgp.AFI_IP, bgp.BGP_ROUTE_REFRESH_BEGIN, bgp.SAFI_UNICAST).Serialize()
		data = append(data, b)
	}
	for _, key := range slices.Sorted(mapKeys(groups)) {
		prefixes := slices.Sorted(slices.Values(groups[key]))
		attrs := attrsOf[key]
		room := bgp.BGP_MAX_MESSAGE_LENGTH - bgp.BGP_HEADER_LENGTH - 4 - sizeOf[key]
		for len(prefixes) > 0 {
			var nlri []bgp.PathNLRI
			used := 0
			for len(prefixes) > 0 {
				p, err := netip.ParsePrefix(prefixes[0])
				if err != nil {
					prefixes = prefixes[1:]
					continue
				}
				if size := 1 + (p.Bits()+7)/8; used+size <= room {
					n, _ := bgp.NewIPAddrPrefix(p)
					nlri = append(nlri, bgp.PathNLRI{NLRI: n})
					used += size
					prefixes = prefixes[1:]
					continue
				}
				break
			}
			if len(nlri) == 0 { // attributes that leave no room for a prefix: the recording held them with one, so send it alone
				p, err := netip.ParsePrefix(prefixes[0])
				prefixes = prefixes[1:]
				if err != nil {
					continue
				}
				n, _ := bgp.NewIPAddrPrefix(p)
				nlri = append(nlri, bgp.PathNLRI{NLRI: n})
			}
			if b, err := bgp.NewBGPUpdateMessage(nil, attrs, nlri).Serialize(); err == nil {
				data = append(data, b)
			}
		}
	}
	if enhanced {
		b, _ := bgp.NewBGPRouteRefreshMessage(bgp.AFI_IP, bgp.BGP_ROUTE_REFRESH_END, bgp.SAFI_UNICAST).Serialize()
		data = append(data, b)
	}
	for i, b := range data {
		if err := f.writeLocked(b, i == len(data)-1); err != nil {
			return err
		}
	}
	return nil
}

func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// Send sends the messages, from at on, by the schedule, base the recorded second at stands for.
func (f *Feeder) Send(at time.Time, paced bool, base float64) {
	times := schedule(f.Messages, paced, base)
	time.Sleep(time.Until(at))
	f.mu.Lock()
	f.started = time.Now()
	f.mu.Unlock()
	for i, m := range f.Messages {
		if paced {
			time.Sleep(time.Until(at.Add(times[i])))
		}
		f.wmu.Lock() // the state and its message together: a refresh comes before or after both
		f.mu.Lock()
		for _, p := range m.withdrawn {
			delete(f.sent, p)
		}
		for _, p := range m.announced {
			f.sent[p] = m.attrs
		}
		f.counts.Sent++
		f.mu.Unlock()
		err := f.writeLocked(m.data, paced || i == len(f.Messages)-1)
		f.wmu.Unlock()
		if err != nil {
			f.fail(fmt.Errorf("sending: %w", err))
			return
		}
	}
	f.mu.Lock()
	f.done = time.Now()
	f.mu.Unlock()
}

// Status is what the lab reads of a feeder.
type Status struct {
	Established bool    `json:"established"`
	Loaded      int     `json:"loaded"`
	Sent        int     `json:"sent"`
	Started     float64 `json:"started,omitempty"` // wall clock, seconds
	Done        float64 `json:"done,omitempty"`
	Updates     int     `json:"updates"`   // received from the router
	Refreshes   int     `json:"refreshes"` // route refreshes the router asked for
	Prefixes    int     `json:"prefixes"`  // the router sends the feeder a route to
	Digest      string  `json:"digest"`    // of those routes and their attributes
	Quality     string  `json:"quality"`   // of the prefixes and the lengths of their AS paths only: the same where timing chose among equal paths
	Error       string  `json:"error,omitempty"`
}

func (f *Feeder) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := Status{Established: f.up, Loaded: len(f.Messages), Sent: f.counts.Sent, Updates: f.counts.Updates,
		Refreshes: f.counts.Refreshes, Prefixes: len(f.received), Digest: digest(f.received), Quality: digest(lengthsText(f.lengths))}
	if !f.started.IsZero() {
		s.Started = float64(f.started.UnixMicro()) / 1e6
	}
	if !f.done.IsZero() {
		s.Done = float64(f.done.UnixMicro()) / 1e6
	}
	if f.err != nil {
		s.Error = f.err.Error()
	}
	return s
}

func lengthsText(lengths map[string]int) map[string]string {
	out := make(map[string]string, len(lengths))
	for p, n := range lengths {
		out[p] = fmt.Sprint(n)
	}
	return out
}

func digest(routes map[string]string) string {
	h := sha256.New()
	for _, p := range slices.Sorted(mapKeys(routes)) {
		fmt.Fprintf(h, "%s %s\n", p, routes[p])
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (f *Feeder) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /load", func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err == nil {
			var msgs []message
			if msgs, err = load(data, f.NextHop); err == nil {
				f.mu.Lock()
				f.Messages = msgs
				f.mu.Unlock()
			}
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(f.Status())
	})
	mux.HandleFunc("POST /start", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			At       float64 `json:"at"`
			Schedule string  `json:"schedule"`
			Base     float64 `json:"base"` // the recorded second at stands for, the same for every feeder
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		ready, again := f.up, f.scheduled
		f.scheduled = true
		f.mu.Unlock()
		if !ready || again {
			http.Error(w, "not established, or started before", http.StatusConflict)
			return
		}
		at := time.UnixMicro(int64(req.At * 1e6))
		go f.Send(at, req.Schedule == "paced", req.Base)
		json.NewEncoder(w).Encode(f.Status())
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(f.Status())
	})
	return mux
}

func main() {
	listen := flag.String("http", "127.0.0.1:8081", "address of the HTTP API")
	peer := flag.String("peer", "", "address of the router under test")
	as := flag.Uint("as", 0, "the AS of the feeder, the recorded neighbor's")
	id := flag.String("id", "", "the router ID of the feeder")
	self := flag.String("address", "", "the feeder's own address, the next hop it sends")
	hold := flag.Uint("hold", 90, "hold time")
	retry := flag.Duration("retry", 2*time.Second, "between attempts to connect")
	flag.Parse()
	f := &Feeder{As: uint32(*as), ID: netip.MustParseAddr(*id), NextHop: netip.MustParseAddr(*self), Hold: uint16(*hold),
		sent: map[string][]bgp.PathAttributeInterface{}, received: map[string]string{}, lengths: map[string]int{}}
	go func() { log.Fatal(http.ListenAndServe(*listen, f.handler())) }()
	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(*peer, "179"), 5*time.Second)
		if err != nil {
			time.Sleep(*retry)
			continue
		}
		err = f.Session(conn)
		conn.Close()
		f.fail(fmt.Errorf("the session ended: %w", err))
		log.Fatal(f.Status().Error) // one session per run: the controller ends the pod and the run fails
	}
}
