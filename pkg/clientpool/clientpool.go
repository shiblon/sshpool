// Package clientpool manages a set of SSH connections, each with their own
// session pool, partitioned by custom IDs (a good candidate might be
// serialized SSH configs). Uses a leaky bucket, where connections are aged out
// after they have no open sessions for a time.
//
// Example:
//
//  p := New()
//  defer p.Close()
//
//  // set addr and  clientConfig, then
//
//  sftpCli, cleanup, err := sesspool.AsSFTPClient(p.ClaimSession(ctx, WithDialArgs("tcp", addr, clientConfig)))
//  if err != nil {
//      log.Fatalf("Error claiming sftp session: %v", err)
//  }
//  defer cleanup()
//
//  // Use the sftpCli to do stuff with the session.
//
// When a connection has no open sessions for a configurable amount of time,
// a reaper clears it out of the pool, making room for new configurations to
// take its place if needed.
package clientpool // import "entrogo.com/sshpool/pkg/clientpool"
import (
	"context"
	"fmt"
	"sync"
	"time"

	"entrogo.com/sshpool/pkg/sesspool"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

const (
	DefaultExpireAfter = 5 * time.Minute
)

var (
	PoolExhausted = errors.New("client pool exhausted")
)

type connItem struct {
	id       string
	lastUsed time.Time
	pool     *sesspool.Pool
}

// ClientPool is a set of client session pools, partitioned by ID (such as
// serialized SSH configuration), and using the leaky bucket algorithm to age
// out unused connections.
type ClientPool struct {
	sync.Mutex

	done  chan bool
	conns map[string]*connItem

	expireAfter time.Duration
	poolSize    int
}

// Session is a wrapper around sesspool.Session that knows which client pool it
// came from, allowing it to be used to invalidate an entire connection and
// remove it from the pool if a session returns a connection error.
type Session struct {
	sesspool.Session
	item       *connItem
	clientPool *ClientPool
}

// InvalidateClient closes the session, its underlying pool, and the
// connection, removing it from the client pool associated with this session.
// Useful when a session returns an error that is really an underlying
// connection error, and no sessions on that connection can work anymore..
func (s *Session) InvalidateClient() error {
	serr := s.Session.Close()
	perr := s.item.pool.Close()
	defer un(lock(s.clientPool))
	s.clientPool.unsafeRemoveClient(s.item.id)

	if perr != nil {
		return errors.Wrap(perr, "invalidate client")
	}
	if serr != nil {
		return errors.Wrap(serr, "invalidate client")
	}
	return nil
}

func (p *ClientPool) applyOpts(opts ...Option) {
	for _, o := range opts {
		o(p)
	}
}

// Option sets client pool characteristics
type Option func(*ClientPool)

// WithExpireAfter sets the expiration time of a connection in the pool. If a
// connection is available past this amount of time, it is reaped.
func WithExpireAfter(d time.Duration) Option {
	if d == 0 {
		d = DefaultExpireAfter
	}
	return func(p *ClientPool) {
		p.expireAfter = d
	}
}

// WithPoolSize sets the pool size to something other than the default.
func WithPoolSize(max int) Option {
	if max < 0 {
		max = 0
	}
	return func(p *ClientPool) {
		p.poolSize = max
	}
}

// New creates a new ClientPool with the given options.
func New(opts ...Option) *ClientPool {
	p := &ClientPool{
		done:        make(chan bool),
		conns:       make(map[string]*connItem),
		expireAfter: DefaultExpireAfter,
	}
	p.applyOpts(opts...)

	go func() {
		for {
			select {
			case <-time.After(10 * time.Second):
				p.reap()
			case <-p.done:
				return
			}
		}
	}()

	return p
}

// Exhausted tells us whether there are slots for new IDs to be added into the pool.
func (p *ClientPool) Exhausted() bool {
	defer un(lock(p))
	return p.unsafeExhausted()
}

// HasID indicates whether the pool has the given ID in it (an open connection).
func (p *ClientPool) HasID(id string) bool {
	defer un(lock(p))
	_, ok := p.conns[id]
	return ok
}

// PoolStats returns a map of all client IDs to the number of sessions in each pool.
func (p *ClientPool) PoolStats() map[string]int {
	m := make(map[string]int)
	defer un(lock(p))
	for id, cc := range p.conns {
		m[id] = cc.pool.Used()
	}
	return m
}

// NumSessionsForID returns the number of sessions in the session pool for this client ID.
func (p *ClientPool) NumSessionsForID(id string) int {
	defer un(lock(p))
	cc, ok := p.conns[id]
	if !ok || cc == nil {
		return 0
	}
	return cc.pool.Used()
}

// unsafeExhausted calculates whether the pool is exhausted without grabbing a lock.
func (p *ClientPool) unsafeExhausted() bool {
	return p.poolSize > 0 && len(p.conns) >= p.poolSize
}

func (p *ClientPool) getOrCreate(ctx context.Context, opts *claimOptions) (*connItem, error) {
	defer un(lock(p))

	id := opts.clientID()

	cc := p.conns[id]
	if cc != nil {
		return cc, nil
	}

	if p.unsafeExhausted() {
		return nil, PoolExhausted
	}

	// Not found, room for it, create it.
	cli, err := opts.newSSHClient(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "get or create client")
	}
	if cli == nil {
		return nil, errors.Errorf("ssh client function returned nil for id %v", id)
	}
	cc = &connItem{
		id:       id,
		lastUsed: time.Now(),
		pool:     sesspool.New(cli, opts.sessOpts...),
	}
	p.conns[id] = cc
	return cc, nil
}

func (p *ClientPool) reap() {
	defer un(lock(p))

	var toRemove []string

	for id, v := range p.conns {
		if v.pool.Used() > 0 {
			v.lastUsed = time.Now()
			continue
		}
		// None busy - are we past allowed idle time?
		if time.Now().After(v.lastUsed.Add(p.expireAfter)) {
			toRemove = append(toRemove, id)
		}
	}

	for _, rmid := range toRemove {
		p.unsafeRemoveClient(rmid)
	}
}

func (p *ClientPool) unsafeRemoveClient(id string) {
	delete(p.conns, id)
}

// DialArgsID computes an ID from arguments that would be passed to ssh.Dial.
// The ID is relatively sure to be unique, so is used to identify different SSH
// connections in the pool.
//
// If you are specifying your own ID when creating an SSH client from scratch,
// this can be useful to provide an ID with it.
func DialArgsID(net, addr string, conf *ssh.ClientConfig) string {
	return fmt.Sprintf("n=%v a=%v u=%v z=%v", net, addr, conf.User, conf.Auth)
}

type dialArgs struct {
	net  string
	addr string
	conf *ssh.ClientConfig
}

type claimOptions struct {
	id       string
	dial     *dialArgs
	sessOpts []sesspool.Option
	newSSH   NewSSHClientFunc
}

func newClaimOptions(os ...ClaimOption) *claimOptions {
	opts := new(claimOptions)
	opts.apply(os...)
	return opts
}

func (co *claimOptions) apply(opts ...ClaimOption) {
	for _, opt := range opts {
		opt(co)
	}
}

func (co *claimOptions) newSSHClient(ctx context.Context) (*ssh.Client, error) {
	if co.dial != nil && co.newSSH != nil {
		return nil, errors.New("both dial args and client factory specified, only one can be given")
	}
	if co.newSSH != nil && co.id == "" {
		return nil, errors.New("no ID provided with client factory")
	}

	if co.dial != nil {
		return ssh.Dial(co.dial.net, co.dial.addr, co.dial.conf)
	}

	return co.newSSH(ctx)
}

func (co *claimOptions) clientID() string {
	if co.id != "" {
		return co.id
	}

	return DialArgsID(co.dial.net, co.dial.addr, co.dial.conf)
}

// ClaimOption changes how claims are done.
type ClaimOption func(*claimOptions)

// WithDialArgs specifies dial arguments to use for creating a new connection when claiming.
// If no ID is also given using WithClientID, the ID is inferred from the dial arguments.
func WithDialArgs(net, addr string, conf *ssh.ClientConfig) ClaimOption {
	return func(co *claimOptions) {
		co.dial = &dialArgs{
			net:  net,
			addr: addr,
			conf: conf,
		}
	}
}

// WithID specifies a client ID to use when claiming. If none is given, it is
// inferred from dial arguments.
func WithID(id string) ClaimOption {
	return func(co *claimOptions) {
		co.id = id
	}
}

// WithSessPoolOptions specifies session pool options to use during claims.
func WithSessPoolOption(opts ...sesspool.Option) ClaimOption {
	return func(co *claimOptions) {
		co.sessOpts = append(co.sessOpts, opts...)
	}
}

// WithClientFactory specifies a function to call to create a new SSH client.
// Supports fully custom creation. Must specify an ID with this.
func WithClientFactory(f NewSSHClientFunc) ClaimOption {
	return func(co *claimOptions) {
		co.newSSH = f
	}
}

// NewSSHClientFunc returns a new ssh client.
type NewSSHClientFunc func(ctx context.Context) (*ssh.Client, error)

// TryClaimSession attempts, without blocking, to claim a session from the given ID in the pool.
// Returns PoolExhausted error (from errors.Cause) if there are no available resources.
func (p *ClientPool) TryClaimSession(ctx context.Context, opts ...ClaimOption) (*Session, error) {
	co := newClaimOptions(opts...)

	cc, err := p.getOrCreate(ctx, co)
	if err != nil {
		return nil, errors.Wrap(err, "try claim session")
	}
	sch, err := cc.pool.TryClaim(ctx)
	if err != nil {
		if errors.Cause(err) == sesspool.PoolExhausted {
			return nil, errors.Wrap(PoolExhausted, "try claim from session pool")
		}
		// Any error in a Claim will indicate a problem with the underlying
		// connection (right?). Since this is a waiting claim, it won't ever
		// return sesspool.PoolExhausted.
		cc.pool.Close()
		defer un(lock(p))
		p.unsafeRemoveClient(cc.id)
		return nil, errors.Wrap(err, "try claim from session pool")
	}
	return &Session{
		Session:    *sch,
		clientPool: p,
		item:       cc,
	}, nil
}

// ClaimSession blocks until the context expires or a session is obtained from the given ID in the pool.
// Will block until an appropriate connection is available, or until a session is available on a connection.
func (p *ClientPool) ClaimSession(ctx context.Context, opts ...ClaimOption) (*Session, error) {
	co := newClaimOptions(opts...)
	var (
		cc  *connItem
		err error
	)
	for {
		cc, err = p.getOrCreate(ctx, co)
		if err == nil {
			break
		}
		if errors.Cause(err) != PoolExhausted {
			return nil, errors.Wrap(err, "claim session")
		}
		select {
		case <-time.After(10 * time.Second):
		case <-ctx.Done():
			return nil, errors.Wrap(ctx.Err(), "claim session")
		}
	}

	sch, err := cc.pool.Claim(ctx)
	if err != nil {
		// Any error in a Claim will indicate a problem with the underlying
		// connection (right?). Since this is a waiting claim, it won't ever
		// return sesspool.PoolExhausted.
		cc.pool.Close()
		defer un(lock(p))
		p.unsafeRemoveClient(cc.id)
		return nil, errors.Wrap(err, "claim session")
	}
	return &Session{
		Session:    *sch,
		clientPool: p,
		item:       cc,
	}, nil
}

// Close closes all connections in the pool (all session pools) and cleans up.
func (p *ClientPool) Close() error {
	defer un(lock(p))
	defer close(p.done)

	var err error
	for _, v := range p.conns {
		if cerr := v.pool.Close(); cerr != nil {
			err = cerr
		}
	}
	p.conns = make(map[string]*connItem)
	return err
}

// lock is used with un in this pattern:
// 	 defer un(lock(foo))
func lock(l sync.Locker) func() {
	l.Lock()
	return l.Unlock
}

// un is used with lock in this pattern:
// 	 defer un(lock(foo))
func un(undo func()) {
	undo()
}
