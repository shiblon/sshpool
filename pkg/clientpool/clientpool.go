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
//  sch, err := p.ClaimSession(clientConfig.String, func(context.Context) (*ssh.Client, error) {
//  	return ssh.Dial("tcp", addr, clientConfig)
//  })
//  if err != nil {
//      log.Fatalf("Error claiming session: %v", err)
//  }
//  defer sch.Close()
//
//  sftpCli, err := sftp.NewClientPipe(sch, sch)
//  if err != nil {
//      log.Fatalf("Error creating sftp client: %v", err)
//  }
//  defer sftpCli.Close()
//
//  // Use the sftpCli to do stuff with the session.
//
// When a connection has no open sessions for a configurable amount of time,
// a reaper clears it out of the pool, making room for new configurations to
// take its place if needed.
package clientpool // import "entrogo.com/sshpool/pkg/clientpool"
import (
	"context"
	"sync"
	"time"

	"entrogo.com/sshpool/pkg/sesspool"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

const (
	DefaultPoolSize    = 10
	DefaultExpireAfter = 5 * time.Minute
)

var (
	PoolExhausted = errors.New("pool full")
)

type connItem struct {
	id       string
	lastUsed time.Time
	pool     *sesspool.Pool
}

// ClientPool is a set of client session pools, patitioned by ID (such as serialized
// SSH configuration), and using the leaky bucket algorithm to age out unused
// connections.
type ClientPool struct {
	sync.Mutex

	done  chan bool
	conns map[string]*connItem

	expireAfter time.Duration
	poolSize    int
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
	if max <= 0 {
		max = DefaultPoolSize
	}
	return func(p *ClientPool) {
		p.poolSize = max
	}
}

// NewSSHClientFunc returns a new ssh client.
type NewSSHClientFunc func(ctx context.Context) (*ssh.Client, error)

// New creates a new ClientPool with the given options.
func New(opts ...Option) *ClientPool {
	p := &ClientPool{
		done:        make(chan bool),
		conns:       make(map[string]*connItem),
		expireAfter: DefaultExpireAfter,
		poolSize:    DefaultPoolSize,
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
	return len(p.conns) >= p.poolSize
}

func (p *ClientPool) getOrCreate(ctx context.Context, id string, newSSH NewSSHClientFunc, opts ...sesspool.Option) (*connItem, error) {
	defer un(lock(p))

	cc := p.conns[id]
	if cc != nil {
		return cc, nil
	}

	if len(p.conns) >= p.poolSize {
		return nil, PoolExhausted
	}

	// Not found, room for it, create it.
	cli, err := newSSH(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "get or create client")
	}
	if cli == nil {
		return nil, errors.Errorf("ssh client function returned nil for id %v", id)
	}
	cc = &connItem{
		id:       id,
		lastUsed: time.Now(),
		pool:     sesspool.New(cli, opts...),
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
		delete(p.conns, rmid)
	}
}

// TryClaimSession attempts, without blocking, to claim a session from the given ID in the pool.
// Returns PoolExhausted error (from errors.Cause) if there are no available resources.
func (p *ClientPool) TryClaimSession(ctx context.Context, id string, newSSH NewSSHClientFunc, opts ...sesspool.Option) (*sesspool.Session, error) {
	cc, err := p.getOrCreate(ctx, id, newSSH, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "try claim session")
	}
	sch, err := cc.pool.TryClaim(ctx)
	if err != nil {
		if errors.Cause(err) == sesspool.PoolExhausted {
			return nil, errors.Wrap(PoolExhausted, "try claim from session pool")
		}
		return nil, errors.Wrap(err, "try claim from session pool")
	}
	return sch, nil
}

// ClaimSession blocks until the context expires or a session is obtained from the given ID in the pool.
// Will block until an appropriate connection is available, or until a session is available on a connection.
func (p *ClientPool) ClaimSession(ctx context.Context, id string, newSSH NewSSHClientFunc, opts ...sesspool.Option) (*sesspool.Session, error) {
	var (
		cc  *connItem
		err error
	)
	for {
		cc, err = p.getOrCreate(ctx, id, newSSH, opts...)
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
		return nil, errors.Wrap(err, "claim session")
	}
	return sch, nil
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
