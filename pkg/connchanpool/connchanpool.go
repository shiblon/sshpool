// Package connchanpool manages a set of SSH connections, each with their own
// channel pool, partitioned by custom IDs (a good candidate might be
// serialized SSH configs). Uses a leaky bucket, where connections are aged out
// after they have no open channels for a time.
//
// Example:
//
//  p := New(func(id string) ssh.Conn {
//  	// You supply this - whatever you need to do to make an ssh.Conn
//  	// from the ID passed in.
//      return makeConn(deserializeConfig(id))
//  })
//
//  sch, err := p.ClaimChannel(ctx, serializedConfig)
//  if err != nil {
//      log.Fatalf("Error claiming channel: %v", err)
//  }
//  defer sch.Close()
//
//  sftpCli, err := sftp.NewClientPipe(sch, sch)
//  if err != nil {
//      log.Fatalf("Error creating sftp client: %v", err)
//  }
//  defer sftpCli.Close()
//
//  // Use the sftpCli to do stuff with the channel.
//
// When a connection has no open channels for a configurable amount of time,
// a reaper clears it out of the pool, making room for new configurations to
// take its place if needed.
package connchanpool // import "entrogo.com/sshpool/pkg/connchanpool"
import (
	"context"
	"sync"
	"time"

	"entrogo.com/sshpool/pkg/sshchanpool"
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

// MakeSSHConnFunc creates an ssh.Conn and returns it, from the given ID.
type MakeSSHConnFunc func(id string) ssh.Conn

type connItem struct {
	id       string
	lastUsed time.Time
	chanPool *sshchanpool.Pool
}

// ConnChanPool is a set of client pools, patitioned by ID (such as serialized
// SSH configuration), and using the leaky bucket algorithm to age out unused
// connections.
type ConnChanPool struct {
	sync.Mutex

	makeSSHConn MakeSSHConnFunc

	expireAfter time.Duration
	poolSize    int
	done        chan bool
	conns       map[string]*connItem
}

// Option sets pool characteristics
type Option func(*ConnChanPool)

// WithExpireAfter sets the expiration time of a connection in the pool. If a
// connection is available past this amount of time, it is reaped.
func WithExpireAfter(d time.Duration) Option {
	if d == 0 {
		d = DefaultExpireAfter
	}
	return func(p *ConnChanPool) {
		p.expireAfter = d
	}
}

// WithPoolSize sets the pool size to something other than the default.
func WithPoolSize(max int) Option {
	if max <= 0 {
		max = DefaultPoolSize
	}
	return func(p *ConnChanPool) {
		p.poolSize = max
	}
}

// New creates a new ConnChanPool with the given options.
func New(makeSSHConn MakeSSHConnFunc, opts ...Option) *ConnChanPool {
	p := &ConnChanPool{
		makeSSHConn: makeSSHConn,
		expireAfter: DefaultExpireAfter,
		poolSize:    DefaultPoolSize,
		done:        make(chan bool),
		conns:       make(map[string]*connItem),
	}

	for _, o := range opts {
		o(p)
	}

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

type chanPoolOpts struct {
	poolOpts []sshchanpool.Option
	chanOpts []sshchanpool.ChannelOption
}

// ChanPoolOption changes how ssh channel pools and their channels are created.
type ChanPoolOption func(*chanPoolOpts)

func newChanPoolOpts(opts ...ChanPoolOption) *chanPoolOpts {
	o := new(chanPoolOpts)
	o.apply(opts...)
	return o
}

func (o *chanPoolOpts) apply(opts ...ChanPoolOption) {
	for _, opt := range opts {
		opt(o)
	}
}

// WithSSHChannelPoolOptions sets options for creating a channel pool.
func WithSSHChannelPoolOptions(opts ...sshchanpool.Option) ChanPoolOption {
	return func(co *chanPoolOpts) {
		co.poolOpts = append(co.poolOpts, opts...)
	}
}

// WithSSHChannelOptions sets options for individual channels.
func WithSSHChannelOptions(opts ...sshchanpool.ChannelOption) ChanPoolOption {
	return func(co *chanPoolOpts) {
		co.chanOpts = append(co.chanOpts, opts...)
	}
}

// Exhausted tells us whether there are slots for new IDs to be added into the pool.
func (p *ConnChanPool) Exhausted() bool {
	defer un(lock(p))
	return len(p.conns) >= p.poolSize
}

func (p *ConnChanPool) getOrCreate(ctx context.Context, id string, opts ...sshchanpool.Option) (*connItem, error) {
	defer un(lock(p))

	cc := p.conns[id]
	if cc != nil {
		return cc, nil
	}

	if len(p.conns) >= p.poolSize {
		return nil, PoolExhausted
	}

	// Not found, room for it, create it.
	conn := p.makeSSHConn(id)
	if conn == nil {
		return nil, errors.Errorf("ssh conn function returned nil for id %v", id)
	}
	cc = &connItem{
		id:       id,
		lastUsed: time.Now(),
		chanPool: sshchanpool.New(conn, opts...),
	}
	p.conns[id] = cc
	return cc, nil
}

func (p *ConnChanPool) reap() {
	defer un(lock(p))

	var toRemove []string

	for id, v := range p.conns {
		if v.chanPool.Used() > 0 {
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

// TryClaimChannel attempts, without blocking, to claim a channel from the given ID in the pool.
// Returns PoolExhausted error (from errors.Cause) if there are no available resources.
func (p *ConnChanPool) TryClaimChannel(ctx context.Context, id string, opts ...ChanPoolOption) (*sshchanpool.Chan, error) {
	cpOpt := newChanPoolOpts(opts...)

	cc, err := p.getOrCreate(ctx, id, cpOpt.poolOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "try claim channel")
	}
	sch, err := cc.chanPool.TryClaim(ctx, cpOpt.chanOpts...)
	if err != nil {
		if errors.Cause(err) == sshchanpool.PoolExhausted {
			return nil, errors.Wrap(PoolExhausted, "try claim from channel pool")
		}
		return nil, errors.Wrap(err, "try claim from channel pool")
	}
	return sch, nil
}

// ClaimChannel blocks until the context expires or a channel is obtained from the given ID in the pool.
// Will block until an appropriate connection is available, or until a channel is available on a connection.
func (p *ConnChanPool) ClaimChannel(ctx context.Context, id string, opts ...ChanPoolOption) (*sshchanpool.Chan, error) {
	cpOpt := newChanPoolOpts(opts...)
	var (
		cc  *connItem
		err error
	)
	for {
		cc, err = p.getOrCreate(ctx, id, cpOpt.poolOpts...)
		if err == nil {
			break
		}
		if errors.Cause(err) != PoolExhausted {
			return nil, errors.Wrap(err, "claim channel")
		}
		select {
		case <-time.After(10 * time.Second):
		case <-ctx.Done():
			return nil, errors.Wrap(ctx.Err(), "claim channel")
		}
	}

	sch, err := cc.chanPool.Claim(ctx, cpOpt.chanOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "claim channel")
	}
	return sch, nil
}

// Close closes all connections in the pool (all channel pools) and cleans up.
func (p *ConnChanPool) Close() error {
	defer un(lock(p))
	defer close(p.done)

	var err error
	for _, v := range p.conns {
		if cerr := v.chanPool.Close(); cerr != nil {
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
