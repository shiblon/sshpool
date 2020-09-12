// Package sshchanpool provides a "pool" of ssh channels.
// You can try to claim one from the pool, closing it when done.
// The pool has a configurable maximum size.
//
// Each channel, when released, is actually closed, and a new
// claim creates a new channel over the provided connection.
//
// Example:
//
// 	// Create an ssh.Conn in the conn variable, however you want, then...
//  pool := New(ctx, conn, WithMaxChannels(10))
//  sch, err := pool.Claim(ctx)
//  if err != nil {
//    log.Fatalf("Error claiming: %v", err)
//  }
//  defer sch.Close()
//
//  sftpCli, err := sftp.NewClientPipe(sch, sch)
//  if err != nil {
//    log.Fatalf("Error creating sftp client: %v", err)
//  }
//  defer sftpCli.Close()
//
//  // Use the sftpCli over the channel until done.
//
package sshchanpool // import "entrogo.com/sshpool/pkg/sshchanpool"

import (
	"context"
	"sync"

	"entrogo.com/entroq/subq"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

var (
	// PoolExhausted is returned when the pool is "empty", meaning no more
	// channels can be claimed.
	PoolExhausted = errors.New("too many channels")

	// ChannelNotFound is returned when attempting to close a channel not in the pool.
	ChannelNotFound = errors.New("channel not found")
)

// RequestHandler handles out-of-band SSH channel requests by replying true or false.
type RequestHandler func(t string, wantReply bool, payload []byte) bool

// FalseRequestHandler returns true for every request regardless of payload.
func TrueRequestHandler(t string, wantReply bool, payload []byte) bool {
	return true
}

// FalseRequestHandler returns false for every request regardless of payload.
func FalseRequestHandler(t string, wantReply bool, payload []byte) bool {
	return true
}

// Chan is an abstraction around ssh.Channel that is pool-aware.
// When finished, callers should invoke Close on it to return it
// to the pool.
type Chan struct {
	ssh.Channel

	handler RequestHandler
	pool    *Pool
	done    chan bool
}

func newChan(pool *Pool, ch ssh.Channel, reqCh <-chan *ssh.Request, opts ...ChannelOption) *Chan {
	sch := &Chan{
		Channel: ch,
		done:    make(chan bool),
		pool:    pool,
	}

	for _, o := range opts {
		o(sch)
	}

	if sch.handler == nil {
		sch.handler = DefaultRequestHandler
	}

	go func() {
		for {
			select {
			case <-sch.done:
				return
			case req := <-reqCh:
				val := sch.handler(req.Type, req.WantReply, req.Payload)
				if req.WantReply {
					req.Reply(val, nil)
				}
			}
		}
	}()

	return sch
}

// Close returns this channel to the pool and closes the underlying channel.
func (c *Chan) Close() (err error) {
	defer close(c.done) // stop the handler
	defer func() {
		cerr := c.Channel.Close()
		if err == nil {
			err = errors.Wrap(cerr, "close ssh chan")
		}
	}()
	return errors.Wrap(c.pool.release(c), "close ssh chan")
}

// ChannelOption is used to specify characteristics of the requested channel, when claiming.
type ChannelOption func(*Chan)

// WithRequestHandler sets a function to call whenever an out-of-band
// request comes in on the client channel. Uses DefaultRequestHandler
// when not specified.
func WithRequestHandler(h RequestHandler) ChannelOption {
	return func(c *Chan) {
		c.handler = h
	}
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

// Pool provides convenient ways to create new channels within
// an existing SSH connection.
type Pool struct {
	sync.Mutex

	Conn ssh.Conn

	maxChannels int // maximum allowed channels, 0 indicates no imposed limit.
	busy        []*Chan

	poolSub *subq.SubQ // notify/wait for pool size changes
}

// Option is used to modify how pools are created.
type Option func(*Pool)

// WithMaxChannels sets the maximum allowed simultaneous channels for a connection.
func WithMaxChannels(max int) Option {
	return func(cp *Pool) {
		cp.maxChannels = max
	}
}

// New creates a new Pool given an already-created ssh connection
// It does not take ownership of the connection: callers should clean it
// up on their own when finished.
func New(conn ssh.Conn, opts ...Option) *Pool {
	cp := &Pool{
		Conn:    conn,
		poolSub: subq.New(),
	}
	for _, o := range opts {
		o(cp)
	}
	return cp
}

// Exhausted indicates whether this pool is exhausted (not free for claims).
func (p *Pool) Exhausted() bool {
	return p.maxChannels > 0 && p.Used() >= p.maxChannels
}

// Len indicates how many things are busy from the pool.
func (p *Pool) Used() int {
	defer un(lock(p))
	return len(p.busy)
}

// TryClaim creates a Chan (if it can) and passes it back.
// The caller should close the Chan when finished, to return it
// to the pool. The underlying channel is closed at that time.
//
// Does not block if the pool is empty, rather returns a PoolExhausted error.
func (p *Pool) TryClaim(opts ...ChannelOption) (*Chan, error) {
	defer un(lock(p))

	if p.maxChannels > 0 && len(p.busy) >= p.maxChannels {
		return nil, PoolExhausted
	}

	sch, rch, err := p.Conn.OpenChannel("session", nil)
	if err != nil {
		return nil, errors.Wrap(err, "try claim")
	}

	c := newChan(p, sch, rch, opts...)
	p.busy = append(p.busy, c)
	return c, nil
}

const poolNotifyQueue = "sshpool"

// Claim blocks on the pool until a channel can be claimed. Returns immediately for unlimited pools.
func (p *Pool) Claim(ctx context.Context, opts ...ChannelOption) (*Chan, error) {
	var (
		c        *Chan
		claimErr error
	)
	if err := p.poolSub.Wait(ctx, []string{poolNotifyQueue}, 0, func() bool {
		defer p.poolSub.Notify(poolNotifyQueue)
		c, claimErr = p.TryClaim(opts...)
		// Stop trying if successful, or a non-waitable error occurs.
		return claimErr != nil || errors.Cause(claimErr) != PoolExhausted
	}); err != nil {
		return nil, errors.Wrap(err, "claim")
	}
	if claimErr != nil {
		return nil, errors.Wrap(claimErr, "claim")
	}
	return c, nil
}

// release returns the channel to the pool. It does not close it, that should be done by the caller.
func (p *Pool) release(c *Chan) error {
	defer un(lock(p))
	for i, b := range p.busy {
		if b == c {
			// Swap the one we found to the end, then shorten, since order is unimportant.
			p.busy[len(p.busy)-1], p.busy[i] = p.busy[i], p.busy[len(p.busy)-1]
			p.busy = p.busy[:len(p.busy)-1]
			p.poolSub.Notify(poolNotifyQueue)
			return nil
		}
	}
	return ChannelNotFound
}

// Close cleans up the channels in this pool (but does not clean up the
// underlying connection). This should always be called when finished.
func (p *Pool) Close() error {
	defer un(lock(p))

	var err error // captures the last close error in the group.
	for _, sch := range p.busy {
		if serr := sch.Close(); serr != nil {
			err = serr
		}
	}
	p.busy = nil
	return err
}

var (
	// DefaultRequestHandler is used when no request handler is specified
	// when claiming a channel.
	DefaultRequestHandler = TrueRequestHandler
)
