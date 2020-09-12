// Package sshchanpool provides a "pool" of ssh channels.
// You can try to claim one from the pool, closing it when done.
// The pool has a configurable maximum size.
//
// Each channel, when released, is actually closed, and a new
// claim creates a new channel over the provided connection.
package sshchanpool // import "entrogo.com/sshpool/pkg/sshchanpool"

import (
	"context"
	"log"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

var (
	// TooManyChannels is returned when the pool is "empty", meaning no more
	// channels can be claimed.
	TooManyChannels = errors.New("too many channels")

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

// SSHChan is an abstraction around ssh.Channel that is pool-aware.
// When finished, callers should invoke Close on it to return it
// to the pool.
type SSHChan struct {
	Ch      ssh.Channel
	handler RequestHandler

	pool *SSHChanPool
	done chan bool
}

func newSSHChan(ctx context.Context, pool *SSHChanPool, ch ssh.Channel, reqCh <-chan *ssh.Request, opts ...ChannelOption) *SSHChan {
	sch := &SSHChan{
		Ch:   ch,
		done: make(chan bool),
		pool: pool,
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
			case <-ctx.Done():
				log.Printf("SSHChan context canceled: %v", ctx.Err())
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
func (c *SSHChan) Close() (err error) {
	defer close(c.done) // stop the handler
	defer func() {
		cerr := c.Ch.Close()
		if err == nil {
			err = errors.Wrap(cerr, "close ssh chan")
		}
	}()
	return errors.Wrap(c.pool.release(c), "close ssh chan")
}

// ChannelOption is used to specify characteristics of the requested channel, when claiming.
type ChannelOption func(*SSHChan)

// WithRequestHandler sets a function to call whenever an out-of-band
// request comes in on the client channel. Uses DefaultRequestHandler
// when not specified.
func WithRequestHandler(h RequestHandler) ChannelOption {
	return func(c *SSHChan) {
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

// SSHChanPool provides convenient ways to create new channels within
// an existing SSH connection.
type SSHChanPool struct {
	sync.Mutex

	Conn ssh.Conn

	maxChannels int // maximum allowed channels, 0 indicates no imposed limit.
	busy        []*SSHChan
}

// Option is used to modify how pools are created.
type Option func(*SSHChanPool)

// WithMaxChannels sets the maximum allowed simultaneous channels for a connection.
func WithMaxChannels(max int) Option {
	return func(cp *SSHChanPool) {
		cp.maxChannels = max
	}
}

// New creates a new SSHChanPool given an already-created ssh connection
// It does not take ownership of the connection: callers should clean it
// up on their own when finished.
func New(ctx context.Context, conn ssh.Conn, opts ...Option) (*SSHChanPool, error) {
	cp := &SSHChanPool{
		Conn: conn,
	}
	for _, o := range opts {
		o(cp)
	}
	return cp, nil
}

// Claim creates an SSHChan (if it can) and passes it back.
// The caller should close the SSHChan when finished, to return it
// to the pool. The underlying channel is closed at that time.
func (p *SSHChanPool) TryClaim(ctx context.Context, opts ...ChannelOption) (*SSHChan, error) {
	defer un(lock(p))

	if p.maxChannels > 0 && len(p.busy) >= p.maxChannels {
		return nil, TooManyChannels
	}

	sch, rch, err := p.Conn.OpenChannel("session", nil)
	if err != nil {
		return nil, errors.Wrap(err, "try claim")
	}

	return newSSHChan(ctx, p, sch, rch, opts...), nil
}

// release returns the channel to the pool. It does not close it, that should be done by the caller.
func (p *SSHChanPool) release(c *SSHChan) error {
	defer un(lock(p))
	for i, b := range p.busy {
		if b == c {
			// Swap the one we found to the end, then shorten, since order is unimportant.
			p.busy[len(p.busy)-1], p.busy[i] = p.busy[i], p.busy[len(p.busy)-1]
			p.busy = p.busy[:len(p.busy)-1]
			return nil
		}
	}
	return ChannelNotFound
}

// Close cleans up the channels in this pool (but does not clean up the
// underlying connection). This should always be called when finished.
func (p *SSHChanPool) Close() error {
	defer un(lock(p))

	var err error // captures the last close error in the group.
	for _, sch := range p.busy {
		if serr := sch.Ch.Close(); serr != nil {
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
