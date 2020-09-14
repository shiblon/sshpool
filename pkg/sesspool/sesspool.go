// Package sesspool provides a "pool" of ssh sessions.
// You can try to claim one from the pool, closing it when done.
// The pool has a configurable maximum size.
//
// Each session, when released, is actually closed, and a new
// claim creates a new session over the provided connection.
//
// Example:
//
// 	// Create an ssh.Client however you want, then...
//  pool := New(ctx, sshClient, WithMaxSessions(10))
//  sess, err := pool.Claim(ctx)
//  if err != nil {
//    log.Fatalf("Error claiming: %v", err)
//  }
//  defer sess.Close()
//
//  sftpCli, err := sess.SFTPClient()
//  if err != nil {
//    log.Fatalf("Error getting sftp client: %v", err)
//  }
//  defer sftpCli.Close()
//
//  // Use the sftpCli over the session until done.
//
package sesspool // import "entrogo.com/sshpool/pkg/sesspool"

import (
	"context"
	"sync"

	"entrogo.com/entroq/subq"
	"github.com/pkg/errors"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	// PoolExhausted is returned when the pool is "empty", meaning no more
	// session can be claimed.
	PoolExhausted = errors.New("session pool exhausted")

	// SessionNotFound is returned when attempting to close a session not in the pool.
	SessionNotFound = errors.New("not found")
)

// Session is an abstraction around ssh.Session that is pool-aware.
// When finished, callers should invoke Close on it to return it
// to the pool.
type Session struct {
	sess *ssh.Session
	pool *Pool
}

func newSession(pool *Pool, sess *ssh.Session) *Session {
	return &Session{
		sess: sess,
		pool: pool,
	}
}

// AsSFTPClient can wrap a Claim method to produce an SFTP client.
//
// Example:
//   cli, cleanup, err := AsSFTPClient(pool.Claim(ctx))
//   if err != nil {
//     // handle err
//   }
//   defer cleanup()
//   // use cli
func AsSFTPClient(s *Session, err error) (*sftp.Client, func() error, error) {
	if err != nil {
		return nil, nil, errors.Wrap(err, "as sftp client")
	}
	cli, err := s.SFTPClient()
	if err != nil {
		return nil, nil, errors.Wrap(err, "as sftp client")
	}
	return cli, func() error {
		cerr := cli.Close()
		serr := s.Close()
		// Just return the deepest close error.
		if serr != nil {
			return serr
		}
		if cerr != nil {
			return cerr
		}
		return nil
	}, nil
}

// SFTPClient returns an sftp.Client for this session. Be sure to close it when finished.
func (s *Session) SFTPClient(opts ...sftp.ClientOption) (*sftp.Client, error) {
	if err := s.sess.RequestSubsystem("sftp"); err != nil {
		return nil, errors.Wrap(err, "sftp client request")
	}
	writer, err := s.sess.StdinPipe()
	if err != nil {
		return nil, errors.Wrap(err, "sftp client stdin")
	}
	reader, err := s.sess.StdoutPipe()
	if err != nil {
		return nil, errors.Wrap(err, "sftp client stdout")
	}
	return sftp.NewClientPipe(reader, writer, opts...)
}

// Close returns this session to the pool and closes the underlying session.
func (s *Session) Close() (err error) {
	defer func() {
		cerr := s.sess.Close()
		if err == nil {
			err = errors.Wrap(cerr, "close ssh chan")
		}
	}()
	return errors.Wrap(s.pool.release(s), "close ssh chan")
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

// Pool provides convenient ways to create new sessions within
// an existing SSH connection.
type Pool struct {
	sync.Mutex

	SSHClient *ssh.Client

	maxSessions int // maximum allowed sessions, 0 indicates no imposed limit.
	busy        []*Session

	poolSub *subq.SubQ // notify/wait for pool size changes
}

// Option is used to modify how pools are created.
type Option func(*Pool)

// WithMaxSessions sets the maximum allowed simultaneous sessions for a connection.
func WithMaxSessions(max int) Option {
	return func(cp *Pool) {
		cp.maxSessions = max
	}
}

// New creates a new Pool given an already-created ssh client.
// It does not take ownership of the client: callers should clean it
// up on their own when finished.
func New(client *ssh.Client, opts ...Option) *Pool {
	cp := &Pool{
		SSHClient: client,
		poolSub:   subq.New(),
	}
	for _, o := range opts {
		o(cp)
	}
	return cp
}

// Exhausted indicates whether this pool is exhausted (not free for claims).
func (p *Pool) Exhausted() bool {
	defer un(lock(p))
	return p.unsafeExhausted()
}

// unsafeExhausted provides access to whether the pool is exhausted, without
// taking a mutex to do it.
func (p *Pool) unsafeExhausted() bool {
	return p.maxSessions > 0 && len(p.busy) >= p.maxSessions
}

// Len indicates how many things are busy from the pool.
func (p *Pool) Used() int {
	defer un(lock(p))
	return len(p.busy)
}

// TryClaim creates a Session (if it can) and passes it back.
// The caller should close the Session when finished, to return it
// to the pool. The underlying session is closed at that time.
//
// Does not block if the pool is empty, rather returns a PoolExhausted error.
func (p *Pool) TryClaim(ctx context.Context) (*Session, error) {
	defer un(lock(p))

	if p.unsafeExhausted() {
		return nil, PoolExhausted
	}

	sess, err := p.SSHClient.NewSession()
	if err != nil {
		return nil, errors.Wrap(err, "try claim")
	}

	s := newSession(p, sess)
	p.busy = append(p.busy, s)
	return s, nil
}

const poolNotifyQueue = "sesspool"

// Claim blocks on the pool until a session can be claimed. Returns immediately for unlimited pools.
func (p *Pool) Claim(ctx context.Context) (*Session, error) {
	var (
		s        *Session
		claimErr error
	)
	if err := p.poolSub.Wait(ctx, []string{poolNotifyQueue}, 0, func() bool {
		defer p.poolSub.Notify(poolNotifyQueue)
		s, claimErr = p.TryClaim(ctx)
		// Stop trying if successful, or a non-waitable error occurs.
		return claimErr != nil || errors.Cause(claimErr) != PoolExhausted
	}); err != nil {
		return nil, errors.Wrap(err, "claim")
	}
	if claimErr != nil {
		return nil, errors.Wrap(claimErr, "claim")
	}
	return s, nil
}

// release returns the session to the pool. It does not close it, that should be done by the caller.
func (p *Pool) release(s *Session) error {
	defer un(lock(p))
	for i, b := range p.busy {
		if b == s {
			// Swap the one we found to the end, then shorten, since order is unimportant.
			p.busy[len(p.busy)-1], p.busy[i] = p.busy[i], p.busy[len(p.busy)-1]
			p.busy = p.busy[:len(p.busy)-1]
			p.poolSub.Notify(poolNotifyQueue)
			return nil
		}
	}
	return SessionNotFound
}

// Close cleans up the sessions in this pool (but does not clean up the
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
