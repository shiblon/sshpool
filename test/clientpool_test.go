package test

import (
	"context"
	"entrogo.com/sshpool/pkg/clientpool"
	"entrogo.com/sshpool/pkg/sesspool"
	"fmt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"strings"
	"testing"
	"time"
)

var (
	testPool *clientpool.ClientPool

	sshHost = hostConfig{
		Host:     "sftp",
		Port:     10022,
		Username: "testuser",
		Password: "testuser",
	}

	sshTunnelHost = hostConfig{
		Host:     "sftp",
		Port:     10022,
		Username: "testshareuser",
		Password: "testshareuser",
	}

	sshSecondTunnelHost = hostConfig{
		Host:     "jump",
		Port:     10033,
		Username: "testotheruser",
		Password: "testotheruser",
	}
)

// simple struct to hold test host connectivity info
type hostConfig struct {
	Host     string
	Port     int
	Username string
	Password string
}

// serializes host connectivity info to string
func (c *hostConfig) String() string {
	return fmt.Sprintf("%s:%s:%d:%s", c.Username, c.Host, c.Port, c.Password)
}

// generates a ClaimOption for use when obtaining a host ssh.ClientConfig from a clientpool.ClientPool
func (c *hostConfig) ClaimOption() clientpool.ClaimOption {
	cfg := &ssh.ClientConfig{
		User:            c.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(c.Password)},
		Timeout:         60 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)

	return clientpool.WithDialArgs("tcp", addr, cfg)
}

// Creates a session id based on a semicolon delimited list of serialized hostConfigs.
func sessionId(hostConfigs ...*hostConfig) string {
	var ids []string
	for _, cfg := range hostConfigs {
		ids = append(ids, cfg.String())
	}

	return strings.Join(ids, ";")
}

// dumps the current pool stats to stdout
func printPoolStats() {
	stats := testPool.PoolStats()
	log.Printf("Connection pool stats: %v", stats)
}

// Tests that the connection pool increments on new connection and decrements on cleanup. The expected behavior
// is that multiple calls to sesspool.AsSFTPClient followed by a call to the cleanup callback will result in
// the testPool retaining a single entry while the session pool will increment and decrement, resulting in
// a net size of zero clients for the session.
func TestAsSFTPClient(t *testing.T) {

	testPool = clientpool.New()

	sessionId := sessionId(&sshHost)

	for range []int{0, 1, 2, 3, 4} {

		sess, err := testPool.ClaimSession(context.Background(), sshHost.ClaimOption(), clientpool.WithID(sessionId))

		_, cleanup, err := sesspool.AsSFTPClient(sess, err)
		if err != nil {
			assert.FailNowf(t, err.Error(), "Failed to connect to test server: %v", err)
		}

		//printPoolStats()
		assert.Equal(t, len(testPool.PoolStats()), 1, "test pool size should be 1 when the same host and credentials are used")
		assert.True(t, testPool.HasID(sessionId), "Session should be present in test pool after successful login(s)")
		beforeSessionPoolSize := testPool.NumSessionsForID(sessionId)
		assert.Equal(t, 1, beforeSessionPoolSize, "Session should have a single connection before cleanup")

		err = cleanup()
		// Ignore EOF errors as they are likely not errors.
		assert.True(t, err == nil || errors.Cause(err) == io.EOF, "Cleanup should return null or io.EOF: %v", err)

		//printPoolStats()
		assert.Equal(t, 1, len(testPool.PoolStats()), "test pool size should be 1 when the same host and credentials are used")
		assert.True(t, testPool.HasID(sessionId), "Session should be present in test pool after cleanup")
		afterSessionPoolSize := testPool.NumSessionsForID(sessionId)
		assert.Equal(t, 0, afterSessionPoolSize, "Session should have a single connection after cleanup")
	}

	err := testPool.Close()
	assert.Nil(t, err, fmt.Sprintf("Closing test pool should not throw error: %v", err))
}

// Tests that establishing ssh tunnels authenticates to the jump host and forwards connection.
func TestAsSFTPClientWithTunnel(t *testing.T) {

	testPool = clientpool.New()

	sessionId := sessionId(&sshHost, &sshTunnelHost)

	sess, err := testPool.ClaimSession(context.Background(),
		sshHost.ClaimOption(),
		sshTunnelHost.ClaimOption(),
		clientpool.WithID(sessionId))

	_, cleanup, err := sesspool.AsSFTPClient(sess, err)
	if err != nil {
		assert.FailNowf(t, err.Error(), "Failed to create ssh tunnel to jump server: %v", err)
	}

	//printPoolStats()
	assert.True(t, testPool.HasID(sessionId), "Session should be present in test pool after successful login(s)")
	beforeSessionPoolSize := testPool.NumSessionsForID(sessionId)
	assert.Equal(t, 1, beforeSessionPoolSize, "Session should have a single connection before cleanup")

	err = cleanup()
	// Ignore EOF errors as they are likely not errors.
	assert.True(t, err == nil || errors.Cause(err) == io.EOF, "Cleanup should return null or io.EOF: %v", err)

	//printPoolStats()
	assert.Equal(t, 1, len(testPool.PoolStats()), "test pool size should be 1 when the same host and credentials are used")
	assert.True(t, testPool.HasID(sessionId), "Session should be present in test pool after cleanup")
	afterSessionPoolSize := testPool.NumSessionsForID(sessionId)
	assert.Equal(t, 0, afterSessionPoolSize, "Session should have a single connection after cleanup")

	err = testPool.Close()
	assert.Nil(t, err, fmt.Sprintf("Closing test pool should not throw error: %v", err))
}

// Tests that establishing multi-hop ssh tunnels
func TestAsSFTPClientWithMultiHopTunnel(t *testing.T) {

	testPool = clientpool.New()

	sessionId := sessionId(&sshHost, &sshTunnelHost, &sshSecondTunnelHost)

	sess, err := testPool.ClaimSession(context.Background(),
		sshHost.ClaimOption(),
		sshTunnelHost.ClaimOption(),
		sshSecondTunnelHost.ClaimOption(),
		clientpool.WithID(sessionId))

	_, cleanup, err := sesspool.AsSFTPClient(sess, err)
	if err != nil {
		assert.FailNowf(t, err.Error(), "Failed to create ssh tunnel to jump server: %v", err)
	}

	//printPoolStats()
	assert.True(t, testPool.HasID(sessionId), "Session should be present in test pool after successful login(s)")
	beforeSessionPoolSize := testPool.NumSessionsForID(sessionId)
	assert.Equal(t, 1, beforeSessionPoolSize, "Session should have a single connection before cleanup")

	err = cleanup()
	// Ignore EOF errors as they are likely not errors.
	assert.True(t, err == nil || errors.Cause(err) == io.EOF, "Cleanup should return null or io.EOF: %v", err)

	//printPoolStats()
	assert.Equal(t, 1, len(testPool.PoolStats()), "test pool size should be 1 when the same host and credentials are used")
	assert.True(t, testPool.HasID(sessionId), "Session should be present in test pool after cleanup")
	afterSessionPoolSize := testPool.NumSessionsForID(sessionId)
	assert.Equal(t, 0, afterSessionPoolSize, "Session should have a single connection after cleanup")

	err = testPool.Close()
	assert.Nil(t, err, fmt.Sprintf("Closing test pool should not throw error: %v", err))
}
