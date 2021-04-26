package test

import (
	"context"
	"entrogo.com/sshpool/pkg/clientpool"
	"entrogo.com/sshpool/pkg/sesspool"
	"fmt"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	"log"
	"testing"
	"time"
)

const (
	SSH_HOST     = "sftp"
	SSH_PORT     = 10022
	SSH_USERNAME = "testuser"
	SSH_PASSWORD = "testuser"
)

var testPool = clientpool.New()

func sessionId() string {
	return fmt.Sprintf("%s:%s:%d:%s", SSH_USERNAME, SSH_HOST, SSH_PORT, SSH_PASSWORD)
}

func newClient() (*sftp.Client, func() error, error) {

	cfg := &ssh.ClientConfig{
		User:            SSH_USERNAME,
		Auth:            []ssh.AuthMethod{ssh.Password(SSH_PASSWORD)},
		Timeout:         60 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := fmt.Sprintf("%s:%d", SSH_HOST, SSH_PORT)

	return sesspool.AsSFTPClient(testPool.ClaimSession(context.Background(), clientpool.WithDialArgs("tcp", addr, cfg), clientpool.WithID(sessionId())))
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

	for range []int{0, 1, 2, 3, 4} {
		_, cleanup, err := newClient()
		if err != nil {
			assert.FailNowf(t, err.Error(), "Failed to connect to test server: %v", err)
		}

		printPoolStats()
		assert.Equal(t, len(testPool.PoolStats()), 1, "test pool size should be 1 when the same host and credentials are used")
		assert.True(t, testPool.HasID(sessionId()), "Session should be present in test pool after successful login(s)")
		beforeSessionPoolSize := testPool.NumSessionsForID(sessionId())
		assert.Equal(t, 1, beforeSessionPoolSize, "Session should have a single connection before cleanup")

		err = cleanup()
		if err != nil {
			// This will always return an err.Error() == "close ssh chan: not found"
			log.Printf("Error cleaning up client callback: %v", err.Error())
		}

		printPoolStats()
		assert.Equal(t, len(testPool.PoolStats()), 1, "test pool size should be 1 when the same host and credentials are used")
		assert.True(t, testPool.HasID(sessionId()), "Session should be present in test pool after cleanup")
		afterSessionPoolSize := testPool.NumSessionsForID(sessionId())
		assert.Equal(t, 0, afterSessionPoolSize, "Session should have a single connection after cleanup")
	}

	log.Printf("Test completed")
	//defer func() {
	//	# This causes the test to deadlock indefinitely
	//	err := testPool.Close()
	//	if err != nil {
	//		log.Printf("Error closing test pool: %v", err.Error())
	//		assert.FailNowf(t, err.Error(), "Failed to close pool after test: %v", err)
	//	}
	//}()
}
