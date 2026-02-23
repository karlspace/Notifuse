package service

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-sasl"
)

// xoauth2Client implements sasl.Client for the XOAUTH2 mechanism.
// XOAUTH2 format: "user=" + user + "\x01auth=Bearer " + token + "\x01\x01"
type xoauth2Client struct {
	username    string
	accessToken string
}

func (c *xoauth2Client) Start() (string, []byte, error) {
	ir := fmt.Sprintf("user=%s\x01auth=Bearer %s\x01\x01", c.username, c.accessToken)
	return "XOAUTH2", []byte(ir), nil
}

func (c *xoauth2Client) Next(challenge []byte) ([]byte, error) {
	// XOAUTH2 error challenges are base64-encoded JSON; respond with empty to terminate
	return nil, fmt.Errorf("XOAUTH2 challenge: %s", string(challenge))
}

// Ensure xoauth2Client implements sasl.Client at compile time
var _ sasl.Client = (*xoauth2Client)(nil)

// IMAPMessage represents a fetched email message
type IMAPMessage struct {
	UID     imap.UID
	RawBody []byte
}

// IMAPAuthConfig holds authentication configuration for IMAP connections
type IMAPAuthConfig struct {
	Host     string
	Port     int
	UseTLS   bool
	AuthType string // "basic" or "oauth2"

	// Basic auth
	Username string
	Password string

	// OAuth2
	AccessToken string // Pre-fetched OAuth2 access token for XOAUTH2
}

// IMAPClient abstracts IMAP operations for testing
type IMAPClient interface {
	Connect(config IMAPAuthConfig) error
	FetchUnseenMessages(folder string) ([]IMAPMessage, error)
	MarkAsSeen(uids []imap.UID) error
	Close() error
}

// NewIMAPClient creates a new real IMAP client
func NewIMAPClient() IMAPClient {
	return &realIMAPClient{}
}

type realIMAPClient struct {
	client *imapclient.Client
}

func (c *realIMAPClient) Connect(config IMAPAuthConfig) error {
	addr := net.JoinHostPort(config.Host, fmt.Sprintf("%d", config.Port))

	var client *imapclient.Client
	var err error

	if config.UseTLS {
		client, err = imapclient.DialTLS(addr, &imapclient.Options{
			TLSConfig: &tls.Config{ServerName: config.Host},
		})
	} else {
		client, err = imapclient.DialInsecure(addr, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to connect to IMAP server %s: %w", addr, err)
	}

	if config.AuthType == "oauth2" {
		// XOAUTH2 authentication
		saslClient := &xoauth2Client{username: config.Username, accessToken: config.AccessToken}
		if err := client.Authenticate(saslClient); err != nil {
			client.Close()
			return fmt.Errorf("IMAP XOAUTH2 authentication failed: %w", err)
		}
	} else {
		// Basic authentication (default)
		if err := client.Login(config.Username, config.Password).Wait(); err != nil {
			client.Close()
			return fmt.Errorf("IMAP login failed: %w", err)
		}
	}

	c.client = client
	return nil
}

func (c *realIMAPClient) FetchUnseenMessages(folder string) ([]IMAPMessage, error) {
	if c.client == nil {
		return nil, fmt.Errorf("IMAP client not connected")
	}

	// Select the mailbox
	if _, err := c.client.Select(folder, nil).Wait(); err != nil {
		return nil, fmt.Errorf("failed to select folder %q: %w", folder, err)
	}

	// Search for unseen messages
	criteria := &imap.SearchCriteria{
		NotFlag: []imap.Flag{imap.FlagSeen},
	}
	searchData, err := c.client.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return nil, fmt.Errorf("IMAP search failed: %w", err)
	}

	uidSet, ok := searchData.All.(imap.UIDSet)
	if !ok || len(uidSet) == 0 {
		return nil, nil
	}

	// Fetch full message body for each UID
	fetchOptions := &imap.FetchOptions{
		UID: true,
		BodySection: []*imap.FetchItemBodySection{
			{}, // Empty section = full message
		},
	}

	fetchCmd := c.client.Fetch(uidSet, fetchOptions)
	defer fetchCmd.Close()

	var messages []IMAPMessage

	for {
		msg := fetchCmd.Next()
		if msg == nil {
			break
		}

		var uid imap.UID
		var body []byte

		for {
			item := msg.Next()
			if item == nil {
				break
			}

			switch data := item.(type) {
			case imapclient.FetchItemDataUID:
				uid = data.UID
			case imapclient.FetchItemDataBodySection:
				if data.Literal != nil {
					body, _ = io.ReadAll(data.Literal)
				}
			}
		}

		if uid > 0 && len(body) > 0 {
			messages = append(messages, IMAPMessage{
				UID:     uid,
				RawBody: body,
			})
		}
	}

	return messages, nil
}

func (c *realIMAPClient) MarkAsSeen(uids []imap.UID) error {
	if c.client == nil {
		return fmt.Errorf("IMAP client not connected")
	}

	if len(uids) == 0 {
		return nil
	}

	var uidSet imap.UIDSet
	for _, uid := range uids {
		uidSet.AddNum(uid)
	}

	storeFlags := &imap.StoreFlags{
		Op:     imap.StoreFlagsAdd,
		Silent: true,
		Flags:  []imap.Flag{imap.FlagSeen},
	}

	if err := c.client.Store(uidSet, storeFlags, nil).Close(); err != nil {
		return fmt.Errorf("failed to mark messages as seen: %w", err)
	}

	return nil
}

func (c *realIMAPClient) Close() error {
	if c.client == nil {
		return nil
	}

	if err := c.client.Logout().Wait(); err != nil {
		c.client.Close()
		return err
	}

	return c.client.Close()
}
