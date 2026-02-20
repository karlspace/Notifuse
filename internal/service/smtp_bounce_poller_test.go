package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Notifuse/notifuse/internal/domain"
)

// mockIMAPClient implements IMAPClient for testing
type mockIMAPClient struct {
	connectErr error
	fetchErr   error
	markErr    error
	messages   []IMAPMessage
	seenUIDs   []imap.UID
	connected  bool
	closed     bool
}

func (m *mockIMAPClient) Connect(host string, port int, useTLS bool, username, password string) error {
	if m.connectErr != nil {
		return m.connectErr
	}
	m.connected = true
	return nil
}

func (m *mockIMAPClient) FetchUnseenMessages(folder string) ([]IMAPMessage, error) {
	if m.fetchErr != nil {
		return nil, m.fetchErr
	}
	return m.messages, nil
}

func (m *mockIMAPClient) MarkAsSeen(uids []imap.UID) error {
	if m.markErr != nil {
		return m.markErr
	}
	m.seenUIDs = append(m.seenUIDs, uids...)
	return nil
}

func (m *mockIMAPClient) Close() error {
	m.closed = true
	return nil
}

// mockWebhookService implements InboundWebhookEventServiceInterface for testing
type mockWebhookService struct {
	mu       sync.Mutex
	calls    []webhookCall
	err      error
	listErr  error
}

type webhookCall struct {
	workspaceID   string
	integrationID string
	payload       []byte
}

func (m *mockWebhookService) ProcessWebhook(ctx context.Context, workspaceID, integrationID string, rawPayload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, webhookCall{
		workspaceID:   workspaceID,
		integrationID: integrationID,
		payload:       rawPayload,
	})
	return m.err
}

func (m *mockWebhookService) ListEvents(ctx context.Context, workspaceID string, params domain.InboundWebhookEventListParams) (*domain.InboundWebhookEventListResult, error) {
	return nil, m.listErr
}

func (m *mockWebhookService) getCalls() []webhookCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]webhookCall, len(m.calls))
	copy(result, m.calls)
	return result
}

// mockBounceWorkspaceRepo implements domain.WorkspaceRepository for testing
type mockBounceWorkspaceRepo struct {
	workspaces []*domain.Workspace
	listErr    error
}

func (m *mockBounceWorkspaceRepo) List(ctx context.Context) ([]*domain.Workspace, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.workspaces, nil
}

func (m *mockBounceWorkspaceRepo) Create(ctx context.Context, workspace *domain.Workspace) error {
	return nil
}
func (m *mockBounceWorkspaceRepo) GetByID(ctx context.Context, id string) (*domain.Workspace, error) {
	return nil, nil
}
func (m *mockBounceWorkspaceRepo) GetWorkspaceByCustomDomain(ctx context.Context, hostname string) (*domain.Workspace, error) {
	return nil, nil
}
func (m *mockBounceWorkspaceRepo) Update(ctx context.Context, workspace *domain.Workspace) error {
	return nil
}
func (m *mockBounceWorkspaceRepo) Delete(ctx context.Context, id string) error { return nil }
func (m *mockBounceWorkspaceRepo) AddUserToWorkspace(ctx context.Context, uw *domain.UserWorkspace) error {
	return nil
}
func (m *mockBounceWorkspaceRepo) RemoveUserFromWorkspace(ctx context.Context, userID string, workspaceID string) error {
	return nil
}
func (m *mockBounceWorkspaceRepo) GetUserWorkspaces(ctx context.Context, userID string) ([]*domain.UserWorkspace, error) {
	return nil, nil
}
func (m *mockBounceWorkspaceRepo) GetWorkspaceUsersWithEmail(ctx context.Context, workspaceID string) ([]*domain.UserWorkspaceWithEmail, error) {
	return nil, nil
}
func (m *mockBounceWorkspaceRepo) GetUserWorkspace(ctx context.Context, userID string, workspaceID string) (*domain.UserWorkspace, error) {
	return nil, nil
}
func (m *mockBounceWorkspaceRepo) UpdateUserWorkspacePermissions(ctx context.Context, uw *domain.UserWorkspace) error {
	return nil
}
func (m *mockBounceWorkspaceRepo) CreateInvitation(ctx context.Context, inv *domain.WorkspaceInvitation) error {
	return nil
}
func (m *mockBounceWorkspaceRepo) GetInvitationByID(ctx context.Context, id string) (*domain.WorkspaceInvitation, error) {
	return nil, nil
}
func (m *mockBounceWorkspaceRepo) GetInvitationByEmail(ctx context.Context, workspaceID, email string) (*domain.WorkspaceInvitation, error) {
	return nil, nil
}
func (m *mockBounceWorkspaceRepo) GetWorkspaceInvitations(ctx context.Context, workspaceID string) ([]*domain.WorkspaceInvitation, error) {
	return nil, nil
}
func (m *mockBounceWorkspaceRepo) DeleteInvitation(ctx context.Context, id string) error { return nil }
func (m *mockBounceWorkspaceRepo) IsUserWorkspaceMember(ctx context.Context, userID, workspaceID string) (bool, error) {
	return false, nil
}
func (m *mockBounceWorkspaceRepo) GetConnection(ctx context.Context, workspaceID string) (*sql.DB, error) {
	return nil, nil
}
func (m *mockBounceWorkspaceRepo) GetSystemConnection(ctx context.Context) (*sql.DB, error) {
	return nil, nil
}
func (m *mockBounceWorkspaceRepo) CreateDatabase(ctx context.Context, workspaceID string) error {
	return nil
}
func (m *mockBounceWorkspaceRepo) DeleteDatabase(ctx context.Context, workspaceID string) error {
	return nil
}
func (m *mockBounceWorkspaceRepo) WithWorkspaceTransaction(ctx context.Context, workspaceID string, fn func(*sql.Tx) error) error {
	return nil
}

func buildTestDSNMessage(recipient, status, messageID string) []byte {
	return []byte("From: mailer-daemon@example.com\r\n" +
		"Subject: DSN\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=\"testbnd\"\r\n" +
		"\r\n" +
		"--testbnd\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Bounce.\r\n" +
		"\r\n" +
		"--testbnd\r\n" +
		"Content-Type: message/delivery-status\r\n" +
		"\r\n" +
		"Final-Recipient: rfc822;" + recipient + "\r\n" +
		"Status: " + status + "\r\n" +
		"Diagnostic-Code: smtp; 550 " + status + " User unknown\r\n" +
		"\r\n" +
		"--testbnd\r\n" +
		"Content-Type: message/rfc822\r\n" +
		"\r\n" +
		"Message-Id: <" + messageID + ">\r\n" +
		"\r\n" +
		"--testbnd--\r\n")
}

func createTestWorkspaceWithBounceMailbox() *domain.Workspace {
	return &domain.Workspace{
		ID:   "ws-test",
		Name: "Test Workspace",
		Integrations: []domain.Integration{
			{
				ID:   "int-smtp-1",
				Name: "SMTP with bounce",
				Type: domain.IntegrationTypeEmail,
				EmailProvider: domain.EmailProvider{
					Kind: domain.EmailProviderKindSMTP,
					SMTP: &domain.SMTPSettings{
						Host:                      "smtp.example.com",
						Port:                      587,
						BounceMailboxHost:         "imap.example.com",
						BounceMailboxPort:         993,
						BounceMailboxTLS:          true,
						BounceMailboxUsername:      "bounce@example.com",
						BounceMailboxPassword:     "secret",
						BounceMailboxFolder:       "INBOX",
						BounceMailboxPollIntervalMins: 5,
					},
				},
			},
		},
	}
}

func TestSMTPBouncePoller_ProcessesBounceMessages(t *testing.T) {
	mockClient := &mockIMAPClient{
		messages: []IMAPMessage{
			{UID: 1, RawBody: buildTestDSNMessage("bounced@example.org", "5.1.1", "msg-001@sender.com")},
			{UID: 2, RawBody: buildTestDSNMessage("softbounce@example.org", "4.2.2", "msg-002@sender.com")},
		},
	}

	webhookSvc := &mockWebhookService{}
	workspaceRepo := &mockBounceWorkspaceRepo{
		workspaces: []*domain.Workspace{createTestWorkspaceWithBounceMailbox()},
	}

	poller := NewSMTPBouncePoller(workspaceRepo, webhookSvc, &noopLogger{}, 1*time.Minute)
	poller.newIMAPClient = func() IMAPClient { return mockClient }

	ctx := context.Background()
	poller.pollAll(ctx)

	calls := webhookSvc.getCalls()
	require.Len(t, calls, 2)

	// Verify first bounce (hard)
	var payload1 domain.SMTPWebhookPayload
	err := json.Unmarshal(calls[0].payload, &payload1)
	require.NoError(t, err)
	assert.Equal(t, "bounce", payload1.Event)
	assert.Equal(t, "bounced@example.org", payload1.Recipient)
	assert.Equal(t, "Permanent", payload1.BounceCategory)
	assert.Equal(t, "msg-001@sender.com", payload1.MessageID)
	assert.Equal(t, "ws-test", calls[0].workspaceID)
	assert.Equal(t, "int-smtp-1", calls[0].integrationID)

	// Verify second bounce (soft)
	var payload2 domain.SMTPWebhookPayload
	err = json.Unmarshal(calls[1].payload, &payload2)
	require.NoError(t, err)
	assert.Equal(t, "Temporary", payload2.BounceCategory)

	// Verify messages marked as seen
	assert.Len(t, mockClient.seenUIDs, 2)
	assert.True(t, mockClient.closed)
}

func TestSMTPBouncePoller_SkipsNonSMTPIntegrations(t *testing.T) {
	ws := &domain.Workspace{
		ID: "ws-non-smtp",
		Integrations: []domain.Integration{
			{
				ID:   "int-ses",
				Type: domain.IntegrationTypeEmail,
				EmailProvider: domain.EmailProvider{
					Kind: domain.EmailProviderKindSES,
				},
			},
		},
	}

	webhookSvc := &mockWebhookService{}
	workspaceRepo := &mockBounceWorkspaceRepo{workspaces: []*domain.Workspace{ws}}

	poller := NewSMTPBouncePoller(workspaceRepo, webhookSvc, &noopLogger{}, 1*time.Minute)
	poller.pollAll(context.Background())

	assert.Empty(t, webhookSvc.getCalls())
}

func TestSMTPBouncePoller_SkipsIntegrationsWithoutBounceMailbox(t *testing.T) {
	ws := &domain.Workspace{
		ID: "ws-no-bounce",
		Integrations: []domain.Integration{
			{
				ID:   "int-smtp-plain",
				Type: domain.IntegrationTypeEmail,
				EmailProvider: domain.EmailProvider{
					Kind: domain.EmailProviderKindSMTP,
					SMTP: &domain.SMTPSettings{
						Host: "smtp.example.com",
						Port: 587,
						// No BounceMailboxHost set
					},
				},
			},
		},
	}

	webhookSvc := &mockWebhookService{}
	workspaceRepo := &mockBounceWorkspaceRepo{workspaces: []*domain.Workspace{ws}}

	poller := NewSMTPBouncePoller(workspaceRepo, webhookSvc, &noopLogger{}, 1*time.Minute)
	poller.pollAll(context.Background())

	assert.Empty(t, webhookSvc.getCalls())
}

func TestSMTPBouncePoller_RespectsPollInterval(t *testing.T) {
	mockClient := &mockIMAPClient{messages: nil}
	webhookSvc := &mockWebhookService{}
	workspaceRepo := &mockBounceWorkspaceRepo{
		workspaces: []*domain.Workspace{createTestWorkspaceWithBounceMailbox()},
	}

	poller := NewSMTPBouncePoller(workspaceRepo, webhookSvc, &noopLogger{}, 1*time.Minute)
	poller.newIMAPClient = func() IMAPClient { return mockClient }

	ctx := context.Background()

	// First poll should execute
	poller.pollAll(ctx)
	assert.True(t, mockClient.connected)

	// Reset and poll again immediately — should be skipped
	mockClient2 := &mockIMAPClient{messages: nil}
	poller.newIMAPClient = func() IMAPClient { return mockClient2 }
	poller.pollAll(ctx)
	assert.False(t, mockClient2.connected, "second poll should be skipped due to interval")
}

func TestSMTPBouncePoller_IMAPConnectionError(t *testing.T) {
	mockClient := &mockIMAPClient{
		connectErr: assert.AnError,
	}

	webhookSvc := &mockWebhookService{}
	workspaceRepo := &mockBounceWorkspaceRepo{
		workspaces: []*domain.Workspace{createTestWorkspaceWithBounceMailbox()},
	}

	poller := NewSMTPBouncePoller(workspaceRepo, webhookSvc, &noopLogger{}, 1*time.Minute)
	poller.newIMAPClient = func() IMAPClient { return mockClient }

	// Should not panic — errors are logged and skipped
	poller.pollAll(context.Background())
	assert.Empty(t, webhookSvc.getCalls())
}

func TestSMTPBouncePoller_NonBounceMessagesMarkedAsSeen(t *testing.T) {
	regularEmail := []byte("From: alice@example.com\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: Hello!\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Just a regular email.\r\n")

	mockClient := &mockIMAPClient{
		messages: []IMAPMessage{
			{UID: 10, RawBody: regularEmail},
		},
	}

	webhookSvc := &mockWebhookService{}
	workspaceRepo := &mockBounceWorkspaceRepo{
		workspaces: []*domain.Workspace{createTestWorkspaceWithBounceMailbox()},
	}

	poller := NewSMTPBouncePoller(workspaceRepo, webhookSvc, &noopLogger{}, 1*time.Minute)
	poller.newIMAPClient = func() IMAPClient { return mockClient }

	poller.pollAll(context.Background())

	// No webhook calls for non-bounce messages
	assert.Empty(t, webhookSvc.getCalls())
	// But message should still be marked as seen
	assert.Len(t, mockClient.seenUIDs, 1)
	assert.Equal(t, imap.UID(10), mockClient.seenUIDs[0])
}

func TestSMTPBouncePoller_StartStop(t *testing.T) {
	webhookSvc := &mockWebhookService{}
	workspaceRepo := &mockBounceWorkspaceRepo{workspaces: nil}

	poller := NewSMTPBouncePoller(workspaceRepo, webhookSvc, &noopLogger{}, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		poller.Start(ctx)
		close(done)
	}()

	// Let it run a couple ticks
	time.Sleep(150 * time.Millisecond)

	poller.Stop()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("poller did not stop in time")
	}
}

func TestSMTPBouncePoller_WorkspaceListError(t *testing.T) {
	webhookSvc := &mockWebhookService{}
	workspaceRepo := &mockBounceWorkspaceRepo{
		listErr: assert.AnError,
	}

	poller := NewSMTPBouncePoller(workspaceRepo, webhookSvc, &noopLogger{}, 1*time.Minute)

	// Should not panic
	poller.pollAll(context.Background())
	assert.Empty(t, webhookSvc.getCalls())
}

func buildTestARFMessage(recipient, feedbackType, messageID string) []byte {
	return []byte("From: feedback@isp.example.com\r\n" +
		"Subject: Complaint\r\n" +
		"Content-Type: multipart/report; report-type=feedback-report; boundary=\"arfbnd\"\r\n" +
		"\r\n" +
		"--arfbnd\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Spam complaint.\r\n" +
		"\r\n" +
		"--arfbnd\r\n" +
		"Content-Type: message/feedback-report\r\n" +
		"\r\n" +
		"Feedback-Type: " + feedbackType + "\r\n" +
		"Version: 1\r\n" +
		"Original-Rcpt-To: " + recipient + "\r\n" +
		"\r\n" +
		"--arfbnd\r\n" +
		"Content-Type: message/rfc822\r\n" +
		"\r\n" +
		"Message-Id: <" + messageID + ">\r\n" +
		"\r\n" +
		"--arfbnd--\r\n")
}

func TestSMTPBouncePoller_ProcessesComplaintMessages(t *testing.T) {
	mockClient := &mockIMAPClient{
		messages: []IMAPMessage{
			{UID: 1, RawBody: buildTestARFMessage("complainer@example.com", "abuse", "spam-msg-001@sender.com")},
		},
	}

	webhookSvc := &mockWebhookService{}
	workspaceRepo := &mockBounceWorkspaceRepo{
		workspaces: []*domain.Workspace{createTestWorkspaceWithBounceMailbox()},
	}

	poller := NewSMTPBouncePoller(workspaceRepo, webhookSvc, &noopLogger{}, 1*time.Minute)
	poller.newIMAPClient = func() IMAPClient { return mockClient }

	poller.pollAll(context.Background())

	calls := webhookSvc.getCalls()
	require.Len(t, calls, 1)

	var payload domain.SMTPWebhookPayload
	err := json.Unmarshal(calls[0].payload, &payload)
	require.NoError(t, err)
	assert.Equal(t, "complaint", payload.Event)
	assert.Equal(t, "complainer@example.com", payload.Recipient)
	assert.Equal(t, "abuse", payload.ComplaintType)
	assert.Equal(t, "spam-msg-001@sender.com", payload.MessageID)
	assert.Equal(t, "ws-test", calls[0].workspaceID)
	assert.Equal(t, "int-smtp-1", calls[0].integrationID)

	assert.Len(t, mockClient.seenUIDs, 1)
	assert.True(t, mockClient.closed)
}

func TestSMTPBouncePoller_MixedBounceAndComplaint(t *testing.T) {
	mockClient := &mockIMAPClient{
		messages: []IMAPMessage{
			{UID: 1, RawBody: buildTestDSNMessage("bounced@example.org", "5.1.1", "msg-001@sender.com")},
			{UID: 2, RawBody: buildTestARFMessage("complainer@example.com", "abuse", "spam-001@sender.com")},
			{UID: 3, RawBody: []byte("From: alice@example.com\r\nSubject: Hello\r\nContent-Type: text/plain\r\n\r\nRegular email.\r\n")},
		},
	}

	webhookSvc := &mockWebhookService{}
	workspaceRepo := &mockBounceWorkspaceRepo{
		workspaces: []*domain.Workspace{createTestWorkspaceWithBounceMailbox()},
	}

	poller := NewSMTPBouncePoller(workspaceRepo, webhookSvc, &noopLogger{}, 1*time.Minute)
	poller.newIMAPClient = func() IMAPClient { return mockClient }

	poller.pollAll(context.Background())

	calls := webhookSvc.getCalls()
	require.Len(t, calls, 2)

	// First call should be bounce
	var payload1 domain.SMTPWebhookPayload
	err := json.Unmarshal(calls[0].payload, &payload1)
	require.NoError(t, err)
	assert.Equal(t, "bounce", payload1.Event)
	assert.Equal(t, "bounced@example.org", payload1.Recipient)

	// Second call should be complaint
	var payload2 domain.SMTPWebhookPayload
	err = json.Unmarshal(calls[1].payload, &payload2)
	require.NoError(t, err)
	assert.Equal(t, "complaint", payload2.Event)
	assert.Equal(t, "complainer@example.com", payload2.Recipient)
	assert.Equal(t, "abuse", payload2.ComplaintType)

	// All 3 messages should be marked as seen
	assert.Len(t, mockClient.seenUIDs, 3)
}
