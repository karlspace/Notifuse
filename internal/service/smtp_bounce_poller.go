package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/Notifuse/notifuse/internal/domain"
	"github.com/Notifuse/notifuse/pkg/bounceparser"
	"github.com/Notifuse/notifuse/pkg/logger"
)

// IMAPOAuth2TokenProvider fetches an OAuth2 access token for IMAP bounce mailbox authentication.
// This reuses the same OAuth2 token infrastructure as the SMTP service.
type IMAPOAuth2TokenProvider interface {
	GetIMAPAccessToken(smtp *domain.SMTPSettings) (string, error)
}

// SMTPBouncePoller polls IMAP bounce mailboxes for all SMTP integrations
// and feeds parsed DSN events into InboundWebhookEventService
type SMTPBouncePoller struct {
	workspaceRepo      domain.WorkspaceRepository
	webhookService     domain.InboundWebhookEventServiceInterface
	oauth2Provider     IMAPOAuth2TokenProvider
	logger             logger.Logger
	interval           time.Duration
	stopChan           chan struct{}
	stoppedChan        chan struct{}
	mu                 sync.Mutex
	running            bool
	lastPollTimes      map[string]time.Time
	newIMAPClient      func() IMAPClient
}

// NewSMTPBouncePoller creates a new SMTP bounce poller
func NewSMTPBouncePoller(
	workspaceRepo domain.WorkspaceRepository,
	webhookService domain.InboundWebhookEventServiceInterface,
	logger logger.Logger,
	interval time.Duration,
) *SMTPBouncePoller {
	return &SMTPBouncePoller{
		workspaceRepo:  workspaceRepo,
		webhookService: webhookService,
		logger:         logger,
		interval:       interval,
		stopChan:       make(chan struct{}),
		stoppedChan:    make(chan struct{}),
		lastPollTimes:  make(map[string]time.Time),
		newIMAPClient:  NewIMAPClient,
	}
}

// SetOAuth2Provider sets the OAuth2 token provider for IMAP bounce mailbox authentication
func (p *SMTPBouncePoller) SetOAuth2Provider(provider IMAPOAuth2TokenProvider) {
	p.oauth2Provider = provider
}

// Start begins the polling loop. Blocks until Stop is called or ctx is cancelled.
func (p *SMTPBouncePoller) Start(ctx context.Context) {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return
	}
	p.running = true
	p.mu.Unlock()

	defer func() {
		close(p.stoppedChan)
	}()

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	// Execute immediately on start
	p.pollAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.pollAll(ctx)
		}
	}
}

// Stop signals the poller to stop and waits for it to finish
func (p *SMTPBouncePoller) Stop() {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return
	}
	p.running = false
	p.mu.Unlock()

	close(p.stopChan)

	select {
	case <-p.stoppedChan:
	case <-time.After(5 * time.Second):
		p.logger.Warn("SMTP bounce poller stop timed out")
	}
}

func (p *SMTPBouncePoller) pollAll(ctx context.Context) {
	workspaces, err := p.workspaceRepo.List(ctx)
	if err != nil {
		p.logger.WithField("error", err.Error()).Error("Failed to list workspaces for bounce polling")
		return
	}

	for _, workspace := range workspaces {
		if ctx.Err() != nil {
			return
		}

		emailIntegrations := workspace.GetIntegrationsByType(domain.IntegrationTypeEmail)
		for _, integration := range emailIntegrations {
			if integration.EmailProvider.Kind != domain.EmailProviderKindSMTP {
				continue
			}
			if integration.EmailProvider.SMTP == nil || !integration.EmailProvider.SMTP.HasBounceMailbox() {
				continue
			}

			p.pollIntegration(ctx, workspace.ID, integration)
		}
	}
}

func (p *SMTPBouncePoller) pollIntegration(ctx context.Context, workspaceID string, integration *domain.Integration) {
	smtp := integration.EmailProvider.SMTP
	key := fmt.Sprintf("%s:%s", workspaceID, integration.ID)

	// Check if enough time has passed since last poll
	pollInterval := time.Duration(smtp.BounceMailboxPollIntervalMins) * time.Minute
	if pollInterval < time.Minute {
		pollInterval = 5 * time.Minute
	}

	if lastPoll, ok := p.lastPollTimes[key]; ok {
		if time.Since(lastPoll) < pollInterval {
			return
		}
	}

	p.lastPollTimes[key] = time.Now()

	logFields := p.logger.WithField("workspace_id", workspaceID).
		WithField("integration_id", integration.ID).
		WithField("imap_host", smtp.BounceMailboxHost)

	// Build IMAP auth config
	authConfig := IMAPAuthConfig{
		Host:     smtp.BounceMailboxHost,
		Port:     smtp.BounceMailboxPort,
		UseTLS:   smtp.BounceMailboxTLS,
		AuthType: smtp.BounceMailboxAuthType,
		Username: smtp.BounceMailboxUsername,
		Password: smtp.BounceMailboxPassword,
	}

	if authConfig.AuthType == "oauth2" && p.oauth2Provider != nil {
		accessToken, tokenErr := p.oauth2Provider.GetIMAPAccessToken(smtp)
		if tokenErr != nil {
			logFields.WithField("error", tokenErr.Error()).Error("Failed to get OAuth2 access token for bounce mailbox")
			return
		}
		authConfig.AccessToken = accessToken
	}

	client := p.newIMAPClient()
	err := client.Connect(authConfig)
	if err != nil {
		logFields.WithField("error", err.Error()).Error("Failed to connect to bounce mailbox")
		return
	}
	defer client.Close()

	folder := smtp.BounceMailboxFolder
	if folder == "" {
		folder = "INBOX"
	}

	messages, err := client.FetchUnseenMessages(folder)
	if err != nil {
		logFields.WithField("error", err.Error()).Error("Failed to fetch unseen messages from bounce mailbox")
		return
	}

	if len(messages) == 0 {
		return
	}

	logFields.WithField("message_count", len(messages)).Info("Processing bounce mailbox messages")

	var processedUIDs []imap.UID
	var bouncesFound int
	var complaintsFound int

	for _, msg := range messages {
		if ctx.Err() != nil {
			break
		}

		// Try bounce detection first (RFC 3464 DSN)
		bounceInfo, err := bounceparser.ParseDSN(msg.RawBody)
		if err != nil {
			logFields.WithField("uid", msg.UID).
				WithField("error", err.Error()).
				Warn("Failed to parse bounce message")
			processedUIDs = append(processedUIDs, msg.UID)
			continue
		}

		if bounceInfo != nil {
			bounceCategory := "Temporary"
			if bounceInfo.IsHardBounce {
				bounceCategory = "Permanent"
			}

			payload := domain.SMTPWebhookPayload{
				Event:          "bounce",
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				MessageID:      bounceInfo.OriginalMessageID,
				Recipient:      bounceInfo.OriginalRecipient,
				BounceCategory: bounceCategory,
				DiagnosticCode: bounceInfo.DiagnosticCode,
			}

			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				logFields.WithField("error", err.Error()).Error("Failed to marshal bounce payload")
				processedUIDs = append(processedUIDs, msg.UID)
				continue
			}

			if err := p.webhookService.ProcessWebhook(ctx, workspaceID, integration.ID, payloadJSON); err != nil {
				logFields.WithField("error", err.Error()).
					WithField("recipient", bounceInfo.OriginalRecipient).
					Warn("Failed to process bounce event")
			} else {
				bouncesFound++
			}

			processedUIDs = append(processedUIDs, msg.UID)
			continue
		}

		// Not a bounce — try complaint/ARF detection (RFC 5965)
		complaintInfo, err := bounceparser.ParseARF(msg.RawBody)
		if err != nil {
			logFields.WithField("uid", msg.UID).
				WithField("error", err.Error()).
				Warn("Failed to parse complaint message")
			processedUIDs = append(processedUIDs, msg.UID)
			continue
		}

		if complaintInfo != nil {
			payload := domain.SMTPWebhookPayload{
				Event:         "complaint",
				Timestamp:     time.Now().UTC().Format(time.RFC3339),
				MessageID:     complaintInfo.OriginalMessageID,
				Recipient:     complaintInfo.OriginalRecipient,
				ComplaintType: complaintInfo.FeedbackType,
			}

			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				logFields.WithField("error", err.Error()).Error("Failed to marshal complaint payload")
				processedUIDs = append(processedUIDs, msg.UID)
				continue
			}

			if err := p.webhookService.ProcessWebhook(ctx, workspaceID, integration.ID, payloadJSON); err != nil {
				logFields.WithField("error", err.Error()).
					WithField("recipient", complaintInfo.OriginalRecipient).
					Warn("Failed to process complaint event")
			} else {
				complaintsFound++
			}

			processedUIDs = append(processedUIDs, msg.UID)
			continue
		}

		// Neither bounce nor complaint
		processedUIDs = append(processedUIDs, msg.UID)
	}

	// Mark all processed messages as seen
	if len(processedUIDs) > 0 {
		if err := client.MarkAsSeen(processedUIDs); err != nil {
			logFields.WithField("error", err.Error()).Error("Failed to mark messages as seen")
		}
	}

	if bouncesFound > 0 || complaintsFound > 0 {
		logFields.WithField("bounces_processed", bouncesFound).
			WithField("complaints_processed", complaintsFound).
			Info("Mailbox processing complete")
	}
}
