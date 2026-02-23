package bounceparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDSN_StandardRFC3464_HardBounce(t *testing.T) {
	raw := []byte("From: mailer-daemon@example.com\r\n" +
		"To: sender@example.com\r\n" +
		"Subject: Delivery Status Notification (Failure)\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=\"boundary42\"\r\n" +
		"\r\n" +
		"--boundary42\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Your message could not be delivered.\r\n" +
		"\r\n" +
		"--boundary42\r\n" +
		"Content-Type: message/delivery-status\r\n" +
		"\r\n" +
		"Reporting-MTA: dns; mail.example.com\r\n" +
		"\r\n" +
		"Final-Recipient: rfc822;bounced@example.org\r\n" +
		"Status: 5.1.1\r\n" +
		"Diagnostic-Code: smtp; 550 5.1.1 User unknown\r\n" +
		"\r\n" +
		"--boundary42\r\n" +
		"Content-Type: message/rfc822\r\n" +
		"\r\n" +
		"Message-Id: <original-msg-123@sender.com>\r\n" +
		"From: sender@example.com\r\n" +
		"To: bounced@example.org\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"--boundary42--\r\n")

	info, err := ParseDSN(raw)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "bounced@example.org", info.OriginalRecipient)
	assert.Equal(t, "5.1.1", info.Status)
	assert.Contains(t, info.DiagnosticCode, "550 5.1.1 User unknown")
	assert.Equal(t, "original-msg-123@sender.com", info.OriginalMessageID)
	assert.True(t, info.IsHardBounce)
}

func TestParseDSN_StandardRFC3464_SoftBounce(t *testing.T) {
	raw := []byte("From: mailer-daemon@example.com\r\n" +
		"To: sender@example.com\r\n" +
		"Subject: Delivery Status Notification\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=\"soft-boundary\"\r\n" +
		"\r\n" +
		"--soft-boundary\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Temporary delivery failure.\r\n" +
		"\r\n" +
		"--soft-boundary\r\n" +
		"Content-Type: message/delivery-status\r\n" +
		"\r\n" +
		"Reporting-MTA: dns; mail.example.com\r\n" +
		"\r\n" +
		"Final-Recipient: rfc822;full@example.org\r\n" +
		"Status: 4.2.2\r\n" +
		"Diagnostic-Code: smtp; 452 4.2.2 Mailbox full\r\n" +
		"\r\n" +
		"--soft-boundary\r\n" +
		"Content-Type: message/rfc822\r\n" +
		"\r\n" +
		"Message-Id: <soft-msg-456@sender.com>\r\n" +
		"\r\n" +
		"--soft-boundary--\r\n")

	info, err := ParseDSN(raw)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "full@example.org", info.OriginalRecipient)
	assert.Equal(t, "4.2.2", info.Status)
	assert.Contains(t, info.DiagnosticCode, "Mailbox full")
	assert.Equal(t, "soft-msg-456@sender.com", info.OriginalMessageID)
	assert.False(t, info.IsHardBounce)
}

func TestParseDSN_NonBounceMessage(t *testing.T) {
	raw := []byte("From: alice@example.com\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: Hello!\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Just a regular email.\r\n")

	info, err := ParseDSN(raw)
	assert.NoError(t, err)
	assert.Nil(t, info)
}

func TestParseDSN_HeuristicBounce_HardBounce(t *testing.T) {
	raw := []byte("From: mailer-daemon@example.com\r\n" +
		"To: sender@example.com\r\n" +
		"Subject: Mail delivery failed: returning message to sender\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"This message was created automatically by mail delivery software.\r\n" +
		"\r\n" +
		"A message that you sent could not be delivered to one or more of\r\n" +
		"its recipients.\r\n" +
		"\r\n" +
		"The following address failed:\r\n" +
		"  nobody@invalid-domain.test\r\n" +
		"  550 User unknown\r\n")

	info, err := ParseDSN(raw)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "nobody@invalid-domain.test", info.OriginalRecipient)
	assert.True(t, info.IsHardBounce)
	assert.Equal(t, "5.0.0", info.Status)
}

func TestParseDSN_HeuristicBounce_SoftBounce(t *testing.T) {
	raw := []byte("From: MAILER-DAEMON@example.com\r\n" +
		"To: sender@example.com\r\n" +
		"Subject: Undelivered Mail Returned to Sender\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Delivery to the following recipient was deferred:\r\n" +
		"\r\n" +
		"  busy-user@example.org\r\n" +
		"\r\n" +
		"Reason: Mailbox temporarily unavailable, please try again later.\r\n")

	info, err := ParseDSN(raw)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "busy-user@example.org", info.OriginalRecipient)
	assert.False(t, info.IsHardBounce)
	assert.Equal(t, "4.0.0", info.Status)
}

func TestParseDSN_MalformedMessage(t *testing.T) {
	raw := []byte("not a valid email at all")
	info, err := ParseDSN(raw)
	assert.Error(t, err)
	assert.Nil(t, info)
}

func TestParseDSN_MultipartReport_MissingFields(t *testing.T) {
	raw := []byte("From: mailer-daemon@example.com\r\n" +
		"Subject: DSN\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=\"empty\"\r\n" +
		"\r\n" +
		"--empty\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Something happened.\r\n" +
		"\r\n" +
		"--empty\r\n" +
		"Content-Type: message/delivery-status\r\n" +
		"\r\n" +
		"Reporting-MTA: dns; mail.example.com\r\n" +
		"\r\n" +
		"--empty--\r\n")

	info, err := ParseDSN(raw)
	assert.NoError(t, err)
	assert.Nil(t, info) // No Final-Recipient or Status → nil
}

func TestParseDSN_MultilineDiagnosticCode(t *testing.T) {
	raw := []byte("From: mailer-daemon@example.com\r\n" +
		"Subject: DSN\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=\"multi\"\r\n" +
		"\r\n" +
		"--multi\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Bounce.\r\n" +
		"\r\n" +
		"--multi\r\n" +
		"Content-Type: message/delivery-status\r\n" +
		"\r\n" +
		"Final-Recipient: rfc822;user@example.com\r\n" +
		"Status: 5.2.1\r\n" +
		"Diagnostic-Code: smtp; 550 5.2.1 The email account that you tried to reach\r\n" +
		"    is disabled. Learn more at https://support.example.com\r\n" +
		"\r\n" +
		"--multi--\r\n")

	info, err := ParseDSN(raw)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "user@example.com", info.OriginalRecipient)
	assert.Equal(t, "5.2.1", info.Status)
	assert.Contains(t, info.DiagnosticCode, "is disabled")
	assert.True(t, info.IsHardBounce)
}

func TestParseDSNStatus(t *testing.T) {
	body := []byte("Reporting-MTA: dns; mail.example.com\r\n" +
		"\r\n" +
		"Final-Recipient: rfc822;test@example.com\r\n" +
		"Status: 5.1.1\r\n" +
		"Diagnostic-Code: smtp; 550 No such user\r\n")

	recipient, status, diagnostic := parseDSNStatus(body)
	assert.Equal(t, "test@example.com", recipient)
	assert.Equal(t, "5.1.1", status)
	assert.Contains(t, diagnostic, "550 No such user")
}

func TestParseDSNStatus_FinalRecipientWithoutSemicolon(t *testing.T) {
	body := []byte("Final-Recipient: user@example.com\r\n" +
		"Status: 5.1.1\r\n")

	recipient, status, _ := parseDSNStatus(body)
	assert.Equal(t, "user@example.com", recipient)
	assert.Equal(t, "5.1.1", status)
}

func TestExtractMessageID(t *testing.T) {
	body := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Message-Id: <abc-123@sender.com>\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"Body.\r\n")

	msgID := extractMessageID(body)
	assert.Equal(t, "abc-123@sender.com", msgID)
}

func TestParseDSN_TextRFC822Headers(t *testing.T) {
	raw := []byte("From: mailer-daemon@example.com\r\n" +
		"Subject: DSN\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=\"rfc\"\r\n" +
		"\r\n" +
		"--rfc\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Bounce.\r\n" +
		"\r\n" +
		"--rfc\r\n" +
		"Content-Type: message/delivery-status\r\n" +
		"\r\n" +
		"Final-Recipient: rfc822;user@example.com\r\n" +
		"Status: 5.1.1\r\n" +
		"\r\n" +
		"--rfc\r\n" +
		"Content-Type: text/rfc822-headers\r\n" +
		"\r\n" +
		"Message-Id: <headers-only@sender.com>\r\n" +
		"\r\n" +
		"--rfc--\r\n")

	info, err := ParseDSN(raw)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "headers-only@sender.com", info.OriginalMessageID)
}

// --- ARF / Complaint Parsing Tests ---

func TestParseARF_StandardRFC5965_Abuse(t *testing.T) {
	raw := []byte("From: feedback@isp.example.com\r\n" +
		"To: abuse@sender.example.com\r\n" +
		"Subject: Complaint about message from 192.0.2.1\r\n" +
		"Content-Type: multipart/report; report-type=feedback-report; boundary=\"arf-boundary\"\r\n" +
		"\r\n" +
		"--arf-boundary\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"This is a spam complaint from one of our users.\r\n" +
		"\r\n" +
		"--arf-boundary\r\n" +
		"Content-Type: message/feedback-report\r\n" +
		"\r\n" +
		"Feedback-Type: abuse\r\n" +
		"User-Agent: ISP/1.0\r\n" +
		"Version: 1\r\n" +
		"Original-Mail-From: marketing@sender.example.com\r\n" +
		"Original-Rcpt-To: rfc822;recipient@isp.example.com\r\n" +
		"Arrival-Date: Thu, 8 Mar 2005 14:00:00 -0500\r\n" +
		"Source-IP: 192.0.2.1\r\n" +
		"Reported-Domain: sender.example.com\r\n" +
		"\r\n" +
		"--arf-boundary\r\n" +
		"Content-Type: message/rfc822\r\n" +
		"\r\n" +
		"Message-Id: <original-spam-123@sender.example.com>\r\n" +
		"From: marketing@sender.example.com\r\n" +
		"To: recipient@isp.example.com\r\n" +
		"Subject: Buy now!\r\n" +
		"\r\n" +
		"--arf-boundary--\r\n")

	info, err := ParseARF(raw)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "abuse", info.FeedbackType)
	assert.Equal(t, "recipient@isp.example.com", info.OriginalRecipient)
	assert.Equal(t, "original-spam-123@sender.example.com", info.OriginalMessageID)
	assert.Equal(t, "ISP/1.0", info.UserAgent)
	assert.Equal(t, "192.0.2.1", info.SourceIP)
	assert.Equal(t, "sender.example.com", info.ReportedDomain)
	assert.Equal(t, "Thu, 8 Mar 2005 14:00:00 -0500", info.ArrivalDate)
}

func TestParseARF_FraudFeedbackType(t *testing.T) {
	raw := []byte("From: feedback@isp.example.com\r\n" +
		"Subject: Fraud report\r\n" +
		"Content-Type: multipart/report; report-type=feedback-report; boundary=\"fraud-bnd\"\r\n" +
		"\r\n" +
		"--fraud-bnd\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Fraud complaint.\r\n" +
		"\r\n" +
		"--fraud-bnd\r\n" +
		"Content-Type: message/feedback-report\r\n" +
		"\r\n" +
		"Feedback-Type: fraud\r\n" +
		"User-Agent: FraudDetector/2.0\r\n" +
		"Version: 1\r\n" +
		"Original-Rcpt-To: victim@example.com\r\n" +
		"\r\n" +
		"--fraud-bnd\r\n" +
		"Content-Type: message/rfc822\r\n" +
		"\r\n" +
		"Message-Id: <fraud-msg@phisher.com>\r\n" +
		"\r\n" +
		"--fraud-bnd--\r\n")

	info, err := ParseARF(raw)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "fraud", info.FeedbackType)
	assert.Equal(t, "victim@example.com", info.OriginalRecipient)
	assert.Equal(t, "fraud-msg@phisher.com", info.OriginalMessageID)
}

func TestParseARF_NonComplaintMessage(t *testing.T) {
	raw := []byte("From: alice@example.com\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: Hello!\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Just a regular email.\r\n")

	info, err := ParseARF(raw)
	assert.NoError(t, err)
	assert.Nil(t, info)
}

func TestParseARF_HeuristicComplaint_SubjectMatch(t *testing.T) {
	raw := []byte("From: abuse-team@isp.com\r\n" +
		"To: postmaster@sender.com\r\n" +
		"Subject: Spam complaint regarding your message\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"We received a spam complaint about a message sent to:\r\n" +
		"  complainer@isp.com\r\n" +
		"\r\n" +
		"Message-ID: <spammy-msg@sender.com>\r\n" +
		"Please investigate.\r\n")

	info, err := ParseARF(raw)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "abuse", info.FeedbackType)
	assert.Equal(t, "complainer@isp.com", info.OriginalRecipient)
	assert.Equal(t, "spammy-msg@sender.com", info.OriginalMessageID)
}

func TestParseARF_HeuristicComplaint_XComplaintsToHeader(t *testing.T) {
	raw := []byte("From: fbl@isp.com\r\n" +
		"To: postmaster@sender.com\r\n" +
		"Subject: Notification\r\n" +
		"X-Complaints-To: abuse@isp.com\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"User user@isp.com reported your message as spam.\r\n")

	info, err := ParseARF(raw)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "abuse", info.FeedbackType)
	assert.Equal(t, "user@isp.com", info.OriginalRecipient)
}

func TestParseARF_MalformedMessage(t *testing.T) {
	raw := []byte("not a valid email at all")
	info, err := ParseARF(raw)
	assert.Error(t, err)
	assert.Nil(t, info)
}

func TestParseARF_MissingFeedbackType(t *testing.T) {
	raw := []byte("From: feedback@isp.com\r\n" +
		"Subject: Report\r\n" +
		"Content-Type: multipart/report; report-type=feedback-report; boundary=\"empty-fb\"\r\n" +
		"\r\n" +
		"--empty-fb\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Something.\r\n" +
		"\r\n" +
		"--empty-fb\r\n" +
		"Content-Type: message/feedback-report\r\n" +
		"\r\n" +
		"User-Agent: ISP/1.0\r\n" +
		"Version: 1\r\n" +
		"\r\n" +
		"--empty-fb--\r\n")

	info, err := ParseARF(raw)
	assert.NoError(t, err)
	assert.Nil(t, info)
}

func TestParseARF_RecipientFromOriginalMessage(t *testing.T) {
	raw := []byte("From: feedback@isp.com\r\n" +
		"Subject: Complaint\r\n" +
		"Content-Type: multipart/report; report-type=feedback-report; boundary=\"norecip\"\r\n" +
		"\r\n" +
		"--norecip\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Complaint.\r\n" +
		"\r\n" +
		"--norecip\r\n" +
		"Content-Type: message/feedback-report\r\n" +
		"\r\n" +
		"Feedback-Type: abuse\r\n" +
		"Version: 1\r\n" +
		"\r\n" +
		"--norecip\r\n" +
		"Content-Type: message/rfc822\r\n" +
		"\r\n" +
		"Message-Id: <abc@sender.com>\r\n" +
		"From: sender@sender.com\r\n" +
		"To: complainer@isp.com\r\n" +
		"\r\n" +
		"--norecip--\r\n")

	info, err := ParseARF(raw)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "abuse", info.FeedbackType)
	assert.Equal(t, "complainer@isp.com", info.OriginalRecipient)
	assert.Equal(t, "abc@sender.com", info.OriginalMessageID)
}

func TestParseARF_DSNBounceNotDetectedAsComplaint(t *testing.T) {
	raw := []byte("From: mailer-daemon@example.com\r\n" +
		"Subject: Delivery Status Notification (Failure)\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=\"dsnbnd\"\r\n" +
		"\r\n" +
		"--dsnbnd\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Your message could not be delivered.\r\n" +
		"\r\n" +
		"--dsnbnd\r\n" +
		"Content-Type: message/delivery-status\r\n" +
		"\r\n" +
		"Final-Recipient: rfc822;bounced@example.org\r\n" +
		"Status: 5.1.1\r\n" +
		"\r\n" +
		"--dsnbnd--\r\n")

	info, err := ParseARF(raw)
	assert.NoError(t, err)
	assert.Nil(t, info)
}
