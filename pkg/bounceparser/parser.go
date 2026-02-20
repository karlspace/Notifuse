package bounceparser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"regexp"
	"strings"
)

// BounceInfo holds parsed bounce information from a DSN message
type BounceInfo struct {
	OriginalRecipient string // Final-Recipient email address
	Status            string // Enhanced status code, e.g. "5.1.1" or "4.2.2"
	DiagnosticCode    string // Human-readable diagnostic reason
	OriginalMessageID string // Message-ID of the original bounced message
	IsHardBounce      bool   // true if Status starts with "5."
}

var emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// ParseDSN parses a raw email message and extracts bounce information.
// Returns nil, nil if the message is not a bounce notification.
func ParseDSN(rawMessage []byte) (*BounceInfo, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(rawMessage))
	if err != nil {
		return nil, fmt.Errorf("failed to parse email message: %w", err)
	}

	contentType := msg.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		// Not a MIME message — try heuristic
		return parseHeuristicBounce(msg)
	}

	// Standard RFC 3464: multipart/report with report-type=delivery-status
	if mediaType == "multipart/report" && strings.EqualFold(params["report-type"], "delivery-status") {
		return parseMultipartReport(msg.Body, params["boundary"])
	}

	// Not a standard DSN — try heuristic fallback
	return parseHeuristicBounce(msg)
}

func parseMultipartReport(body io.Reader, boundary string) (*BounceInfo, error) {
	if boundary == "" {
		return nil, fmt.Errorf("missing boundary in multipart/report")
	}

	reader := multipart.NewReader(body, boundary)
	info := &BounceInfo{}

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read MIME part: %w", err)
		}

		partContentType := part.Header.Get("Content-Type")
		partMediaType, _, _ := mime.ParseMediaType(partContentType)

		switch partMediaType {
		case "message/delivery-status":
			partBody, err := io.ReadAll(part)
			if err != nil {
				return nil, fmt.Errorf("failed to read delivery-status part: %w", err)
			}
			info.OriginalRecipient, info.Status, info.DiagnosticCode = parseDSNStatus(partBody)

		case "message/rfc822", "text/rfc822-headers":
			partBody, err := io.ReadAll(part)
			if err != nil {
				continue
			}
			info.OriginalMessageID = extractMessageID(partBody)
		}
	}

	if info.OriginalRecipient == "" && info.Status == "" {
		return nil, nil
	}

	info.IsHardBounce = strings.HasPrefix(info.Status, "5.")
	return info, nil
}

// parseDSNStatus extracts Final-Recipient, Status, and Diagnostic-Code
// from a message/delivery-status body. This body contains one or more
// groups of header-like fields separated by blank lines.
func parseDSNStatus(body []byte) (recipient, status, diagnostic string) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	var currentKey string
	var currentVal string

	flushField := func() {
		switch strings.ToLower(currentKey) {
		case "final-recipient":
			// Format: "rfc822;user@example.com" or just "user@example.com"
			if idx := strings.Index(currentVal, ";"); idx >= 0 {
				recipient = strings.TrimSpace(currentVal[idx+1:])
			} else {
				match := emailRegex.FindString(currentVal)
				if match != "" {
					recipient = match
				}
			}
		case "status":
			status = strings.TrimSpace(currentVal)
		case "diagnostic-code":
			diagnostic = strings.TrimSpace(currentVal)
		}
		currentKey = ""
		currentVal = ""
	}

	for scanner.Scan() {
		line := scanner.Text()

		// Continuation line (starts with whitespace)
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if currentKey != "" {
				currentVal += " " + strings.TrimSpace(line)
			}
			continue
		}

		// Flush previous field
		if currentKey != "" {
			flushField()
		}

		// Blank line separates per-message and per-recipient groups
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Parse "Key: Value"
		if idx := strings.Index(line, ":"); idx >= 0 {
			currentKey = strings.TrimSpace(line[:idx])
			currentVal = strings.TrimSpace(line[idx+1:])
		}
	}

	// Flush last field
	if currentKey != "" {
		flushField()
	}

	return recipient, status, diagnostic
}

func extractMessageID(body []byte) string {
	msg, err := mail.ReadMessage(bytes.NewReader(body))
	if err != nil {
		// Try scanning manually for Message-ID header
		scanner := bufio.NewScanner(bytes.NewReader(body))
		for scanner.Scan() {
			line := scanner.Text()
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "message-id:") {
				val := strings.TrimSpace(line[len("message-id:"):])
				return strings.Trim(val, "<>")
			}
		}
		return ""
	}
	return strings.Trim(msg.Header.Get("Message-Id"), "<>")
}

var bounceSubjectPatterns = []string{
	"delivery status notification",
	"undeliverable",
	"undelivered mail",
	"returned mail",
	"mail delivery failed",
	"delivery failure",
	"failure notice",
	"non-delivery",
}

// parseHeuristicBounce attempts to detect bounce information from non-standard NDR messages
func parseHeuristicBounce(msg *mail.Message) (*BounceInfo, error) {
	subject := strings.ToLower(msg.Header.Get("Subject"))

	isBounce := false
	for _, pattern := range bounceSubjectPatterns {
		if strings.Contains(subject, pattern) {
			isBounce = true
			break
		}
	}

	if !isBounce {
		return nil, nil
	}

	bodyBytes, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, nil
	}
	bodyStr := string(bodyBytes)

	// Try to find an email address in the body
	recipient := ""
	matches := emailRegex.FindAllString(bodyStr, 10)
	// Skip common addresses (postmaster, mailer-daemon)
	for _, m := range matches {
		lower := strings.ToLower(m)
		if !strings.HasPrefix(lower, "postmaster@") && !strings.HasPrefix(lower, "mailer-daemon@") {
			recipient = m
			break
		}
	}

	if recipient == "" {
		return nil, nil
	}

	// Determine hard/soft bounce from body content
	lowerBody := strings.ToLower(bodyStr)
	isHard := strings.Contains(lowerBody, "user unknown") ||
		strings.Contains(lowerBody, "no such user") ||
		strings.Contains(lowerBody, "does not exist") ||
		strings.Contains(lowerBody, "recipient rejected") ||
		strings.Contains(lowerBody, "address rejected") ||
		strings.Contains(lowerBody, "invalid recipient") ||
		strings.Contains(lowerBody, "mailbox not found") ||
		strings.Contains(lowerBody, "550 ")

	status := "4.0.0"
	if isHard {
		status = "5.0.0"
	}

	info := &BounceInfo{
		OriginalRecipient: recipient,
		Status:            status,
		DiagnosticCode:    truncateDiagnostic(bodyStr),
		IsHardBounce:      isHard,
	}

	// Try to extract original Message-ID
	msgID := msg.Header.Get("X-Failed-Recipients")
	if msgID == "" {
		// Scan body for Message-ID reference
		scanner := bufio.NewScanner(strings.NewReader(bodyStr))
		for scanner.Scan() {
			line := scanner.Text()
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "message-id:") {
				val := strings.TrimSpace(line[len("message-id:"):])
				info.OriginalMessageID = strings.Trim(val, "<>")
				break
			}
		}
	}

	return info, nil
}

func truncateDiagnostic(body string) string {
	// Take first 500 chars as diagnostic context
	if len(body) > 500 {
		return body[:500]
	}
	return body
}
