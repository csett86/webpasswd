package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/msteinert/pam/v2"
)

// Sentinel errors returned by ChangePassword.
var (
	ErrAuthFailed = errors.New("authentication failed: current password is incorrect")
	ErrPermDenied = errors.New("permission denied: password policy not satisfied or operation not allowed")
	ErrPAMUnknown = errors.New("password change failed")
)

// changePasswordFunc is the function used by the HTTP handler to change a
// password. It defaults to ChangePassword but can be replaced in tests.
var changePasswordFunc = ChangePassword

// ChangePassword authenticates username with currentPassword via PAM and then
// changes the password to newPassword. It opens a PAM transaction against the
// "passwd" service so that /etc/pam.d/passwd policy is enforced.
//
// The process must have sufficient privilege (typically root) for PAM to be
// able to authenticate and update the shadow database.
func ChangePassword(username, currentPassword, newPassword string) error {
	authTx, err := pam.StartFunc("passwd", username, func(s pam.Style, _ string) (string, error) {
		switch s {
		case pam.PromptEchoOff, pam.PromptEchoOn:
			return currentPassword, nil
		case pam.ErrorMsg, pam.TextInfo:
			return "", nil
		default:
			return "", fmt.Errorf("unhandled PAM message style %d", s)
		}
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPAMUnknown, err)
	}

	defer authTx.End()

	// Authenticate with the current password.
	if err := authTx.Authenticate(0); err != nil {
		return classifyPAMError(err, ErrAuthFailed)
	}

	changeTx, err := pam.StartFunc("passwd", username, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff, pam.PromptEchoOn:
			lowerMsg := strings.ToLower(msg)
			if strings.Contains(lowerMsg, "current") || strings.Contains(lowerMsg, "old") {
				return currentPassword, nil
			}
			return newPassword, nil
		case pam.ErrorMsg, pam.TextInfo:
			return "", nil
		default:
			return "", fmt.Errorf("unhandled PAM message style %d", s)
		}
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPAMUnknown, err)
	}

	defer changeTx.End()

	// Request the password change.
	if err := changeTx.ChangeAuthTok(0); err != nil {
		return classifyPAMError(err, ErrPermDenied)
	}

	return nil
}

// classifyPAMError maps a raw PAM error to one of our sentinel errors.
// fallback is used when the message does not match a known auth-related code.
func classifyPAMError(err error, fallback error) error {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "authentication failure"),
		strings.Contains(msg, "user not known"),
		strings.Contains(msg, "user unknown"),
		strings.Contains(msg, "invalid credentials"):
		return fmt.Errorf("%w: %w", ErrAuthFailed, err)
	case strings.Contains(msg, "permission denied"),
		strings.Contains(msg, "authentication token manipulation error"),
		strings.Contains(msg, "bad item"),
		strings.Contains(msg, "authtok"):
		return fmt.Errorf("%w: %w", ErrPermDenied, err)
	default:
		return fmt.Errorf("%w: %w", fallback, err)
	}
}
