package utils

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/markbates/goth"
	"golang.org/x/exp/rand"
)

// DoWithRetry executes the function fn with retry attempts in case of an error.
// Parameters:
// fn - the function to be executed.
// attempts - the number of execution attempts.
// delay - the delay between attempts.
func DoWithRetry(fn func() error, attempts int, delay time.Duration) (err error) {
	for attempts > 0 {
		if err = fn(); err != nil {

			attempts--
			time.Sleep(delay)
			continue
		}
		return nil
	}
	return err
}

// maskEmail masks the email address by replacing some characters with asterisks.
// Example: example@example.com ->  ex*****@*******le.com
func MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}

	localPart := parts[0]
	domainPart := parts[1]

	if len(localPart) > 2 {
		localPart = localPart[:2] + strings.Repeat("*", len(localPart)-2)
	}

	if len(domainPart) > 2 {
		domainPart = strings.Repeat("*", len(domainPart)-2) + domainPart[len(domainPart)-2:]
	}

	return localPart + "@" + domainPart
}

// GenerateID generates a new unique identifier.
func GenerateID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("failed to generate UUID: %w", err)
	}
	return id.String(), nil
}
func GenerateSimpleID() string {
	return uuid.New().String()
}

func GenerateUsername(userInfo goth.User) string {
	if userInfo.NickName != "" {
		return userInfo.NickName
	}
	name := strings.TrimSpace(userInfo.FirstName + " " + userInfo.LastName)
	if name != "" {
		return name
	}
	if userInfo.Email != "" {
		return userInfo.Email
	}
	return "user_" + strconv.Itoa(rand.Intn(100000))
}
