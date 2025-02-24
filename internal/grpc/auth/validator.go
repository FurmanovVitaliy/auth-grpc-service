package auth

import (
	"errors"
	"strings"

	sso "github.com/FurmanovVitaliy/grpc-api/gen/go/sso_v1"
	"github.com/go-playground/validator/v10"
)

// Todo: init sql injection validator
var validate *validator.Validate

// Initialize the validator with custom rules
func init() {
	validate = validator.New()
	validate.RegisterValidation("no_sql_phrases", containsNoRestrictedSQL)
}

// containsNoRestrictedSQL validates that the input does not contain SQL injection phrases
func containsNoRestrictedSQL(fl validator.FieldLevel) bool {
	restrictedPhrases := []string{"DROP DATABASE", "DROP TABLE", "DELETE FROM", "INSERT INTO", "UPDATE ", "ALTER TABLE"}
	value := strings.ToUpper(fl.Field().String())
	for _, phrase := range restrictedPhrases {
		if strings.Contains(value, phrase) {
			return false
		}
	}
	return true
}

// isStrongPassword checks if a password is strong
func isStrongPassword(fl validator.FieldLevel) bool {
	var hasUpper, hasLower, hasNumber, hasSpecial bool
	password := fl.Field().String()

	if len(password) < 8 {
		return false
	}

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasNumber = true
		case strings.ContainsRune("!@#$%^&*()_-+={[}]|:;<,>.?/`~", char):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasNumber && hasSpecial
}

// validateRegisterRequest performs validation for RegisterRequest
func validateRegisterRequest(req *sso.RegisterRequest) error {
	// Perform standard validation
	err := validate.Struct(req)
	if err != nil {
		return err
	}

	if strings.TrimSpace(req.Username) == "" {
		return errors.New("username cannot be empty or just whitespace")
	}

	req.GetPassword()

	return nil
}
