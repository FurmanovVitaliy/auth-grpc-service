package auth

import (
	"strings"

	ssov1 "github.com/FurmanovVitaliy/grpc-api/gen/go/sso"
	"github.com/go-playground/validator/v10"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var validate *validator.Validate

// Initialize the validator with custom rules
func init() {
	validate = validator.New()
	validate.RegisterValidation("no_sql_phrases", containsNoRestrictedSQL)
	validate.RegisterValidation("strong_password", isStrongPassword)
}

// ContainsNoRestrictedSQL validates that the input does not contain SQL injection phrases
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

// IsStrongPassword checks if a password is strong (contains upper, lower, digit, special character)
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

// ValidateLoginRequest validates LoginRequest using the custom validator
func ValidateLoginRequest(req *ssov1.LoginRequest) error {

	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}

	if err := validate.Var(req.GetEmail(), "required,email,no_sql_phrases"); err != nil {
		return status.Error(codes.InvalidArgument, "invalid email format or SQL injection detected")
	}

	if err := validate.Var(req.GetPassword(), "required,no_sql_phrases"); err != nil {
		return status.Error(codes.InvalidArgument, "invalid password or SQL injection detected")
	}

	if req.GetAppId() == 0 {
		return status.Error(codes.InvalidArgument, "app_id is required")
	}
	return nil
}

// ValidateRegisterRequest validates RegisterRequest with custom rules
func ValidateRegisterRequest(req *ssov1.RegisterRequest) error {
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}

	if err := validate.Var(req.GetEmail(), "required,email,no_sql_phrases"); err != nil {
		return status.Error(codes.InvalidArgument, "invalid email format or SQL injection detected")
	}

	if err := validate.Var(req.GetPassword(), "required,no_sql_phrases,strong_password"); err != nil {
		return status.Error(codes.InvalidArgument, "invalid password format or SQL injection detected")
	}

	return nil
}

// ValidateIsAdminRequest validates that user ID is provided
func ValidateIsAdminRequest(req *ssov1.IsAdminRequest) error {
	if req.GetUserId() == 0 {
		return status.Error(codes.InvalidArgument, "user_id is required")
	}
	return nil
}
