package helpers

import (
	"cloudadmin/domain"
	"crypto/sha256"
	"encoding/base64"

	"github.com/google/uuid"
	"golang.org/x/exp/slices"
)

// GenerateRole returns a unique role for the current user in order to use their apps
func GenerateRole(userData *domain.UserData) *domain.UserData {
	id := uuid.New().String()
	userData.UserID = id
	currentRole := AddSaltToRole(id, userData.UserName)
	hashedRole := HashPassword(currentRole)

	userData.Role = hashedRole
	return userData

}

// AddSaltToRole combines id with a certain salt
func AddSaltToRole(id, salt string) string {
	return id + ":" + salt
}

// HashPassword uses sha256 to generate a hash over password
func HashPassword(password string) string {
	sum := sha256.Sum256([]byte(password))
	return base64.URLEncoding.EncodeToString(sum[:])
}

// CheckPasswordHash verifies hashes between a plaintext password and a hash
func CheckPasswordHash(password, hash string) bool {
	passHash := HashPassword(password)
	return passHash == hash
}

// CheckUser verifies if user is authorized
func CheckUser(userData *domain.UserData, role string) bool {
	possibleRole := AddSaltToRole(userData.UserID, userData.UserName)
	return CheckPasswordHash(possibleRole, role)

}

// CheckUserCredentials validates username and passwod match
func CheckUserCredentials(userData *domain.UserData, username, password string) bool {
	if userData.UserName != username || userData.Password != password {
		return false
	}
	return true
}

// CheckAppExists validates that the app appears in user apps
func CheckAppExist(applications []string, appsData []*domain.ApplicationData) bool {
	if len(applications) == 0 {
		return false
	}
	for _, app := range appsData {
		if !slices.Contains(applications, app.Name) {
			return false
		}
	}
	return true
}

// Unique removes dups from slice
func Unique(s domain.GetApplicationsData) domain.GetApplicationsData {
	inResult := make(map[string]bool)
	var result domain.GetApplicationsData
	for _, str := range s.Response {
		if _, ok := inResult[str.Name]; !ok {
			inResult[str.Name] = true
			result.Response = append(result.Response, str)
		}
	}
	for _, str := range s.Errors {
		if _, ok := inResult[str.Message]; !ok {
			inResult[str.Message] = true
			result.Errors = append(result.Errors, str)
		}
	}
	return result
}
