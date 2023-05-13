package helpers

import (
	"cloudadmin/domain"
	"log"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/slices"
)

// GenerateRole returns a unique role for the current user in order to use their apps
func GenerateRole(userData *domain.UserData) *domain.UserData {
	id := uuid.New().String()
	userData.UserID = id
	currentRole := AddSaltToRole(id, userData.UserName)
	hashedRole, err := HashPassword(currentRole)
	if err != nil {
		log.Printf("[ERROR] Couldn't hash role : " + currentRole)
		return nil
	}
	userData.Role = hashedRole
	return userData

}

// AddSaltToRole combines id with a certain salt
func AddSaltToRole(id, salt string) string {
	return id + ":" + salt
}

// HashPassword uses bcrypt to generate a hash over password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// CheckPasswordHash verifies hashes between a plaintext password and a hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
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
	for _, app := range appsData {
		if !slices.Contains(applications, app.Name) {
			return false
		}
	}
	return true
}
