package helpers

import (
	"cloudadmin/domain"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"sort"
	"strings"

	fql "github.com/ganigeorgiev/fexpr"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

// GetRandomInt returns a random int used for postgres params
func GetRandomInt() int {
	nBig, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		panic(err)
	}
	n := nBig.Int64()
	return int(n)
}

// GenerateRole returns a unique role used for authenticating the current user
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
	return userData.Role == role

}

// CheckAppsExists validates that the list of applications appear in user apps
func CheckAppsExist(applications []string, appsData []*domain.ApplicationData) bool {
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

func SortApps(apps []*domain.ApplicationData, sortBy, sortDir string) []*domain.ApplicationData {
	switch sortBy {
	case "name":
		if sortDir == "asc" {
			sort.SliceStable(apps, func(i, j int) bool {
				return apps[i].Name < apps[j].Name
			})
		} else {
			sort.SliceStable(apps, func(i, j int) bool {
				return apps[i].Name > apps[j].Name
			})
		}

	case "created_timestamp":
		if sortDir == "asc" {
			sort.SliceStable(apps, func(i, j int) bool {
				return apps[i].CreatedTimestamp.String() < apps[j].CreatedTimestamp.String()
			})
		} else {
			sort.SliceStable(apps, func(i, j int) bool {
				return apps[i].CreatedTimestamp.String() >= apps[j].CreatedTimestamp.String()
			})
		}

	case "updated_timestamp":
		if sortDir == "asc" {
			sort.SliceStable(apps, func(i, j int) bool {
				return apps[i].UpdatedTimestamp.String() <= apps[j].UpdatedTimestamp.String()
			})
		} else {
			sort.SliceStable(apps, func(i, j int) bool {
				return apps[i].UpdatedTimestamp.String() >= apps[j].UpdatedTimestamp.String()
			})
		}

	}
	return apps
}

/*
example of combined filters
description=NULL&&is_running="false"||kname="test"&&created_timestamp<"1day"
(description=NULL && is_running="false")||(kname="test" && description="integer")
*/

// ParseFQLFilter returns filters in slice of slices of strings
func ParseFQLFilter(fqlString string, logger *logrus.Logger) [][]string {
	s := fql.NewScanner(strings.NewReader(fqlString))

	listFilters := make([][]string, 20)
	idx := 0

	listFilters[idx] = make([]string, 0)
	for {
		t, err := s.Scan()
		if t.Type == fql.TokenEOF {
			logger.Debug("End of parsing")
			break
		}

		if err != nil {
			logger.Errorf("error in scanning : %v", err)
			return nil
		}
		if t.Type == fql.TokenWS || (t.Type == fql.TokenText && t.Literal == "NULL") ||
			(t.Type == fql.TokenIdentifier && !slices.Contains(GetAppsFilters, t.Literal) && t.Literal != "NULL") {
			logger.Errorf("invalid fql value")
			return nil
		}
		if t.Type == fql.TokenSign || t.Type == fql.TokenJoin || t.Type == fql.TokenIdentifier || t.Type == fql.TokenText || t.Type == fql.TokenGroup {
			if t.Type == fql.TokenGroup {
				for _, literal := range strings.Split(t.Literal, " ") {
					if literal == "&&" || literal == "||" {
						idx = idx + 1
						listFilters[idx] = append(listFilters[idx], literal)
						idx = idx + 1
					} else {
						var separatedLiteral []string
						var separator string
						if strings.Contains(literal, "!=") {
							separatedLiteral = strings.Split(literal, "=")
							separator = "!="
						} else if strings.Contains(literal, ">=") {
							separatedLiteral = strings.Split(literal, ">=")
							separator = ">="
						} else if strings.Contains(literal, "<=") {
							separatedLiteral = strings.Split(literal, "<=")
							separator = "<="
						} else if strings.Contains(literal, "=") {
							separatedLiteral = strings.Split(literal, "=")
							separator = "="
						} else if strings.Contains(literal, ">") {
							separatedLiteral = strings.Split(literal, ">")
							separator = ">"
						} else if strings.Contains(literal, "<") {
							separatedLiteral = strings.Split(literal, "<")
							separator = "<"
						}

						listFilters[idx] = append(listFilters[idx], separatedLiteral[0])
						listFilters[idx] = append(listFilters[idx], separator)
						listFilters[idx] = append(listFilters[idx], separatedLiteral[1])
					}

				}

			} else {
				if t.Literal == "||" && len(listFilters[idx]) == 3 {
					idx = idx + 1
				}
				listFilters[idx] = append(listFilters[idx], t.Literal)
			}

			if t.Type == fql.TokenText || t.Literal == "NULL" || t.Literal == "&&" || t.Literal == "||" {
				idx = idx + 1
			}

		}

	}

	fmt.Println(listFilters)
	return listFilters
}
