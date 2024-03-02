package api

import (
	"archive/zip"
	"cloudadmin/domain"
	"cloudadmin/helpers"
	"cloudadmin/priority_queue"
	schedule_alghoritms "cloudadmin/schedule_algorithms"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/VirusTotal/vt-go"
	graphite "github.com/cyberdelia/go-metrics-graphite"
	"github.com/emicklei/go-restful/v3"
	"github.com/pquerna/otp/totp"
	metrics "github.com/rcrowley/go-metrics"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
)

var (
	//map of users with their specific cached requests as value
	cachedRequests = make(map[string][]string, 0)
	// register metrics for graphite client
	getAppsMetric        = metrics.GetOrRegisterMeter("applications.get", nil)
	getAppsLatencyMetric = metrics.GetOrRegisterTimer("get_apps_latency.response", nil)
	updateAppsMetric     = metrics.GetOrRegisterMeter("applications.update", nil)
	registerAppMetric    = metrics.GetOrRegisterMeter("applications.register", nil)

	malwareFileMetric = metrics.GetOrRegisterMeter("applications.malware", nil)
	safeFileMetric    = metrics.GetOrRegisterMeter("applications.safe", nil)

	scheduleAppsMetric        = metrics.GetOrRegisterMeter("applications.schedule", nil)
	scheduleAppsLatencyMetric = metrics.GetOrRegisterTimer("schedule_apps_latency.response", nil)
	getPodResultsMetric       = metrics.GetOrRegisterMeter("applications.get_pod_results", nil)

	loginMetrics       = metrics.GetOrRegisterMeter("users_login", nil)
	failedLoginMetrics = metrics.GetOrRegisterMeter("users_failed_login", nil)
	getUserMetric      = metrics.GetOrRegisterMeter("users.get.profile", nil)
	updateUserMetric   = metrics.GetOrRegisterMeter("users.update.profile", nil)
	userLatencyMeric   = metrics.GetOrRegisterTimer("users_get_profile_latency.response", nil)

	totalRequestsMetric = metrics.GetOrRegisterCounter("total_requests.count", nil)

	mutex sync.Mutex
)

// AdminAuthenticate verifies role and user_id for admin
func (api *API) AdminAuthenticate(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	errorData := domain.ErrorResponse{}
	authHeader := request.HeaderParameter("USER-AUTH")
	userIDHeader := request.HeaderParameter("USER-UUID")

	userData, err := api.psqlRepo.GetUserDataWithUUID(userIDHeader)
	if err != nil || !helpers.CheckUser(userData, authHeader) || userData.UserName != "admin" {
		api.apiLogger.Error(" User id not authorized", zap.String("user_id", userIDHeader))
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + userIDHeader + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}
	chain.ProcessFilter(request, response)
}

// BasicAuthenticate verifies role and user_id for auth
func (api *API) BasicAuthenticate(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	errorData := domain.ErrorResponse{}
	authHeader := request.HeaderParameter("USER-AUTH")
	userIDHeader := request.HeaderParameter("USER-UUID")

	userData, err := api.psqlRepo.GetUserDataWithUUID(userIDHeader)
	if err != nil || !helpers.CheckUser(userData, authHeader) {
		api.apiLogger.Error(" User id not authorized", zap.String("user_id", userIDHeader))
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + userIDHeader + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}
	chain.ProcessFilter(request, response)
}

// UserRegister creates a user
func (api *API) UserRegister(request *restful.Request, response *restful.Response) {

	userData := domain.UserData{}
	errorData := domain.ErrorResponse{}
	err := request.ReadEntity(&userData)
	if err != nil {
		api.apiLogger.Error(" Couldn't read body with error : ", zap.Error(err))
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	if userData.UserName == "" {
		api.apiLogger.Error(" Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	if len(userData.Password) < 16 {
		api.apiLogger.Error(" password too short")
		errorData.Message = "Bad Request/ Password too short(must have at least 16 characters)"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if !regexp.MustCompile(`\d`).MatchString(userData.Password) {
		api.apiLogger.Error(" password does not contain digits")
		errorData.Message = "Bad Request/ Password does not contain digits"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if !unicode.IsUpper(rune(userData.Password[0])) {
		api.apiLogger.Error(" password does not start with uppercase")
		errorData.Message = "Bad Request/ Password does not start with uppercase"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if !helpers.HasSymbol(userData.Password) {
		api.apiLogger.Error(" password does not have special characters")
		errorData.Message = "Bad Request/ Password does not have special characters"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if strings.Contains(userData.Password, userData.UserName) {
		api.apiLogger.Error(" password contains user")
		errorData.Message = "Bad Request/ Password contains user"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	userRetrievedData, _ := api.psqlRepo.GetUserData(userData.UserName)
	if userRetrievedData != nil {
		api.apiLogger.Error(" User already exists", zap.String("user_name", userData.UserName))
		errorData.Message = "User already exists"
		errorData.StatusCode = http.StatusFound
		response.WriteHeader(http.StatusFound)
		response.WriteEntity(errorData)
		return
	}
	userRetrievedData, _ = api.psqlRepo.GetUserDataWithEmail(userData.Email)
	if userRetrievedData != nil {
		api.apiLogger.Error(" Email already used", zap.String("user_email", userData.Email))
		errorData.Message = "Bad Request/Email already used"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	nowTime := time.Now()
	userData.JoinedDate = &nowTime
	userData.LastTimeOnline = &nowTime
	userData.Applications = []string{}
	userData.NrDeployedApps = helpers.DefaultNrDeployedApps
	userData.WantNotify = false
	userData.UserLocked = false
	userData.UserTimeout = nil
	userData.UserLimitLoginAttempts = helpers.LoginAttempts
	userData.UserLimitTimeout = helpers.TimeoutLimit
	userData.OTPData = domain.OneTimePassData{OTPEnabled: false, OTPVerified: false}

	err = api.psqlRepo.InsertUserData(&userData)
	if err != nil {
		errorData.Message = "Internal error/ insert user data in postgres"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}

	registerResponse := domain.QueryResponse{}
	registerResponse.Message = "User registered succesfully"
	registerResponse.ResourcesAffected = append(registerResponse.ResourcesAffected, userData.UserName)
	response.WriteEntity(registerResponse)
	totalRequestsMetric.Inc(1)
}

// UserLogin verifies user credentials
func (api *API) UserLogin(request *restful.Request, response *restful.Response) {
	userData := domain.UserData{}
	newUserData := &domain.UserData{}
	errorData := domain.ErrorResponse{}
	oldPass := request.QueryParameter("old_password")

	err := request.ReadEntity(&userData)
	if err != nil {
		api.apiLogger.Error(" Couldn't read body with error : ", zap.Error(err))
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if userData.UserName == "" {
		api.apiLogger.Error(" Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if userData.UserName == "admin" || strings.Contains(userData.UserName, "admin") {
		api.apiLogger.Error(" You are not allowed to login as admin")
		errorData.Message = "Status forbidden/  You are not allowed to login as admin"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	if userData.Password == "" {
		failedLoginMetrics.Mark(1)
		go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
		api.apiLogger.Error(" Couldn't read password query parameter")
		errorData.Message = "Bad Request/ empty password"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	if len(userData.Password) < 16 {
		failedLoginMetrics.Mark(1)
		go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
		api.apiLogger.Error(" password too short")
		errorData.Message = "Bad Request/ Password too short(must have at least 16 characters)"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if !regexp.MustCompile(`\d`).MatchString(userData.Password) {
		failedLoginMetrics.Mark(1)
		go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
		api.apiLogger.Error(" password does not contain digits")
		errorData.Message = "Bad Request/ Password does not contain digits"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if !unicode.IsUpper(rune(userData.Password[0])) {
		failedLoginMetrics.Mark(1)
		go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
		api.apiLogger.Error(" password does not start with uppercase")
		errorData.Message = "Bad Request/ Password does not start with uppercase"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if !helpers.HasSymbol(userData.Password) {
		failedLoginMetrics.Mark(1)
		go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
		api.apiLogger.Error(" password does not have special characters")
		errorData.Message = "Bad Request/ Password does not have special characters"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if strings.Contains(userData.Password, userData.UserName) {
		failedLoginMetrics.Mark(1)
		go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
		api.apiLogger.Error(" password contains user")
		errorData.Message = "Bad Request/ Password contains user"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	reqUrl, _ := request.Request.URL.Parse(request.Request.URL.Host + userPath + "/" + userData.UserName)
	marshalledRequest, err := json.Marshal(reqUrl)
	if err != nil {
		api.apiLogger.Error(" Couldn't marshal request", zap.Any("request_url", request.Request.URL))
		errorData.Message = "Internal server error/Cannot marshal marshalledRequest in User Login"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}

	dbUserData, err := api.psqlRepo.GetUserData(userData.UserName)
	if err != nil {
		failedLoginMetrics.Mark(1)
		go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
		api.apiLogger.Error(" User not found", zap.String("user_name", userData.UserName))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}

	if !helpers.CheckPasswordHash(userData.Password, dbUserData.Password) {
		failedLoginMetrics.Mark(1)
		go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
		//rate limit mechanism + update in cache
		if !dbUserData.UserLocked {
			// update postgres for timeout
			dbUserData.UserLimitLoginAttempts = dbUserData.UserLimitLoginAttempts - 1
			if dbUserData.UserLimitLoginAttempts <= 0 {
				if dbUserData.UserTimeout == nil {
					dbUserData.UserLimitTimeout = dbUserData.UserLimitTimeout - 1
					if dbUserData.UserLimitTimeout <= 0 {
						dbUserData.UserLocked = true
					}
					nowTime := time.Now()
					dbUserData.UserTimeout = &nowTime
					dbUserData.Password = ""
					err = api.psqlRepo.UpdateUserData(dbUserData)
					if err != nil {
						errorData.Message = "Internal error / updating user data in postgres"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
						return
					}
					//gather the fresh new data to be cached
					newUserData, _ := api.psqlRepo.GetUserData(userData.UserName)
					api.apiCache.SetWithTTL(string(marshalledRequest), newUserData, 1, time.Hour*24)
				} else {
					if time.Since(*dbUserData.UserTimeout) < 5*time.Second {
						api.apiLogger.Error(" Too many requests. Please try again in 5 minutes.")
						errorData.Message = "Too many requests. Please try again in 5 minutes"
						errorData.StatusCode = http.StatusTooManyRequests
						response.WriteHeader(http.StatusTooManyRequests)
						response.WriteEntity(errorData)
						return
					} else {
						dbUserData.UserLimitLoginAttempts = 5
						dbUserData.UserTimeout = nil
						dbUserData.UserLocked = false
						dbUserData.Password = ""
						err = api.psqlRepo.UpdateUserData(dbUserData)
						if err != nil {
							errorData.Message = "Internal error / updating user data in postgres"
							errorData.StatusCode = http.StatusInternalServerError
							response.WriteHeader(http.StatusInternalServerError)
							response.WriteEntity(errorData)
							return
						}
						//gather the fresh new data to be cached
						newUserData, _ := api.psqlRepo.GetUserData(userData.UserName)
						api.apiCache.SetWithTTL(string(marshalledRequest), newUserData, 1, time.Hour*24)
					}
				}
			}

		} else {
			errorData.Message = "Status forbidden/  You are not allowed to use app anymore.Please contact admin"
			errorData.StatusCode = http.StatusForbidden
			response.WriteHeader(http.StatusForbidden)
			response.WriteEntity(errorData)
			return
		}
		newUserData, _ := api.psqlRepo.GetUserData(userData.UserName)
		api.apiCache.SetWithTTL(string(marshalledRequest), newUserData, 1, time.Hour*24)

		dbUserData.Password = ""
		err = api.psqlRepo.UpdateUserData(dbUserData)
		if err != nil {
			errorData.Message = "Internal error / updating user data in postgres"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

		//gather the fresh new data to be cached
		newUserData, _ = api.psqlRepo.GetUserData(userData.UserName)
		api.apiCache.SetWithTTL(string(marshalledRequest), newUserData, 1, time.Hour*24)

		failedLoginMetrics.Mark(1)
		go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
		api.apiLogger.Error(" Wrong password given. Please try again.")
		errorData.Message = "Wrong Password"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if dbUserData.UserTimeout != nil && time.Since(*dbUserData.UserTimeout) < 5*time.Second {
		api.apiLogger.Error(" Too many requests. Please try again in 5 minutes.")
		errorData.Message = "Too many requests. Please try again in 5 minutes"
		errorData.StatusCode = http.StatusTooManyRequests
		response.WriteHeader(http.StatusTooManyRequests)
		response.WriteEntity(errorData)
		return
	} else {
		dbUserData.UserLimitLoginAttempts = 5
		dbUserData.UserTimeout = nil
		dbUserData.UserLocked = false
		dbUserData.Password = ""
		err = api.psqlRepo.UpdateUserData(dbUserData)
		if err != nil {
			errorData.Message = "Internal error / updating user data in postgres"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}
		//gather the fresh new data to be cached
		newUserData, _ := api.psqlRepo.GetUserData(userData.UserName)
		api.apiCache.SetWithTTL(string(marshalledRequest), newUserData, 1, time.Hour*24)
	}
	if dbUserData.UserLocked {
		errorData.Message = "Status forbidden/  You are not allowed to use app anymore.Please contact admin"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	if dbUserData.Role == "" {
		newUserData = helpers.GenerateRole(dbUserData)
		err = api.psqlRepo.UpdateUserRoleData(newUserData.Role, newUserData.UserID, newUserData)
		if err != nil {
			errorData.Message = "Internal error / updating role in postgres"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}
	} else {
		newUserData = dbUserData
	}

	if oldPass == "" || oldPass == "false" {
		nowTime := time.Now()
		newUserData.LastTimeOnline = &nowTime

		err = api.psqlRepo.UpdateUserLastTimeOnlineData(*newUserData.LastTimeOnline, newUserData)
		if err != nil {
			errorData.Message = "Internal error / updating last_time in postgres"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

		//gather the fresh new data to be cached
		newUserData, _ := api.psqlRepo.GetUserData(userData.UserName)
		api.apiCache.SetWithTTL(string(marshalledRequest), newUserData, 1, time.Hour*24)
	}

	newUserData.Password = ""
	newUserData.Applications = []string{}
	newUserData.BirthDate = ""
	newUserData.Email = ""
	newUserData.JobRole = ""
	newUserData.JobRole = ""
	newUserData.JoinedDate = nil
	newUserData.LastTimeOnline = nil
	newUserData.NrDeployedApps = 0
	newUserData.UserLimitLoginAttempts = 5
	newUserData.UserLimitTimeout = 3
	newUserData.UserLocked = false
	newUserData.UserTimeout = nil
	newUserData.OTPData = domain.OneTimePassData{}
	loginMetrics.Mark(1)
	totalRequestsMetric.Inc(1)
	go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
	response.WriteEntity(newUserData)
}

// GetUserProfile returns user profile based on username
func (api *API) GetUserProfile(request *restful.Request, response *restful.Response) {
	startTime := time.Now()
	errorData := domain.ErrorResponse{}

	//calculate key and use cache to get the response
	marshalledRequest, err := json.Marshal(request.Request.URL)
	if err != nil {
		api.apiLogger.Error(" Couldn't marshal request", zap.Any("request_url", request.Request.URL))
		errorData.Message = "Internal server error/Cannot marshal marshalledRequest in User Profile"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	userDataCache, userFound := api.apiCache.Get(marshalledRequest)
	if !userFound {

		username := request.PathParameter("username")
		if username == "" {
			api.apiLogger.Error(" Couldn't read username path parameter")
			errorData.Message = "Bad Request/ empty username"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}

		userData, err := api.psqlRepo.GetUserData(username)
		if err != nil {
			api.apiLogger.Error(" User not found", zap.String("user_name", username))
			errorData.Message = "User not found"
			errorData.StatusCode = http.StatusNotFound
			response.WriteHeader(http.StatusNotFound)
			response.WriteEntity(errorData)
			return
		}
		userUUID := request.HeaderParameter("USER-UUID")
		checkUserData, err := api.psqlRepo.GetUserDataWithUUID(userUUID)
		if err != nil {
			api.apiLogger.Error(" User not found", zap.String("user_uuid", userUUID))
			errorData.Message = "User not found"
			errorData.StatusCode = http.StatusNotFound
			response.WriteHeader(http.StatusNotFound)
			response.WriteEntity(errorData)
			return
		}
		if checkUserData.UserName != "admin" && userData.UserName != checkUserData.UserName {
			errorData.Message = "Status forbidden"
			errorData.StatusCode = http.StatusForbidden
			response.WriteHeader(http.StatusForbidden)
			response.WriteEntity(errorData)
			return
		}
		if userData.UserLocked {
			errorData.Message = "Status forbidden/  You are not allowed to use app anymore.Please contact admin"
			errorData.StatusCode = http.StatusForbidden
			response.WriteHeader(http.StatusForbidden)
			response.WriteEntity(errorData)
			return
		}
		api.apiLogger.Debug(" Not found in cache", zap.String("user_name", username))
		userData.Password = ""
		userData.Role = ""
		userData.UserID = ""
		response.WriteEntity(userData)
		// If not in cache, set it
		api.apiCache.SetWithTTL(string(marshalledRequest), userData, 1, time.Hour*24)
		cachedRequests[username] = append(cachedRequests[username], string(marshalledRequest))

	} else {

		userData := userDataCache.(*domain.UserData)

		api.apiLogger.Debug(" Found in cache", zap.String("user_name", userData.UserName))

		userData.Password = ""
		userData.Role = ""
		userData.UserID = ""
		response.WriteEntity(userData)
	}
	endTime := time.Since(startTime)
	userLatencyMeric.Update(time.Duration(endTime.Microseconds()))
	getUserMetric.Mark(1)
	totalRequestsMetric.Inc(1)
	go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)

}

// UpdateUserProfile updates user profile
func (api *API) UpdateUserProfile(request *restful.Request, response *restful.Response) {
	userData := domain.UserData{}
	errorData := domain.ErrorResponse{}

	err := request.ReadEntity(&userData)
	if err != nil {
		api.apiLogger.Error(" Couldn't read body with error : ", zap.Error(err))
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	dbUserData, err := api.psqlRepo.GetUserData(userData.UserName)
	if err != nil {
		api.apiLogger.Error(" User id not found", zap.String("user_name", userData.UserName))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}
	userUUID := request.HeaderParameter("USER-UUID")
	checkUserData, err := api.psqlRepo.GetUserDataWithUUID(userUUID)
	if err != nil {
		api.apiLogger.Error(" User not found", zap.String("user_uuid", userUUID))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}
	if checkUserData.UserName != "admin" && dbUserData.UserName != checkUserData.UserName {
		errorData.Message = "Status forbidden"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}
	if dbUserData.UserLocked {
		errorData.Message = "Status forbidden/  You are not allowed to use app anymore.Please contact admin"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	if userData.Role != "" || userData.UserID != "" || len(userData.Applications) > 0 || userData.UserLimitLoginAttempts > 0 ||
		userData.UserLimitTimeout > 0 {
		api.apiLogger.Error(" Wrong fields to update")
		errorData.Message = "Bad Request/ wrong fields , you can only update birth_date ,job_role,email,  want_notify or password"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if userData.Password != "" {
		if len(userData.Password) < 8 {
			api.apiLogger.Error(" password too short")
			errorData.Message = "Bad Request/ Password too short"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}
		if !unicode.IsUpper(rune(userData.Password[0])) {
			api.apiLogger.Error(" password does not start with uppercase")
			errorData.Message = "Bad Request/ Password does not start with uppercase"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}
	}

	err = api.psqlRepo.UpdateUserData(&userData)
	if err != nil {
		if strings.Contains(err.Error(), "no row found") {
			errorData.Message = "User not found"
			errorData.StatusCode = http.StatusNotFound
			response.WriteHeader(http.StatusNotFound)
			response.WriteEntity(errorData)
			return
		} else {
			errorData.Message = "Internal error / updating user data in postgres"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

	}
	reqUrl, _ := request.Request.URL.Parse(request.Request.URL.String() + "/" + userData.UserName)

	marshalledRequest, err := json.Marshal(reqUrl)
	if err != nil {
		api.apiLogger.Error(" Couldn't marshal request", zap.Any("request_url", request.Request.URL))
		errorData.Message = "Internal server error/Cannot marshal marshalledRequest in User Profile"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}

	//gather the fresh new data to be cached
	newUserData, _ := api.psqlRepo.GetUserData(userData.UserName)
	api.apiCache.SetWithTTL(string(marshalledRequest), newUserData, 1, time.Hour*24)

	updateUserMetric.Mark(1)
	totalRequestsMetric.Inc(1)
	go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)

	updateResponse := domain.QueryResponse{}
	updateResponse.Message = "User updated succesfully"
	updateResponse.ResourcesAffected = append(updateResponse.ResourcesAffected, userData.UserName)
	response.WriteEntity(updateResponse)
}

// DeleteUser deletes user
func (api *API) DeleteUser(request *restful.Request, response *restful.Response) {
	errorData := domain.ErrorResponse{}
	usersName := request.QueryParameter("usernames")
	if usersName == "" {
		api.apiLogger.Error(" Couldn't read usernames query parameter")
		errorData.Message = "Bad Request/ empty usernames"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	listUsersName := strings.Split(usersName, ",")

	for _, username := range listUsersName {
		//Get user data and update applications column + delete apps
		//calculate key and use cache to get the response
		reqUrl, _ := request.Request.URL.Parse(request.Request.URL.String() + "/" + username)

		marshalledRequest, err := json.Marshal(reqUrl)
		if err != nil {
			api.apiLogger.Error(" Couldn't marshal request", zap.Any("request_url", request.Request.URL))
			errorData.Message = "Internal server error/Cannot marshal marshalledRequest in User Profile"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

		var userErr error
		userApps := make([]string, 0)
		userData := &domain.UserData{}
		userDataCache, userFound := api.apiCache.Get(marshalledRequest)
		if !userFound {
			userData, userErr = api.psqlRepo.GetUserData(username)
			if userErr != nil {
				errorData.Message = "User not found"
				errorData.StatusCode = http.StatusNotFound
				response.WriteHeader(http.StatusNotFound)
				response.WriteEntity(errorData)
				return
			}

		} else {
			userData = userDataCache.(*domain.UserData)

		}
		if userData != nil {
			userApps = append(userApps, userData.Applications...)
		}

		for _, userApp := range userApps {
			err = api.psqlRepo.DeleteAppData(userApp, username)
			if err != nil {
				api.apiLogger.Error(" App could not be deleted/not found ", zap.String("app_name", userApp))
				errorData.Message = "App not found"
				errorData.StatusCode = http.StatusNotFound
				response.WriteHeader(http.StatusNotFound)
				response.WriteEntity(errorData)
				return
			}
			execName := strings.Split(userApp, ".")[0]
			extensionName := strings.Split(userApp, ".")[1]
			err = api.dockerClient.ListImagesAndDelete(execName + "_" + extensionName)
			if err != nil {
				errorData.Message = "Internal error/ failed to remove images"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
		}

		_, _, userAppsData, err := api.psqlRepo.GetAppsData(username, "", "", "", []string{})
		if err != nil {
			api.apiLogger.Error("Got error when retrieving apps", zap.Error(err))
			errorData.Message = "Internal error / retrieving apps"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

		for _, app := range userAppsData {
			if app.IsRunning {
				execName := strings.Split(app.Name, ".")[0]
				extensionName := strings.Split(app.Name, ".")[1]
				deployName := strings.ToLower(strings.ReplaceAll(execName, "_", "-") + "-" + extensionName + "-" + extensionName + "-deployment")
				err = api.kubeClient.DeleteDeployment(deployName, app.Namespace)
				if err != nil {
					errorData.Message = "Internal error/ failed to delete deployment"
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}
			}
		}
		namespaces := api.kubeClient.ListNamespaces()
		for _, namespace := range namespaces {
			if strings.Contains(namespace, strings.ReplaceAll(username, "_", "-")) {
				err = api.kubeClient.DeleteNamespace(namespace)
				if err != nil {
					errorData.Message = "Internal error/ failed to delete namespace"
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}
			}
		}

		marshalledRequest, err = json.Marshal(request.Request.URL)
		if err != nil {
			api.apiLogger.Error(" Couldn't marshal request", zap.Any("request_url", request.Request.URL))
			errorData.Message = "Internal server error/Cannot marshal marshalledRequest in User Profile"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

		//delete entry from cache
		api.apiCache.Del(marshalledRequest)
		cachedRequests[username] = make([]string, 0)

		err = api.psqlRepo.DeleteUserData(strings.TrimSpace(username))
		if err != nil {
			if strings.Contains(err.Error(), "no row found") {
				api.apiLogger.Error(" User not found", zap.String("user_name", username))
				errorData.Message = "User not found"
				errorData.StatusCode = http.StatusNotFound
				response.WriteHeader(http.StatusNotFound)
				response.WriteEntity(errorData)
				return
			} else {
				errorData.Message = "Internal error / delete user data in postgres"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}

		}
	}

	deleteResponse := domain.QueryResponse{}
	deleteResponse.Message = "Users deleted succesfully"
	deleteResponse.ResourcesAffected = append(deleteResponse.ResourcesAffected, listUsersName...)
	response.WriteEntity(deleteResponse)
	totalRequestsMetric.Inc(1)
}

// GenerateOTPToken generates OTP token
func (api *API) GenerateOTPToken(request *restful.Request, response *restful.Response) {
	errorData := domain.ErrorResponse{}

	userUUID := request.HeaderParameter("USER-UUID")
	userData, err := api.psqlRepo.GetUserDataWithUUID(userUUID)
	if err != nil {
		api.apiLogger.Error(" User id not found", zap.String("user_id", userUUID))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "cloudadmin.com",
		AccountName: userData.Email,
	})
	if err != nil {
		api.apiLogger.Error("failed to generate otp key", zap.Error(err))
		errorData.Message = "Internal error/ failed to generate otp key"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}

	otpData := domain.OneTimePassData{
		OTPEnabled:  false,
		OTPVerified: false,
		OTPSecret:   key.Secret(),
		OTPAuthURL:  key.URL(),
	}
	err = api.psqlRepo.UpdateUserOTP(otpData, userData)
	if err != nil {
		api.apiLogger.Error("failed to update otp", zap.Error(err))
		errorData.Message = "Internal error/ failed to update otp"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}

	for _, cachedReq := range cachedRequests[userData.UserName] {
		api.apiCache.Del(cachedReq)
	}
	cachedRequests[userData.UserName] = make([]string, 0)

	otpResponse := domain.GenerateOTPResponse{
		Key: key.Secret(),
		URL: key.URL(),
	}
	response.WriteEntity(otpResponse)
	totalRequestsMetric.Inc(1)
}

// VerifyOTPToken checks otp token
func (api *API) VerifyOTPToken(request *restful.Request, response *restful.Response) {
	otpInputData := domain.OTPInput{}
	errorData := domain.ErrorResponse{}
	err := request.ReadEntity(&otpInputData)
	if err != nil {
		api.apiLogger.Error(" Couldn't read body with error : ", zap.Error(err))
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	userUUID := request.HeaderParameter("USER-UUID")
	userData, err := api.psqlRepo.GetUserDataWithUUID(userUUID)
	if err != nil {
		api.apiLogger.Error(" User id not found", zap.String("user_id", userUUID))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}
	valid := totp.Validate(otpInputData.Token, userData.OTPData.OTPSecret)
	if !valid {
		api.apiLogger.Error(" Token is invalid or user doesn't exist", zap.String("user_id", userUUID))
		errorData.Message = "Token is invalid or user doesn't exist"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	otpData := userData.OTPData
	otpData.OTPEnabled = true
	otpData.OTPVerified = true
	err = api.psqlRepo.UpdateUserOTP(otpData, userData)
	if err != nil {
		api.apiLogger.Error("failed to update otp", zap.Error(err))
		errorData.Message = "Internal error/ failed to update otp"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}

	for _, cachedReq := range cachedRequests[userData.UserName] {
		api.apiCache.Del(cachedReq)
	}
	cachedRequests[userData.UserName] = make([]string, 0)
	updateResponse := domain.QueryResponse{}
	updateResponse.Message = "User otp enabled succesfully"
	updateResponse.ResourcesAffected = append(updateResponse.ResourcesAffected, userData.UserName)
	response.WriteEntity(updateResponse)
	totalRequestsMetric.Inc(1)
}

// ValidateOTPToken validates otp token
func (api *API) ValidateOTPToken(request *restful.Request, response *restful.Response) {
	otpInputData := domain.OTPInput{}
	errorData := domain.ErrorResponse{}
	err := request.ReadEntity(&otpInputData)
	if err != nil {
		api.apiLogger.Error(" Couldn't read body with error : ", zap.Error(err))
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	userUUID := request.HeaderParameter("USER-UUID")
	userData, err := api.psqlRepo.GetUserDataWithUUID(userUUID)
	if err != nil {
		api.apiLogger.Error(" User id not found", zap.String("user_id", userUUID))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}

	valid := totp.Validate(otpInputData.Token, userData.OTPData.OTPSecret)
	if !valid {
		api.apiLogger.Error(" Token is invalid or user doesn't exist", zap.String("user_id", userUUID))
		errorData.Message = "Token is invalid or user doesn't exist"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	updateResponse := domain.QueryResponse{}
	updateResponse.Message = "User otp validated succesfully"
	updateResponse.ResourcesAffected = append(updateResponse.ResourcesAffected, userData.UserName)
	response.WriteEntity(updateResponse)
	totalRequestsMetric.Inc(1)
}

// DisableOTP disables otp
func (api *API) DisableOTP(request *restful.Request, response *restful.Response) {
	otpInputData := domain.OTPInput{}
	errorData := domain.ErrorResponse{}
	err := request.ReadEntity(&otpInputData)
	if err != nil {
		api.apiLogger.Error(" Couldn't read body with error : ", zap.Error(err))
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	userUUID := request.HeaderParameter("USER-UUID")
	userData, err := api.psqlRepo.GetUserDataWithUUID(userUUID)
	if err != nil {
		api.apiLogger.Error(" User id not found", zap.String("user_id", userUUID))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}

	otpData := userData.OTPData
	otpData.OTPEnabled = false
	otpData.OTPSecret = ""
	otpData.OTPAuthURL = ""
	otpData.OTPVerified = false
	err = api.psqlRepo.UpdateUserOTP(otpData, userData)
	if err != nil {
		api.apiLogger.Error("failed to update otp", zap.Error(err))
		errorData.Message = "Internal error/ failed to update otp"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	for _, cachedReq := range cachedRequests[userData.UserName] {
		api.apiCache.Del(cachedReq)
	}
	cachedRequests[userData.UserName] = make([]string, 0)
	updateResponse := domain.QueryResponse{}
	updateResponse.Message = "User otp disabled succesfully"
	updateResponse.ResourcesAffected = append(updateResponse.ResourcesAffected, userData.UserName)
	response.WriteEntity(updateResponse)
	totalRequestsMetric.Inc(1)
}

// UploadApp uploads app to s3
// We have 2 situations : each file has a text file and all apps have main function and we have a program that uses at least 2 source code files
// and we have to determine which file has main function
func (api *API) UploadApp(request *restful.Request, response *restful.Response) {
	allApps, _ := api.psqlRepo.GetAllApps()
	allAppsNames := helpers.GetAppsName(allApps)

	errorData := domain.ErrorResponse{}

	appsUploaded := make([]string, 0)

	username := request.QueryParameter("username")
	if username == "" {
		api.apiLogger.Error(" Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	userData, err := api.psqlRepo.GetUserData(username)
	if err != nil {
		api.apiLogger.Error(" User id not found", zap.String("user_name", username))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}
	if userData.UserLocked {
		errorData.Message = "Status forbidden/  You are not allowed to use app anymore.Please contact admin"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	flag := true
	userUUID := request.HeaderParameter("USER-UUID")
	checkUserData, err := api.psqlRepo.GetUserDataWithUUID(userUUID)
	if err != nil {
		api.apiLogger.Error(" User not found", zap.String("user_uuid", userUUID))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}
	if !helpers.CheckUser(checkUserData, request.HeaderParameter("USER-AUTH")) || checkUserData.UserName != userData.UserName {
		flag = false
	}
	if !flag {
		api.apiLogger.Error(" User not authorized", zap.String("user_name", username))
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + username + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return

	}
	multipartReader, _ := request.Request.MultipartReader()
	multipartReadForm, _ := multipartReader.ReadForm(int64(1000000))

	//init port and ip address
	port := 0
	ipAddr := ""

	formFilesName := multipartReadForm.File["file"]
	if len(formFilesName) == 0 {
		api.apiLogger.Error(" Couldn't form file")
		errorData.Message = "Bad Request/ Empty form"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	isComplex := request.QueryParameter("is_complex")
	if isComplex == "true" {
		appsData := make([]*domain.ApplicationData, 0)
		appsDescription := ""
		appTxt := ""
		mainAppData := domain.ApplicationData{}
		for _, fileName := range formFilesName {

			// Create a new file in the uploads directory
			f, err := os.OpenFile(fileName.Filename, os.O_WRONLY|os.O_CREATE, 0666)
			if err != nil {
				api.apiLogger.Error(" Couldn't open new file", zap.Error(err))
				errorData.Message = "Internal error/ could not open new file"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}

			openFormFile, err := fileName.Open()
			if err != nil {
				api.apiLogger.Error(" Couldn't open form file", zap.Error(err))
				errorData.Message = "Internal error/ could not open file"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}

			// Copy the contents of the file to the new file
			_, err = io.Copy(f, openFormFile)
			if err != nil {
				api.apiLogger.Error(" Couldn't copy file", zap.Error(err))
				errorData.Message = "Internal error/ could not copy file"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}

			r, err := zip.OpenReader(fileName.Filename)
			if err != nil {
				api.apiLogger.Error(" Couldn't open zipReader", zap.Error(err))
				errorData.Message = "Internal error/ could not open zipReader"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
			}

			// Iterate through the files in the archive,
			// printing some of their contents.
			for i, f := range r.File {
				appData := domain.ApplicationData{}

				api.apiLogger.Debug("Writting information for file", zap.String("file_name", f.Name))
				rc, err := f.Open()
				if err != nil {
					api.apiLogger.Error("failed to open file", zap.Error(err))
					errorData.Message = "Internal Error/ Failed to open file"
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}
				if api.vtClient != nil {
					// scan file using virus total
					vtObject, err := api.vtClient.NewFileScanner().Scan(rc, f.Name, nil)
					if err != nil {
						api.apiLogger.Error(" Couldn't scan file", zap.Error(err))
						errorData.Message = "Internal error/ Couldn't scan file"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
						return
					}
					analyseID := vtObject.ID()
					resp, err := api.vtClient.Get(vt.URL("analyses/%s", analyseID))
					if err != nil {
						api.apiLogger.Error(" Couldn't get analyse file", zap.Error(err))
						errorData.Message = "Internal error/ Couldn't get analyse file"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
						return
					}

					var respVT domain.VTResponse
					err = json.Unmarshal(resp.Data, &respVT)
					if err != nil {
						api.apiLogger.Error(" failed to unmarshal vt resp", zap.Error(err))
						errorData.Message = "Internal error/ failed to unmarshal vt resp"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
						return
					}
					for respVT.Attributes.Status == "queued" {
						time.Sleep(time.Second * 30)
						resp, err := api.vtClient.Get(vt.URL("analyses/%s", analyseID))
						if err != nil {
							api.apiLogger.Error(" Couldn't get analyse file", zap.Error(err))
							errorData.Message = "Internal error/ Couldn't get analyse file"
							errorData.StatusCode = http.StatusInternalServerError
							response.WriteHeader(http.StatusInternalServerError)
							response.WriteEntity(errorData)
							return
						}
						err = json.Unmarshal(resp.Data, &respVT)
						if err != nil {
							api.apiLogger.Error(" failed to unmarshal vt resp", zap.Error(err))
							errorData.Message = "Internal error/ failed to unmarshal vt resp"
							errorData.StatusCode = http.StatusInternalServerError
							response.WriteHeader(http.StatusInternalServerError)
							response.WriteEntity(errorData)
							return
						}
					}
					if respVT.Attributes.Stats.Malicious > 0 || respVT.Attributes.Stats.Suspicious > 0 {
						malwareFileMetric.Mark(1)
						go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
						api.apiLogger.Warn("malware detected")
						errorData.Message = "Bad request/ malware detected "
						errorData.StatusCode = http.StatusBadRequest
						response.WriteHeader(http.StatusBadRequest)
						response.WriteEntity(errorData)
						return
					}
					safeFileMetric.Mark(1)
					go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
				}

				descr, err1 := io.ReadAll(rc)
				if err1 != nil {
					api.apiLogger.Error(" Couldn't read io.Reader with error : ", zap.Error(err1))
					errorData.Message = "Internal Error/  Couldn't read io.Reader"
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}
				defer rc.Close()
				if strings.Contains(f.Name, ".txt") && f.Name != "requirements.txt" {
					if i%2 == 0 && i+1 < len(r.File) {
						appTxt = r.File[i+1].Name
					} else if i-1 >= 0 {
						appTxt = r.File[i-1].Name
					}
					appsDescription = string(descr)
					api.apiLogger.Debug("got text", zap.String("text", appTxt))
					api.apiLogger.Debug("got app description", zap.String("app_descr", appsDescription))

				} else {
					//+ write in s3
					nowTime := time.Now()
					appData.CreatedTimestamp = nowTime
					appData.UpdatedTimestamp = nowTime
					appData.IsRunning = false
					appData.FlagArguments = ""
					appData.ParamArguments = ""
					appData.IsMain = false
					appData.SubgroupFiles = []string{}
					appData.Description = appsDescription
					appData.Name = f.Name
					appData.Owner = username
					regexCompiler, err := regexp.Compile("main")
					if err != nil {
						api.apiLogger.Error(" Couldn't compile regex ", zap.Error(err))
						errorData.Message = "Internal Error/  Couldn't compile regex"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
					}
					if regexCompiler.MatchString(string(descr)) {
						mainAppData.CreatedTimestamp = appData.CreatedTimestamp
						mainAppData.UpdatedTimestamp = appData.UpdatedTimestamp
						mainAppData.IsRunning = false
						mainAppData.FlagArguments = ""
						mainAppData.ParamArguments = ""
						mainAppData.IsMain = true
						mainAppData.SubgroupFiles = []string{}
						mainAppData.Description = appsDescription
						mainAppData.Name = f.Name
						mainAppData.Owner = username
					} else {
						api.apiLogger.Info("got sub apps", zap.Any("sub_app", appData.Name))
						appsData = append(appsData, &appData)
					}
				}

			}
			subGroupMainFiles := make([]string, 0)

			for _, app := range appsData {

				if slices.Contains(allAppsNames, app.Name) {
					api.apiLogger.Error(" App  already exists", zap.String("app_name", app.Name))
					errorData.Message = "App already exists"
					errorData.StatusCode = http.StatusFound
					response.WriteHeader(http.StatusFound)
					response.WriteEntity(errorData)
					return
				}
				subGroupMainFiles = append(subGroupMainFiles, app.Name)
				appsUploaded = append(appsUploaded, app.Name)
				app.Description = appsDescription
				app.Port = &port
				app.IpAddress = &ipAddr
				err = api.psqlRepo.InsertAppData(app)
				if err != nil {
					errorData.Message = "Internal error/ insert app data in postgres"
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}

				err = api.psqlRepo.UpdateUserAppsData(app.Name, username)
				if err != nil {
					errorData.Message = "Internal error/ update user apps in postgres"
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}

			}

			if slices.Contains(userData.Applications, mainAppData.Name) {
				api.apiLogger.Error(" App  already exists", zap.String("app_name", mainAppData.Name))
				errorData.Message = "App already exists"
				errorData.StatusCode = http.StatusFound
				response.WriteHeader(http.StatusFound)
				response.WriteEntity(errorData)
				return
			}

			appsUploaded = append(appsUploaded, mainAppData.Name)
			mainAppData.Description = appsDescription
			mainAppData.SubgroupFiles = append(mainAppData.SubgroupFiles, subGroupMainFiles...)
			mainAppData.Port = &port
			mainAppData.IpAddress = &ipAddr
			err = api.psqlRepo.InsertAppData(&mainAppData)
			if err != nil {
				errorData.Message = "Internal error/ insert main app data in postgres"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}

			err = api.psqlRepo.UpdateUserAppsData(mainAppData.Name, username)
			if err != nil {
				errorData.Message = "Internal error/ update user apps in postgres"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}

			//Close handlers and delete temp files
			openFormFile.Close()
			f.Close()
			r.Close()
			os.Remove(fileName.Filename)
		}
	} else {

		for _, fileName := range formFilesName {
			// Create a new file in the uploads directory
			f, err := os.OpenFile(fileName.Filename, os.O_WRONLY|os.O_CREATE, 0666)
			if err != nil {
				api.apiLogger.Error(" Couldn't open new file", zap.Error(err))
				errorData.Message = "Internal error/ could not open new file"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}

			openFormFile, err := fileName.Open()
			if err != nil {
				api.apiLogger.Error(" Couldn't open form file", zap.Error(err))
				errorData.Message = "Internal error/ could not open file"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}

			// Copy the contents of the file to the new file
			_, err = io.Copy(f, openFormFile)
			if err != nil {
				api.apiLogger.Error(" Couldn't copy file", zap.Error(err))
				errorData.Message = "Internal error/ could not copy file"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}

			r, err := zip.OpenReader(fileName.Filename)
			if err != nil {
				api.apiLogger.Error(" Couldn't open zipReader", zap.Error(err))
				errorData.Message = "Internal error/ could not open zipReader"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
			}

			// Iterate through the files in the archive,
			// printing some of their contents.
			for i, f := range r.File {
				api.apiLogger.Debug("Writting information for file", zap.String("file_name", f.Name))
				rc, err := f.Open()
				if err != nil {
					api.apiLogger.Error("failed to open file", zap.Error(err))
					errorData.Message = "Internal Error/ Failed to open file"
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}
				if api.vtClient != nil {
					// scan file using virus total
					vtObject, err := api.vtClient.NewFileScanner().Scan(rc, f.Name, nil)
					if err != nil {
						api.apiLogger.Error(" Couldn't scan file", zap.Error(err))
						errorData.Message = "Internal error/ Couldn't scan file"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
						return
					}
					analyseID := vtObject.ID()
					resp, err := api.vtClient.Get(vt.URL("analyses/%s", analyseID))
					if err != nil {
						api.apiLogger.Error(" Couldn't get analyse file", zap.Error(err))
						errorData.Message = "Internal error/ Couldn't get analyse file"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
						return
					}

					var respVT domain.VTResponse
					err = json.Unmarshal(resp.Data, &respVT)
					if err != nil {
						api.apiLogger.Error(" failed to unmarshal vt resp", zap.Error(err))
						errorData.Message = "Internal error/ failed to unmarshal vt resp"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
						return
					}
					for respVT.Attributes.Status == "queued" {
						time.Sleep(time.Second * 30)
						resp, err := api.vtClient.Get(vt.URL("analyses/%s", analyseID))
						if err != nil {
							api.apiLogger.Error(" Couldn't get analyse file", zap.Error(err))
							errorData.Message = "Internal error/ Couldn't get analyse file"
							errorData.StatusCode = http.StatusInternalServerError
							response.WriteHeader(http.StatusInternalServerError)
							response.WriteEntity(errorData)
							return
						}
						err = json.Unmarshal(resp.Data, &respVT)
						if err != nil {
							api.apiLogger.Error(" failed to unmarshal vt resp", zap.Error(err))
							errorData.Message = "Internal error/ failed to unmarshal vt resp"
							errorData.StatusCode = http.StatusInternalServerError
							response.WriteHeader(http.StatusInternalServerError)
							response.WriteEntity(errorData)
							return
						}
					}
					if respVT.Attributes.Stats.Malicious > 0 || respVT.Attributes.Stats.Suspicious > 0 {
						malwareFileMetric.Mark(1)
						go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
						api.apiLogger.Warn("malware detected")
						errorData.Message = "Bad request/ malware detected "
						errorData.StatusCode = http.StatusBadRequest
						response.WriteHeader(http.StatusBadRequest)
						response.WriteEntity(errorData)
						return
					}
					safeFileMetric.Mark(1)
					go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
				}

				appData := domain.ApplicationData{}
				nowTime := time.Now()
				appData.CreatedTimestamp = nowTime
				appData.UpdatedTimestamp = nowTime

				if f.FileInfo().IsDir() {
					err = os.MkdirAll(f.Name, 0777)
					if err != nil {
						api.apiLogger.Error("failed to create dir", zap.Error(err))
						errorData.Message = "Internal Error/ Failed to create dir"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
					}

					mainAppData, subApps, appTxt, err := helpers.CreateFilesFromDir(f.Name, api.apiLogger)
					if err != nil {
						api.apiLogger.Error("failed to create files from dir", zap.Error(err))
						errorData.Message = "Internal Error/ Failed to create files from dir"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
					}

					subGroupMainFiles := make([]string, 0)

					for _, app := range subApps {

						if slices.Contains(allAppsNames, app.Name) {
							api.apiLogger.Error(" App  already exists", zap.String("app_name", app.Name))
							errorData.Message = "App already exists"
							errorData.StatusCode = http.StatusFound
							response.WriteHeader(http.StatusFound)
							response.WriteEntity(errorData)
							return
						}
						subGroupMainFiles = append(subGroupMainFiles, app.Name)
						appsUploaded = append(appsUploaded, app.Name)
						err = api.psqlRepo.InsertAppData(app)
						if err != nil {
							errorData.Message = "Internal error/ insert app data in postgres"
							errorData.StatusCode = http.StatusInternalServerError
							response.WriteHeader(http.StatusInternalServerError)
							response.WriteEntity(errorData)
							return
						}

						err = api.psqlRepo.UpdateUserAppsData(app.Name, username)
						if err != nil {
							errorData.Message = "Internal error/ update user apps in postgres"
							errorData.StatusCode = http.StatusInternalServerError
							response.WriteHeader(http.StatusInternalServerError)
							response.WriteEntity(errorData)
							return
						}

					}

					if slices.Contains(allAppsNames, mainAppData.Name) {
						api.apiLogger.Error(" App  already exists", zap.String("app_name", mainAppData.Name))
						errorData.Message = "App already exists"
						errorData.StatusCode = http.StatusFound
						response.WriteHeader(http.StatusFound)
						response.WriteEntity(errorData)
						return
					}

					indexFile := strings.Index(appTxt, ".")
					indexApp := strings.Index(mainAppData.Name, ".")
					if indexFile == -1 || indexApp == -1 {
						api.apiLogger.Error(" Wrong archive format", zap.String("mismatch_files", appData.Name+"/"+r.File[i].Name))
						errorData.Message = "Bad Request/ Wrong archive format"
						errorData.StatusCode = http.StatusBadRequest
						response.WriteHeader(http.StatusBadRequest)
						response.WriteEntity(errorData)
						return
					}
					trimmedFileName := appTxt[:indexFile]
					trimmedAppName := mainAppData.Name[:indexFile]
					if trimmedFileName != trimmedAppName {
						api.apiLogger.Error(" Wrong archive format", zap.String("mismatch_files", appData.Name+"/"+r.File[i].Name))
						errorData.Message = "Bad Request/ Wrong archive format"
						errorData.StatusCode = http.StatusBadRequest
						response.WriteHeader(http.StatusBadRequest)
						response.WriteEntity(errorData)
						return
					}
					appsUploaded = append(appsUploaded, mainAppData.Name)
					mainAppData.SubgroupFiles = append(mainAppData.SubgroupFiles, subGroupMainFiles...)
					err = api.psqlRepo.InsertAppData(&mainAppData)
					if err != nil {
						errorData.Message = "Internal error/ insert main app data in postgres"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
						return
					}

					err = api.psqlRepo.UpdateUserAppsData(mainAppData.Name, username)
					if err != nil {
						errorData.Message = "Internal error/ update user apps in postgres"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
						return
					}
					continue
				}

				descr, err1 := io.ReadAll(rc)
				if err1 != nil {
					api.apiLogger.Error(" Couldn't read io.Reader with error : ", zap.Error(err1))
					errorData.Message = "Internal Error/  Couldn't read io.Reader"
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}
				defer rc.Close()
				if strings.Contains(f.Name, ".txt") && f.Name != "requirements.txt" {
					if i%2 == 0 && i+1 < len(r.File) {
						appData.Name = r.File[i+1].Name
					} else if i-1 >= 0 {
						appData.Name = r.File[i-1].Name
					}
					appData.Description = string(descr)

					appData.IsRunning = false
					appData.FlagArguments = ""
					appData.ParamArguments = ""
					appData.IsMain = true
					appData.SubgroupFiles = []string{}
					appData.Owner = username
					appData.Port = &port
					appData.IpAddress = &ipAddr

					if slices.Contains(allAppsNames, appData.Name) {
						api.apiLogger.Error(" App  already exists", zap.String("app_name", appData.Name))
						errorData.Message = "App already exists"
						errorData.StatusCode = http.StatusFound
						response.WriteHeader(http.StatusFound)
						response.WriteEntity(errorData)
						return
					}

					indexFile := strings.Index(r.File[i].Name, ".")
					indexApp := strings.Index(appData.Name, ".")
					if indexFile == -1 || indexApp == -1 {
						api.apiLogger.Error(" Wrong archive format", zap.String("mismatch_files", appData.Name+"/"+r.File[i].Name))
						errorData.Message = "Bad Request/ Wrong archive format"
						errorData.StatusCode = http.StatusBadRequest
						response.WriteHeader(http.StatusBadRequest)
						response.WriteEntity(errorData)
						return
					}
					trimmedFileName := r.File[i].Name[:indexFile]
					trimmedAppName := appData.Name[:indexFile]
					if trimmedFileName != trimmedAppName {
						api.apiLogger.Error(" Wrong archive format", zap.String("mismatch_files", appData.Name+"/"+r.File[i].Name))
						errorData.Message = "Bad Request/ Wrong archive format"
						errorData.StatusCode = http.StatusBadRequest
						response.WriteHeader(http.StatusBadRequest)
						response.WriteEntity(errorData)
						return
					}

					appsUploaded = append(appsUploaded, appData.Name)

					err = api.psqlRepo.InsertAppData(&appData)
					if err != nil {
						errorData.Message = "Internal error/ insert app data in postgres"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
						return
					}

					err = api.psqlRepo.UpdateUserAppsData(appData.Name, username)
					if err != nil {
						errorData.Message = "Internal error/ update user apps in postgres"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
						return
					}
				} else {
					//upload in s3
					api.apiLogger.Info("upload s3")
					api.apiLogger.Info(string(descr))

				}

			}

			//Close handlers and delete temp files
			openFormFile.Close()
			f.Close()
			r.Close()
			os.Remove(fileName.Filename)
		}
	}

	//clear all the cache for that specific user
	for _, cachedReq := range cachedRequests[username] {
		api.apiCache.Del(cachedReq)
	}
	cachedRequests[username] = make([]string, 0)

	registerAppMetric.Mark(1)
	totalRequestsMetric.Inc(1)
	go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)

	registerResponse := domain.QueryResponse{}
	registerResponse.Message = "Apps uploaded succesfully"
	registerResponse.ResourcesAffected = append(registerResponse.ResourcesAffected, appsUploaded...)
	response.WriteEntity(registerResponse)
}

// GetAppsInfo retrieves apps information
func (api *API) GetAppsInfo(request *restful.Request, response *restful.Response) {
	startTime := time.Now()
	errorData := domain.ErrorResponse{}

	userIDHeader := request.HeaderParameter("USER-UUID")
	authHeader := request.HeaderParameter("USER-AUTH")

	//Calculate key and use cache to get the response
	marshalledRequest, err := json.Marshal(request.Request.URL)
	if err != nil {
		api.apiLogger.Error(" Couldn't marshal request", zap.Any("request_url", request.Request.URL))
		errorData.Message = "Internal server error/Cannot marshal"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}

	appsDataCache, appsFound := api.apiCache.Get(marshalledRequest)

	if !appsFound {
		var appNamesList []string
		var filter string

		username := request.QueryParameter("username")
		if username == "" {
			api.apiLogger.Error(" Couldn't read username query parameter")
			errorData.Message = "Bad Request/ empty username"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}
		api.apiLogger.Debug(" Apps not found in cache for user ", zap.String("user_name", username))

		userData, err := api.psqlRepo.GetUserDataWithUUID(userIDHeader)
		if err != nil || !helpers.CheckUser(userData, authHeader) {
			api.apiLogger.Error(" User id not authorized", zap.String("user_id", userIDHeader))
			response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
			errorData.Message = "User " + userIDHeader + " is Not Authorized"
			errorData.StatusCode = http.StatusForbidden
			response.WriteHeader(http.StatusForbidden)
			response.WriteEntity(errorData)
			return
		}
		if userData.UserLocked {
			errorData.Message = "Status forbidden/  You are not allowed to use app anymore.Please contact admin"
			errorData.StatusCode = http.StatusForbidden
			response.WriteHeader(http.StatusForbidden)
			response.WriteEntity(errorData)
			return
		}

		// Check filter to be valid
		filter = request.QueryParameter("filter")

		if filter != "" {
			filterFlag := 0
			for _, appFilter := range helpers.GetAppsFilters {
				if strings.Contains(filter, appFilter) {
					filterFlag = 1
				}
			}
			if filterFlag == 0 {
				api.apiLogger.Error(" Cannot filter", zap.String("filter", filter))
				errorData.Message = "Bad Request /Cannot filter"
				errorData.StatusCode = http.StatusBadRequest
				response.WriteHeader(http.StatusBadRequest)
				response.WriteEntity(errorData)
				return
			}
		}
		sortParams := make([]string, 0)

		sortQuery := request.QueryParameter("sort")
		if sortQuery != "" {
			sortParams = strings.Split(sortQuery, "|")
			if len(sortParams) != 2 {
				api.apiLogger.Error(" Invalid sort query", zap.Any("sort_query", sortParams))
				errorData.Message = "Bad Request /Invalid sort query"
				errorData.StatusCode = http.StatusBadRequest
				response.WriteHeader(http.StatusBadRequest)
				response.WriteEntity(errorData)
				return
			}
			if !slices.Contains(helpers.GetAppsSortFields, sortParams[0]) {
				api.apiLogger.Error(" Invalid sort field in query", zap.Any("sort_query", sortParams))
				errorData.Message = "Bad Request /Unknown sort field"
				errorData.StatusCode = http.StatusBadRequest
				response.WriteHeader(http.StatusBadRequest)
				response.WriteEntity(errorData)
				return
			}
			if !slices.Contains(helpers.SortDirections, sortParams[1]) {
				api.apiLogger.Error(" Invalid sort direction in query", zap.Any("sort_query", sortParams))
				errorData.Message = "Bad Request /Unknown sort direction"
				errorData.StatusCode = http.StatusBadRequest
				response.WriteHeader(http.StatusBadRequest)
				response.WriteEntity(errorData)
				return
			}
		}

		limit := request.QueryParameter("limit")
		offset := request.QueryParameter("offset")

		appnames := request.QueryParameter("appnames")
		if appnames == "" {
			appNamesList = userData.Applications
		} else {
			appNamesList = strings.Split(appnames, ",")
		}

		var appsInfo domain.GetApplicationsData
		appsInfo.Response = make([]*domain.ApplicationData, 0)
		appsInfo.Errors = make([]domain.ErrorResponse, 0)

		if len(sortParams) == 2 {
			api.apiLogger.Debug("sorting by ", zap.Any("sort_query", sortParams))
		}

		total, resultsCount, appsData, err := api.psqlRepo.GetAppsData(username, filter, limit, offset, sortParams)
		if err != nil {
			if strings.Contains(err.Error(), "fql") {
				api.apiLogger.Error(" Invalid fql filter for get apps", zap.Error(err))
				errorData.Message = "Bad Request / Invalid fql filter"
				errorData.StatusCode = http.StatusBadRequest
				appsInfo.Errors = append(appsInfo.Errors, errorData)
			} else {
				api.apiLogger.Error("Got error when retrieving apps", zap.Error(err))
				errorData.Message = "Internal error / retrieving apps"
				errorData.StatusCode = http.StatusInternalServerError
				appsInfo.Errors = append(appsInfo.Errors, errorData)
				response.WriteEntity(appsInfo)
				return

			}
		}
		if len(appsData) == 0 {
			api.apiLogger.Debug(" no apps found")
			errorData.Message = "No apps found"
			errorData.StatusCode = http.StatusNotFound
			appsInfo.Errors = append(appsInfo.Errors, errorData)
			response.WriteEntity(appsInfo)
			return
		}
		if len(appNamesList) > 0 {
			for _, appData := range appsData {
				if slices.Contains(appNamesList, appData.Name) && appData.IsMain {
					appsInfo.Response = append(appsInfo.Response, appData)
				}
			}
			resultsCount = len(appsInfo.Response)
		} else {
			for _, appData := range appsData {
				if appData.IsMain {
					appsInfo.Response = append(appsInfo.Response, appData)
				}
			}
		}

		if len(appsInfo.Response) > 1 {
			appsInfo = helpers.Unique(appsInfo)
		}
		appsName := helpers.GetAppsName(appsInfo.Response)
		if !helpers.CheckAppsExist(userData.Applications, appsName) && userData.UserName != "admin" {
			api.apiLogger.Error("User forbidden for apps", zap.Any("apps", appsName))
			errorData.Message = "Forbidden User"
			errorData.StatusCode = http.StatusForbidden
			appsInfo.Errors = append(appsInfo.Errors, errorData)
		}
		appsInfo.QueryInfo.Total = total
		appsInfo.QueryInfo.ResourcesCount = resultsCount
		response.WriteEntity(appsInfo)
		if len(appsInfo.Response) > 0 {
			api.apiCache.SetWithTTL(string(marshalledRequest), appsInfo, 1, time.Hour*24)
			cachedRequests[username] = append(cachedRequests[username], string(marshalledRequest))
		}
	} else {
		appsData := appsDataCache.(domain.GetApplicationsData)
		api.apiLogger.Debug(" Apps  found in cache")
		response.WriteEntity(appsData)
	}

	endTime := time.Since(startTime)
	getAppsLatencyMetric.Update(time.Duration(endTime.Microseconds()))
	getAppsMetric.Mark(1)
	totalRequestsMetric.Inc(1)
	go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)

}

// UpdateApp updates app info
func (api *API) UpdateApp(request *restful.Request, response *restful.Response) {

	appData := domain.ApplicationData{}
	errorData := domain.ErrorResponse{}

	err := request.ReadEntity(&appData)
	if err != nil {
		api.apiLogger.Error(" Couldn't read body with error : ", zap.Error(err))
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	username := request.QueryParameter("username")
	if username == "" {
		api.apiLogger.Error(" Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	userData, err := api.psqlRepo.GetUserData(username)
	if err != nil {
		api.apiLogger.Error(" User not found", zap.String("user_name", username))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}
	if userData.UserLocked {
		errorData.Message = "Status forbidden/  You are not allowed to use app anymore.Please contact admin"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	flag := true
	userUUID := request.HeaderParameter("USER-UUID")
	checkUserData, err := api.psqlRepo.GetUserDataWithUUID(userUUID)
	if err != nil {
		api.apiLogger.Error(" User not found", zap.String("user_uuid", userUUID))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}
	if !helpers.CheckUser(checkUserData, request.HeaderParameter("USER-AUTH")) || checkUserData.UserName != userData.UserName {
		flag = false
	}
	if !flag {
		api.apiLogger.Error(" User not authorized", zap.String("user_name", username))
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + username + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	if !helpers.CheckAppsExist(userData.Applications, []string{appData.Name}) {
		api.apiLogger.Error("Apps not found", zap.String("app_name", appData.Name))
		errorData.Message = "Apps not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}

	nrReplicas := request.QueryParameter("nr_replicas")
	maxReplicas := request.QueryParameter("max_nr_replicas")
	newImage := request.QueryParameter("new_image")
	if nrReplicas != "" || newImage != "" || maxReplicas != "" {
		var appInfo domain.ApplicationData

		_, _, appsData, err := api.psqlRepo.GetAppsData(username, "", "", "", []string{})
		if err != nil {
			api.apiLogger.Error("Got error when retrieving apps", zap.Error(err))
			errorData.Message = "Internal error / retrieving apps"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
		}
		for _, app := range appsData {
			if appData.Name == app.Name {
				appInfo = *app
				break
			}
		}
		if !appInfo.IsRunning && (nrReplicas != "" || newImage != "" || maxReplicas != "") {
			api.apiLogger.Error(" Bad Request / app is not running")
			errorData.Message = " Bad Request / app is not running"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
		} else {
			splitAppName := strings.Split(appInfo.Name, ".")
			imageName := strings.ReplaceAll(splitAppName[0]+"-"+splitAppName[1], "_", "-")
			nrReplicasInteger, _ := strconv.ParseInt(nrReplicas, 10, 32)
			maxReplicasInteger, _ := strconv.ParseInt(maxReplicas, 10, 32)
			if appInfo.ScheduleType == "random_scheduler" {
				api.kubeClient.UpdateAutoScaler(imageName, appInfo.Namespace, int32(nrReplicasInteger), int32(maxReplicasInteger))
			} else {
				api.kubeClient.UpdateDeployment(imageName, appInfo.Namespace, newImage, int32(nrReplicasInteger))
			}

		}
	}

	nowTime := time.Now()
	port := 0
	ipAddr := ""
	appData.UpdatedTimestamp = nowTime
	appData.Port = &port
	appData.IpAddress = &ipAddr
	err = api.psqlRepo.UpdateAppData(&appData)
	if err != nil {
		if strings.Contains(err.Error(), "no row found") {
			api.apiLogger.Error(" App  not found", zap.String("app_name", appData.Name))
			errorData.Message = "App not found"
			errorData.StatusCode = http.StatusNotFound
			response.WriteHeader(http.StatusNotFound)
			response.WriteEntity(errorData)
			return
		} else {
			errorData.Message = "Internal error / updating app data in postgres"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

	}

	//clear all the cache for that specific user
	for _, cachedReq := range cachedRequests[username] {
		api.apiCache.Del(cachedReq)
	}
	cachedRequests[username] = make([]string, 0)

	updateAppsMetric.Mark(1)
	totalRequestsMetric.Inc(1)
	go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)

	updateResponse := domain.QueryResponse{}
	updateResponse.Message = "App updated succesfully"
	updateResponse.ResourcesAffected = append(updateResponse.ResourcesAffected, appData.Name)
	response.WriteEntity(updateResponse)
}

// DeleteApp deletes app
func (api *API) DeleteApp(request *restful.Request, response *restful.Response) {

	errorData := domain.ErrorResponse{}

	appnames := request.QueryParameter("appnames")
	if appnames == "" {
		api.apiLogger.Error(" Couldn't read appname query parameter")
		errorData.Message = "Bad Request/ empty appname"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	username := request.QueryParameter("username")
	if username == "" {
		api.apiLogger.Error(" Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	userData, err := api.psqlRepo.GetUserData(username)
	if err != nil {
		api.apiLogger.Error(" User not found", zap.String("user_name", username))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}
	userUUID := request.HeaderParameter("USER-UUID")
	checkUserData, err := api.psqlRepo.GetUserDataWithUUID(userUUID)
	if err != nil {
		api.apiLogger.Error(" User not found", zap.String("user_uuid", userUUID))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}
	if checkUserData.UserName != "admin" && userData.UserName != checkUserData.UserName {
		errorData.Message = "Status forbidden"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}
	if userData.UserLocked {
		errorData.Message = "Status forbidden/  You are not allowed to use app anymore.Please contact admin"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	appNamesList := strings.Split(appnames, ",")

	if !helpers.CheckAppsExist(userData.Applications, appNamesList) {
		api.apiLogger.Error("Apps not found", zap.Any("apps", appNamesList))
		errorData.Message = "Apps not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return

	}

	appsData := make([]*domain.ApplicationData, 0)
	_, _, userAppsData, err := api.psqlRepo.GetAppsData(username, "", "", "", []string{})
	if err != nil {
		api.apiLogger.Error("Got error when retrieving apps", zap.Error(err))
		errorData.Message = "Internal error / retrieving apps"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	for _, app := range userAppsData {
		if slices.Contains(appNamesList, app.Name) {
			appsData = append(appsData, app)
		}
	}

	for _, appName := range appNamesList {
		err := api.psqlRepo.DeleteAppData(strings.TrimSpace(appName), username)
		if err != nil {
			if strings.Contains(err.Error(), "no row found") {
				api.apiLogger.Error(" App  not found", zap.String("app_name", appName))
				errorData.Message = "App not found"
				errorData.StatusCode = http.StatusNotFound
				response.WriteHeader(http.StatusNotFound)
				response.WriteEntity(errorData)
				return
			} else {
				errorData.Message = "Internal Error / Delete app"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
		}
		err = api.psqlRepo.DeleteUserAppsData(strings.TrimSpace(appName), username)
		if err != nil {
			errorData.Message = "Internal Error / Delete app from user"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}
		execName := strings.Split(appName, ".")[0]
		extensionName := strings.Split(appName, ".")[1]
		err = api.dockerClient.ListImagesAndDelete(execName + "_" + extensionName)
		if err != nil {
			errorData.Message = "Internal error/ failed to remove images"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

	}

	for _, app := range appsData {
		if app.IsRunning {
			execName := strings.Split(app.Name, ".")[0]
			extensionName := strings.Split(app.Name, ".")[1]
			deployName := strings.ToLower(strings.ReplaceAll(execName, "_", "-") + "-" + extensionName)
			err := api.kubeClient.DeleteDeployment(deployName, app.Namespace)
			if err != nil {
				errorData.Message = "Internal error/ failed to delete deployment"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
		}
	}

	//clear all the cache for that specific user
	for _, cachedReq := range cachedRequests[username] {
		api.apiCache.Del(cachedReq)
	}
	cachedRequests[username] = make([]string, 0)

	deleteResponse := domain.QueryResponse{}
	deleteResponse.Message = "Apps deleted succesfully"
	deleteResponse.ResourcesAffected = append(deleteResponse.ResourcesAffected, appNamesList...)
	response.WriteEntity(deleteResponse)
	totalRequestsMetric.Inc(1)
}

func (api *API) GetAppsAggregates(request *restful.Request, response *restful.Response) {

	errorData := domain.ErrorResponse{}
	appInfo := domain.AppsAggregatesInfo{}

	username := request.QueryParameter("username")

	mutex.Lock()
	if api.requestCount[username] > api.maxRequestPerMinute {
		mutex.Unlock()
		api.apiLogger.Debug("got request count", zap.Any("req_count", api.requestCount[username]))
		errorData.Message = "Too many requests per minute. Please try again later."
		errorData.StatusCode = http.StatusTooManyRequests
		response.WriteHeader(http.StatusTooManyRequests)
		response.WriteEntity(errorData)
		return
	}
	api.requestCount[username]++
	mutex.Unlock()

	mainAppsOwnerCount, err := api.psqlRepo.GetAppsCount(username, false)
	if err != nil {
		errorData.Message = "Internal Error / Could not get main apps for owner " + username
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	runningAppsOwnerCount, err := api.psqlRepo.GetAppsCount(username, true)
	if err != nil {
		errorData.Message = "Internal Error / Could not get running apps for owner " + username
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	totalMainAppsCount, err := api.psqlRepo.GetAppsCount("", false)
	if err != nil {
		errorData.Message = "Internal Error / Could not get all main apps"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}

	totalRunningAppsCount, err := api.psqlRepo.GetAppsCount("", true)
	if err != nil {
		errorData.Message = "Internal Error / Could not get all running apps"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}

	appInfo.QueryInfo.MainAppsByOwnerCount = int64(mainAppsOwnerCount)
	appInfo.QueryInfo.RunningAppsByOwnerCount = int64(runningAppsOwnerCount)
	appInfo.QueryInfo.MainAppsTotalCount = int64(totalMainAppsCount)
	appInfo.QueryInfo.RunningAppsTotalCount = int64(totalRunningAppsCount)
	response.WriteEntity(appInfo)
	totalRequestsMetric.Inc(1)

}

// ScheduleApps schedule apps
func (api *API) ScheduleApps(request *restful.Request, response *restful.Response) {
	startTime := time.Now()
	errorData := domain.ErrorResponse{}
	dirNames := make([]string, 0)
	appnames := request.QueryParameter("appnames")
	if appnames == "" {
		api.apiLogger.Error(" Couldn't read appname query parameter")
		errorData.Message = "Bad Request/ empty appname"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	username := request.QueryParameter("username")
	if username == "" {
		api.apiLogger.Error(" Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	userData, err := api.psqlRepo.GetUserData(username)
	if err != nil {
		api.apiLogger.Error(" User not found", zap.String("user_name", username))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}
	userUUID := request.HeaderParameter("USER-UUID")
	userAuth := request.HeaderParameter("USER-AUTH")
	checkUserData, err := api.psqlRepo.GetUserDataWithUUID(userUUID)
	if err != nil {
		api.apiLogger.Error(" User not found", zap.String("user_uuid", userUUID))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}
	if userData.UserName != checkUserData.UserName || !helpers.CheckUser(checkUserData, userAuth) {
		errorData.Message = "Status forbidden"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}
	if userData.UserLocked {
		errorData.Message = "Status forbidden/  You are not allowed to use app anymore.Please contact admin"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	appNamesList := strings.Split(appnames, ",")

	if !helpers.CheckAppsExist(userData.Applications, appNamesList) {
		api.apiLogger.Error("Apps not found", zap.Any("apps", appNamesList))
		errorData.Message = "Apps not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return

	}

	scheduleType := request.QueryParameter("schedule_type")
	if scheduleType == "" {
		api.apiLogger.Error(" Couldn't read scheduleType query parameter")
		errorData.Message = "Bad Request/ empty schedule type"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if !slices.Contains(helpers.ScheduleTypes, scheduleType) {
		api.apiLogger.Error("Invalid value for schedule type", zap.String("schedule_type", scheduleType))
		errorData.Message = "Invalid value for schedule type"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	var appsInfo domain.GetApplicationsData
	appsInfo.Response = make([]*domain.ApplicationData, 0)
	appsInfo.Errors = make([]domain.ErrorResponse, 0)

	_, _, appsData, err := api.psqlRepo.GetAppsData(username, "", "", "", []string{})
	if err != nil {
		api.apiLogger.Error("Got error when retrieving apps", zap.Error(err))
		errorData.Message = "Internal error / retrieving apps"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	if len(appNamesList) > 0 {
		for _, appData := range appsData {
			if slices.Contains(appNamesList, appData.Name) {
				appsInfo.Response = append(appsInfo.Response, appData)
			}
		}
	} else {
		appsInfo.Response = append(appsInfo.Response, appsData...)
	}

	nrReplicas, _ := strconv.ParseInt(request.QueryParameter("nr_replicas"), 0, 32)
	if nrReplicas == int64(0) {
		nrReplicas = int64(1)
	}

	serverPort, _ := strconv.ParseInt(request.QueryParameter("server_port"), 0, 32)

	taskItems := make([]priority_queue.TaskItem, 0)
	pairNames := make([][]string, 0)
	deleteDirNames := make([]string, 0)

	// push images to docker registry and retrieve task items
	for _, app := range appsInfo.Response {
		dirName := strings.Split(app.Name, ".")[0]
		newDirName, item, err := helpers.GenerateDockerFile(dirName, scheduleType, int32(serverPort), app, api.apiLogger)
		if err != nil {
			api.apiLogger.Error("Got error when generating docker file", zap.Error(err))
			errorData.Message = "Internal error / generating docker file"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}
		imageName := newDirName
		var tagName string

		//if app was not updated within the last 10 seconds or update_timestamp = created_timestamp,don't build image
		if math.Trunc(time.Since(app.UpdatedTimestamp).Seconds()) <= float64(10) || app.UpdatedTimestamp.UnixNano() == app.CreatedTimestamp.UnixNano() {
			err = api.dockerClient.BuildImage(imageName)
			if err != nil {
				errorData.Message = "Internal error / building image"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
			tagName, err = api.dockerClient.PushImage(imageName)
			if err != nil {
				errorData.Message = "Internal error / pushing image"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}

		} else {
			dockerRegID := os.Getenv("DOCKER_REGISTRY_ID")
			tagName = dockerRegID + "/" + strings.ToLower(imageName)
		}

		deleteDirNames = append(deleteDirNames, newDirName)
		taskItems = append(taskItems, item...)
		pairNames = append(pairNames, []string{tagName, imageName})
	}

	fileData, _ := json.MarshalIndent(taskItems, "", " ")

	// create namespace using username,schedule type to deploy the scheduler + file and data if needed
	var userNameSpace string

	userNameSpace, err = api.kubeClient.CreateNamespace("namespace-"+strings.ReplaceAll(username, "_", "-"), scheduleType)
	if err != nil {
		errorData.Message = "Internal error / creating namespace"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	if scheduleType == "rr_sjf_scheduler" {

		file, err := os.Create("tasks_duration.json")
		if err != nil {
			errorData.Message = "Internal error /  create task duration file"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

		err = os.WriteFile(file.Name(), fileData, 0644)
		if err != nil {
			errorData.Message = "Internal error /  write to task duration file"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

		tasksPQ, err := schedule_alghoritms.CreatePriorityQueueBasedOnTasksDuration(file.Name(), api.apiLogger)
		if err != nil {
			errorData.Message = "Internal error / failed priority queue"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}
		pairNames = schedule_alghoritms.RoundRobinShortestJobFirstAlgorithm(tasksPQ, pairNames, api.apiLogger)
	}

	// create deployments for each app and take into account schedulerType
	for i, pairImageTag := range pairNames {
		var publicIp string
		tagName := pairImageTag[0]
		imageName := strings.ToLower(strings.ReplaceAll(pairImageTag[1], "_", "-"))
		app := appsInfo.Response[i]
		if scheduleType == "random_scheduler" {
			publicIp, err = api.kubeClient.CreateDeployment(tagName, imageName, userNameSpace, "", strings.ReplaceAll(scheduleType, "_", "-")+"-go",
				[]string{}, int32(serverPort), int32(nrReplicas))
			if err != nil {
				errorData.Message = "Internal error / creating deployment"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
			_, err = api.kubeClient.CreateAutoScaler(imageName, userNameSpace, int32(1), int32(5))
			if err != nil {
				errorData.Message = "Internal error / creating auto scaler"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
		} else if scheduleType != "normal" {
			_, err = api.kubeClient.CreateDeployment(tagName, imageName, userNameSpace, "", strings.ReplaceAll(scheduleType, "_", "-")+"-go",
				[]string{}, int32(0), int32(nrReplicas))
			if err != nil {
				errorData.Message = "Internal error / creating deployment"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
		} else {
			_, err = api.kubeClient.CreateDeployment(tagName, imageName, userNameSpace, "", "",
				[]string{}, int32(0), int32(nrReplicas))
			if err != nil {
				errorData.Message = "Internal error / creating deployment"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
		}
		dirNames = append(dirNames, imageName)

		//if everything works well, applications are running and info is updated in postgres

		updatedAppData := domain.ApplicationData{}
		updatedAppData.Name = app.Name
		updatedAppData.Namespace = userNameSpace
		updatedAppData.ScheduleType = scheduleType
		updatedAppData.IsRunning = true
		updatedAppData.UpdatedTimestamp = time.Now()
		port := int(serverPort)
		ipAdress := fmt.Sprintf("http://%s", publicIp)
		updatedAppData.IpAddress = &ipAdress
		updatedAppData.Port = &port

		err = api.psqlRepo.UpdateAppData(&updatedAppData)
		if err != nil {
			errorData.Message = "Internal error / failed to update app"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

	}

	for _, dir := range dirNames {
		err := api.dockerClient.ListContainersAndDelete(dir)
		if err != nil {
			errorData.Message = "Internal error / failed to delete containers"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}
	}

	for _, dir := range deleteDirNames {
		os.RemoveAll(dir)
	}
	endTime := time.Since(startTime)
	scheduleAppsLatencyMetric.Update(time.Duration(endTime.Microseconds()))
	scheduleAppsMetric.Mark(1)
	totalRequestsMetric.Inc(1)
	go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)

	scheduleResponse := domain.QueryResponse{}
	scheduleResponse.Message = "Apps scheduled succesfully"
	scheduleResponse.ResourcesAffected = append(scheduleResponse.ResourcesAffected, appNamesList...)
	response.WriteEntity(scheduleResponse)

}

// GetPodResults returns logs from pod
func (api *API) GetPodResults(request *restful.Request, response *restful.Response) {
	errorData := domain.ErrorResponse{}

	username := request.QueryParameter("username")
	if username == "" {
		api.apiLogger.Error(" Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	podName := request.QueryParameter("pod_name")
	if podName == "" {
		api.apiLogger.Error(" Couldn't read pod name query parameter")
		errorData.Message = "Bad Request/ empty pod name"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	splitPodName := strings.Split(podName, "-deployment")[0]
	splitApp := strings.Split(splitPodName, "-"+splitPodName[len(splitPodName)-2:])
	appName := strings.ReplaceAll(splitApp[0]+"."+splitPodName[len(splitPodName)-2:], "-", "_")

	userData, err := api.psqlRepo.GetUserData(username)
	if err != nil {
		api.apiLogger.Error(" User not found", zap.String("user_name", username))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}
	userUUID := request.HeaderParameter("USER-UUID")
	checkUserData, err := api.psqlRepo.GetUserDataWithUUID(userUUID)
	if err != nil {
		api.apiLogger.Error(" User not found", zap.String("user_name", userData.UserName))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}
	if userData.UserName != checkUserData.UserName {
		errorData.Message = "Status forbidden"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}
	if userData.UserLocked {
		errorData.Message = "Status forbidden/  You are not allowed to use app anymore.Please contact admin"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	if !helpers.CheckAppsExist(userData.Applications, []string{appName}) {
		api.apiLogger.Error("Apps not found", zap.Any("apps", appName))
		errorData.Message = "Apps not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return

	}

	appData := domain.ApplicationData{}
	_, _, userAppsData, err := api.psqlRepo.GetAppsData(username, "", "", "", []string{})
	if err != nil {
		api.apiLogger.Error("Got error when retrieving apps", zap.Error(err))
		errorData.Message = "Internal error / retrieving apps"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	for _, app := range userAppsData {
		if app.Name == appName {
			appData = *app
			break
		}
	}

	podLogs, err := api.kubeClient.GetLogsForPodName(podName, appData.Namespace)
	if err != nil {
		errorData.Message = "Bad Request/ no pod found"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
	}

	getPodResultsMetric.Mark(1)
	totalRequestsMetric.Inc(1)
	go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)

	podLogsResponse := domain.GetLogsFromPod{}
	podLogsResponse.PrintMessage = podLogs
	podLogsResponse.AppName = podName
	response.WriteEntity(podLogsResponse)

}

// StartProfiler starts the cpu profiler
func (api *API) StartProfiler(request *restful.Request, response *restful.Response) {
	if api.profiler.Cpufile != nil {
		io.WriteString(response.ResponseWriter, "[restful] CPU profiling already running")
		return
	}
	api.profiler.StartProfiling()
	io.WriteString(response.ResponseWriter, "[restful] CPU profiling started, writing on:"+api.profiler.Cpuprofile)
}

// StopProfiler stops the cpu profiler
func (api *API) StopProfiler(request *restful.Request, response *restful.Response) {
	if api.profiler.Cpufile == nil {
		io.WriteString(response.ResponseWriter, "[restful] CPU profiling not active")
		return
	}
	api.profiler.StopProfiling()
	io.WriteString(response.ResponseWriter, "[restful] CPU profiling stopped, closing:"+api.profiler.Cpuprofile)
}
