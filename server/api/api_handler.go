package api

import (
	"archive/zip"
	"bytes"
	"cloudadmin/domain"
	"cloudadmin/helpers"

	schedule_alghoritms "cloudadmin/schedule_algorithms"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"reflect"
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
	// map of users with their specific cached requests as value
	cachedRequests = make(map[string][]string, 0)
	// metrics for graphite client
	getAppsMetric           = metrics.GetOrRegisterMeter("applications.get", nil)
	getAppsLatencyMetric    = metrics.GetOrRegisterTimer("get_apps_latency.response", nil)
	updateAppsMetric        = metrics.GetOrRegisterMeter("applications.update", nil)
	failedUpdateAppMetric   = metrics.GetOrRegisterMeter("applications.failed_update", nil)
	registerAppMetric       = metrics.GetOrRegisterMeter("applications.register", nil)
	failedRegisterAppMetric = metrics.GetOrRegisterMeter("applications.failed_register", nil)

	malwareFileMetric = metrics.GetOrRegisterMeter("applications.malware", nil)
	safeFileMetric    = metrics.GetOrRegisterMeter("applications.safe", nil)

	scheduleAppsMetric        = metrics.GetOrRegisterMeter("applications.schedule", nil)
	scheduleAppsLatencyMetric = metrics.GetOrRegisterTimer("schedule_apps_latency.response", nil)
	getPodResultsMetric       = metrics.GetOrRegisterMeter("applications.get_pod_results", nil)

	loginMetrics             = metrics.GetOrRegisterMeter("users_login", nil)
	failedLoginMetrics       = metrics.GetOrRegisterMeter("users_failed_login", nil)
	getUserMetric            = metrics.GetOrRegisterMeter("users.get.profile", nil)
	updateUserMetric         = metrics.GetOrRegisterMeter("users.update.profile", nil)
	failedUpdateUserMetric   = metrics.GetOrRegisterMeter("users.failed_update_profile", nil)
	registerUserMetric       = metrics.GetOrRegisterMeter("users.register", nil)
	failedRegisterUserMetric = metrics.GetOrRegisterMeter("users.failed_register", nil)
	userLatencyMeric         = metrics.GetOrRegisterTimer("users_get_profile_latency.response", nil)

	totalRequestsMetric = metrics.GetOrRegisterCounter("total_requests.count", nil)

	mutex sync.Mutex
)

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

// CompressedEncodingFilter compresses response
func (api *API) CompressedEncodingFilter(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	// wrap responseWriter into a compressing one
	compress, _ := restful.NewCompressingResponseWriter(resp.ResponseWriter, restful.ENCODING_GZIP)
	resp.ResponseWriter = compress
	defer func() {
		compress.Close()
	}()
	chain.ProcessFilter(req, resp)
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
		failedRegisterUserMetric.Mark(1)
		go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
		api.apiLogger.Error(" password too short")
		errorData.Message = "Bad Request/ Password too short(must have at least 16 characters)"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if !regexp.MustCompile(`\d`).MatchString(userData.Password) {
		failedRegisterUserMetric.Mark(1)
		go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
		api.apiLogger.Error(" password does not contain digits")
		errorData.Message = "Bad Request/ Password does not contain digits"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if !unicode.IsUpper(rune(userData.Password[0])) {
		failedRegisterUserMetric.Mark(1)
		go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
		api.apiLogger.Error(" password does not start with uppercase")
		errorData.Message = "Bad Request/ Password does not start with uppercase"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if !helpers.HasSymbol(userData.Password) {
		failedRegisterUserMetric.Mark(1)
		go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
		api.apiLogger.Error(" password does not have special characters")
		errorData.Message = "Bad Request/ Password does not have special characters"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if strings.Contains(strings.ToLower(userData.Password), strings.ToLower(userData.UserName)) {
		failedRegisterUserMetric.Mark(1)
		go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
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
	registerUserMetric.Mark(1)
	totalRequestsMetric.Inc(1)
	go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)

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
	if strings.Contains(strings.ToLower(userData.Password), strings.ToLower(userData.UserName)) {
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
						errorData.Message = "Internal error / error in updating user data in postgres"
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
							errorData.Message = "Internal error / error in updating user data in postgres"
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
			errorData.Message = "Internal error / error in updating user data in postgres"
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
			errorData.Message = "Internal error / error in updating user data in postgres"
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
			errorData.Message = "Internal error / error in updating role in postgres"
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
			errorData.Message = "Internal error / error in updating last_time in postgres"
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
	defer func() {
		userLatencyMeric.UpdateSince(startTime)
	}()
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
		userData.UserLimitTimeout > 0 || userData.UserTimeout != nil ||
		userData.NrDeployedApps != 0 || userData.WantNotify || userData.UserLocked ||
		!reflect.DeepEqual(userData.OTPData, domain.OneTimePassData{}) {
		failedUpdateUserMetric.Mark(1)
		go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
		api.apiLogger.Error(" Wrong fields to update")
		errorData.Message = "Bad Request/ wrong fields to update"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if userData.Password != "" {
		if len(userData.Password) < 16 {
			failedUpdateUserMetric.Mark(1)
			go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
			api.apiLogger.Error(" password too short")
			errorData.Message = "Bad Request/ Password too short(must have at least 16 characters)"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}
		if !regexp.MustCompile(`\d`).MatchString(userData.Password) {
			failedUpdateUserMetric.Mark(1)
			go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
			api.apiLogger.Error(" password does not contain digits")
			errorData.Message = "Bad Request/ Password does not contain digits"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}
		if !unicode.IsUpper(rune(userData.Password[0])) {
			failedUpdateUserMetric.Mark(1)
			go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
			api.apiLogger.Error(" password does not start with uppercase")
			errorData.Message = "Bad Request/ Password does not start with uppercase"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}
		if !helpers.HasSymbol(userData.Password) {
			failedUpdateUserMetric.Mark(1)
			go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
			api.apiLogger.Error(" password does not have special characters")
			errorData.Message = "Bad Request/ Password does not have special characters"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}
		if strings.Contains(userData.Password, userData.UserName) {
			failedUpdateUserMetric.Mark(1)
			go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
			api.apiLogger.Error(" password contains user")
			errorData.Message = "Bad Request/ Password contains user"
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
			errorData.Message = "Internal error / error in updating user data in postgres"
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
	if checkUserData.UserName != "admin" && (len(listUsersName) > 1 || listUsersName[0] != checkUserData.UserName) {
		errorData.Message = "Status forbidden"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}
	if checkUserData.UserLocked {
		errorData.Message = "Status forbidden/  You are not allowed to use app anymore.Please contact admin"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}
	for _, username := range listUsersName {
		if checkUserData.UserName != "admin" && checkUserData.UserName != username {
			continue
		}
		//Get user data and delete apps
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
			if api.s3Client != nil {
				key := strings.ReplaceAll(strings.Split(userApp, ".")[0], "_", "-")
				s3FilesName, err := api.s3Client.ListFileFolder(key)
				if err != nil {
					errorData.Message = "Internal error / error in retrieving files from s3"
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}
				err = api.s3Client.DeleteFiles(s3FilesName, key)
				if err != nil {
					errorData.Message = "Internal error / error in deleting files from s3"
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}
			}
			err = api.psqlRepo.DeleteAppData(userApp, username)
			if err != nil {
				api.apiLogger.Error(" App could not be deleted/not found ", zap.String("app_name", userApp))
				errorData.Message = "App not found"
				errorData.StatusCode = http.StatusNotFound
				response.WriteHeader(http.StatusNotFound)
				response.WriteEntity(errorData)
				return
			}
		}

		_, _, userAppsData, err := api.psqlRepo.GetAppsData(username, `is_running="true"`, "", "", userApps, []string{})
		if err != nil {
			api.apiLogger.Error("Got error when retrieving apps", zap.Error(err))
			errorData.Message = "Internal error / error in retrieving apps"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

		for _, app := range userAppsData {
			execName := strings.Split(app.Name, ".")[0]
			extensionName := strings.Split(app.Name, ".")[1]
			deployName := strings.ToLower(strings.ReplaceAll(execName, "_", "-") + "-" + extensionName)
			err = api.kubeClient.DeleteDeployment(deployName, app.Namespace)
			if err != nil {
				errorData.Message = "Internal error/ failed to delete deployment"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
			if app.IpAddress != nil && *app.IpAddress != "" {
				err := api.kubeClient.DeleteAutoScaler(deployName, app.Namespace)
				if err != nil {
					errorData.Message = "Internal error/ failed to delete autoscaler"
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}
				err = api.kubeClient.DeleteLoadBalancer(deployName, app.Namespace)
				if err != nil {
					errorData.Message = "Internal error/ failed to delete load balancer"
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}
				if len(app.SubgroupFiles) > 0 {
					for _, subGroupApp := range app.SubgroupFiles {
						err = api.psqlRepo.DeleteAppData(strings.TrimSpace(subGroupApp), username)
						if err != nil {
							if strings.Contains(err.Error(), "no row found") {
								api.apiLogger.Error(" Subgroup App  not found", zap.String("sub_group_app_name", subGroupApp))
								errorData.Message = "Subgropup App not found"
								errorData.StatusCode = http.StatusNotFound
								response.WriteHeader(http.StatusNotFound)
								response.WriteEntity(errorData)
								return
							} else {
								errorData.Message = "Internal Error / error Delete app"
								errorData.StatusCode = http.StatusInternalServerError
								response.WriteHeader(http.StatusInternalServerError)
								response.WriteEntity(errorData)
								return
							}
						}
					}
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
				errorData.Message = "Internal error / error in delete user data in postgres"
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

			if !strings.HasSuffix(fileName.Filename, ".zip") {
				failedRegisterAppMetric.Mark(1)
				go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
				errorData.Message = "Bad Request/Only zip supported"
				errorData.StatusCode = http.StatusBadRequest
				response.WriteHeader(http.StatusBadRequest)
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
				return
			}

			// Iterate through the files in the archive,
			// printing some of their contents.
			s3Key := strings.ReplaceAll(strings.Split(fileName.Filename, ".")[0], "_", "-")
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
				if api.s3Client != nil {
					err = api.s3Client.UploadFile(s3Key, f.Name, rc)
					if err != nil {
						errorData.Message = "Internal error/ upload s3"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
						return
					}
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
						failedRegisterAppMetric.Mark(1)
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
					regexCompiler, _ := regexp.Compile("main")
					if regexCompiler.MatchString(string(descr)) {
						mainAppData.CreatedTimestamp = appData.CreatedTimestamp
						mainAppData.UpdatedTimestamp = appData.UpdatedTimestamp
						mainAppData.IsRunning = false
						mainAppData.FlagArguments = ""
						mainAppData.ParamArguments = ""
						mainAppData.IsMain = true
						mainAppData.SubgroupFiles = []string{}
						mainAppData.AlertIDs = []string{}
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
					failedRegisterAppMetric.Mark(1)
					go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
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
				failedRegisterAppMetric.Mark(1)
				go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
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

			if !strings.HasSuffix(fileName.Filename, ".zip") {
				failedRegisterAppMetric.Mark(1)
				go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
				errorData.Message = "Bad Request/Only zip supported"
				errorData.StatusCode = http.StatusBadRequest
				response.WriteHeader(http.StatusBadRequest)
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
				return
			}

			// Iterate through the files in the archive,
			// printing some of their contents.
			s3Key := strings.ReplaceAll(strings.Split(fileName.Filename, ".")[0], "_", "-")
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
				if api.s3Client != nil {
					err = api.s3Client.UploadFile(s3Key, f.Name, rc)
					if err != nil {
						errorData.Message = "Internal error/ upload s3"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
						return
					}
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
						failedRegisterAppMetric.Mark(1)
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
						return
					}

					mainAppData, subApps, appTxt, err := helpers.CreateFilesFromDir(f.Name, api.apiLogger)
					if err != nil {
						api.apiLogger.Error("failed to create files from dir", zap.Error(err))
						errorData.Message = "Internal Error/ Failed to create files from dir"
						errorData.StatusCode = http.StatusInternalServerError
						response.WriteHeader(http.StatusInternalServerError)
						response.WriteEntity(errorData)
						return
					}

					subGroupMainFiles := make([]string, 0)

					for _, app := range subApps {

						if slices.Contains(allAppsNames, app.Name) {
							failedRegisterAppMetric.Mark(1)
							go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
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
						failedRegisterAppMetric.Mark(1)
						go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
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
						failedRegisterAppMetric.Mark(1)
						go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
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
						failedRegisterAppMetric.Mark(1)
						go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
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
						if r.File[i+1].Name == "requirements.txt" {
							appData.Name = r.File[i-1].Name
						} else {
							appData.Name = r.File[i+1].Name
						}

					} else if i-1 >= 0 {
						if r.File[i-1].Name == "requirements.txt" {
							appData.Name = r.File[i+1].Name
						} else {
							appData.Name = r.File[i-1].Name
						}

					}
					appData.Description = string(descr)

					appData.IsRunning = false
					appData.FlagArguments = ""
					appData.ParamArguments = ""
					appData.IsMain = true
					appData.AlertIDs = []string{}
					appData.SubgroupFiles = []string{}
					appData.Owner = username
					appData.Port = &port
					appData.IpAddress = &ipAddr

					if slices.Contains(allAppsNames, appData.Name) {
						failedRegisterAppMetric.Mark(1)
						go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
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
						failedRegisterAppMetric.Mark(1)
						go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
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
						failedRegisterAppMetric.Mark(1)
						go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
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
		if regexp.MustCompile(`\D`).MatchString(limit) {
			api.apiLogger.Error(" Invalid limit", zap.Any("limit", limit))
			errorData.Message = "Bad Request /Invalid limit"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}
		offset := request.QueryParameter("offset")
		if regexp.MustCompile(`\D`).MatchString(offset) {
			api.apiLogger.Error(" Invalid offset", zap.Any("offset", offset))
			errorData.Message = "Bad Request /Invalid offset"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}

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

		total, resultsCount, appsData, err := api.psqlRepo.GetAppsData(username, filter, limit, offset, appNamesList, sortParams)
		if err != nil {
			if strings.Contains(err.Error(), "fql") {
				api.apiLogger.Error(" Invalid fql filter for get apps", zap.Error(err))
				errorData.Message = "Bad Request / " + err.Error()
				errorData.StatusCode = http.StatusBadRequest
				appsInfo.Errors = append(appsInfo.Errors, errorData)
			} else {
				api.apiLogger.Error("Got error when retrieving apps", zap.Error(err))
				errorData.Message = "Internal error / error retrieving apps"
				errorData.StatusCode = http.StatusInternalServerError
				appsInfo.Errors = append(appsInfo.Errors, errorData)
			}
		}
		if len(appsData) == 0 {
			api.apiLogger.Debug(" no apps found")
			errorData.Message = "No apps found"
			errorData.StatusCode = http.StatusNotFound
			appsInfo.Errors = append(appsInfo.Errors, errorData)
		}
		appsInfo.Response = append(appsInfo.Response, appsData...)

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
		if len(appsInfo.Response) > 0 && len(appsInfo.Errors) == 0 {
			api.apiCache.SetWithTTL(string(marshalledRequest), appsInfo, 1, time.Hour*24)
			cachedRequests[username] = append(cachedRequests[username], string(marshalledRequest))
		}
	} else {
		appsData := appsDataCache.(domain.GetApplicationsData)
		api.apiLogger.Debug(" Apps  found in cache")
		response.WriteEntity(appsData)
	}

	defer func() {
		getAppsLatencyMetric.UpdateSince(startTime)
	}()

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
	if !flag && checkUserData.UserName != "admin" {
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
	memResources := request.QueryParameter("mem_usage")
	cpuResources := request.QueryParameter("cpu_usage")
	limitMemResources := request.QueryParameter("max_mem_usage")
	limitCpuResources := request.QueryParameter("max_cpu_usage")

	if nrReplicas != "" || newImage != "" || maxReplicas != "" || cpuResources != "" {
		var appInfo domain.ApplicationData

		_, _, appsData, err := api.psqlRepo.GetAppsData(username, "", "", "", []string{appData.Name}, []string{})
		if err != nil {
			api.apiLogger.Error("Got error when retrieving apps", zap.Error(err))
			errorData.Message = "Internal error / error in retrieving apps"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}
		appInfo = *appsData[0]
		if !appInfo.IsRunning && (nrReplicas != "" || newImage != "" || maxReplicas != "") {
			failedUpdateAppMetric.Mark(1)
			go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
			api.apiLogger.Error(" Bad Request / app is not running")
			errorData.Message = " Bad Request / app is not running"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		} else {

			splitAppName := strings.Split(appInfo.Name, ".")
			imageName := strings.ReplaceAll(splitAppName[0]+"-"+splitAppName[1], "_", "-")
			nrReplicasInteger, _ := strconv.ParseInt(nrReplicas, 10, 32)
			maxReplicasInteger, _ := strconv.ParseInt(maxReplicas, 10, 32)
			newImage = strings.ToLower(strings.ReplaceAll(request.QueryParameter("new_image"), "_", "-"))
			if appInfo.ScheduleType == "random_scheduler" {
				err = api.kubeClient.UpdateAutoScaler(imageName, appInfo.Namespace, int32(nrReplicasInteger), int32(maxReplicasInteger))
				if err != nil {
					failedUpdateAppMetric.Mark(1)
					go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
					api.apiLogger.Error("error in updating autoscaler", zap.Error(err))
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}
				err = api.kubeClient.UpdateDeployment(imageName, appInfo.Namespace, newImage, memResources, limitMemResources,
					cpuResources, limitCpuResources, int32(0))
				if err != nil {
					failedUpdateAppMetric.Mark(1)
					go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
					api.apiLogger.Error("error in updating deployment", zap.Error(err))
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}
			} else {
				err = api.kubeClient.UpdateDeployment(imageName, appInfo.Namespace, newImage, memResources, limitMemResources,
					cpuResources, limitCpuResources, int32(nrReplicasInteger))
				if err != nil {
					failedUpdateAppMetric.Mark(1)
					go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
					api.apiLogger.Error("error in updating deployment", zap.Error(err))
					errorData.Message = err.Error()
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}
			}

		}
	}
	if len(appData.SubgroupFiles) > 0 || appData.ScheduleType != "" || appData.Namespace != "" || appData.Owner != "" || appData.IsMain ||
		appData.IsRunning || appData.IpAddress != nil && appData.Port != nil && len(appData.AlertIDs) != 0 {
		failedUpdateAppMetric.Mark(1)
		go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
		api.apiLogger.Error(" Wrong fields to update")
		errorData.Message = "Bad Request/ wrong fields to update"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
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
			errorData.Message = "Internal error / error in updating app data in postgres"
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
	_, _, userAppsData, err := api.psqlRepo.GetAppsData(username, `is_running="true"`, "", "", appNamesList, []string{})
	if err != nil {
		api.apiLogger.Error("Got error when retrieving apps", zap.Error(err))
		errorData.Message = "Internal error / error in retrieving apps"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	appsData = append(appsData, userAppsData...)

	for _, appName := range appNamesList {
		if api.s3Client != nil {
			key := strings.ReplaceAll(strings.Split(appName, ".")[0], "_", "-")
			s3FilesName, err := api.s3Client.ListFileFolder(key)
			if err != nil {
				errorData.Message = "Internal error / error in retrieving files from s3"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
			err = api.s3Client.DeleteFiles(s3FilesName, key)
			if err != nil {
				errorData.Message = "Internal error / error in deleting files from s3"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
		}

		err = api.psqlRepo.DeleteAppData(strings.TrimSpace(appName), username)
		if err != nil {
			if strings.Contains(err.Error(), "no row found") {
				api.apiLogger.Error(" App  not found", zap.String("app_name", appName))
				errorData.Message = "App not found"
				errorData.StatusCode = http.StatusNotFound
				response.WriteHeader(http.StatusNotFound)
				response.WriteEntity(errorData)
				return
			} else {
				errorData.Message = "Internal Error / error Delete app"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
		}
	}

	for _, app := range appsData {
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
		if app.IpAddress != nil && *app.IpAddress != "" {
			err := api.kubeClient.DeleteAutoScaler(deployName, app.Namespace)
			if err != nil {
				errorData.Message = "Internal error/ failed to delete autoscaler"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
			err = api.kubeClient.DeleteLoadBalancer(deployName, app.Namespace)
			if err != nil {
				errorData.Message = "Internal error/ failed to delete load balancer"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
			if len(app.SubgroupFiles) > 0 {
				for _, subGroupApp := range app.SubgroupFiles {
					err = api.psqlRepo.DeleteAppData(strings.TrimSpace(subGroupApp), username)
					if err != nil {
						if strings.Contains(err.Error(), "no row found") {
							api.apiLogger.Error(" Subgroup App  not found", zap.String("sub_groupapp_name", subGroupApp))
							errorData.Message = "Subgropup App not found"
							errorData.StatusCode = http.StatusNotFound
							response.WriteHeader(http.StatusNotFound)
							response.WriteEntity(errorData)
							return
						} else {
							errorData.Message = "Internal Error / error Delete app"
							errorData.StatusCode = http.StatusInternalServerError
							response.WriteHeader(http.StatusInternalServerError)
							response.WriteEntity(errorData)
							return
						}
					}
				}
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

	_, _, appsData, err := api.psqlRepo.GetAppsData(username, "", "", "", appNamesList, []string{})
	if err != nil {
		api.apiLogger.Error("Got error when retrieving apps", zap.Error(err))
		errorData.Message = "Internal error / error in retrieving apps"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	appsInfo.Response = append(appsInfo.Response, appsData...)

	nrReplicas, _ := strconv.ParseInt(request.QueryParameter("nr_replicas"), 0, 32)
	if nrReplicas == int64(0) {
		nrReplicas = int64(1)
	}

	serverPort, _ := strconv.ParseInt(request.QueryParameter("server_port"), 0, 32)

	taskItems := make([]domain.TaskItem, 0)
	pairNames := make([][]string, 0)
	deleteDirNames := make([]string, 0)

	errChan := make(chan error)

	var wg sync.WaitGroup
	var deleteDirNamesMutex sync.Mutex
	var taskItemsMutex sync.Mutex
	var pairNamesMutex sync.Mutex
	wg.Add(len(appsInfo.Response))
	// push images to docker registry and retrieve task items
	for _, app := range appsInfo.Response {
		go func(app *domain.ApplicationData) {
			defer wg.Done()
			dirName := strings.ReplaceAll(strings.Split(app.Name, ".")[0], "_", "-")
			filesFromAppFolder := make([]string, 0)

			// Handle s3 operations concurrently
			if api.s3Client != nil {
				dirNameFiles, err := api.s3Client.ListFileFolder(dirName)
				if err != nil {
					errChan <- err
					return
				}
				err = api.s3Client.DownloadFiles(dirName, dirNameFiles)
				if err != nil {
					errChan <- err
					return
				}
				for _, fileName := range dirNameFiles {
					name := strings.Split(fileName, dirName+"/")
					filesFromAppFolder = append(filesFromAppFolder, name[1])
				}
			}

			newDirName, item, err := helpers.GenerateDockerFile(dirName, scheduleType, filesFromAppFolder, int32(serverPort), app, api.apiLogger)
			if err != nil {
				if !strings.Contains(err.Error(), "file already exists") {
					errChan <- err
					return
				}
			}

			imageName := newDirName
			var tagName string

			// Build and push images concurrently
			if math.Trunc(time.Since(app.UpdatedTimestamp).Seconds()) <= float64(60) || app.UpdatedTimestamp.UnixNano() == app.CreatedTimestamp.UnixNano() {
				err = api.dockerClient.BuildImage(imageName)
				if err != nil {
					errChan <- err
					return
				}
				tagName, err = api.dockerClient.PushImage(imageName)
				if err != nil {
					errChan <- err
					return
				}
			} else {
				dockerRegID := os.Getenv("DOCKER_REGISTRY_ID")
				tagName = dockerRegID + "/" + strings.ToLower(imageName)
			}

			deleteDirNamesMutex.Lock()
			deleteDirNames = append(deleteDirNames, newDirName)
			deleteDirNamesMutex.Unlock()

			taskItemsMutex.Lock()
			taskItems = append(taskItems, item...)
			taskItemsMutex.Unlock()

			pairNamesMutex.Lock()
			pairNames = append(pairNames, []string{tagName, imageName})
			pairNamesMutex.Unlock()
		}(app)
	}
	go func() {
		wg.Wait()
		close(errChan)
	}()
	for err := range errChan {
		api.apiLogger.Error("Got error when generating docker image", zap.Error(err))
		errorData.Message = "Internal error / error in generating docker image"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	fileData, _ := json.MarshalIndent(taskItems, "", " ")

	// create namespace using username,schedule type to deploy the scheduler + file and data if needed
	var userNameSpace string

	userNameSpace, err = api.kubeClient.CreateNamespace("namespace-"+strings.ReplaceAll(strings.ReplaceAll(username, "_", "-"), ".", "-"), scheduleType)
	if err != nil {
		errorData.Message = "Internal error / error in creating namespace"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	if scheduleType == "rr_sjf_scheduler" {

		file, err := os.Create("tasks_duration.json")
		if err != nil {
			errorData.Message = "Internal error /  error in create task duration file"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

		err = os.WriteFile(file.Name(), fileData, 0644)
		if err != nil {
			errorData.Message = "Internal error /  error in write to task duration file"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

		tasksPQ, err := schedule_alghoritms.CreatePriorityQueueBasedOnTasksDuration(file.Name(), api.apiLogger)
		if err != nil {
			errorData.Message = "Internal error / failed to create priority queue"
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
			if serverPort <= int64(0) || serverPort > int64(65535) {
				errorData.Message = "Bad request / invalid port"
				errorData.StatusCode = http.StatusBadRequest
				response.WriteHeader(http.StatusBadRequest)
				response.WriteEntity(errorData)
				return
			}
			publicIp, err = api.kubeClient.CreateDeployment(tagName, imageName, userNameSpace, "", strings.ReplaceAll(scheduleType, "_", "-")+"-go",
				int32(serverPort), int32(nrReplicas))
			if err != nil {
				errorData.Message = "Internal error / error in creating deployment"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
			_, err = api.kubeClient.CreateAutoScaler(imageName, userNameSpace, int32(1), int32(5))
			if err != nil {
				errorData.Message = "Internal error / error in creating auto scaler"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
		} else if scheduleType != "normal" {
			_, err = api.kubeClient.CreateDeployment(tagName, imageName, userNameSpace, "", strings.ReplaceAll(scheduleType, "_", "-")+"-go",
				int32(0), int32(nrReplicas))
			if err != nil {
				errorData.Message = "Internal error / error in creating deployment"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
		} else {
			_, err = api.kubeClient.CreateDeployment(tagName, imageName, userNameSpace, "", "",
				int32(0), int32(nrReplicas))
			if err != nil {
				errorData.Message = "Internal error / error in creating deployment"
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
		var ipAddress string
		if publicIp != "" {
			ipAddress = fmt.Sprintf("http://%s", publicIp)
		}

		updatedAppData.IpAddress = &ipAddress
		updatedAppData.Port = &port

		err = api.psqlRepo.UpdateAppData(&updatedAppData)
		if err != nil {
			errorData.Message = "Internal error / failed to update app"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

		userData.NrDeployedApps = userData.NrDeployedApps + 1
		err = api.psqlRepo.UpdateUserData(userData)
		if err != nil {
			errorData.Message = "Internal error / failed to update user"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

	}

	for _, dir := range dirNames {
		err := api.dockerClient.ListImagesAndDelete(dir)
		if err != nil {
			errorData.Message = "Internal error / failed to delete containers"
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

	for _, dir := range deleteDirNames {
		os.RemoveAll(dir)
	}
	defer func() {
		scheduleAppsLatencyMetric.UpdateSince(startTime)
	}()

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

	appName := request.QueryParameter("app_name")
	if appName == "" {
		api.apiLogger.Error(" Couldn't read app name query parameter")
		errorData.Message = "Bad Request/ empty app name"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	podName := strings.ReplaceAll(appName, "_", "-")
	podName = strings.ReplaceAll(podName, ".", "-") + "-deployment"

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
	_, _, userAppsData, err := api.psqlRepo.GetAppsData(username, "", "", "", []string{appName}, []string{})
	if err != nil {
		api.apiLogger.Error("Got error when retrieving apps", zap.Error(err))
		errorData.Message = "Internal error / error in retrieving apps"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	appData = *userAppsData[0]

	podLogs, err := api.kubeClient.GetLogsForPodName(podName, appData.Namespace)
	if err != nil {
		errorData.Message = "Bad Request/ no pod found"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	getPodResultsMetric.Mark(1)
	totalRequestsMetric.Inc(1)
	go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)

	podLogsResponse := domain.GetLogsFromPod{}
	podLogsResponse.PrintMessage = podLogs
	podLogsResponse.AppName = podName
	response.WriteEntity(podLogsResponse)
}

func (api *API) GetPodFile(request *restful.Request, response *restful.Response) {

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

	appName := request.QueryParameter("app_name")
	if appName == "" {
		api.apiLogger.Error(" Couldn't read app name query parameter")
		errorData.Message = "Bad Request/ empty app name"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	podName := strings.ReplaceAll(appName, "_", "-")
	podName = strings.ReplaceAll(podName, ".", "-") + "-deployment"

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
	_, _, userAppsData, err := api.psqlRepo.GetAppsData(username, "", "", "", []string{appName}, []string{})
	if err != nil {
		api.apiLogger.Error("Got error when retrieving apps", zap.Error(err))
		errorData.Message = "Internal error / error in retrieving apps"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	appData = *userAppsData[0]

	fileName := request.QueryParameter("file_name")
	podFileContent, err := api.kubeClient.GetPodFile(fileName, appName, podName, appData.Namespace)
	if err != nil {
		errorData.Message = "Bad Request/ no pod found"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	totalRequestsMetric.Inc(1)
	go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", api.graphiteAddr)
	response.AddHeader("Content-Disposition", "attachment; filename="+fileName)
	response.AddHeader("Content-Type", "application/octet-stream")
	io.Copy(response, bytes.NewReader(podFileContent))
}

// SubmitForm submits form
func (api *API) SubmitForm(request *restful.Request, response *restful.Response) {
	formData := make(map[int]string, 0)
	errorData := domain.ErrorResponse{}
	err := request.ReadEntity(&formData)
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

	formActualFields := make(map[string]string, 0)
	for formKey, formValue := range formData {
		formActualFields[helpers.FormFieldsReplacement[formKey]] = formValue
	}

	postgresFormData := domain.FormData{
		BadFeatures:          formActualFields["bad_features"],
		GoodFeatures:         formActualFields["good_features"],
		ProjectLikeRate:      formActualFields["project_like_rate"],
		FriendsRecommendRate: formActualFields["friends_recommend_rate"],
		ProjectHasIssues:     formActualFields["project_has_issues"],
		ProjectIssues:        formActualFields["project_issues"],
		ProjectSuggestions:   formActualFields["project_suggestions"],
	}
	formID, err := api.psqlRepo.InsertFormData(&postgresFormData)
	if err != nil {
		errorData.Message = "Internal error/ insert form data in postgres"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	createFormResponse := domain.QueryResponse{}
	createFormResponse.Message = fmt.Sprintf("Form created succesfully with ID : %d", formID)
	response.WriteEntity(createFormResponse)

}

func (api *API) GetFormStats(request *restful.Request, response *restful.Response) {
	errorData := domain.ErrorResponse{}
	completeFormStats := make([]*domain.FormStatistics, 0)
	completeTimestampsList := make([]string, 0)
	timestampsList, timestampsFound := api.apiCache.Get("form_timestamps")
	if timestampsFound {
		completeTimestampsList = append(completeTimestampsList, timestampsList.([]string)...)
	}
	for _, timestamp := range completeTimestampsList {
		oldFormStats, _ := api.apiCache.Get(timestamp)
		completeFormStats = append(completeFormStats, oldFormStats.(*domain.FormStatistics))
	}
	formStatsData, err := api.psqlRepo.GetFormStatistics()
	if err != nil {
		errorData.Message = "Internal error/ get form stats"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	formStatsData.Timestamp = time.Now().Format(time.RFC3339)
	api.apiCache.SetWithTTL(formStatsData.Timestamp, formStatsData, 1, time.Hour*24)
	completeTimestampsList = append(completeTimestampsList, formStatsData.Timestamp)
	api.apiCache.SetWithTTL("form_timestamps", completeTimestampsList, 1, time.Hour*24)
	completeFormStats = append(completeFormStats, formStatsData)
	response.WriteEntity(completeFormStats)
}

// GetGrafanaDashboardData retrieves grafana data based on grafana query
func (api *API) GetGrafanaDashboardData(request *restful.Request, response *restful.Response) {
	errorData := domain.ErrorResponse{}

	appName := strings.ReplaceAll(strings.ReplaceAll(request.QueryParameter("app_name"), ".", "-"), "_", "-") + "-deployment"
	grafanaFormat := request.QueryParameter("grafana_format")
	grafanaFrom := request.QueryParameter("grafana_from")
	grafanaUsageType := request.QueryParameter("grafana_usage_type")
	dataSourceData, err := api.grafanaHTTPClient.GetDataSourceData(appName, grafanaFrom, grafanaFormat, grafanaUsageType)
	if err != nil {
		errorData.Message = "Bad Request/ " + err.Error()
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	response.WriteEntity(dataSourceData)
}

func (api *API) CreateAppAlert(request *restful.Request, response *restful.Response) {
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

	appName := request.QueryParameter("app_name")
	if appName == "" {
		api.apiLogger.Error(" Couldn't read app name query parameter")
		errorData.Message = "Bad Request/ empty app name"
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
		api.apiLogger.Error("App not found", zap.Any("app", appName))
		errorData.Message = "App not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return

	}
	_, _, appInfo, _ := api.psqlRepo.GetAppsData(username, "", "", "", []string{appName}, []string{})
	if len(appInfo[0].AlertIDs) != 0 {
		errorData.Message = "Bad Request / App has alerts"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	deployAppName := strings.ReplaceAll(strings.ReplaceAll(appName, ".", "-"), "_", "-") + "-deployment"

	// create mem alert for app
	alertBody := domain.GrafanaAlertInfo{
		OrgID:     1,
		FolderUID: "efe8a245-bb05-4919-b8cc-9a2c9620a6e0",
		RuleGroup: "cloud-admin-team",
		Title:     "Mem Alert for app " + appName,
		Condition: "C",
		Updated:   time.Now().Format(time.RFC3339),
		For:       "5m",
		Annotations: domain.Annotations{
			Description: "Mem Alert for app " + appName,
			Summary:     "Mem Alert for app " + appName,
		},
		IsPaused:     false,
		ExecErrState: "Error",
		NoDataState:  "NoData",
		Data: []domain.Data{
			{
				RefID: "A",
				RelativeTimeRange: domain.RelativeTimeRange{
					From: 10800,
					To:   0,
				},
				DatasourceUUID: "P6575522ED8660310",
				Model: domain.Model{
					Hide:          false,
					IntervalMs:    1000,
					MaxDataPoints: 43200,
					RefID:         "A",
					Target:        fmt.Sprintf(`cloudadminapi.*.*.%s.mem_usage.value`, deployAppName),
				},
			},
			{
				RefID: "B",
				RelativeTimeRange: domain.RelativeTimeRange{
					From: 10800,
					To:   0,
				},
				DatasourceUUID: "__expr__",
				Model: domain.Model{
					Conditions: []domain.Condition{
						{
							Evaluator: domain.Evaluator{
								Params: []int{},
								Type:   "gt",
							},
							Operator: domain.Operator{
								Type: "and",
							},
							Query: domain.Query{
								Params: []string{"B"},
							},
							Reducer: domain.Reducer{
								Params: []string{},
								Type:   "last",
							},
							Type: "query",
						},
					},
					Datasource: domain.Datasource{
						Type: "__expr__",
						UID:  "__expr__",
					},
					Expression:    "A",
					Reducer:       "last",
					Hide:          false,
					IntervalMs:    1000,
					MaxDataPoints: 43200,
					RefID:         "B",
					Type:          "reduce",
				},
			},
			{
				RefID:          "C",
				DatasourceUUID: "__expr__",
				Model: domain.Model{
					RefID: "C",
					Hide:  false,
					Type:  "threshold",
					Datasource: domain.Datasource{
						Type: "__expr__",
						UID:  "__expr__",
					},
					Conditions: []domain.Condition{
						{
							Type: "query",
							Evaluator: domain.Evaluator{
								Params: []int{128},
								Type:   "gt",
							},
							Operator: domain.Operator{
								Type: "and",
							},
							Query: domain.Query{
								Params: []string{"C"},
							},
							Reducer: domain.Reducer{
								Params: []string{},
								Type:   "last",
							},
						},
					},
					Expression:    "B",
					IntervalMs:    1000,
					MaxDataPoints: 43200,
				},
				RelativeTimeRange: domain.RelativeTimeRange{
					From: 10800,
					To:   0,
				},
			},
		},
	}

	respAlert, err := api.grafanaHTTPClient.CreateAlertRule(alertBody)
	if err != nil {
		errorData.Message = "Bad Request/ " + err.Error()
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	alertRules := make([]string, 0)
	alertRules = append(alertRules, respAlert.UID)
	err = api.psqlRepo.UpdateAppAlertID(appName, respAlert.UID)
	if err != nil {
		if strings.Contains(err.Error(), "no row found") {
			api.apiLogger.Error(" App  not found", zap.String("app_name", appName))
			errorData.Message = "App not found"
			errorData.StatusCode = http.StatusNotFound
			response.WriteHeader(http.StatusNotFound)
			response.WriteEntity(errorData)
			return
		} else {
			errorData.Message = "Internal error / error in updating app data in postgres"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}
	}

	// create cpu alert for app
	alertBody.Title = "CPU Alert for app " + appName
	alertBody.Annotations.Description = "CPU Alert for app " + appName
	alertBody.Annotations.Summary = "CPU Alert for app " + appName
	alertBody.Updated = time.Now().Format(time.RFC3339)
	alertBody.Data[0].Model.Target = fmt.Sprintf(`cloudadminapi.*.*.%s.cpu_usage.value`, deployAppName)
	alertBody.Data[2].Model.Conditions[0].Evaluator.Params[0] = 500

	respAlert, err = api.grafanaHTTPClient.CreateAlertRule(alertBody)
	if err != nil {
		errorData.Message = "Bad Request/ " + err.Error()
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	alertRules = append(alertRules, respAlert.UID)
	err = api.psqlRepo.UpdateAppAlertID(appName, respAlert.UID)
	if err != nil {
		if strings.Contains(err.Error(), "no row found") {
			api.apiLogger.Error(" App  not found", zap.String("app_name", appName))
			errorData.Message = "App not found"
			errorData.StatusCode = http.StatusNotFound
			response.WriteHeader(http.StatusNotFound)
			response.WriteEntity(errorData)
			return
		} else {
			errorData.Message = "Internal error / error in updating app data in postgres"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}
	}

	for _, cachedReq := range cachedRequests[username] {
		api.apiCache.Del(cachedReq)
	}
	cachedRequests[username] = make([]string, 0)

	createAlertResponse := domain.QueryResponse{}
	createAlertResponse.Message = "Alerts created succesfully"
	createAlertResponse.ResourcesAffected = append(createAlertResponse.ResourcesAffected, alertRules...)
	response.WriteEntity(createAlertResponse)

}

func (api *API) UpdateAppAlert(request *restful.Request, response *restful.Response) {
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

	cpuNewThreshold := request.QueryParameter("alert_new_cpu_value")
	if cpuNewThreshold == "" {
		api.apiLogger.Error(" Couldn't read alert_new_cpu_value query parameter")
		errorData.Message = "Bad Request/ empty alert_new_cpu_value"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	memNewThreshold := request.QueryParameter("alert_new_mem_value")
	if memNewThreshold == "" {
		api.apiLogger.Error(" Couldn't read alert_new_mem_value query parameter")
		errorData.Message = "Bad Request/ empty alert_new_mem_value"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	alertRuleIDs := request.QueryParameter("alert_ids")
	if alertRuleIDs == "" {
		api.apiLogger.Error(" Couldn't read alert_ids query parameter")
		errorData.Message = "Bad Request/ empty alert id"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	appName := request.QueryParameter("app_name")
	if appName == "" {
		api.apiLogger.Error(" Couldn't read app name query parameter")
		errorData.Message = "Bad Request/ empty app name"
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
		api.apiLogger.Error("App not found", zap.Any("app", appName))
		errorData.Message = "App not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return

	}

	_, _, appInfo, _ := api.psqlRepo.GetAppsData(username, "", "", "", []string{appName}, []string{})
	if len(appInfo[0].AlertIDs) == 0 {
		errorData.Message = "Bad Request / App does not have an alert created"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	deployAppName := strings.ReplaceAll(strings.ReplaceAll(appName, ".", "-"), "_", "-") + "-deployment"
	alertUIDs := strings.Split(alertRuleIDs, ",")
	newMemTreshholdValue, _ := strconv.ParseInt(memNewThreshold, 10, 64)
	newCPUTreshholdValue, _ := strconv.ParseInt(cpuNewThreshold, 10, 64)
	if newCPUTreshholdValue == int64(0) || newMemTreshholdValue == int64(0) {
		errorData.Message = "Bad Request / Found zero values " + memNewThreshold + "," + cpuNewThreshold
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}
	// update mem alert
	alertBody := domain.GrafanaAlertInfo{
		OrgID:     1,
		FolderUID: "efe8a245-bb05-4919-b8cc-9a2c9620a6e0",
		RuleGroup: "cloud-admin-team",
		Title:     "Mem Alert for app " + appName,
		Condition: "C",
		Updated:   time.Now().Format(time.RFC3339),
		For:       "5m",
		Annotations: domain.Annotations{
			Description: "Mem Alert for app " + appName,
			Summary:     "Mem Alert for app " + appName,
		},
		IsPaused:     false,
		ExecErrState: "Error",
		NoDataState:  "NoData",
		Data: []domain.Data{
			{
				RefID: "A",
				RelativeTimeRange: domain.RelativeTimeRange{
					From: 10800,
					To:   0,
				},
				DatasourceUUID: "P6575522ED8660310",
				Model: domain.Model{
					Hide:          false,
					IntervalMs:    1000,
					MaxDataPoints: 43200,
					RefID:         "A",
					Target:        fmt.Sprintf(`cloudadminapi.*.*.%s.mem_usage.value`, deployAppName),
				},
			},
			{
				RefID: "B",
				RelativeTimeRange: domain.RelativeTimeRange{
					From: 10800,
					To:   0,
				},
				DatasourceUUID: "__expr__",
				Model: domain.Model{
					Conditions: []domain.Condition{
						{
							Evaluator: domain.Evaluator{
								Params: []int{},
								Type:   "gt",
							},
							Operator: domain.Operator{
								Type: "and",
							},
							Query: domain.Query{
								Params: []string{"B"},
							},
							Reducer: domain.Reducer{
								Params: []string{},
								Type:   "last",
							},
							Type: "query",
						},
					},
					Datasource: domain.Datasource{
						Type: "__expr__",
						UID:  "__expr__",
					},
					Expression:    "A",
					Reducer:       "last",
					Hide:          false,
					IntervalMs:    1000,
					MaxDataPoints: 43200,
					RefID:         "B",
					Type:          "reduce",
				},
			},
			{
				RefID:          "C",
				DatasourceUUID: "__expr__",
				Model: domain.Model{
					RefID: "C",
					Hide:  false,
					Type:  "threshold",
					Datasource: domain.Datasource{
						Type: "__expr__",
						UID:  "__expr__",
					},
					Conditions: []domain.Condition{
						{
							Type: "query",
							Evaluator: domain.Evaluator{
								Params: []int{int(newMemTreshholdValue)},
								Type:   "gt",
							},
							Operator: domain.Operator{
								Type: "and",
							},
							Query: domain.Query{
								Params: []string{"C"},
							},
							Reducer: domain.Reducer{
								Params: []string{},
								Type:   "last",
							},
						},
					},
					Expression:    "B",
					IntervalMs:    1000,
					MaxDataPoints: 43200,
				},
				RelativeTimeRange: domain.RelativeTimeRange{
					From: 10800,
					To:   0,
				},
			},
		},
	}
	err = api.grafanaHTTPClient.UpdateAlertRule(alertUIDs[0], alertBody)
	if err != nil {
		errorData.Message = "Bad Request/ " + err.Error()
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	// update cpu alert
	alertBody.Title = "CPU Alert for app " + appName
	alertBody.Annotations.Description = "CPU Alert for app " + appName
	alertBody.Annotations.Summary = "CPU Alert for app " + appName
	alertBody.Updated = time.Now().Format(time.RFC3339)
	alertBody.Data[0].Model.Target = fmt.Sprintf(`cloudadminapi.*.*.%s.cpu_usage.value`, deployAppName)
	alertBody.Data[2].Model.Conditions[0].Evaluator.Params[0] = int(newCPUTreshholdValue)
	alertBody.UID = alertUIDs[1]
	err = api.grafanaHTTPClient.UpdateAlertRule(alertUIDs[1], alertBody)
	if err != nil {
		errorData.Message = "Bad Request/ " + err.Error()
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	updateAlertResponse := domain.QueryResponse{}
	updateAlertResponse.Message = "Alerts updated succesfully"
	updateAlertResponse.ResourcesAffected = append(updateAlertResponse.ResourcesAffected, alertUIDs...)
	response.WriteEntity(updateAlertResponse)
}

func (api *API) DeleteAppAlert(request *restful.Request, response *restful.Response) {
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

	alertRuleIDs := request.QueryParameter("alert_ids")
	if alertRuleIDs == "" {
		api.apiLogger.Error(" Couldn't read alert_ids query parameter")
		errorData.Message = "Bad Request/ empty alert id"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	appName := request.QueryParameter("app_name")
	if appName == "" {
		api.apiLogger.Error(" Couldn't read app name query parameter")
		errorData.Message = "Bad Request/ empty app name"
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
		api.apiLogger.Error("App not found", zap.Any("app", appName))
		errorData.Message = "App not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}

	_, _, appInfo, _ := api.psqlRepo.GetAppsData(username, "", "", "", []string{appName}, []string{})
	if len(appInfo[0].AlertIDs) == 0 {
		errorData.Message = "Bad Request / App does not have an alert created"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	alertRuleIDsList := strings.Split(alertRuleIDs, ",")
	for _, alertRuleID := range alertRuleIDsList {
		err = api.grafanaHTTPClient.DeleteAlertRule(alertRuleID)
		if err != nil {
			errorData.Message = "Bad Request/ " + err.Error()
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}

		err = api.psqlRepo.RemoveAppAlertID(alertRuleID, appName)
		if err != nil {
			errorData.Message = "Bad Request/ " + err.Error()
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}
	}

	deleteAlertResponse := domain.QueryResponse{}
	deleteAlertResponse.Message = "Alerts deleted succesfully"
	deleteAlertResponse.ResourcesAffected = append(deleteAlertResponse.ResourcesAffected, alertRuleIDsList...)
	response.WriteEntity(deleteAlertResponse)
}

func (api *API) GetAlertTriggerNotification(request *restful.Request, response *restful.Response) {
	errorData := domain.ErrorResponse{}
	alertsStatus := make([]*domain.AlertNotification, 0)

	username := request.QueryParameter("username")
	if username == "" {
		api.apiLogger.Error(" Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	appName := request.QueryParameter("app_name")
	if appName == "" {
		api.apiLogger.Error(" Couldn't read app name query parameter")
		errorData.Message = "Bad Request/ empty app name"
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
		api.apiLogger.Error("App not found", zap.Any("app", appName))
		return
	}

	_, _, appInfo, _ := api.psqlRepo.GetAppsData(username, "", "", "", []string{appName}, []string{})
	if len(appInfo[0].AlertIDs) == 0 {
		api.apiLogger.Debug("no alerts found for app", zap.String("app_name", appName))
		return
	}

	alertRuleInfo, err := api.grafanaHTTPClient.GetAlertRuleByID(appInfo[0].AlertIDs[0])
	if err != nil {
		errorData.Message = "Bad Request/ " + err.Error()
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	alertTriggerInformation, err := api.grafanaHTTPClient.GetAlertNotification(alertRuleInfo.ID)
	if err != nil {
		errorData.Message = "Bad Request/ " + err.Error()
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	alertsStatus = append(alertsStatus, alertTriggerInformation[0])

	alertRuleInfo, err = api.grafanaHTTPClient.GetAlertRuleByID(appInfo[0].AlertIDs[1])
	if err != nil {
		errorData.Message = "Bad Request/ " + err.Error()
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	alertTriggerInformation, err = api.grafanaHTTPClient.GetAlertNotification(alertRuleInfo.ID)
	if err != nil {
		errorData.Message = "Bad Request/ " + err.Error()
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	alertsStatus = append(alertsStatus, alertTriggerInformation[0])

	response.WriteEntity(alertsStatus)
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
