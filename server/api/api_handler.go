package api

import (
	"archive/zip"
	"cloudadmin/domain"
	"cloudadmin/helpers"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/emicklei/go-restful/v3"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
)

var (
	//map of users with their specific cached requests as value
	cachedRequests = make(map[string][]string, 0)
)

// AdminAuthenticate verifies role and user_id for admin
func (api *API) AdminAuthenticate(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	errorData := domain.ErrorResponse{}
	authHeader := request.HeaderParameter("USER-AUTH")
	userIDHeader := request.HeaderParameter("USER-UUID")

	userData, err := api.psqlRepo.GetUserDataWithUUID(userIDHeader)
	if err != nil || !helpers.CheckUser(userData, authHeader) || userData.UserName != "admin" {
		api.apiLogger.Error(" User id " + userIDHeader + " not authorized")
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
		api.apiLogger.Error(" User id " + userIDHeader + " not authorized")
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
	userData.NrDeployedApps = &helpers.DefaultNrDeployedApps

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
}

// UserLogin verifies user credentials
func (api *API) UserLogin(request *restful.Request, response *restful.Response) {
	userData := domain.UserData{}
	newUserData := &domain.UserData{}

	oldPass := request.QueryParameter("old_password")

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
	if userData.UserName == "admin" || strings.Contains(userData.UserName, "admin") {
		api.apiLogger.Error(" You are not allowed to login as admin")
		errorData.Message = "Status forbidden/  You are not allowed to login as admin"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	if userData.Password == "" {
		api.apiLogger.Error(" Couldn't read password query parameter")
		errorData.Message = "Bad Request/ empty password"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

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

	dbUserData, err := api.psqlRepo.GetUserData(userData.UserName)
	if err != nil {
		api.apiLogger.Error(" User not found", zap.String("user_name", userData.UserName))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}

	if !helpers.CheckPasswordHash(userData.Password, dbUserData.Password) {
		api.apiLogger.Error(" Wrong password given. Please try again.")
		errorData.Message = "Wrong Password"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
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

		reqUrl, _ := request.Request.URL.Parse(userPath + "/" + userData.UserName)

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
		api.apiCache.SetWithTTL(marshalledRequest, newUserData, 1, time.Hour*24)
	}

	newUserData.Password = ""
	newUserData.Applications = []string{}
	newUserData.BirthDate = ""
	newUserData.Email = ""
	newUserData.JobRole = ""
	newUserData.JobRole = ""
	newUserData.JoinedDate = nil
	newUserData.LastTimeOnline = nil
	newUserData.NrDeployedApps = nil
	response.WriteEntity(newUserData)
}

// GetUserProfile returns user profile based on username
func (api *API) GetUserProfile(request *restful.Request, response *restful.Response) {

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
			api.apiLogger.Error(" User not found", zap.String("user_name", userData.UserName))
			errorData.Message = "User not found"
			errorData.StatusCode = http.StatusNotFound
			response.WriteHeader(http.StatusNotFound)
			response.WriteEntity(errorData)
			return
		}
		api.apiLogger.Debug(" Not found in cache", zap.String("user_name", username))
		userData.Password = ""
		userData.Role = ""
		userData.UserID = ""
		response.WriteEntity(userData)
		// If not in cache, set it
		api.apiCache.SetWithTTL(marshalledRequest, userData, 1, time.Hour*24)
		cachedRequests[username] = append(cachedRequests[username], string(marshalledRequest))

	} else {

		userData := userDataCache.(*domain.UserData)

		api.apiLogger.Error(" Found in cache", zap.String("user_name", userData.UserName))

		userData.Password = ""
		userData.Role = ""
		userData.UserID = ""
		response.WriteEntity(userData)
	}

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

	if userData.Role != "" || userData.UserID != "" || len(userData.Applications) > 0 {
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
		errorData.Message = "Internal error / updating user data in postgres"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
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
	api.apiCache.SetWithTTL(marshalledRequest, newUserData, 1, time.Hour*24)

	registerResponse := domain.QueryResponse{}
	registerResponse.Message = "User updated succesfully"
	registerResponse.ResourcesAffected = append(registerResponse.ResourcesAffected, userData.UserName)
	response.WriteEntity(registerResponse)
}

// DeleteUser deletes user
func (api *API) DeleteUser(request *restful.Request, response *restful.Response) {
	errorData := domain.ErrorResponse{}
	usersName := request.QueryParameter("usernames")
	if usersName == "" {
		api.apiLogger.Error(" Couldn't read usernames query parameter")
		errorData.Message = "Bad Request/ empty username"
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
		userApps := make([]string, 0)
		userData := &domain.UserData{}
		userDataCache, userFound := api.apiCache.Get(marshalledRequest)
		if !userFound {
			userData, _ = api.psqlRepo.GetUserData(username)

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
			api.apiLogger.Error(" User not found", zap.String("user_name", username))
			errorData.Message = "User not found"
			errorData.StatusCode = http.StatusNotFound
			response.WriteHeader(http.StatusNotFound)
			response.WriteEntity(errorData)
			return
		}
	}

	registerResponse := domain.QueryResponse{}
	registerResponse.Message = "Users deleted succesfully"
	registerResponse.ResourcesAffected = append(registerResponse.ResourcesAffected, listUsersName...)
	response.WriteEntity(registerResponse)
}

// UploadApp uploads app to s3
func (api *API) UploadApp(request *restful.Request, response *restful.Response) {

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
		api.apiLogger.Error(" User id" + username + " not found")
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}

	flag := true

	userData.UserName = username

	if !helpers.CheckUser(userData, userData.Role) {
		flag = false
	}
	if !flag {
		api.apiLogger.Error(" User" + username + " not authorized")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + username + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return

	}
	formFilesName := request.Request.MultipartForm.File["file"]
	if len(formFilesName) == 0 {
		api.apiLogger.Error(" Couldn't form file")
		errorData.Message = "Internal error/ could not form file"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	for _, fileName := range formFilesName {
		// Create a new file in the uploads directory
		f, err := os.OpenFile(fileName.Filename, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			api.apiLogger.Error(" Couldn't open new file")
			errorData.Message = "Internal error/ could not open new file"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

		openFormFile, err := fileName.Open()
		if err != nil {
			api.apiLogger.Error(" Couldn't open form file")
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

			nowTime := time.Now()
			appData.CreatedTimestamp = nowTime
			appData.UpdatedTimestamp = nowTime

			api.apiLogger.Debug("Writting information for file :\n", zap.String("file_name", f.Name))
			rc, err := f.Open()
			if err != nil {
				api.apiLogger.Error("failed to open file", zap.Error(err))
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
			if strings.Contains(f.Name, ".txt") {
				if i%2 == 0 {
					appData.Name = r.File[i+1].Name
				} else {
					appData.Name = r.File[i-1].Name
				}
				appData.Description = string(descr)

				appData.IsRunning = "false"
				appsRetrievedData, err := api.psqlRepo.GetAppsData(appData.Name, "")

				if err != nil {
					errorData.Message = "Internal error / get app in postgres"
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}
				if len(appsRetrievedData) != 0 {
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
					api.apiLogger.Error(" Wrong archive format", zap.String("mismatch_files", appData.Name+r.File[i].Name))
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

	//clear all the cache for that specific user
	for _, cachedReq := range cachedRequests[username] {
		api.apiCache.Del(cachedReq)
	}
	cachedRequests[username] = make([]string, 0)

	registerResponse := domain.QueryResponse{}
	registerResponse.Message = "Apps uploaded succesfully"
	registerResponse.ResourcesAffected = append(registerResponse.ResourcesAffected, appsUploaded...)
	response.WriteEntity(registerResponse)
}

// GetAppsInfo retrieves apps information
func (api *API) GetAppsInfo(request *restful.Request, response *restful.Response) {

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

		appnames := request.QueryParameter("appnames")

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
			api.apiLogger.Error(" User id " + userIDHeader + " not authorized")
			response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
			errorData.Message = "User " + userIDHeader + " is Not Authorized"
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

		if appnames == "" {
			appNamesList = userData.Applications
		} else {
			appNamesList = strings.Split(appnames, ",")
		}

		var appsInfo domain.GetApplicationsData
		appsInfo.Response = make([]*domain.ApplicationData, 0)
		appsInfo.Errors = make([]domain.ErrorResponse, 0)
		for _, appName := range appNamesList {
			appsData, err := api.psqlRepo.GetAppsData(strings.TrimSpace(appName), filter)
			if err != nil {
				if strings.Contains(err.Error(), "fql") {
					api.apiLogger.Error(" Invalid fql filter for app", zap.String("app_name", appName))
					errorData.Message = "Bad Request / Invalid fql filter"
					errorData.StatusCode = http.StatusBadRequest
					appsInfo.Errors = append(appsInfo.Errors, errorData)
				} else {
					api.apiLogger.Error(" App  not found", zap.String("app_name", appName))
					errorData.Message = "App " + appName + " not found"
					errorData.StatusCode = http.StatusNotFound
					appsInfo.Errors = append(appsInfo.Errors, errorData)
				}

				continue
			}
			if len(appsData) == 0 {
				api.apiLogger.Debug(" no apps found")

				errorData.Message = "App " + appName + " not found"
				errorData.StatusCode = http.StatusNotFound
				appsInfo.Errors = append(appsInfo.Errors, errorData)
				continue
			}
			appsInfo.Response = append(appsInfo.Response, appsData...)

		}
		if len(appsInfo.Response) > 1 {
			appsInfo = helpers.Unique(appsInfo)
		}

		if !helpers.CheckAppsExist(userData.Applications, appsInfo.Response) {
			api.apiLogger.Error(" User " + username + " not authorized")
			response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
			errorData.Message = "User " + username + " is Not Authorized"
			errorData.StatusCode = http.StatusForbidden
			response.WriteHeader(http.StatusForbidden)
			response.WriteEntity(errorData)
			return
		}

		if len(sortParams) == 2 {
			api.apiLogger.Info("sorting by ", zap.Any("sort_query", sortParams))
			appsInfo.Response = helpers.SortApps(appsInfo.Response, sortParams[0], sortParams[1])
		}

		response.WriteEntity(appsInfo)
		if len(appsInfo.Response) > 0 {
			api.apiCache.SetWithTTL(marshalledRequest, appsInfo, 1, time.Hour*24)
			cachedRequests[username] = append(cachedRequests[username], string(marshalledRequest))
		}

		return
	} else {
		appsData := appsDataCache.(domain.GetApplicationsData)
		api.apiLogger.Debug(" Apps  found in cache")
		response.WriteEntity(appsData)
	}

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

	userUUID := request.HeaderParameter("USER-UUID")
	userData, err := api.psqlRepo.GetUserDataWithUUID(userUUID)
	if err != nil {
		api.apiLogger.Error(" User id" + userUUID + " not authorized")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + userUUID + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	flag := true

	userData.UserName = username

	if !helpers.CheckUser(userData, userData.Role) {
		flag = false
	}
	if !flag {
		api.apiLogger.Error(" User " + username + " not authorized")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + username + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	if !helpers.CheckAppsExist(userData.Applications, []*domain.ApplicationData{&appData}) {
		api.apiLogger.Error(" User " + username + " not authorized")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + username + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	nowTime := time.Now()
	appData.UpdatedTimestamp = nowTime

	err = api.psqlRepo.UpdateAppData(&appData)
	if err != nil {
		errorData.Message = "Internal error / updating app data in postgres"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}

	//clear all the cache for that specific user
	for _, cachedReq := range cachedRequests[username] {
		api.apiCache.Del(cachedReq)
	}
	cachedRequests[username] = make([]string, 0)

	response.Write([]byte("App updated succesfully"))
	registerResponse := domain.QueryResponse{}
	registerResponse.Message = "App updated succesfully"
	registerResponse.ResourcesAffected = append(registerResponse.ResourcesAffected, appData.Name)
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

	listAppNames := strings.Split(appnames, ",")
	for _, appName := range listAppNames {
		err := api.psqlRepo.DeleteAppData(strings.TrimSpace(appName), username)
		if err != nil {
			api.apiLogger.Error(" App  not found", zap.String("app_name", appName))
			errorData.Message = "App not found"
			errorData.StatusCode = http.StatusNotFound
			response.WriteHeader(http.StatusNotFound)
			response.WriteEntity(errorData)
			return
		}
	}

	//clear all the cache for that specific user
	for _, cachedReq := range cachedRequests[username] {
		api.apiCache.Del(cachedReq)
	}
	cachedRequests[username] = make([]string, 0)

	registerResponse := domain.QueryResponse{}
	registerResponse.Message = "Apps deleted succesfully"
	registerResponse.ResourcesAffected = append(registerResponse.ResourcesAffected, listAppNames...)
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
