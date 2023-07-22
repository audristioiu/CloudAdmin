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
)

var (
	//map of users with their specific cached requests as value
	cachedRequests = make(map[string][]string, 0)
	//filters that can be used for GetAppsInfo
	getAppsFilters = []string{"name", "kname", "description", "created_timestamp", "updated_timestamp"}
)

// AdminAuthenticate verifies role and user_id for admin
func (api *API) AdminAuthenticate(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	errorData := domain.ErrorResponse{}
	authHeader := request.HeaderParameter("USER-AUTH")
	userIDHeader := request.HeaderParameter("USER-UUID")

	userData, err := api.psqlRepo.GetUserDataWithUUID(userIDHeader)
	if err != nil || !helpers.CheckUser(userData, authHeader) || userData.UserName != "admin" {
		api.apiLogger.Errorf("[ERROR] User id " + userIDHeader + " not authorized")
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
		api.apiLogger.Errorf("[ERROR] User id " + userIDHeader + " not authorized")
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
		api.apiLogger.Errorf("[ERROR] Couldn't read body with error : %+v", err)
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	if userData.UserName == "" {
		api.apiLogger.Errorf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	if len(userData.Password) < 8 {
		api.apiLogger.Errorf("[ERROR] password too short")
		errorData.Message = "Bad Request/ Password too short"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if !unicode.IsUpper(rune(userData.Password[0])) {
		api.apiLogger.Errorf("[ERROR] password does not start with uppercase")
		errorData.Message = "Bad Request/ Password does not start with uppercase"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	userRetrievedData, _ := api.psqlRepo.GetUserData(userData.UserName)
	if userRetrievedData != nil {
		api.apiLogger.Errorf("[ERROR] User %v already exists", userData.UserName)
		errorData.Message = "User already exists"
		errorData.StatusCode = http.StatusFound
		response.WriteHeader(http.StatusFound)
		response.WriteEntity(errorData)
		return
	}

	nowTime := time.Now()
	userData.JoinedDate = nowTime
	userData.LastTimeOnline = nowTime
	userData.Applications = []string{}
	userData.NrDeployedApps = 0

	err = api.psqlRepo.InsertUserData(&userData)
	if err != nil {
		errorData.Message = "Internal error/ insert user data in postgres"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	response.Write([]byte("User registered succesfully"))
}

// UserLogin verifies user credentials
func (api *API) UserLogin(request *restful.Request, response *restful.Response) {
	userData := domain.UserData{}
	newUserData := &domain.UserData{}

	oldPass := request.QueryParameter("old_password")

	errorData := domain.ErrorResponse{}
	err := request.ReadEntity(&userData)
	if err != nil {
		api.apiLogger.Errorf("[ERROR] Couldn't read body with error : %+v", err)
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if userData.UserName == "" {
		api.apiLogger.Errorf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if userData.UserName == "admin" || strings.Contains(userData.UserName, "admin") {
		api.apiLogger.Errorf("[ERROR] You are not allowed to login as admin")
		errorData.Message = "Status forbidden/  You are not allowed to login as admin"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	if userData.Password == "" {
		api.apiLogger.Errorf("[ERROR] Couldn't read password query parameter")
		errorData.Message = "Bad Request/ empty password"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	if len(userData.Password) < 8 {
		api.apiLogger.Errorf("[ERROR] password too short")
		errorData.Message = "Bad Request/ Password too short"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if !unicode.IsUpper(rune(userData.Password[0])) {
		api.apiLogger.Errorf("[ERROR] password does not start with uppercase")
		errorData.Message = "Bad Request/ Password does not start with uppercase"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	dbUserData, err := api.psqlRepo.GetUserData(userData.UserName)
	if err != nil {
		api.apiLogger.Errorf("[ERROR] User %v not found", userData.UserName)
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}

	if !helpers.CheckPasswordHash(userData.Password, dbUserData.Password) {
		api.apiLogger.Errorf("[ERROR] Wrong password given. Please try again.")
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
		newUserData.LastTimeOnline = nowTime

		err = api.psqlRepo.UpdateUserLastTimeOnlineData(newUserData.LastTimeOnline, newUserData)
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
			api.apiLogger.Errorf("[ERROR] Couldn't marshal request %v", request.Request.URL)
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

	response.WriteEntity(newUserData)
}

// GetUserProfile returns user profile based on username
func (api *API) GetUserProfile(request *restful.Request, response *restful.Response) {

	errorData := domain.ErrorResponse{}

	//calculate key and use cache to get the response
	marshalledRequest, err := json.Marshal(request.Request.URL)
	if err != nil {
		api.apiLogger.Errorf("[ERROR] Couldn't marshal request %v", request.Request.URL)
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
			api.apiLogger.Errorf("[ERROR] Couldn't read username path parameter")
			errorData.Message = "Bad Request/ empty username"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}

		userData, err := api.psqlRepo.GetUserData(username)
		if err != nil {
			api.apiLogger.Errorf("[ERROR] User %v not found", userData.UserName)
			errorData.Message = "User not found"
			errorData.StatusCode = http.StatusNotFound
			response.WriteHeader(http.StatusNotFound)
			response.WriteEntity(errorData)
			return
		}
		api.apiLogger.Debugf("[DEBUG] Not found in cache %v", username)
		userData.Password = ""
		userData.Role = ""
		userData.UserID = ""
		response.WriteEntity(userData)
		// If not in cache, set it
		api.apiCache.SetWithTTL(marshalledRequest, userData, 1, time.Hour*24)
		cachedRequests[username] = append(cachedRequests[username], string(marshalledRequest))

	} else {

		userData := userDataCache.(*domain.UserData)

		api.apiLogger.Errorf("[INFO] Found in cache %v", userData.UserName)

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
		api.apiLogger.Errorf("[ERROR] Couldn't read body with error : %+v", err)
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	if userData.Role != "" || userData.UserID != "" || len(userData.Applications) > 0 {
		api.apiLogger.Errorf("[ERROR] Wrong fields to update")
		errorData.Message = "Bad Request/ wrong fields , you can only update birth_date ,job_role,email,  want_notify or password"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if userData.Password != "" {
		if len(userData.Password) < 8 {
			api.apiLogger.Errorf("[ERROR] password too short")
			errorData.Message = "Bad Request/ Password too short"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}
		if !unicode.IsUpper(rune(userData.Password[0])) {
			api.apiLogger.Errorf("[ERROR] password does not start with uppercase")
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
		api.apiLogger.Errorf("[ERROR] Couldn't marshal request %v", request.Request.URL)
		errorData.Message = "Internal server error/Cannot marshal marshalledRequest in User Profile"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}

	//gather the fresh new data to be cached
	newUserData, _ := api.psqlRepo.GetUserData(userData.UserName)
	api.apiCache.SetWithTTL(marshalledRequest, newUserData, 1, time.Hour*24)

	response.Write([]byte("User updated succesfully"))
}

// DeleteUser deletes user
func (api *API) DeleteUser(request *restful.Request, response *restful.Response) {
	errorData := domain.ErrorResponse{}
	usersName := request.QueryParameter("usernames")
	if usersName == "" {
		api.apiLogger.Errorf("[ERROR] Couldn't read usernames query parameter")
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
			api.apiLogger.Errorf("[ERROR] Couldn't marshal request %v", request.Request.URL)
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
				api.apiLogger.Errorf("[ERROR] App %v could not be deleted/not found ", userApp)
				errorData.Message = "App not found"
				errorData.StatusCode = http.StatusNotFound
				response.WriteHeader(http.StatusNotFound)
				response.WriteEntity(errorData)
				return
			}
		}

		marshalledRequest, err = json.Marshal(request.Request.URL)
		if err != nil {
			api.apiLogger.Errorf("[ERROR] Couldn't marshal request %v", request.Request.URL)
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
			api.apiLogger.Errorf("[ERROR] User %v not found", username)
			errorData.Message = "User not found"
			errorData.StatusCode = http.StatusNotFound
			response.WriteHeader(http.StatusNotFound)
			response.WriteEntity(errorData)
			return
		}
	}

	response.Write([]byte("User deleted succesfully"))
}

// UploadApp uploads app to s3
func (api *API) UploadApp(request *restful.Request, response *restful.Response) {

	errorData := domain.ErrorResponse{}

	username := request.QueryParameter("username")
	if username == "" {
		api.apiLogger.Errorf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	userData, err := api.psqlRepo.GetUserData(username)
	if err != nil {
		api.apiLogger.Errorf("[ERROR] User id" + username + " not found")
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
		api.apiLogger.Errorf("[ERROR] User" + username + " not authorized")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + username + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return

	}
	formFilesName := request.Request.MultipartForm.File["type"]
	if len(formFilesName) == 0 {
		api.apiLogger.Errorf("[ERROR] Couldn't form file")
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
			api.apiLogger.Errorf("[ERROR] Couldn't open new file")
			errorData.Message = "Internal error/ could not open new file"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

		openFormFile, err := fileName.Open()
		if err != nil {
			api.apiLogger.Errorf("[ERROR] Couldn't open form file")
			errorData.Message = "Internal error/ could not open file"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

		// Copy the contents of the file to the new file
		_, err = io.Copy(f, openFormFile)
		if err != nil {
			api.apiLogger.Errorf("[ERROR] Couldn't copy file with error : %+v", err)
			errorData.Message = "Internal error/ could not copy file"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

		r, err := zip.OpenReader(fileName.Filename)
		if err != nil {
			api.apiLogger.Errorf("[ERROR] Couldn't open zipReader with error : %+v", err)
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

			api.apiLogger.Errorf("Writting information for file %v:\n", f.Name)
			rc, err := f.Open()
			if err != nil {
				api.apiLogger.Fatal(err)
			}
			descr, err1 := io.ReadAll(rc)
			if err1 != nil {
				api.apiLogger.Errorf("[ERROR] Couldn't read io.Reader with error : %+v", err1)
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
					api.apiLogger.Errorf("[ERROR] App %v already exists", appData.Name)
					errorData.Message = "App already exists"
					errorData.StatusCode = http.StatusFound
					response.WriteHeader(http.StatusFound)
					response.WriteEntity(errorData)
					return
				}

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
				api.apiLogger.Println("upload s3")
				api.apiLogger.Errorf("%v\n", string(descr))

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

	response.Write([]byte("App uploaded succesfully"))
}

// GetAppsInfo retrieves apps information
func (api *API) GetAppsInfo(request *restful.Request, response *restful.Response) {

	errorData := domain.ErrorResponse{}

	userIDHeader := request.HeaderParameter("USER-UUID")
	authHeader := request.HeaderParameter("USER-AUTH")

	//Calculate key and use cache to get the response
	marshalledRequest, err := json.Marshal(request.Request.URL)
	if err != nil {
		api.apiLogger.Errorf("[ERROR] Couldn't marshal request %v", request.Request.URL)
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
			api.apiLogger.Errorf("[ERROR] Couldn't read username query parameter")
			errorData.Message = "Bad Request/ empty username"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}
		api.apiLogger.Debugf("[DEBUG] Apps not found in cache for user %v", username)

		userData, err := api.psqlRepo.GetUserDataWithUUID(userIDHeader)
		if err != nil || !helpers.CheckUser(userData, authHeader) {
			api.apiLogger.Errorf("[ERROR] User id " + userIDHeader + " not authorized")
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
			for _, appFilter := range getAppsFilters {
				if strings.Contains(filter, appFilter) {
					filterFlag = 1
				}
			}
			if filterFlag == 0 {
				api.apiLogger.Errorf("[ERROR] Cannot filter by %v", filter)
				errorData.Message = "Bad Request /Cannot filter"
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
					api.apiLogger.Errorf("[ERROR] Invalid fql filter for app %+v", appName)
					errorData.Message = "Invalid fql filter"
					errorData.StatusCode = http.StatusBadRequest
					appsInfo.Errors = append(appsInfo.Errors, errorData)
				} else {
					api.apiLogger.Errorf("[ERROR] App %v not found", appName)
					errorData.Message = "App " + appName + " not found"
					errorData.StatusCode = http.StatusNotFound
					appsInfo.Errors = append(appsInfo.Errors, errorData)
				}

				continue
			}
			if len(appsData) == 0 {
				api.apiLogger.Debug("[DEBUG] no apps found")

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
			api.apiLogger.Errorf("[ERROR] User " + username + " not authorized")
			response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
			errorData.Message = "User " + username + " is Not Authorized"
			errorData.StatusCode = http.StatusForbidden
			response.WriteHeader(http.StatusForbidden)
			response.WriteEntity(errorData)
			return
		}

		response.WriteEntity(appsInfo)

		api.apiCache.SetWithTTL(marshalledRequest, appsInfo, 1, time.Hour*24)
		cachedRequests[username] = append(cachedRequests[username], string(marshalledRequest))
		return
	} else {
		appsData := appsDataCache.(domain.GetApplicationsData)
		api.apiLogger.Debugf("[DEBUG] Apps  found in cache")
		response.WriteEntity(appsData)
	}

}

// UpdateApp updates app info
func (api *API) UpdateApp(request *restful.Request, response *restful.Response) {

	appData := domain.ApplicationData{}
	errorData := domain.ErrorResponse{}

	err := request.ReadEntity(&appData)
	if err != nil {
		api.apiLogger.Errorf("[ERROR] Couldn't read body with error : %+v", err)
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	username := request.QueryParameter("username")
	if username == "" {
		api.apiLogger.Errorf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	userUUID := request.HeaderParameter("USER-UUID")
	userData, err := api.psqlRepo.GetUserDataWithUUID(userUUID)
	if err != nil {
		api.apiLogger.Errorf("[ERROR] User id" + userUUID + " not authorized")
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
		api.apiLogger.Errorf("[ERROR] User " + username + " not authorized")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + username + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	if !helpers.CheckAppsExist(userData.Applications, []*domain.ApplicationData{&appData}) {
		api.apiLogger.Errorf("[ERROR] User " + username + " not authorized")
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
}

// DeleteApp deletes app
func (api *API) DeleteApp(request *restful.Request, response *restful.Response) {

	errorData := domain.ErrorResponse{}

	appnames := request.QueryParameter("appnames")
	if appnames == "" {
		api.apiLogger.Errorf("[ERROR] Couldn't read appname query parameter")
		errorData.Message = "Bad Request/ empty appname"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	username := request.QueryParameter("username")
	if username == "" {
		api.apiLogger.Errorf("[ERROR] Couldn't read username query parameter")
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
			api.apiLogger.Errorf("[ERROR] App %v not found", appName)
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

	response.Write([]byte("App deleted succesfully"))
}
