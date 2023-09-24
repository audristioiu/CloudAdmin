package api

import (
	"archive/zip"
	"cloudadmin/domain"
	"cloudadmin/helpers"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
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
	userData.NrDeployedApps = helpers.DefaultNrDeployedApps

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
			api.apiLogger.Error(" User not found", zap.String("user_name", username))
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
}

// UploadApp uploads app to s3
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

	flag := true

	userData.UserName = username

	if !helpers.CheckUser(userData, userData.Role) {
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
	formFilesName := request.Request.MultipartForm.File["file"]
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

				api.apiLogger.Debug("Writting information for file :\n", zap.String("file_name", f.Name))
				rc, err := f.Open()
				if err != nil {
					api.apiLogger.Error("failed to open file", zap.Error(err))
					errorData.Message = "Internal Error/ Failed to open file"
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
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
						appTxt = r.File[i+1].Name
					} else {
						appTxt = r.File[i-1].Name
					}
					appsDescription = string(descr)
					fmt.Println(appTxt)
					fmt.Println(appsDescription)

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
				app.SubgroupFiles = append(app.SubgroupFiles, mainAppData.Name)
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

			subGroupMainFiles = append(subGroupMainFiles, mainAppData.Name)
			appsUploaded = append(appsUploaded, mainAppData.Name)
			mainAppData.Description = appsDescription
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
				appData := domain.ApplicationData{}
				nowTime := time.Now()
				appData.CreatedTimestamp = nowTime
				appData.UpdatedTimestamp = nowTime

				api.apiLogger.Debug("Writting information for file :\n", zap.String("file_name", f.Name))
				rc, err := f.Open()
				if err != nil {
					api.apiLogger.Error("failed to open file", zap.Error(err))
					errorData.Message = "Internal Error/ Failed to open file"
					errorData.StatusCode = http.StatusInternalServerError
					response.WriteHeader(http.StatusInternalServerError)
					response.WriteEntity(errorData)
					return
				}

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
						app.SubgroupFiles = append(app.SubgroupFiles, mainAppData.Name)
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
					subGroupMainFiles = append(subGroupMainFiles, mainAppData.Name)
					appsUploaded = append(appsUploaded, mainAppData.Name)
					mainAppData.SubgroupFiles = append(subGroupMainFiles, subGroupMainFiles...)
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

					appData.IsRunning = false
					appData.FlagArguments = ""
					appData.ParamArguments = ""
					appData.IsMain = true
					appData.SubgroupFiles = []string{}
					appData.Owner = username

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
			api.apiLogger.Error(" User id not authorized", zap.String("user_id", userIDHeader))
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

		if len(sortParams) == 2 {
			api.apiLogger.Debug("sorting by ", zap.Any("sort_query", sortParams))
		}

		appsData, err := api.psqlRepo.GetAppsData(username, filter, sortParams)
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

			}
		}
		if len(appsData) == 0 {
			api.apiLogger.Debug(" no apps found")
			errorData.Message = "No apps found"
			errorData.StatusCode = http.StatusNotFound
			appsInfo.Errors = append(appsInfo.Errors, errorData)
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

		if len(appsInfo.Response) > 1 {
			appsInfo = helpers.Unique(appsInfo)
		}
		appsName := helpers.GetAppsName(appsInfo.Response)
		if !helpers.CheckAppsExist(userData.Applications, appsName) {
			api.apiLogger.Error("User forbidden for apps", zap.Any("apps", appsName))
			errorData.Message = "Forbidden User"
			errorData.StatusCode = http.StatusForbidden
			appsInfo.Errors = append(appsInfo.Errors, errorData)
		}

		response.WriteEntity(appsInfo)
		if len(appsInfo.Response) > 0 {
			api.apiCache.SetWithTTL(string(marshalledRequest), appsInfo, 1, time.Hour*24)
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

	userData, err := api.psqlRepo.GetUserData(username)
	if err != nil {
		api.apiLogger.Error(" User not found", zap.String("user_name", username))
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}

	flag := true

	userData.UserName = username

	if !helpers.CheckUser(userData, userData.Role) || userData.UserName != username {
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

	nowTime := time.Now()
	appData.UpdatedTimestamp = nowTime

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

	appNamesList := strings.Split(appnames, ",")

	if !helpers.CheckAppsExist(userData.Applications, appNamesList) {
		api.apiLogger.Error("Apps not found", zap.Any("apps", appNamesList))
		errorData.Message = "Apps not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return

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
}

// ScheduleApps schedule apps
func (api *API) ScheduleApps(request *restful.Request, response *restful.Response) {
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

	appsData, err := api.psqlRepo.GetAppsData(username, "", []string{})
	if err != nil {
		api.apiLogger.Error("Got error when retrieving apps", zap.Error(err))
		errorData.Message = "Internal error / retrieving apps"
		errorData.StatusCode = http.StatusInternalServerError
		appsInfo.Errors = append(appsInfo.Errors, errorData)
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

	// for _, app := range appsInfo.Response {
	// 	dockerFileName, err := helpers.GenerateDockerFile(app, api.apiLogger)
	// 	if err != nil {
	// 		api.apiLogger.Error("Got error when generating docker file", zap.Error(err))
	// 		errorData.Message = "Internal error / generating docker file"
	// 		errorData.StatusCode = http.StatusInternalServerError
	// 		response.WriteHeader(http.StatusInternalServerError)
	// 		response.WriteEntity(errorData)
	// 	}
	// }

	scheduleResponse := domain.QueryResponse{}
	scheduleResponse.Message = "Apps scheduled succesfully"
	scheduleResponse.ResourcesAffected = append(scheduleResponse.ResourcesAffected, appNamesList...)
	response.WriteEntity(scheduleResponse)

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
