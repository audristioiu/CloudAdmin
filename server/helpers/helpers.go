package helpers

import (
	"cloudadmin/domain"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	fql "github.com/ganigeorgiev/fexpr"
	"github.com/google/uuid"
	"go.uber.org/zap"
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

// GetAppsName returns a slice of names of ApplicationData array
func GetAppsName(applications []*domain.ApplicationData) []string {
	result := make([]string, 0)
	for _, app := range applications {
		result = append(result, app.Name)
	}
	return result
}

// CheckAppsExists validates that the list of applications appears in user apps
func CheckAppsExist(applications []string, appsData []string) bool {
	if len(applications) == 0 || len(appsData) == 0 {
		return false
	}

	for _, app := range appsData {

		if !slices.Contains(applications, app) {
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

/*
example of combined filters
description=NULL&&is_running="false"||kname="test"&&created_timestamp<"1day"
(description=NULL && is_running="false")||(kname="test" && description="integer")
*/

// ParseFQLFilter returns filters in slice of slices of strings
func ParseFQLFilter(fqlString string, logger *zap.Logger) [][]string {
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
			logger.Error("error in scanning", zap.Error(err))
			return nil
		}
		if t.Type == fql.TokenWS || (t.Type == fql.TokenText && t.Literal == "NULL") ||
			(t.Type == fql.TokenIdentifier && !slices.Contains(GetAppsFilters, t.Literal) && t.Literal != "NULL") {
			logger.Error("invalid fql value", zap.String("literal", t.Literal))
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

	logger.Debug("got list of filters", zap.Any("filter list", listFilters))
	return listFilters
}

// WriteDockerFile writes parameters for Dockerfile
func WriteDockerFile(dockerFile *os.File, dockProperties domain.DockerFile, logger *zap.Logger) error {
	var sb strings.Builder
	_, err := sb.WriteString("FROM " + dockProperties.From)
	if err != nil {
		logger.Error("could not writeString", zap.Error(err))
		return err
	}

	_, err = sb.WriteString("\n")
	if err != nil {
		logger.Error("could not writeString", zap.Error(err))
		return err
	}

	_, err = sb.WriteString("WORKDIR " + dockProperties.Workdir)
	if err != nil {
		logger.Error("could not writeString", zap.Error(err))
		return err
	}

	_, err = sb.WriteString("\n")
	if err != nil {
		logger.Error("could not writeString", zap.Error(err))
		return err
	}

	_, err = sb.WriteString("COPY " + dockProperties.Copy)
	if err != nil {
		logger.Error("could not writeString", zap.Error(err))
		return err
	}

	_, err = sb.WriteString("\n")
	if err != nil {
		logger.Error("could not writeString", zap.Error(err))
		return err
	}
	_, err = sb.WriteString("RUN " + dockProperties.Run)
	if err != nil {
		logger.Error("could not writeString", zap.Error(err))
		return err
	}

	_, err = sb.WriteString("\n")
	if err != nil {
		logger.Error("could not writeString", zap.Error(err))
		return err
	}

	if len(dockProperties.Cmd) > 0 {
		_, err = sb.WriteString("CMD " + "[")
		if err != nil {
			logger.Error("could not writeString", zap.Error(err))
			return err
		}

		for i, cmdArg := range dockProperties.Cmd {
			_, err = sb.WriteString(fmt.Sprintf("\"%s\"", cmdArg))
			if err != nil {
				logger.Error("could not writeString", zap.Error(err))
				return err
			}

			if i != len(dockProperties.Cmd)-1 {
				_, err = sb.WriteString(",")
				if err != nil {
					logger.Error("could not writeString", zap.Error(err))
					return err
				}

			} else {
				_, err = sb.WriteString("]\n")
				if err != nil {
					logger.Error("could not writeString", zap.Error(err))
					return err
				}

				break
			}
		}
	}

	if len(dockProperties.Shell) > 0 {
		_, err = sb.WriteString("SHELL " + "[")
		if err != nil {
			logger.Error("could not writeString", zap.Error(err))
			return err
		}
		for i, shellArg := range dockProperties.Shell {
			_, err = sb.WriteString(fmt.Sprintf("\"%s\"", shellArg))
			if err != nil {
				logger.Error("could not writeString", zap.Error(err))
				return err
			}
			if i != len(dockProperties.Shell)-1 {
				_, err = sb.WriteString(",")
				if err != nil {
					logger.Error("could not writeString", zap.Error(err))
					return err
				}
			} else {
				_, err = sb.WriteString("]\n")
				if err != nil {
					logger.Error("could not writeString", zap.Error(err))
					return err
				}
				break
			}
		}
	}

	if len(dockProperties.Volume) > 0 {
		_, err = sb.WriteString("VOLUME " + "[")
		if err != nil {
			logger.Error("could not writeString", zap.Error(err))
			return err
		}
		for i, volArg := range dockProperties.Volume {
			_, err = sb.WriteString(fmt.Sprintf("\"%s\"", volArg))
			if err != nil {
				logger.Error("could not writeString", zap.Error(err))
				return err
			}
			if i != len(dockProperties.Volume)-1 {
				_, err = sb.WriteString(",")
				if err != nil {
					logger.Error("could not writeString", zap.Error(err))
					return err
				}
			} else {
				_, err = sb.WriteString("]\n")
				if err != nil {
					logger.Error("could not writeString", zap.Error(err))
					return err
				}
				break
			}
		}
	}

	if len(dockProperties.EntryPoint) > 0 {
		_, err = sb.WriteString("ENTRYPOINT " + "[")
		if err != nil {
			logger.Error("could not writeString", zap.Error(err))
			return err
		}
		for i, entryPointArg := range dockProperties.EntryPoint {
			_, err = sb.WriteString(fmt.Sprintf("\"%s\"", entryPointArg))
			if err != nil {
				logger.Error("could not writeString", zap.Error(err))
				return err
			}
			if i != len(dockProperties.EntryPoint)-1 {
				_, err = sb.WriteString(",")
				if err != nil {
					logger.Error("could not writeString", zap.Error(err))
					return err
				}
			} else {
				_, err = sb.WriteString("]\n")
				if err != nil {
					logger.Error("could not writeString", zap.Error(err))
					return err
				}
				break
			}
		}
	}

	if dockProperties.User != "" {
		_, err = sb.WriteString("USER " + dockProperties.User)
		if err != nil {
			logger.Error("could not writeString", zap.Error(err))
			return err
		}
		_, err = sb.WriteString("\n")
		if err != nil {
			logger.Error("could not writeString", zap.Error(err))
			return err
		}
	}
	if dockProperties.Arg != "" {
		_, err = sb.WriteString("ARG " + dockProperties.Arg)
		if err != nil {
			logger.Error("could not writeString", zap.Error(err))
			return err
		}
		_, err = sb.WriteString("\n")
		if err != nil {
			logger.Error("could not writeString", zap.Error(err))
			return err
		}
	}
	if dockProperties.Label != "" {
		_, err = sb.WriteString("LABEL " + dockProperties.Label)
		if err != nil {
			logger.Error("could not writeString", zap.Error(err))
			return err
		}
		_, err = sb.WriteString("\n")
		if err != nil {
			logger.Error("could not writeString", zap.Error(err))
			return err
		}
	}
	if dockProperties.Env != "" {
		_, err = sb.WriteString("ENV " + dockProperties.Env)
		if err != nil {
			logger.Error("could not writeString", zap.Error(err))
			return err
		}
		_, err = sb.WriteString("\n")
		if err != nil {
			logger.Error("could not writeString", zap.Error(err))
			return err
		}
	}
	if dockProperties.ExposePort > 0 {
		_, err = sb.WriteString("EXPOSE " + strconv.Itoa(dockProperties.ExposePort))
		if err != nil {
			logger.Error("could not writeString", zap.Error(err))
			return err
		}
		_, err = sb.WriteString("\n")
		if err != nil {
			logger.Error("could not writeString", zap.Error(err))
			return err
		}
	}

	_, err = dockerFile.Write([]byte(sb.String()))
	if err != nil {
		logger.Error("could not writeString", zap.Error(err))
		return err
	}
	return nil
}

// GenerateDockerFile returns name of the dockerfile created using app info
func GenerateDockerFile(appData domain.ApplicationData, logger *zap.Logger) (string, error) {

	dockFile, err := os.CreateTemp("", "Dockerfile_test")
	if err != nil {
		logger.Error("could not create temp file", zap.Error(err))
		return "", err
	}

	appName := appData.Name
	extension := strings.Split(appName, ".")[1]

	switch mapCodeExtension[extension] {
	//todo rework dockerfiles
	case "nodejs":
		{
			dockProps := domain.DockerFile{
				From:    "node18-alpine",
				Workdir: "/app",
				Copy:    appName + " /app",
				// EntryPoint: []string{"top", "-b"},
				// Volume:     []string{"/myvol"},
				Run: "yarn install --production",
				Cmd: []string{"node", appName},
				//Shell:      []string{"powershell", "-command"},
				// User:       "Patrick",
				// Arg:        "CONT_IMG_VER",
				// Label:      "com.example.label-with-value=\"foo\"",
				// Env:        "COMT_IMG_VER=hello",
				// ExposePort: 3000,
			}

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", err
			}

		}
	case "golang":
		{
			newCMD := []string{"go", "run"}
			newCMD = append(newCMD, appData.FlagArguments, appName, appData.ParamArguments)
			dockProps := domain.DockerFile{
				From:    "golang:1.21",
				Workdir: "/src",
				Copy:    appName + " /src",
				// EntryPoint: []string{"top", "-b"},
				// Volume:     []string{"/myvol"},
				Run: "mkdir /src",
				Cmd: newCMD,
				// Shell:      []string{"powershell", "-command"},
				// User:       "Patrick",
				// Arg:        "CONT_IMG_VER",
				// Label:      "com.example.label-with-value=\"foo\"",
				// Env:        "COMT_IMG_VER=hello",
				// ExposePort: 3000,
			}

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", err
			}

		}

	case "python":
		{

			newCMD := []string{"python"}
			newCMD = append(newCMD, appData.FlagArguments, appName, appData.ParamArguments)
			dockProps := domain.DockerFile{
				From:    "python:3.10-slim",
				Workdir: "/app",
				Copy:    appName + " /app",
				// EntryPoint: []string{"top", "-b"},
				// Volume:     []string{"/myvol"},
				Run: "pip install -r requirements.txt",
				Cmd: newCMD,
				//Shell:      []string{"powershell", "-command"},
				// User:       "Patrick",
				// Arg:        "CONT_IMG_VER",
				// Label:      "com.example.label-with-value=\"foo\"",
				// Env:        "COMT_IMG_VER=hello",
				// ExposePort: 3000,
			}

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", err
			}

		}
	case "java":
		{
			execName := strings.Split(appName, ".")[0]
			newCMD := []string{"java"}
			newCMD = append(newCMD, appData.FlagArguments, execName, appData.ParamArguments)
			dockProps := domain.DockerFile{
				From:    "alpine:latest",
				Workdir: "/app",
				Copy:    "--chown=nobody " + appName + " /app",
				// EntryPoint: []string{"top", "-b"},
				// Volume:     []string{"/myvol"},
				Run: "apk update && \\ \n apk fetch openjdk8 && \\ \n apk add --no-cache openjdk8 \\ \n mkdir app && \\ \n chown nobody. /app && \\ \n javac " + appName,
				Cmd: newCMD,
				//Shell:      []string{"powershell", "-command"},
				User: "nobdy",
				//Arg:        "CONT_IMG_VER",
				//Label:      "com.example.label-with-value=\"foo\"",
				Env: "JAVA_HOME=/usr/lib/jvm/java-1.8-openjdk;PATH=\"$JAVA_HOME/bin:${PATH}",
				//ExposePort: 3000,
			}

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", err
			}

		}
	case "c":
		{
			var newRun string

			newCMD := make([]string, 0)
			execName := strings.Split(appName, ".")[0]
			if appData.ParamArguments != "" {
				newCMD = append(newCMD, "./"+execName, appData.ParamArguments)
			} else {
				newCMD = append(newCMD, "./"+execName)
			}
			if appData.FlagArguments != "" {
				newRun = "addgroup -S dockergroup && \\ \n adduser -S dockeruser -G dockergroup && \\ \n apk add --no-cache build-base && \\ \n  mkdir /src && \\ \n gcc -o " + execName + " " + strings.Join(appData.SubgroupFiles, " ") + " " + appData.FlagArguments
			} else {
				newRun = "addgroup -S dockergroup && \\ \n adduser -S dockeruser -G dockergroup && \\ \n apk add --no-cache build-base && \\ \n  mkdir /src && \\ \n gcc -o " + execName + " " + strings.Join(appData.SubgroupFiles, " ")
			}

			dockProps := domain.DockerFile{
				From:    "alpine:latest",
				Workdir: "/src",
				Copy:    appName + " /src",
				// EntryPoint: []string{"top", "-b"},
				// Volume:     []string{"/myvol"},
				Run: newRun,
				Cmd: newCMD,
				// Shell:      []string{"powershell", "-command"},
				User: "dockeruser",
				// Arg:        "CONT_IMG_VER",
				// Label:      "com.example.label-with-value=\"foo\"",
				// Env:        "COMT_IMG_VER=hello",
				// ExposePort: 3000,
			}

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", err
			}

		}
	case "c++":
		{
			var newRun string

			newCMD := make([]string, 0)
			execName := strings.Split(appName, ".")[0]
			if appData.ParamArguments != "" {
				newCMD = append(newCMD, "./"+execName, appData.ParamArguments)
			} else {
				newCMD = append(newCMD, "./"+execName)
			}
			if appData.FlagArguments != "" {
				newRun = "addgroup -S dockergroup && \\ \n adduser -S dockeruser -G dockergroup && \\ \n apk add --no-cache build-base && \\ \n  mkdir /src && \\ \n g++ -o " + execName + " " + strings.Join(appData.SubgroupFiles, " ") + " " + appData.FlagArguments
			} else {
				newRun = "addgroup -S dockergroup && \\ \n adduser -S dockeruser -G dockergroup && \\ \n apk add --no-cache build-base && \\ \n  mkdir /src && \\ \n g++ -o " + execName + " " + strings.Join(appData.SubgroupFiles, " ")
			}
			dockProps := domain.DockerFile{
				From:    "alpine:latest",
				Workdir: "/src",
				Copy:    "/src/main.cpp /src",
				// EntryPoint: []string{"top", "-b"},
				// Volume:     []string{"/myvol"},
				Run: newRun,
				Cmd: newCMD,
				// Shell:      []string{"powershell", "-command"},
				User: "dockeruser",
				// Arg:        "CONT_IMG_VER",
				// Label:      "com.example.label-with-value=\"foo\"",
				// Env:        "COMT_IMG_VER=hello",
				// ExposePort: 3000,
			}

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", err
			}

		}
	default:
		{
			return "", fmt.Errorf("unsupported extension")
		}
	}
	defer dockFile.Close()
	return dockFile.Name(), nil
}

// CreateFilesFromDir returns ApplicationData struct for main app and subgroup apps
func CreateFilesFromDir(filePath string, logger *zap.Logger) (mainApp domain.ApplicationData, subApps []*domain.ApplicationData, fileTxt string, err error) {
	pathFiles := make([]string, 0)
	err = filepath.Walk(filePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Error("error in filepath Walk function", zap.Error(err))
			return err
		}
		if !info.IsDir() {
			pathFiles = append(pathFiles, path)
		}

		fmt.Printf("dir: %v: name: %s\n", info.IsDir(), path)
		return nil
	})
	if err != nil {
		logger.Error("error in filepath Walk", zap.Error(err))
		return domain.ApplicationData{}, nil, "", err
	}

	appsData := make([]*domain.ApplicationData, 0)
	appsDescription := ""
	mainAppData := domain.ApplicationData{}
	appTxt := ""
	for _, path := range pathFiles {
		file, err := os.ReadFile(path)
		if err != nil {
			logger.Error(" Couldn't read io.Reader with error : ", zap.Error(err))
			return domain.ApplicationData{}, nil, "", err
		}
		appData := domain.ApplicationData{}
		descr := string(file)
		if strings.Contains(path, ".txt") {
			appsDescription = descr
			appTxt = strings.Split(path, "/")[1]

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
			appData.Name = strings.Split(path, "/")[1]

			regexCompiler, _ := regexp.Compile("main.")
			if regexCompiler.MatchString(descr) {
				mainAppData.CreatedTimestamp = appData.CreatedTimestamp
				mainAppData.UpdatedTimestamp = appData.UpdatedTimestamp
				mainAppData.IsRunning = false
				mainAppData.FlagArguments = ""
				mainAppData.ParamArguments = ""
				mainAppData.IsMain = true
				mainAppData.SubgroupFiles = []string{}
				mainAppData.Description = appsDescription
				mainAppData.Name = strings.Split(path, "/")[1]
			} else {
				appsData = append(appsData, &appData)
			}
		}
	}

	return mainApp, appsData, appTxt, nil
}
