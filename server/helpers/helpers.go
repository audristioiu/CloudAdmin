package helpers

import (
	"bytes"
	"cloudadmin/domain"
	"cloudadmin/priority_queue"
	"container/heap"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	fql "github.com/ganigeorgiev/fexpr"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
)

var (
	specialCharacters = []string{"`", "~", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_",
		"=", "+", "[", "]", "{", "}", ";", ":", "'", "|", ",", "<", ".", ">", "/", "?"}
)

// HasSymbol checks if str contains special characters
func HasSymbol(str string) bool {
	for _, character := range specialCharacters {
		hasSpecialChar := strings.ContainsAny(str, character)
		if hasSpecialChar {
			return true
		}
	}

	return false
}

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
	currentRole := AddSaltToRole(id, string(generateRandomSalt(16)))
	updatedRole := AddPepperToRole(currentRole, uuid.New().String())
	hashedRole := HashPassword(updatedRole)

	userData.Role = hashedRole
	return userData

}

// AddSaltToRole combines id with a certain salt
func AddSaltToRole(id, salt string) string {
	return id + ":" + salt
}

// AddPepperToRole combines id with a certain salt
func AddPepperToRole(id, pepper string) string {
	return id + ":" + pepper
}

func generateRandomSalt(saltSize int) []byte {
	var salt = make([]byte, saltSize)

	_, err := rand.Read(salt[:])

	if err != nil {
		panic(err)
	}

	return salt
}

// HashPassword uses sha512 to generate a hash over password using salt and pepper
func HashPassword(password string) string {
	sha512Hasher := sha512.New()
	passwordBytes := []byte(password)
	sha512Hasher.Write(passwordBytes)
	sum := sha512Hasher.Sum(nil)
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

// CheckSliceContains validates that element exists
func CheckSliceContains(elements []string, searchElem string) string {
	for _, elem := range elements {
		if strings.Contains(elem, searchElem) {
			return elem
		}
	}
	return ""
}

/*
example of combined filters
description=NULL&&is_running="false"||kname="test"&&created_timestamp<"1day"
(description=NULL && is_running="false")||(kname="test" && description="integer")
*/

// ParseFQLFilter returns filters in slice of slices of strings
func ParseFQLFilter(fqlString string, logger *zap.Logger) ([][]string, error) {
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
			return nil, err
		}
		if t.Type == fql.TokenWS {
			logger.Error("invalid fql value", zap.String("literal", t.Literal))
			return nil, fmt.Errorf("invalid fql value , no whitespace allowed")
		}
		if t.Type == fql.TokenText && t.Literal == "NULL" {
			logger.Error("invalid fql value for text token", zap.String("literal", t.Literal))
			return nil, fmt.Errorf("invalid fql value for text token . NULL is not allowed ")
		}
		if t.Type == fql.TokenIdentifier && !slices.Contains(GetAppsFilters, t.Literal) && t.Literal != "NULL" {
			logger.Error("invalid fql value for identifier token", zap.String("literal", t.Literal))
			return nil, fmt.Errorf("invalid fql value for identifier token . Text is not allowed")

		}
		if t.Type == fql.TokenSign || t.Type == fql.TokenJoin || t.Type == fql.TokenIdentifier || t.Type == fql.TokenText ||
			t.Type == fql.TokenGroup || t.Type == fql.TokenNumber {
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
	for _, filter := range listFilters {
		if len(filter) == 3 {
			if filter[0] == "port" && regexp.MustCompile(`\D`).MatchString(filter[2]) {
				logger.Error("invalid fql value for port", zap.String("port_value", filter[2]))
				return nil, fmt.Errorf("invalid fql value for port . Text is not allowed")
			}
			if strings.Contains(filter[0], "timestamp") && !regexp.MustCompile(`[0-9]{1,2}[day]`).MatchString(filter[2]) {
				logger.Error("invalid fql value for created_timestamp", zap.String("timestamp_value", filter[2]))
				return nil, fmt.Errorf("invalid fql value for timestamp . Format is not allowed")
			}
		}
	}
	return listFilters, nil
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

	if len(dockProperties.CopyArgs) > 0 {
		for _, copyArg := range dockProperties.CopyArgs {
			_, err = sb.WriteString("COPY " + copyArg)
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

	if len(dockProperties.RunApt) > 0 {
		for _, aptCmd := range dockProperties.RunApt {
			_, err = sb.WriteString("RUN " + aptCmd)
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
	}
	if dockProperties.Run != "" {
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
		_, err = sb.WriteString("EXPOSE " + strconv.Itoa(int(dockProperties.ExposePort)))
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

	_, err = dockerFile.Write([]byte(sb.String()[:len(sb.String())-1]))
	if err != nil {
		logger.Error("could not writeString", zap.Error(err))
		return err
	}
	return nil
}

func copy(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

// GenerateDockerFile returns name of the dockerfile created using app info + task item
func GenerateDockerFile(dirName,
	scheduleType string,
	files []string,
	port int32,
	appData *domain.ApplicationData,
	logger *zap.Logger) (string, []domain.TaskItem, error) {
	mkDirName := dirName + "-" + strings.Split(appData.Name, ".")[1]
	var packageJs []string
	var inOutFiles []string
	var runJs, runPy, runGo string
	hasPkg := false
	hasReqs := false
	hasGoMod := false
	path, _ := os.Getwd()
	path = strings.ReplaceAll(path, "CloudAdmin", "")
	path = strings.ReplaceAll(path, "server", "")
	path = filepath.Join(path, filepath.Base(mkDirName))
	var taskExecutionTime []domain.TaskItem
	err := os.Mkdir(mkDirName, 0777)
	if err != nil {
		logger.Error("failed to create directory", zap.Error(err))
		return "", nil, err
	}
	//todo delete in the end
	if len(files) == 0 {

		_, err = copy(filepath.Join(path, filepath.Base(appData.Name)), filepath.Join(mkDirName, filepath.Base(appData.Name)))
		if err != nil {
			logger.Error("failed to copy", zap.Error(err))
			return "", nil, err
		}

		for _, subApp := range appData.SubgroupFiles {
			_, err = copy(filepath.Join(path, filepath.Base(subApp)), filepath.Join(mkDirName, filepath.Base(subApp)))
			if err != nil {
				logger.Error("failed to copy", zap.Error(err))
				return "", nil, err
			}
		}
		//check if extra files does exist in directory
		_, err = os.Stat(path + strings.Split(appData.Name, ".")[0] + ".in")
		if err == nil {
			copy(path+strings.Split(appData.Name, ".")[0]+".in", filepath.Join(mkDirName, filepath.Base(strings.Split(appData.Name, ".")[0]+".in")))
			inFile := strings.Split(appData.Name, ".")[0] + ".in"
			inOutFiles = append(inOutFiles, inFile+" "+inFile)
		}
		_, err = os.Stat(path + strings.Split(appData.Name, ".")[0] + ".out")
		if err == nil {
			copy(path+strings.Split(appData.Name, ".")[0]+".out", filepath.Join(mkDirName, filepath.Base(strings.Split(appData.Name, ".")[0]+".out")))
			outFile := strings.Split(appData.Name, ".")[0] + ".out"
			inOutFiles = append(inOutFiles, outFile+" "+outFile)
		}
		_, err = os.Stat(path + "package.json")
		if err == nil {
			hasPkg = true
		}
		_, err = os.Stat(path + "requirements.txt")
		if err == nil {
			hasReqs = true
		}
		_, err = os.Stat(path + "go.mod")
		if err == nil {
			hasGoMod = true
		}
	} else {
		for _, file := range files {
			if strings.Contains(file, ".in") || strings.Contains(file, ".out") {
				inOutFiles = append(inOutFiles, file)
			}
			if strings.Contains(file, "package.json") {
				hasPkg = true
				packageJs = []string{"package.json package.json", "package-lock.json package-lock.json"}
				runJs = "npm install"
			}
			if strings.Contains(file, "requirements.txt") {
				hasReqs = true
				runPy = "pip install -r requirements.txt"
			}
			if strings.Contains(file, "go.mod") {
				hasGoMod = true
				runGo = "go mod download"
			}
		}
	}
	dockFile, err := os.Create(filepath.Join(mkDirName, filepath.Base("Dockerfile")))
	if err != nil {
		logger.Error("could not create Dockerfile in directory", zap.Error(err))
		return "", nil, err
	}

	appName := appData.Name
	extension := strings.Split(appName, ".")[1]
	if extension == "js" && hasPkg {
		copy(filepath.Join(path, filepath.Base("package.json")), filepath.Join(mkDirName, filepath.Base("package.json")))
		copy(filepath.Join(path, filepath.Base("package-lock.json")), filepath.Join(mkDirName, filepath.Base("package-lock.json")))
		packageJs = []string{"package.json package.json", "package-lock.json package-lock.json"}
		runJs = "npm install"
	}
	if extension == "py" && hasReqs {
		copy(filepath.Join(path, filepath.Base("requirements.txt")), filepath.Join(mkDirName, filepath.Base("requirements.txt")))
		runPy = "pip install -r requirements.txt"
	}
	if extension == "go" && hasGoMod {
		copy(filepath.Join(path, filepath.Base("go.mod")), filepath.Join(mkDirName, filepath.Base("go.mod")))
		copy(filepath.Join(path, filepath.Base("go.sum")), filepath.Join(mkDirName, filepath.Base("go.sum")))
		runGo = "go mod download"
	}
	os := runtime.GOOS
	switch mapCodeExtension[extension] {
	case "nodejs":
		{
			newCMD := []string{"node"}
			if appData.FlagArguments != "" {
				newCMD = append(newCMD, appData.FlagArguments)
			}
			newCMD = append(newCMD, appName)
			if appData.ParamArguments != "" {
				newCMD = append(newCMD, appData.ParamArguments)
			}
			execName := strings.Split(appName, ".")[0]
			dockProps := domain.DockerFile{
				From:     "node:latest",
				Workdir:  "/" + execName + "/",
				CopyArgs: packageJs,
				Copy:     ". /" + execName,
				Run:      runJs,
				Cmd:      newCMD,
			}
			if len(inOutFiles) > 0 {
				dockProps.CopyArgs = inOutFiles
			}
			if port > int32(0) {
				dockProps.ExposePort = port
			}

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", nil, err
			}
			if scheduleType == "rr_sjf_scheduler" {
				taskExecutionTime, err = GetExecutionTimeForTasks(newCMD, []string{appData.FlagArguments}, []string{appData.ParamArguments},
					[]string{filepath.Join(mkDirName, filepath.Base(appData.Name))}, []string{}, logger)
				if err != nil {
					return "", nil, err
				}
			}

		}
	case "golang":
		{
			execName := strings.Split(appName, ".")[0]
			newCMD := []string{"go", "run", appName}
			if appData.FlagArguments != "" {
				newCMD = append(newCMD, appData.FlagArguments)
			}
			if appData.ParamArguments != "" {
				newCMD = append(newCMD, appData.ParamArguments)
			}
			dockProps := domain.DockerFile{
				From:    "golang:1.21.3",
				Workdir: "/" + execName + "/",
				Copy:    ". /" + execName,
				Run:     runGo,
				Cmd:     newCMD,
			}
			if len(inOutFiles) > 0 {
				dockProps.CopyArgs = inOutFiles
			}
			if port > int32(0) {
				dockProps.ExposePort = port
			}

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", nil, err
			}
			if scheduleType == "rr_sjf_scheduler" {
				taskExecutionTime, err = GetExecutionTimeForTasks(newCMD, []string{appData.FlagArguments}, []string{appData.ParamArguments},
					[]string{filepath.Join(mkDirName, filepath.Base(appData.Name))}, []string{}, logger)
				if err != nil {
					return "", nil, err
				}
			}

		}

	case "python":
		{
			execName := strings.Split(appName, ".")[0]
			newCMD := []string{"python", "-u"}
			if appData.FlagArguments != "" {
				newCMD = append(newCMD, appData.FlagArguments)
			}
			newCMD = append(newCMD, appName)
			if appData.ParamArguments != "" {
				newCMD = append(newCMD, appData.ParamArguments)
			}
			dockProps := domain.DockerFile{
				From:    "python:3.10-slim",
				Workdir: "/" + execName + "/",
				Copy:    ". /" + execName,
				Run:     runPy,
				Cmd:     newCMD,
			}
			if len(inOutFiles) > 0 {
				dockProps.CopyArgs = inOutFiles
			}
			if port > int32(0) {
				dockProps.ExposePort = port
			}

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", nil, err
			}
			if scheduleType == "rr_sjf_scheduler" {
				taskExecutionTime, err = GetExecutionTimeForTasks(newCMD, []string{appData.FlagArguments}, []string{appData.ParamArguments},
					[]string{filepath.Join(mkDirName, filepath.Base(appData.Name))}, []string{}, logger)
				if err != nil {
					return "", nil, err
				}
			}

		}
	case "java":
		{
			execName := strings.Split(appName, ".")[0]
			newCMD := []string{"java"}
			newCMD = append(newCMD, execName)
			if appData.ParamArguments != "" {
				newCMD = append(newCMD, appData.ParamArguments)
			}
			dockProps := domain.DockerFile{
				From:    "openjdk:11-jdk-slim",
				Workdir: "/" + execName + "/",
				Copy:    ". /" + execName,
				Run:     "javac " + appData.FlagArguments + " " + appName,
				Cmd:     newCMD,
			}
			if len(inOutFiles) > 0 {
				dockProps.CopyArgs = inOutFiles
			}
			if port > int32(0) {
				dockProps.ExposePort = port
			}

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", nil, err
			}
			if scheduleType == "rr_sjf_scheduler" {
				taskExecutionTime, err = GetExecutionTimeForTasks([]string{"javac", appName}, []string{appData.FlagArguments}, []string{appData.ParamArguments},
					[]string{filepath.Join(mkDirName, filepath.Base(appData.Name))}, newCMD, logger)
				if err != nil {
					return "", nil, err
				}
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
				newRun = "gcc -o " + execName + " " + appName + " " + strings.Join(appData.SubgroupFiles, " ") + " " + appData.FlagArguments
			} else {
				newRun = "gcc -o " + execName + " " + appName + " " + strings.Join(appData.SubgroupFiles, " ")
			}

			dockProps := domain.DockerFile{
				From:    "gcc:latest",
				Workdir: "/" + execName + "/",
				Copy:    ". " + "/" + execName,
				Run:     newRun,
				Cmd:     newCMD,
			}
			if len(inOutFiles) > 0 {
				dockProps.CopyArgs = inOutFiles
			}
			if port > int32(0) {
				dockProps.ExposePort = port
			}

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", nil, err
			}

			if os == "windows" {
				newCMD[0] = newCMD[0] + ".exe"
			}

			if scheduleType == "rr_sjf_scheduler" {
				taskExecutionTime, err = GetExecutionTimeForTasks(strings.Split(newRun, " "), []string{appData.FlagArguments}, []string{appData.ParamArguments},
					[]string{filepath.Join(mkDirName, filepath.Base(appData.Name))}, newCMD, logger)
				if err != nil {
					return "", nil, err
				}
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
				newRun = "g++ -o " + execName + " " + appName + " " + strings.Join(appData.SubgroupFiles, " ") + " " + appData.FlagArguments
			} else {
				newRun = "g++ -o " + execName + " " + appName + " " + strings.Join(appData.SubgroupFiles, " ")
			}
			dockProps := domain.DockerFile{
				From:    "gcc:latest",
				Workdir: "/" + execName + "/",
				Copy:    ". " + "/" + execName,
				Run:     newRun,
				Cmd:     newCMD,
			}
			if len(inOutFiles) > 0 {
				dockProps.CopyArgs = inOutFiles
			}
			if port > int32(0) {
				dockProps.ExposePort = port
			}

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", nil, err
			}
			if os == "windows" {
				newCMD[0] = newCMD[0] + ".exe"
			}
			if scheduleType == "rr_sjf_scheduler" {
				taskExecutionTime, err = GetExecutionTimeForTasks(strings.Split(newRun, " "), []string{appData.FlagArguments}, []string{appData.ParamArguments},
					[]string{filepath.Join(mkDirName, filepath.Base(appData.Name))}, newCMD, logger)
				if err != nil {
					return "", nil, err
				}
			}

		}
	default:
		{
			return "", nil, fmt.Errorf("unsupported extension")
		}
	}
	defer dockFile.Close()
	return mkDirName, taskExecutionTime, nil
}

// GetExecutionTimeForTasks retrieves list of name-execution time items that will be used in RR SJF algorithm
func GetExecutionTimeForTasks(commands, flags, params, tasksPath, runCommands []string, logger *zap.Logger) ([]domain.TaskItem, error) {
	tasks := make([]domain.TaskItem, 0)

	os := runtime.GOOS

	for i, namePath := range tasksPath {
		var execCommand *exec.Cmd
		var hasFlags, hasParams bool
		if len(flags) > 0 && flags[0] != "" {
			hasFlags = true
		}
		if len(params) > 0 && params[0] != "" {
			hasParams = true
		}
		if hasFlags && !hasParams {
			if slices.Contains(commands, "go") {
				execCommand = exec.Command(commands[0], commands[1], namePath, flags[i])
			} else if slices.Contains(commands, "python") {
				execCommand = exec.Command(commands[0], commands[1], flags[i], namePath)
			} else if slices.Contains(commands, "gcc") || slices.Contains(commands, "g++") {
				execCommand = exec.Command(commands[0], commands[1], strings.Split(namePath, ".")[0], flags[i], namePath)
			} else {
				execCommand = exec.Command(commands[0], flags[i], namePath)
			}

		}
		if hasParams && !hasFlags {
			if slices.Contains(commands, "go") || slices.Contains(commands, "python") {
				execCommand = exec.Command(commands[0], commands[1], namePath, params[i])
			} else if slices.Contains(commands, "gcc") || slices.Contains(commands, "g++") {
				execCommand = exec.Command(commands[0], commands[1], strings.Split(namePath, ".")[0], namePath)
			} else if slices.Contains(commands, "javac") {
				execCommand = exec.Command(commands[0], namePath)
			} else {
				execCommand = exec.Command(commands[0], namePath, params[i])
			}
		}
		if !hasParams && !hasFlags {
			if slices.Contains(commands, "go") || slices.Contains(commands, "python") {
				execCommand = exec.Command(commands[0], commands[1], namePath)
			} else if slices.Contains(commands, "gcc") || slices.Contains(commands, "g++") {
				execCommand = exec.Command(commands[0], commands[1], strings.Split(namePath, ".")[0], namePath)
			} else {
				execCommand = exec.Command(commands[0], namePath)
			}
		}
		if hasFlags && hasParams {
			if slices.Contains(commands, "go") {
				execCommand = exec.Command(commands[0], commands[1], namePath, flags[i], params[i])
			} else if slices.Contains(commands, "python") {
				execCommand = exec.Command(commands[0], commands[1], flags[i], namePath, params[i])
			} else if slices.Contains(commands, "gcc") || slices.Contains(commands, "g++") {
				execCommand = exec.Command(commands[0], commands[1], strings.Split(namePath, ".")[0], namePath)
			} else if slices.Contains(commands, "javac") {
				execCommand = exec.Command(commands[0], flags[i], namePath)
			} else {
				execCommand = exec.Command(commands[0], flags[i], namePath, params[i])
			}
		}

		var out bytes.Buffer
		var stderr bytes.Buffer
		execCommand.Stdout = &out
		execCommand.Stderr = &stderr

		start := time.Now()
		err := execCommand.Run()
		if err != nil {
			logger.Error("failed to exec command", zap.String("stderr", stderr.String()), zap.Error(err))
			return nil, err
		}

		if len(runCommands) > 0 {
			startCmd := time.Now()
			var newExecCommand *exec.Cmd
			if os == "windows" {
				if len(runCommands) == 2 {
					newExecCommand = exec.Command("cmd", "/K", runCommands[0], runCommands[1])
				} else {
					newExecCommand = exec.Command("cmd", "/K", runCommands[0])
				}
			} else {
				if len(runCommands) == 2 {
					newExecCommand = exec.Command(runCommands[0], runCommands[1])
				} else {
					newExecCommand = exec.Command(runCommands[0])
				}
			}

			err := newExecCommand.Run()
			if err != nil {
				logger.Error("failed to exec command", zap.String("stderr", stderr.String()), zap.Error(err))
				return nil, err
			}
			elapsedCMD := time.Since(startCmd)
			_, folderName := filepath.Split(namePath)
			_, folderName = filepath.Split(folderName)
			if math.Trunc(elapsedCMD.Seconds()) >= float64(1) {
				tasks = append(tasks, domain.TaskItem{
					Name:     folderName,
					Duration: priority_queue.Duration(elapsedCMD.Seconds() - float64(1)).String(),
				})
			} else {
				tasks = append(tasks, domain.TaskItem{
					Name:     folderName,
					Duration: priority_queue.Duration(elapsedCMD.Seconds()).String(),
				})
			}
		} else {
			elapsed := time.Since(start)
			_, folderName := filepath.Split(namePath)
			_, folderName = filepath.Split(folderName)

			if math.Trunc(elapsed.Seconds()) >= float64(1) {
				tasks = append(tasks, domain.TaskItem{
					Name:     folderName,
					Duration: priority_queue.Duration(elapsed.Seconds() - float64(1)).String(),
				})
			} else {
				tasks = append(tasks, domain.TaskItem{
					Name:     folderName,
					Duration: priority_queue.Duration(elapsed.Seconds()).String(),
				})
			}

		}

	}
	return tasks, nil

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

		logger.Debug("file_path_walk", zap.Any("is_dir", info.IsDir()), zap.String("file_path", path))
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
	port := 0
	for _, path := range pathFiles {
		file, err := os.ReadFile(path)
		if err != nil {
			logger.Error(" Couldn't read io.Reader with error : ", zap.Error(err))
			return domain.ApplicationData{}, nil, "", err
		}
		appData := domain.ApplicationData{}
		descr := string(file)
		if strings.Contains(path, ".txt") && !strings.Contains(path, "requirements.txt") {
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
			mainAppData.Port = &port

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

				mainAppData.Port = &port
			} else {
				appsData = append(appsData, &appData)
			}
		}
	}

	return mainApp, appsData, appTxt, nil
}

// CreatePQ returns a priority queue based on map of task names and task durations
func CreatePQ(items []domain.TaskItem) priority_queue.PriorityQueue {
	// Create a priority queue, put the items in it, and
	// establish the priority queue (heap) invariants.
	tasksPriorityQueue := make(priority_queue.PriorityQueue, len(items))
	i := 0
	for _, task := range items {
		taskDuration, _ := time.ParseDuration(task.Duration)
		tasksPriorityQueue[i] = &domain.Item{
			Name:                task.Name,
			TaskDuration:        taskDuration,
			InitialTaskDuration: taskDuration,
			Index:               i,
		}
		i++
	}
	heap.Init(&tasksPriorityQueue)
	return tasksPriorityQueue
}
