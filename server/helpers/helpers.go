package helpers

import (
	"bytes"
	"cloudadmin/domain"
	"cloudadmin/priority_queue"
	"container/heap"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
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

	_, err = dockerFile.Write([]byte(sb.String()[:len(sb.String())-1]))
	if err != nil {
		logger.Error("could not writeString", zap.Error(err))
		return err
	}
	return nil
}

// todo remove
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
func GenerateDockerFile(dirName string, appData *domain.ApplicationData, logger *zap.Logger) (string, []priority_queue.TaskItem, error) {

	var taskExecutionTime []priority_queue.TaskItem

	mkDirName := dirName + "-" + strings.Split(appData.Name, ".")[1]
	var packageJs []string
	var runJs, runPy string
	hasPkg := false
	hasReqs := false
	//todo luat fisier de pe local(in viitor s3) si scris la locatie
	err := os.Mkdir(mkDirName, 0666)
	if err != nil {
		logger.Error("failed to create directory", zap.Error(err))
		return "", nil, err
	}
	path, _ := os.Getwd()
	path = strings.ReplaceAll(path, "CloudAdmin", "")
	path = strings.ReplaceAll(path, "server", "")
	path = path[:len(path)-1]
	copy(path+appData.Name, filepath.Join(mkDirName, filepath.Base(appData.Name)))
	dockFile, err := os.Create(filepath.Join(mkDirName, filepath.Base("Dockerfile")))
	if err != nil {
		logger.Error("could not create temp file", zap.Error(err))
		return "", nil, err
	}

	appName := appData.Name
	extension := strings.Split(appName, ".")[1]
	if extension == "js" && hasPkg {
		copy(path+"package.json", filepath.Join(mkDirName, filepath.Base("package.json")))
		copy(path+"package-lock.json", filepath.Join(mkDirName, filepath.Base("package-lock.json")))
		packageJs = []string{"package.json package.json", "package-lock.json package-lock.json"}
		runJs = "npm install"
	}
	if extension == "py" && hasReqs {
		copy(path+"requirements.txt", filepath.Join(mkDirName, filepath.Base("requirements.txt")))
		runPy = "pip install -r requirements.txt"
	}
	if extension == "go" {
		copy(path+"go.mod", filepath.Join(mkDirName, filepath.Base("go.mod")))
		copy(path+"go.sum", filepath.Join(mkDirName, filepath.Base("go.sum")))
	}
	switch mapCodeExtension[extension] {
	case "nodejs":
		{
			execName := strings.Split(appName, ".")[0]
			dockProps := domain.DockerFile{
				From:     "node:latest",
				Workdir:  "/" + execName + "/",
				CopyArgs: packageJs,
				Copy:     ". " + "/" + execName,
				Run:      runJs,
				Cmd:      []string{"node", appName},
			}

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", nil, err
			}
			taskExecutionTime, err = GetExecutionTimeForTasks([]string{"node"}, []string{appData.FlagArguments}, []string{appData.ParamArguments},
				[]string{filepath.Join(mkDirName, filepath.Base(appData.Name))}, logger)
			if err != nil {
				return "", nil, err
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
				Run:     "go mod download",
				Cmd:     newCMD,
			}

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", nil, err
			}
			taskExecutionTime, err = GetExecutionTimeForTasks(newCMD, []string{appData.FlagArguments}, []string{appData.ParamArguments},
				[]string{filepath.Join(mkDirName, filepath.Base(appData.Name))}, logger)
			if err != nil {
				return "", nil, err
			}

		}

	case "python":
		{
			execName := strings.Split(appName, ".")[0]
			newCMD := []string{"python", "-u"}
			newCMD = append(newCMD, appName)
			if appData.FlagArguments != "" {
				newCMD = append(newCMD, appData.FlagArguments)
			}
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

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", nil, err
			}
			taskExecutionTime, err = GetExecutionTimeForTasks(newCMD, []string{appData.FlagArguments}, []string{appData.ParamArguments},
				[]string{filepath.Join(mkDirName, filepath.Base(appData.Name))}, logger)
			if err != nil {
				return "", nil, err
			}

		}
	case "java":
		{
			execName := strings.Split(appName, ".")[0]
			newCMD := []string{"java"}
			newCMD = append(newCMD, execName)
			if appData.FlagArguments != "" {
				newCMD = append(newCMD, appData.FlagArguments)
			}
			if appData.ParamArguments != "" {
				newCMD = append(newCMD, appData.ParamArguments)
			}
			dockProps := domain.DockerFile{
				From:    "openjdk:11-jdk-slim",
				Workdir: "/" + execName + "/",
				Copy:    ". /" + execName,
				Run:     "javac " + appName,
				Cmd:     newCMD,
			}

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", nil, err
			}
			taskExecutionTime, err = GetExecutionTimeForTasks(newCMD, []string{appData.FlagArguments}, []string{appData.ParamArguments},
				[]string{filepath.Join(mkDirName, filepath.Base(appData.Name))}, logger)
			if err != nil {
				return "", nil, err
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

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", nil, err
			}
			taskExecutionTime, err = GetExecutionTimeForTasks(newCMD, []string{appData.FlagArguments}, []string{appData.ParamArguments},
				[]string{filepath.Join(mkDirName, filepath.Base(appData.Name))}, logger)
			if err != nil {
				return "", nil, err
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

			err := WriteDockerFile(dockFile, dockProps, logger)
			if err != nil {
				return "", nil, err
			}
			taskExecutionTime, err = GetExecutionTimeForTasks(newCMD, []string{appData.FlagArguments}, []string{appData.ParamArguments},
				[]string{filepath.Join(mkDirName, filepath.Base(appData.Name))}, logger)
			if err != nil {
				return "", nil, err
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
func GetExecutionTimeForTasks(commands, flags, params, tasksPath []string, logger *zap.Logger) ([]priority_queue.TaskItem, error) {
	tasks := make([]priority_queue.TaskItem, 0)

	for i, namePath := range tasksPath {
		cmd := strings.Split(commands[i], " ")
		var execCommand *exec.Cmd
		var hasFlags, hasParams bool
		if len(flags) > 0 {
			hasFlags = true
		}
		if len(params) > 0 {
			hasParams = true
		}
		if hasFlags && !hasParams {
			if slices.Contains(cmd, "go") {
				execCommand = exec.Command(cmd[0], cmd[1], flags[i], namePath)
			} else {
				execCommand = exec.Command(cmd[0], flags[i], namePath)
			}

		}
		if hasParams && !hasFlags {
			if slices.Contains(cmd, "go") {
				execCommand = exec.Command(cmd[0], cmd[1], params[i], namePath)
			} else {
				execCommand = exec.Command(cmd[0], params[i], namePath)
			}
		}
		if !hasParams && !hasFlags {
			if slices.Contains(cmd, "go") {
				execCommand = exec.Command(cmd[0], cmd[1], namePath)
			} else {
				execCommand = exec.Command(cmd[0], namePath)
			}
		}
		if hasFlags && hasParams {
			if slices.Contains(cmd, "go") {
				execCommand = exec.Command(cmd[0], cmd[1], flags[i], params[i], namePath)
			} else {
				execCommand = exec.Command(cmd[0], flags[i], params[i], namePath)
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

		elapsed := time.Since(start)

		folderNames := strings.Split(namePath, `\`)
		tasks = append(tasks, priority_queue.TaskItem{
			Name:     folderNames[len(folderNames)-1],
			Duration: priority_queue.Duration(elapsed.Seconds() - float64(1)).String(),
		})
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

// GetFreePort asks the kernel for a free open port that is ready to use.
func GetFreePort() (port int, err error) {
	var a *net.TCPAddr
	if a, err = net.ResolveTCPAddr("tcp", "localhost:0"); err == nil {
		var l *net.TCPListener
		if l, err = net.ListenTCP("tcp", a); err == nil {
			defer l.Close()
			return l.Addr().(*net.TCPAddr).Port, nil
		}
	}
	return
}

// CreatePQ returns a priority queue based on map of task names and task durations
func CreatePQ(items []priority_queue.TaskItem) priority_queue.PriorityQueue {
	// Create a priority queue, put the items in it, and
	// establish the priority queue (heap) invariants.
	tasksPriorityQueue := make(priority_queue.PriorityQueue, len(items))
	i := 0
	for _, task := range items {
		floatDuration, _ := strconv.ParseFloat(task.Duration, 64)
		tasksPriorityQueue[i] = &priority_queue.Item{
			Name:         task.Name,
			TaskDuration: priority_queue.Duration(floatDuration),
			Index:        i,
		}
		i++
	}
	heap.Init(&tasksPriorityQueue)
	return tasksPriorityQueue
}
