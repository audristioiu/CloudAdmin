package clients

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"go.uber.org/zap"
)

// debug purposes
type ErrorLine struct {
	Error       string      `json:"error"`
	ErrorDetail ErrorDetail `json:"errorDetail"`
}

type ErrorDetail struct {
	Message string `json:"message"`
}

// DockerClient represents info about Docker
type DockerClient struct {
	ctx                  context.Context
	dockerClient         *client.Client
	dockerLogger         *zap.Logger
	dockerRegistryUserID string
	dockerUsername       string
	dockerPass           string
}

func NewDockerClient(ctx context.Context, logger *zap.Logger, dockerID, dockerUser, dockerPass string) *DockerClient {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		logger.Error("failed to create new docker client", zap.Error(err))
		return nil
	}
	return &DockerClient{
		ctx:                  ctx,
		dockerClient:         cli,
		dockerLogger:         logger,
		dockerRegistryUserID: dockerID,
		dockerUsername:       dockerUser,
		dockerPass:           dockerPass,
	}
}

func (dock *DockerClient) BuildImage(dirName string) error {
	//todo remove
	path := `C:\Users\udris\Desktop\CloudAdmin\server\`
	tar, err := archive.TarWithOptions(path+dirName, &archive.TarOptions{})
	if err != nil {
		dock.dockerLogger.Error("failed to create tar with options", zap.Error(err))
		return err
	}

	opts := types.ImageBuildOptions{
		Dockerfile: "Dockerfile",
		Tags:       []string{dock.dockerRegistryUserID + "/" + strings.ToLower(dirName)},
		Remove:     true,
	}

	res, err := dock.dockerClient.ImageBuild(dock.ctx, tar, opts)
	if err != nil {
		dock.dockerLogger.Error("failed to build image", zap.Error(err))
		return err
	}
	defer res.Body.Close()

	err = print(res.Body)
	if err != nil {
		return err
	}

	return nil

}

func (dock *DockerClient) PushImage(dirName string) error {
	authConfig := registry.AuthConfig{
		Username: dock.dockerUsername,
		Password: dock.dockerPass,
	}
	authConfigBytes, _ := json.Marshal(authConfig)
	authConfigEncoded := base64.URLEncoding.EncodeToString(authConfigBytes)
	tag := dock.dockerRegistryUserID + "/" + strings.ToLower(dirName)
	opts := types.ImagePushOptions{RegistryAuth: authConfigEncoded}
	rd, err := dock.dockerClient.ImagePush(dock.ctx, tag, opts)
	if err != nil {
		dock.dockerLogger.Error("failed to push image", zap.Error(err))
		return err
	}

	defer rd.Close()

	err = print(rd)
	if err != nil {
		return err
	}

	return nil
}

// for debug
func print(rd io.Reader) error {
	var lastLine string

	scanner := bufio.NewScanner(rd)
	for scanner.Scan() {
		lastLine = scanner.Text()
		fmt.Println(scanner.Text())
	}

	errLine := &ErrorLine{}
	json.Unmarshal([]byte(lastLine), errLine)
	if errLine.Error != "" {
		return errors.New(errLine.Error)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}
