package clients

import (
	"bufio"
	"cloudadmin/domain"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"go.uber.org/zap"
)

// DockerClient represents info about Docker Client
type DockerClient struct {
	ctx                  context.Context
	dockerClient         *client.Client
	dockerLogger         *zap.Logger
	dockerRegistryUserID string
	dockerUsername       string
	dockerPass           string
}

// NewDockerClient returns a DockerClient
func NewDockerClient(ctx context.Context, logger *zap.Logger, dockerID, dockerUser, dockerPass string) *DockerClient {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation(),
		client.WithTimeout(time.Minute*60))
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

// BuildImage builds image located in dirName
func (dock *DockerClient) BuildImage(dirName string) error {

	path, _ := os.Getwd()
	srcPath := filepath.Join(path, filepath.Base(dirName))
	tar, err := archive.TarWithOptions(srcPath, &archive.TarOptions{})
	if err != nil {
		dock.dockerLogger.Error("failed to create tar with options", zap.Error(err))
		return err
	}

	opts := types.ImageBuildOptions{
		Dockerfile: "Dockerfile",
		Tags:       []string{dock.dockerRegistryUserID + "/" + strings.ToLower(dirName)},
		Remove:     true,
		Version:    types.BuilderBuildKit,
	}

	res, err := dock.dockerClient.ImageBuild(dock.ctx, tar, opts)
	if err != nil {
		dock.dockerLogger.Error("failed to build image", zap.Error(err))
		return err
	}
	defer res.Body.Close()

	err = print(res.Body, dock.dockerLogger)
	if err != nil {
		return err
	}

	return nil

}

// PushImage pushes image to docker registry
func (dock *DockerClient) PushImage(dirName string) (string, error) {
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
		return "", err
	}

	defer rd.Close()

	err = print(rd, dock.dockerLogger)
	if err != nil {
		return "", err
	}

	return tag, nil
}

// ListImagesAndDelete lists images and delete the one's with dirName
func (dock *DockerClient) ListImagesAndDelete(dirName string) error {
	imageName := dock.dockerRegistryUserID + "/" + strings.ToLower(dirName) + ":latest"
	images, err := dock.dockerClient.ImageList(dock.ctx, types.ImageListOptions{})
	if err != nil {
		dock.dockerLogger.Error("failed to list images", zap.Error(err))
		return err
	}
	for _, image := range images {
		if slices.Contains(image.RepoTags, imageName) {

			_, err = dock.dockerClient.ImageRemove(dock.ctx, image.ID, types.ImageRemoveOptions{})
			if err != nil {
				dock.dockerLogger.Error("failed to remove images", zap.String("image_id", image.ID[:10]), zap.Error(err))
				return err
			}

		}
	}

	return nil
}

func print(rd io.Reader, logger *zap.Logger) error {
	var lastLine string

	scanner := bufio.NewScanner(rd)
	for scanner.Scan() {
		lastLine = scanner.Text()
		logger.Debug(scanner.Text())
	}

	errLine := &domain.ErrorLine{}
	err := json.Unmarshal([]byte(lastLine), errLine)
	if err != nil {
		return err
	}
	if errLine.Error != "" {
		return errors.New(errLine.Error)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}
