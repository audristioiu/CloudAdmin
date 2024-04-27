package clients

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"go.uber.org/zap"
)

// S3Client  represents info about Amazon S3 Client
type S3Client struct {
	bucketName string
	region     string
	ctx        context.Context
	s3Logger   *zap.Logger
	s3Client   *s3.Client
}

// NewS3Client returns S3Client
func NewS3Client(ctx context.Context, accessKey, secretKey, bucket, region string, logger *zap.Logger) (*S3Client, error) {
	creds := credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")
	sdkConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(region), config.WithCredentialsProvider(creds))
	if err != nil {
		logger.Error("failed to load sdk config", zap.Error(err))
		return nil, err
	}
	s3Client := s3.NewFromConfig(sdkConfig)
	return &S3Client{
		bucketName: bucket,
		region:     region,
		ctx:        ctx,
		s3Logger:   logger,
		s3Client:   s3Client,
	}, nil
}

// ListFileFolder iterates through list of objects and extracts folder specified to fileName
func (s *S3Client) ListFileFolder(fileName string) ([]string, error) {
	files := make([]string, 0)
	result, err := s.s3Client.ListObjectsV2(s.ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucketName),
	})
	if err != nil {
		s.s3Logger.Error("failed to list objects", zap.Error(err))
		return nil, err
	}
	for _, object := range result.Contents {
		if strings.Contains(*object.Key, fileName) {
			files = append(files, *object.Key)
		}
	}
	return files, err
}

// UploadFile uploads fileName using bucket and object
func (s *S3Client) UploadFile(fileDir, fileName string, fileBody io.Reader) error {
	uploadManager := manager.NewUploader(s.s3Client)
	_, err := uploadManager.Upload(s.ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(fileDir + "/" + fileName),
		Body:   fileBody,
	})
	if err != nil {
		s.s3Logger.Error("failed to put object", zap.Error(err), zap.String("file_name", fileName))
		return err
	}

	return nil
}

// DownloadFiles downloads files from S3 bucket and writes them to folder
func (s *S3Client) DownloadFiles(mkdirName string, fileNames []string) error {
	err := os.Mkdir(mkdirName, 0666)
	if err != nil {
		s.s3Logger.Error("failed to create directory", zap.Error(err))
		return err
	}
	downloadManager := manager.NewDownloader(s.s3Client)
	for _, fileName := range fileNames {
		localPath := fileName
		file, err := os.Create(localPath)
		if err != nil {
			s.s3Logger.Error("failed to create file", zap.Error(err))
			continue
		}
		defer file.Close()
		_, err = downloadManager.Download(s.ctx, file, &s3.GetObjectInput{
			Bucket: aws.String(s.bucketName),
			Key:    aws.String(fileName),
		})
		if err != nil {
			s.s3Logger.Error("failed to download object", zap.Error(err), zap.String("file_name", fileName))
			return err
		}
	}

	return nil
}

// DeleteFiles deletes files from S3 bucket
func (s *S3Client) DeleteFiles(fileNames []string, fileFolder string) error {
	for _, fileName := range fileNames {
		_, err := s.s3Client.DeleteObject(s.ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(s.bucketName),
			Key:    aws.String(fileName),
		})
		if err != nil {
			s.s3Logger.Error("failed to delete file", zap.Error(err), zap.String("file_name", fileName))
			return err
		}
	}
	// delete folder
	_, err := s.s3Client.DeleteObject(s.ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(fileFolder),
	})
	if err != nil {
		s.s3Logger.Error("failed to delete folder", zap.Error(err), zap.String("folder_name", fileFolder))
		return err
	}
	return nil
}
