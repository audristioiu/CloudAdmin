package service

import (
	"cloudadmin/api"
	"cloudadmin/clients"
	"cloudadmin/domain"
	"cloudadmin/helpers"
	"cloudadmin/repositories"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	vt "github.com/VirusTotal/vt-go"
	"github.com/caarlos0/env/v11"
	graphite "github.com/cyberdelia/go-metrics-graphite"
	"github.com/dgraph-io/ristretto"
	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
	"github.com/go-openapi/spec"
	"github.com/joho/godotenv"
	"github.com/rcrowley/go-metrics"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/http2"
)

// Service describes the structure used for starting the web service
type Service struct {
}

// NewService returns a new service object
func NewService() *Service {
	return &Service{}
}

// StartWebService initializez logger,restful and swagger api, postgres and s3 repo, local cache,docker and kubernetes clients + metrics for grafana
func (s *Service) StartWebService() {

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "timestamp"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderCfg.EncodeLevel = zapcore.CapitalLevelEncoder

	loggerConfig := zap.Config{
		Level:             zap.NewAtomicLevelAt(zap.InfoLevel),
		Development:       false,
		DisableCaller:     false,
		DisableStacktrace: false,
		Sampling:          nil,
		Encoding:          "json",
		EncoderConfig:     encoderCfg,
		OutputPaths: []string{
			"stderr",
		},
		ErrorOutputPaths: []string{
			"stderr",
		},
		InitialFields: map[string]interface{}{
			"service_name": "cloudadmin",
		},
	}
	zapLogger := zap.Must(loggerConfig.Build())
	defer zapLogger.Sync()

	ws := new(restful.WebService)

	ctx := context.Background()

	err := godotenv.Load(".env")
	if err != nil {
		zapLogger.Fatal("Error loading environment variables file", zap.Error(err))
		return
	}

	zapLogger.Info("Env variables are loaded")

	//initialize local cache for get info endpoints
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e6,     // Num keys to track frequency of (10k).
		MaxCost:     1 << 19, // Maximum cost of cache (50Mb).
		BufferItems: 64,      // Number of keys per Get buffer.
	})
	if err != nil {
		zapLogger.Fatal("[FATAL] Error initializing ristretto Cache", zap.Error(err))
		return
	}

	zapLogger.Info("Initialized local Ristretto Cache")

	config := domain.Config{}
	err = env.Parse(&config)
	if err != nil {
		zapLogger.Fatal("[FATAL] Error in config parse", zap.Error(err))
	}

	// initialize repos
	psqlRepo := repositories.NewPostgreSqlRepo(ctx, config.PsqlUser, config.PsqlPass, config.DbHost, config.DbName, config.DbPort, zapLogger)
	if psqlRepo == nil {
		zapLogger.Fatal("[FATAL] Error in starting postgres service")
		return
	}
	zapLogger.Info("Initialized Postgres Repo")

	var profilerRepo *repositories.ProfilingService

	if config.EnableCPUProfiler {
		profilerRepo = repositories.NewProfileService("profile_cpu.prof", zapLogger)
		zapLogger.Info("Initialized Profiling Repo")
	} else {
		profilerRepo = repositories.NewProfileService("", zapLogger)
	}

	// initialize clients for kubernetes and docker
	kubernetesClient := clients.NewKubernetesClient(ctx, zapLogger, config.KubeConfigPath, config.RegistryID)
	if kubernetesClient == nil {
		zapLogger.Fatal("[FATAL] Error in creating kubernetes client")
		return
	}
	zapLogger.Info("Initialized Kubernetes client")

	if config.RegistryID == "" || config.DockerUsername == "" || config.DockerPassword == "" {
		zapLogger.Fatal("[FATAL] docker registry_id/username/pass not found")
		return
	}

	dockerClient := clients.NewDockerClient(ctx, zapLogger, config.RegistryID, config.DockerUsername, config.DockerPassword)
	if dockerClient == nil {
		zapLogger.Fatal("[FATAL] Error in creating docker client")
		return
	}
	zapLogger.Info("Initialized Docker client")

	// initialize tcp address for graphite

	graphiteAddr, err := net.ResolveTCPAddr("tcp", config.GraphiteHost)
	if err != nil {
		zapLogger.Fatal("[FATAL] Failed to resolve tcp address for graphite", zap.Error(err))
		return
	}
	zapLogger.Info("Initialized graphite for metrics")

	requestCount := make(map[string]int)

	// initialize Virus Total Client
	var vtClient *vt.Client

	if config.VirusTotalKey != "" {
		vtClient := vt.NewClient(config.VirusTotalKey)
		if vtClient == nil {
			zapLogger.Fatal("[FATAL] Failed to create new virus total client")
			return
		}
		zapLogger.Info("Initialized VT Client")
	} else {
		vtClient = nil
	}

	// initialize S3 Client
	var s3Client *clients.S3Client

	if config.EnableS3 {
		s3Client, err = clients.NewS3Client(ctx, config.AccessKey, config.SecretKey, config.Bucket, config.Region, zapLogger)
		if err != nil {
			zapLogger.Fatal("[FATAL] Error in creating s3 client")
			return
		}
		zapLogger.Info("Initialized S3 Client")
	} else {
		s3Client = nil
	}

	// initialize Grafana Client

	grafanaHTTPClient := clients.NewGrafanaClient(ctx, config.Host, config.GrafanaAdminUser, config.GrafanaAdminPass,
		config.DataSourceUUID, zapLogger)
	zapLogger.Info("Initialized Grafana Client")

	// initialize api
	apiManager := api.NewAPI(ctx, psqlRepo, cache, zapLogger, profilerRepo, dockerClient, kubernetesClient, s3Client,
		graphiteAddr, requestCount, config.MaxRequestPerMinute, config.RegistryID, config.DataSourceUUID, config.FolderUID,
		vtClient, grafanaHTTPClient)
	apiManager.RegisterRoutes(ws)

	restful.DefaultContainer.Add(ws)

	restfulConfig := restfulspec.Config{
		WebServices:                   restful.RegisteredWebServices(), // you control what services are visible
		APIPath:                       "/apidocs.json",
		PostBuildSwaggerObjectHandler: enrichSwaggerObject}
	restfulspec.BuildSwagger(restfulConfig)
	restful.DefaultContainer.Add(restfulspec.NewOpenAPIService(restfulConfig))

	http.Handle("/apidocs/", http.StripPrefix("/apidocs/", http.FileServer(http.Dir("../swagger-ui/dist"))))

	// Optionally, you may need to enable CORS for the UI to work.
	cors := restful.CrossOriginResourceSharing{
		AllowedHeaders: []string{"Content-Type", "Accept", "Accept-Encoding", "USER-AUTH", "USER-UUID"},
		AllowedDomains: []string{"https://localhost:3000", "http://localhost:3000"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		CookiesAllowed: false,
		Container:      restful.DefaultContainer}
	restful.DefaultContainer.Filter(cors.Filter)

	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	server := &http.Server{
		Addr:           ":9443",
		ReadTimeout:    30 * time.Minute,
		WriteTimeout:   30 * time.Minute,
		IdleTimeout:    30 * time.Minute,
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      cfg,
		TLSNextProto:   make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	err = http2.ConfigureServer(server, &http2.Server{})
	if err != nil {
		zapLogger.Fatal("htt2p Configure server", zap.Error(err))
		return
	}

	zapLogger.Info("Started api service on port 9443")

	go func() {
		if err = server.ListenAndServeTLS(config.CertFile, config.CertKeyFile); !errors.Is(err, http.ErrServerClosed) {
			zapLogger.Error("HTTPS server error", zap.Error(err))
		}
		for _, metric := range helpers.MetricsName {
			metrics.Unregister(metric)
		}

		zapLogger.Info("Stopped serving new connections.")
	}()
	kubernetesMetrics := make([]string, 0)

	//goroutine to gather and send kubernetes metrics regarding pods and nodes to Grafana using Graphite
	if config.EnableKubeMetrics {
		go func() {
			for {
				nodeMetricsMap, _ := kubernetesClient.ListNodesMetrics()
				if len(nodeMetricsMap) > 0 {
					for node, nodeMetrics := range nodeMetricsMap {

						nodeCPUMetrics := metrics.GetOrRegisterGaugeFloat64(fmt.Sprintf("%s.cpu_usage", node), nil)
						nodeMemoryMetrics := metrics.GetOrRegisterGaugeFloat64(fmt.Sprintf("%s.mem_usage", node), nil)
						cpuQuantity := math.Round(nodeMetrics[0]*100) / 100
						memQuantity := math.Round(nodeMetrics[1]*100) / 100
						nodeCPUMetrics.Update(cpuQuantity)
						nodeMemoryMetrics.Update(memQuantity)
						go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", graphiteAddr)
						kubernetesMetrics = append(kubernetesMetrics, fmt.Sprintf("%s.cpu_usage", node))
						kubernetesMetrics = append(kubernetesMetrics, fmt.Sprintf("%s.mem_usage", node))
					}
				}
				podMetricsMap, _ := kubernetesClient.ListPodsMetrics()
				if len(podMetricsMap) > 0 {
					for namepace, podContainerMetricsMap := range podMetricsMap {
						for podName, podMetrics := range podContainerMetricsMap {
							for _, podMetricElem := range podMetrics {
								podCPUMetrics := metrics.GetOrRegisterGaugeFloat64(fmt.Sprintf("%s.%s.%s.cpu_usage",
									namepace, podName, podMetricElem.PodContainerName), nil)
								podMemoryMetrics := metrics.GetOrRegisterGaugeFloat64(fmt.Sprintf("%s.%s.%s.mem_usage",
									namepace, podName, podMetricElem.PodContainerName), nil)
								cpuQuantity := math.Round(podMetricElem.CPUMemoryMetrics[2])
								memQuantity := math.Round(podMetricElem.CPUMemoryMetrics[3])

								podCPUMetrics.Update(cpuQuantity)
								podMemoryMetrics.Update(memQuantity)
								go graphite.Graphite(metrics.DefaultRegistry, time.Second, "cloudadminapi", graphiteAddr)
								kubernetesMetrics = append(kubernetesMetrics, fmt.Sprintf("%s.%s.%s.cpu_usage", namepace, podName, podMetricElem.PodContainerName))
								kubernetesMetrics = append(kubernetesMetrics, fmt.Sprintf("%s.%s.%s.mem_usage", namepace, podName, podMetricElem.PodContainerName))
							}

						}
					}
				}
				time.Sleep(time.Second * 60)
			}
		}()
	}

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownRelease()

	if err := server.Shutdown(shutdownCtx); err != nil {
		zapLogger.Error("HTTP shutdown error: %v", zap.Error(err))
	}
	for _, metric := range kubernetesMetrics {
		metrics.Unregister(metric)
	}

	zapLogger.Info("Graceful shutdown complete.")
}

// enrichSwaggerObject describes swagger specs
func enrichSwaggerObject(swo *spec.Swagger) {
	swo.Info = &spec.Info{
		InfoProps: spec.InfoProps{
			Title:       "Cloud Admin API",
			Description: "Cloud API which serves for schedulling apps",
			Contact: &spec.ContactInfo{
				ContactInfoProps: spec.ContactInfoProps{
					Name:  "Alexandru-Mihai Cioplean, Alexandru Udristioiu",
					Email: "alexandru.cioplean@gmail.com, udristioiualexandru@gmail.com",
				},
			},
			License: &spec.License{
				LicenseProps: spec.LicenseProps{
					Name: "MIT",
					URL:  "http://mit.org",
				},
			},
			Version: "2.0.0",
		},
	}
	swo.Tags = []spec.Tag{{TagProps: spec.TagProps{
		Name:        "users",
		Description: "Managing users"}},
		{TagProps: spec.TagProps{
			Name:        "apps",
			Description: "Managing apps"}},
		{TagProps: spec.TagProps{
			Name:        "schedule",
			Description: "schedulling apps",
		}}}
}
