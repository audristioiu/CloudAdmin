package service

import (
	"cloudadmin/api"
	"cloudadmin/clients"
	"cloudadmin/helpers"
	"cloudadmin/repositories"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	vt "github.com/VirusTotal/vt-go"
	"github.com/dgraph-io/ristretto"
	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
	"github.com/go-openapi/spec"
	"github.com/joho/godotenv"
	"github.com/rcrowley/go-metrics"
	"go.uber.org/zap"
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

	log, _ := zap.NewDevelopment()
	defer log.Sync()

	ws := new(restful.WebService)

	ctx := context.Background()

	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading environment variables file", zap.Error(err))
		return
	}

	log.Debug("Env variables are loaded")

	//initialize local cache for get info endpoints
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e6,     // Num keys to track frequency of (10k).
		MaxCost:     1 << 19, // Maximum cost of cache (50Mb).
		BufferItems: 64,      // Number of keys per Get buffer.
	})
	if err != nil {
		log.Fatal("Error intializing ristretto Cache", zap.Error(err))
		return
	}

	log.Debug("Local Ristretto Cache initalized")

	psqlUser := os.Getenv("POSTGRES_USER")
	psqlPass := os.Getenv("POSTGRES_PASSWORD")
	psqlDB := os.Getenv("POSTGRES_DB")
	psqlHost := "localhost"
	psqlPort := 5432

	// initialize repos
	psqlRepo := repositories.NewPostgreSqlRepo(ctx, psqlUser, psqlPass, psqlHost, psqlDB, psqlPort, log)
	if psqlRepo == nil {
		log.Fatal("[FATAL] Error in starting postgres service")
		return
	}
	log.Debug("Postgres Repo initialized")

	var profilerRepo *repositories.ProfilingService
	activateCPUProfiler := os.Getenv("ACTIVATE_CPU_PROFILER")
	if activateCPUProfiler == "true" {
		profilerRepo = repositories.NewProfileService("profile_cpu.prof", log)
		log.Debug("Profiling Repo initialized")
	} else {
		profilerRepo = repositories.NewProfileService("", log)
	}

	dockerRegID := os.Getenv("DOCKER_REGISTRY_ID")

	// initialize clients for kubernetes and docker
	kubeConfigPath := os.Getenv("KUBE_CONFIG_PATH")
	kubernetesClient := clients.NewKubernetesClient(ctx, log, kubeConfigPath, dockerRegID)
	if kubernetesClient == nil {
		log.Fatal("[FATAL] Error in creating kubernetes client")
		return
	}
	log.Debug("Kubernetes client initialized")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*10)
	defer cancel()

	dockerUsername := os.Getenv("DOCKER_USERNAME")
	dockerPassword := os.Getenv("DOCKER_PASSWORD")
	if dockerRegID == "" || dockerUsername == "" || dockerPassword == "" {
		log.Fatal("[FATAL] docker registry_id/username/pass not found")
		return
	}

	dockerClient := clients.NewDockerClient(ctx, log, dockerRegID, dockerUsername, dockerPassword)
	if dockerClient == nil {
		log.Fatal("[FATAL] Error in creating docker client")
		return
	}
	log.Debug("Docker client initialized")

	// initialize tcp address for graphite
	graphiteHost := os.Getenv("GRAPHITE_HOST")
	graphiteAddr, err := net.ResolveTCPAddr("tcp", graphiteHost)
	if err != nil {
		log.Fatal("[FATAL] Failed to resolve tcp address for graphite", zap.Error(err))
		return
	}
	log.Debug("Initialize graphite for metrics")

	requestCount := make(map[string]int)
	maxRequestPerMinute := 10

	// initialize virus total client
	vtAPIKey := os.Getenv("VIRUSTOTAL_KEY")
	vtClient := vt.NewClient(vtAPIKey)
	if vtClient == nil {
		log.Fatal("[FATAL] Failed to create new virus total client")
		return
	}

	// initialize api
	apiManager := api.NewAPI(ctx, psqlRepo, cache, log, profilerRepo, dockerClient, kubernetesClient,
		graphiteAddr, requestCount, maxRequestPerMinute, vtClient)
	apiManager.RegisterRoutes(ws)

	restful.DefaultContainer.Add(ws)

	config := restfulspec.Config{
		WebServices:                   restful.RegisteredWebServices(), // you control what services are visible
		APIPath:                       "/apidocs.json",
		PostBuildSwaggerObjectHandler: enrichSwaggerObject}
	restfulspec.BuildSwagger(config)
	restful.DefaultContainer.Add(restfulspec.NewOpenAPIService(config))

	http.Handle("/apidocs/", http.StripPrefix("/apidocs/", http.FileServer(http.Dir("../swagger-ui/dist"))))

	// Optionally, you may need to enable CORS for the UI to work.
	cors := restful.CrossOriginResourceSharing{
		AllowedHeaders: []string{"Content-Type", "Accept", "USER-AUTH", "USER-UUID"},
		AllowedDomains: []string{"https://localhost:3000"},
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
		Addr:           ":443",
		ReadTimeout:    15 * time.Minute,
		WriteTimeout:   15 * time.Minute,
		IdleTimeout:    15 * time.Minute,
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      cfg,
		TLSNextProto:   make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	err = http2.ConfigureServer(server, &http2.Server{})
	if err != nil {
		log.Fatal("htt2p Configure server", zap.Error(err))
		return
	}
	certFile := os.Getenv("CERT_FILE")
	certKeyFile := os.Getenv("CERT_KEY_FILE")

	log.Info("Started api service on port 443")

	go func() {
		if err = server.ListenAndServeTLS(certFile, certKeyFile); !errors.Is(err, http.ErrServerClosed) {
			log.Error("HTTP server error", zap.Error(err))
		}
		for _, metric := range helpers.MetricsName {
			metrics.Unregister(metric)
		}

		log.Debug("Stopped serving new connections.")
	}()

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownRelease()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Error("HTTP shutdown error: %v", zap.Error(err))
	}

	log.Debug("Graceful shutdown complete.")
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
			Version: "1.9.2",
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
