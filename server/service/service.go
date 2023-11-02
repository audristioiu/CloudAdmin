package service

import (
	"cloudadmin/api"
	"cloudadmin/clients"
	"cloudadmin/repositories"
	"context"
	"net/http"
	"os"
	"time"

	"github.com/dgraph-io/ristretto"
	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
	"github.com/go-openapi/spec"
	"github.com/joho/godotenv"
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

// StartWebService initializez logger,restful and swagger api, postgres and s3 repo, local cache,docker and kubernetes clients
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

	// initialize api
	apiManager := api.NewAPI(ctx, psqlRepo, cache, log, profilerRepo, dockerClient, kubernetesClient)
	apiManager.RegisterRoutes(ws)

	restful.DefaultContainer.Add(ws)

	config := restfulspec.Config{
		WebServices:                   restful.RegisteredWebServices(), // you control what services are visible
		APIPath:                       "/apidocs.json",
		PostBuildSwaggerObjectHandler: enrichSwaggerObject}
	restfulspec.BuildSwagger(config)
	restful.DefaultContainer.Add(restfulspec.NewOpenAPIService(config))

	http.Handle("/apidocs/", http.StripPrefix("/apidocs/", http.FileServer(http.Dir("/Users/udris/Desktop/CloudAdmin/swagger-ui/dist"))))

	// Optionally, you may need to enable CORS for the UI to work.
	cors := restful.CrossOriginResourceSharing{
		AllowedHeaders: []string{"Content-Type", "Accept", "USER-AUTH", "USER-UUID"},
		AllowedDomains: []string{"https://localhost:3000"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		CookiesAllowed: false,
		Container:      restful.DefaultContainer}
	restful.DefaultContainer.Filter(cors.Filter)

	server := &http.Server{
		Addr:           ":443",
		ReadTimeout:    15 * time.Minute,
		WriteTimeout:   15 * time.Minute,
		IdleTimeout:    15 * time.Minute,
		MaxHeaderBytes: 1 << 20,
	}

	http2.ConfigureServer(server, &http2.Server{})
	certFile := os.Getenv("CERT_FILE")
	certKeyFile := os.Getenv("CERT_KEY_FILE")

	log.Info("Started api service on port 443")
	err = server.ListenAndServeTLS(certFile, certKeyFile)
	if err != nil {
		log.Fatal("ListenAndServe: ", zap.Error(err))
	}
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
