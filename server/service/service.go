package service

import (
	"cloudadmin/api"
	"cloudadmin/repositories"
	"context"
	"encoding/json"
	"net/http"
	"os"

	runtime "github.com/banzaicloud/logrus-runtime-formatter"
	"github.com/dgraph-io/ristretto"
	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
	"github.com/go-openapi/spec"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

// Service describes the structure used for starting the web service
type Service struct {
}

// NewService returns a new service object
func NewService() *Service {
	return &Service{}
}

func asJSON(v interface{}) string {
	data, _ := json.MarshalIndent(v, " ", " ")
	return string(data)
}

// StartWebService initializez loggger,restful and swagger api, postgres and s3 repo, local cache,docker and kubernetes clients
func (s *Service) StartWebService() {
	log := logrus.New()
	formatter := runtime.Formatter{ChildFormatter: &logrus.TextFormatter{
		FullTimestamp:          true,
		DisableLevelTruncation: true,
	}}
	formatter.Line = true
	log.SetFormatter(&formatter)
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.TraceLevel)
	log.SetReportCaller(true)

	ws := new(restful.WebService)

	ctx := context.Background()

	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("[FATAL] Error loading environment variables file with error %v", err)
		return
	}

	log.Debugln("Env variables are loaded")

	//initialize local cache for get info endpoints
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e6,     // Num keys to track frequency of (10k).
		MaxCost:     1 << 19, // Maximum cost of cache (50Mb).
		BufferItems: 64,      // Number of keys per Get buffer.
	})
	if err != nil {
		log.Fatalf("[FATAL] Error intializing ristretto Cache with error %v", err)
		return
	}

	log.Debugln("Local Ristretto Cache initalized")

	psqlUser := os.Getenv("POSTGRES_USER")
	psqlPass := os.Getenv("POSTGRES_PASSWORD")
	psqlDB := os.Getenv("POSTGRES_DB")
	psqlHost := "localhost"
	psqlPort := 5432

	// initialize repos
	psqlRepo := repositories.NewPostgreSqlRepo(ctx, psqlUser, psqlPass, psqlHost, psqlDB, psqlPort, log)
	if psqlRepo == nil {
		log.Fatalf("[FATAL] Error in starting postgres service")
		return
	}

	log.Debugln("Postgres Repo initalized")

	// initialize api
	apiManager := api.NewAPI(ctx, psqlRepo, cache, log)
	apiManager.RegisterRoutes(ws)

	restful.DefaultContainer.Add(ws)

	config := restfulspec.Config{
		WebServices:                   restful.RegisteredWebServices(), // you control what services are visible
		APIPath:                       "/apidocs.json",
		PostBuildSwaggerObjectHandler: enrichSwaggerObject}
	actual := restfulspec.BuildSwagger(config)
	log.Println(asJSON(actual))
	restful.DefaultContainer.Add(restfulspec.NewOpenAPIService(config))

	http.Handle("/apidocs/", http.StripPrefix("/apidocs/", http.FileServer(http.Dir("/Users/udris/Desktop/CloudAdmin/swagger-ui-5.0.0/dist"))))

	// Optionally, you may need to enable CORS for the UI to work.
	cors := restful.CrossOriginResourceSharing{
		ExposeHeaders:  []string{"Authorization", "USER-UUID"},
		AllowedHeaders: []string{"Content-Type", "Accept", "Authorization", "USER-UUID"},
		AllowedDomains: []string{"http://localhost:3000"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		CookiesAllowed: false,
		Container:      restful.DefaultContainer}
	restful.DefaultContainer.Filter(cors.Filter)

	log.Printf("Started api service on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
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
			Version: "1.6.0",
		},
	}
	swo.Tags = []spec.Tag{{TagProps: spec.TagProps{
		Name:        "users",
		Description: "Managing users"}},
		{TagProps: spec.TagProps{
			Name:        "apps",
			Description: "Managing apps"}}}
}
