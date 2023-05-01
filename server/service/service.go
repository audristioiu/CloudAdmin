package service

import (
	"cloudadmin/api"
	"cloudadmin/repositories"
	"context"
	"encoding/json"
	"net/http"
	"os"

	runtime "github.com/banzaicloud/logrus-runtime-formatter"
	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
	"github.com/go-openapi/spec"
	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"
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

// StartWebService initializez log , restful api and open api for swagger
func (s *Service) StartWebService() {
	formatter := runtime.Formatter{ChildFormatter: &log.TextFormatter{
		FullTimestamp:          true,
		DisableLevelTruncation: true,
	}}
	formatter.Line = true
	log.SetFormatter(&formatter)
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)

	ws := new(restful.WebService)

	ctx := context.Background()

	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading environment variables file")
		return
	}
	psqlUser := os.Getenv("POSTGRES_USER")
	psqlPass := os.Getenv("POSTGRES_PASSWORD")
	psqlDB := os.Getenv("POSTGRES_DB")
	psqlHost := "localhost"
	psqlPort := 5432

	// initialize repos
	psqlRepo := repositories.NewPostgreSqlRepo(ctx, psqlUser, psqlPass, psqlHost, psqlDB, psqlPort)
	if psqlRepo == nil {
		return
	}
	// initialize api
	apiManager := api.NewAPI(ctx, psqlRepo)
	apiManager.RegisterRoutes(ws)

	restful.DefaultContainer.Add(ws)

	config := restfulspec.Config{
		WebServices:                   restful.RegisteredWebServices(), // you control what services are visible
		APIPath:                       "/apidocs.json",
		PostBuildSwaggerObjectHandler: enrichSwaggerObject}
	actual := restfulspec.BuildSwagger(config)
	log.Println(asJSON(actual))
	restful.DefaultContainer.Add(restfulspec.NewOpenAPIService(config))

	http.Handle("/apidocs/", http.StripPrefix("/apidocs/", http.FileServer(http.Dir("/Users/Alex/Desktop/CloudAdmin/swagger-ui/dist"))))

	// Optionally, you may need to enable CORS for the UI to work.
	cors := restful.CrossOriginResourceSharing{
		AllowedHeaders: []string{"Content-Type", "Accept"},
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
			Description: "Cloud API which servers for schedulling apps",
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
			Version: "1.1.0",
		},
	}
	swo.Tags = []spec.Tag{{TagProps: spec.TagProps{
		Name:        "users",
		Description: "Managing users"}},
		{TagProps: spec.TagProps{
			Name:        "apps",
			Description: "Managing apps"}}}
}
