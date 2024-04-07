package clients

import (
	"cloudadmin/domain"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"go.uber.org/zap"
)

const (
	getDataSourceProxyPath  = "/api/datasources/proxy/uid"
	getDataSourceRenderPath = "/render"
)

// GrafanaClient  represents info about Grafana Client
type GrafanaClient struct {
	ctx           context.Context
	grafanaLogger *zap.Logger
	dataSourceUID string
	baseURL       string
	client        *http.Client
}

// NewGrafanaClient returns GrafanaClient
func NewGrafanaClient(ctx context.Context, baseURL string, logger *zap.Logger) *GrafanaClient {
	httpClient := http.Client{}
	return &GrafanaClient{
		ctx:           ctx,
		grafanaLogger: logger,
		dataSourceUID: "P6575522ED8660310",
		baseURL:       baseURL,
		client:        &httpClient,
	}
}

// APIRequest executes HTTP request and returns response
func APIRequest(baseURL, httpPath, method string, params url.Values, logger *zap.Logger, client *http.Client) ([]byte, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		logger.Error("failed to parse url", zap.Error(err))
		return nil, err
	}
	u.Path = httpPath
	u.RawQuery = params.Encode()
	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		logger.Error("failed to create new request", zap.Error(err))
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("failed to send HTTP request", zap.Error(err))
		return nil, err
	}
	defer resp.Body.Close()
	byteBody, _ := io.ReadAll(resp.Body)
	return byteBody, nil
}

// GetDataSourceData retrieves data source data for a deployName
func (g *GrafanaClient) GetDataSourceData(deployName, from, format, usageType string) ([]domain.GrafanaDataSourceResponse, error) {
	params := url.Values{}
	var targetName string
	if usageType == "mem" {
		targetName = fmt.Sprintf(`cloudadminapi.default.*.%s.mem_usage.*`, deployName)
	} else if usageType == "cpu" {
		targetName = fmt.Sprintf(`cloudadminapi.default.*.%s.cpu_usage.*`, deployName)
	}
	params.Add("target", targetName)
	params.Add("from", from)
	params.Add("format", format)
	resp, err := APIRequest(g.baseURL, getDataSourceProxyPath+"/"+g.dataSourceUID+getDataSourceRenderPath,
		http.MethodGet, params, g.grafanaLogger, g.client)
	if err != nil {
		return nil, err
	}

	var response []domain.GrafanaDataSourceResponse
	err = json.Unmarshal(resp, &response)
	if err != nil {
		g.grafanaLogger.Error("failed to unmarshal data into []GrafanaDataSourceResponse", zap.Error(err))
		return nil, err
	}
	return response, nil
}
