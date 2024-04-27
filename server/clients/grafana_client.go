package clients

import (
	"bytes"
	"cloudadmin/domain"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"go.uber.org/zap"
)

const (
	getDataSourceProxyPath    = "/api/datasources/proxy/uid"
	getDataSourceRenderPath   = "/render"
	alertRuleProvisioningPath = "/api/v1/provisioning/alert-rules"
	alertAnnotationsPath      = "/api/annotations"
)

// GrafanaClient  represents info about Grafana Client
type GrafanaClient struct {
	ctx             context.Context
	grafanaLogger   *zap.Logger
	grafanaUser     string
	grafanaPassword string
	dataSourceUID   string
	baseURL         string
	client          *http.Client
}

// NewGrafanaClient returns GrafanaClient
func NewGrafanaClient(ctx context.Context, baseURL, user, pass, dataSource string, logger *zap.Logger) *GrafanaClient {
	httpClient := http.Client{}
	return &GrafanaClient{
		ctx:             ctx,
		grafanaLogger:   logger,
		grafanaUser:     user,
		grafanaPassword: pass,
		dataSourceUID:   dataSource,
		baseURL:         baseURL,
		client:          &httpClient,
	}
}

// APIRequest executes HTTP request and returns response
func APIRequest(baseURL, user, pass, httpPath, method string, params url.Values, logger *zap.Logger, reqBody io.Reader, client *http.Client) ([]byte, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		logger.Error("failed to parse url", zap.Error(err))
		return nil, err
	}
	u.Path = httpPath
	u.RawQuery = params.Encode()

	req, err := http.NewRequest(method, u.String(), reqBody)
	if err != nil {
		logger.Error("failed to create new request", zap.Error(err))
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(user, pass)
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
	resp, err := APIRequest(g.baseURL, g.grafanaUser, g.grafanaPassword, getDataSourceProxyPath+"/"+g.dataSourceUID+getDataSourceRenderPath,
		http.MethodGet, params, g.grafanaLogger, nil, g.client)
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

// CreateAlertRule creates a new alert rule
func (g *GrafanaClient) CreateAlertRule(alertBody domain.GrafanaAlertInfo) (*domain.GrafanaAlertInfo, error) {
	params := url.Values{}
	jsonBodyRequest, _ := json.MarshalIndent(alertBody, "", "  ")
	resp, err := APIRequest(g.baseURL, g.grafanaUser, g.grafanaPassword, alertRuleProvisioningPath,
		http.MethodPost, params, g.grafanaLogger,
		bytes.NewReader(jsonBodyRequest), g.client)
	if err != nil {
		return nil, err
	}
	response := new(domain.GrafanaAlertInfo)
	err = json.Unmarshal(resp, &response)
	if err != nil {
		g.grafanaLogger.Error("failed to unmarshal data into GrafanaAlertInfo", zap.Error(err))
		return nil, err
	}
	g.grafanaLogger.Info("Alert succesfully created", zap.String("alert_title", response.Title))
	return response, err
}

// UpdateAlertRule updates a new alert rule
func (g *GrafanaClient) UpdateAlertRule(ruleID string, alertBody domain.GrafanaAlertInfo) error {
	jsonBodyRequest, _ := json.Marshal(alertBody)
	_, err := APIRequest(g.baseURL, g.grafanaUser, g.grafanaPassword, alertRuleProvisioningPath+"/"+ruleID,
		http.MethodPut, nil, g.grafanaLogger, bytes.NewReader(jsonBodyRequest), g.client)
	if err != nil {
		return err
	}
	g.grafanaLogger.Info("Alert succesfully updated", zap.String("alert", ruleID))
	return nil
}

// GetAlertRuleByID retrieves alert structure by id
func (g *GrafanaClient) GetAlertRuleByID(ruleID string) (*domain.GrafanaAlertInfo, error) {
	params := url.Values{}
	resp, err := APIRequest(g.baseURL, g.grafanaUser, g.grafanaPassword, alertRuleProvisioningPath+"/"+ruleID,
		http.MethodGet, params, g.grafanaLogger, nil, g.client)
	if err != nil {
		return nil, err
	}
	response := new(domain.GrafanaAlertInfo)
	err = json.Unmarshal(resp, &response)
	if err != nil {
		g.grafanaLogger.Error("failed to unmarshal data into GrafanaAlertInformation", zap.Error(err))
		return nil, err
	}
	return response, nil
}

// GetAlertNotification retrieves info about alert using ID
func (g *GrafanaClient) GetAlertNotification(alertID int) ([]*domain.AlertNotification, error) {
	params := url.Values{}
	params.Add("alertId", strconv.Itoa(alertID))
	resp, err := APIRequest(g.baseURL, g.grafanaUser, g.grafanaPassword, alertAnnotationsPath,
		http.MethodGet, params, g.grafanaLogger, nil, g.client)
	if err != nil {
		return nil, err
	}

	var response []*domain.AlertNotification
	err = json.Unmarshal(resp, &response)
	if err != nil {
		g.grafanaLogger.Error("failed to unmarshal data into AlertNotification", zap.Error(err))
		return nil, err
	}
	return response, nil
}

// DeleteAlertRule deletes alert
func (g *GrafanaClient) DeleteAlertRule(ruleID string) error {
	params := url.Values{}
	params.Add("uid", ruleID)
	_, err := APIRequest(g.baseURL, g.grafanaUser, g.grafanaPassword, alertRuleProvisioningPath+"/"+ruleID, http.MethodDelete,
		params, g.grafanaLogger, nil, g.client)
	if err != nil {
		return err
	}

	g.grafanaLogger.Info("Alert succesfully deleted", zap.String("alert", ruleID))
	return nil
}
