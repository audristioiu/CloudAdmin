import React, { useState, useEffect } from 'react';
import axios from 'axios';
import D3GrafanaChartCPU from './D3GrafanaChartCPU';
import '../../assets/Error.scss';

const GrafanaPanelCPU = () => {
  const [panelData, setPanelData] = useState([]);
  const app = JSON.parse(localStorage.getItem("appInfo"));
  const [appName, setAppName] = useState(app.app_name);
  const [errorMessage, setErrorMessage] = useState('');
  useEffect(() => {
    const fetchData = async () => {
      try {
        // Fetch data from Grafana backend
        const response = await axios.get('https://localhost:9443/grafana/datasource', {
          headers: {
            'Content-Type': 'application/json'
          },
          
          params: {
            'appname' : appName,
            'grafana_from' : '-12h',
            "grafana_format" : 'json',
            "grafana_usage_type" : "cpu"
          }
        });
        // Assuming the response data is in JSON format
        const data = response.data
        setPanelData(data)
      } catch (error) {
        setErrorMessage('Error fetching grafana cpu data:' +error.response.data.message);
      }
    };

    fetchData();

    // Cleanup function
    return () => {
      // Cleanup code if needed
    };
  }, []); // Re-run effect if query changes


  // Render your Grafana panel using the fetched data
  return (
    <div>
      <D3GrafanaChartCPU graphiteData={panelData} />
      {errorMessage && <div className="error-message"> <span className = "error-text">{errorMessage}</span> </div>}
    </div>
  );
};
export default GrafanaPanelCPU;