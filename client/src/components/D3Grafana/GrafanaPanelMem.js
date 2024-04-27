import React, { useState, useEffect } from 'react';
import axios from 'axios';
import D3GraphChartMem from './D3GrafanaChartMem';

const GrafanaPanelMem = () => {
  const [panelData, setPanelData] = useState([]);
  const app = JSON.parse(localStorage.getItem("appInfo"));
  const [appName, setAppName] = useState(app.app_name);
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
            "grafana_usage_type" : "mem"
          }
        });
        // Assuming the response data is in JSON format
        const data = response.data
        setPanelData(data)
      } catch (error) {
        console.error('Error fetching data:', error);
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
      <D3GraphChartMem graphiteData={panelData} />
    </div>
  );
};
export default GrafanaPanelMem;