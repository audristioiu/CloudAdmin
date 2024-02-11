import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Agent } from 'https';
import certs from '../Certs/certs';
import './Login.scss';

function Home() {
  const [userDetails, setUserDetails] = useState({
    nrMainAppsOwner: 0,
    nrRunningAppsOwner: 0,
    nrTotalMainApps: 0,
    nrTotalRunningApps: 0,
  });
  const [errorMessage, setErrorMessage] = useState('');

  useEffect(() => {
    const fetchDetails = async () => {
      try {
        const agent = new Agent({
          cert: certs.certFile,
          key: certs.keyFile,
        });
        const userInfo = JSON.parse(localStorage.getItem('userInfo'));
        const username = userInfo?.username;

        if (username) {
          const response = await axios.get(
            'https://localhost:9443/app/aggregates',
            {
              headers: {
                'Content-type': 'application/json',
              },
              params: {
                username,
              },
            },
            { httpsAgent: agent },
          );

          const {
            main_apps_owner_count,
            running_apps_owner_count,
            main_apps_total_count,
            running_apps_total_count,
          } = response.data.QueryInfo;

          setUserDetails({
            nrMainAppsOwner: main_apps_owner_count,
            nrRunningAppsOwner: running_apps_owner_count,
            nrTotalMainApps: main_apps_total_count,
            nrTotalRunningApps: running_apps_total_count,
          });
        }
      } catch (error) {
        setErrorMessage(`Could not retrieve user details. /${error.response?.data?.message}`);
      }
    };

    fetchDetails();
  }, []);

  return (
    <div className="home-container">
      <h1>Welcome to Cloud Admin!</h1>
      <p>This platform helps you upload and deploy applications in the cloud</p>
      <nav>{}</nav>

      <div className="user-details">
        <ul className="user-info">
          <li>Number of applications owned: {userDetails.nrMainAppsOwner} </li>
          <li>Number of running applications owned: {userDetails.nrRunningAppsOwner} </li>
          <li>Total number of applications: {userDetails.nrTotalMainApps} </li>
          <li>Total number of running applications: {userDetails.nrTotalRunningApps} </li>
        </ul>
      </div>
    </div>
  );
}

export default Home;
