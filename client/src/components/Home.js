import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {Agent} from 'https';
import certs from '../Certs/certs';
import './Login.css';

function Home() {

  const [nrMainAppsOwner, setNrMainAppsOwner] = useState(0);
  const [nrRunningAppsOwner, setRunningAppsOwner] = useState(0);
  const [nrTotalMainApps, setNrTotalMainApps] = useState(0);
  const [nrTotalRunningApps, setNrTotalRunningApps] = useState(0);
  const [errorMessage, setErrorMessage] = useState('');

  useEffect(() => {
    const fetchDetails = async () => {
      try {

        const agent = new Agent({
          cert: certs.certFile,
          key: certs.keyFile,
        })
        const userInfo = JSON.parse(localStorage.getItem('userInfo'));
        const username = userInfo?.username;

        if (username) {


          //trigger last time online update
          const response =await axios.get(
            "https://localhost:443/app/aggregates",
            {
              headers: {
                "Content-type": "application/json",
              },
              params: {
                "username": username,
              },
            },
            { httpsAgent : agent },
          );

          console.log(response)
          const mainAppsOwnerCount = response.data.QueryInfo?.main_apps_owner_count
          const runningAppsOwnerCount = response.data.QueryInfo?.running_apps_owner_count
          const mainAppsTotalCount = response.data.QueryInfo?.main_apps_total_count;
          const runningAppsTotalCount = response.data.QueryInfo?.running_apps_total_count;
        setNrMainAppsOwner(mainAppsOwnerCount);
        setRunningAppsOwner(runningAppsOwnerCount);
        setNrTotalMainApps(mainAppsTotalCount);
        setNrTotalRunningApps(runningAppsTotalCount);
            
        }
      } catch (error) {
        setErrorMessage("Could not retrieve user details. /" + error.response.data.message);
      }
    };

    fetchDetails();
  }, []);

  return (
    <div className="login-box">
      <h1>Welcome to Cloud Admin!</h1>
      <p>This platform helps you upload and deploy applications in cloud</p>
      <nav>
      </nav>

       <div className="user-details">
        <div className="user-info">
        <p>Nr of applications owned : {nrMainAppsOwner} </p>
        <p>Nr of running applications owned : {nrRunningAppsOwner} </p>
        <p>Total number of applications : {nrTotalMainApps} </p>
        <p>Total number of running applications : {nrTotalRunningApps} </p>
        </div>
      </div>
    </div>

    

  );
}

export default Home;