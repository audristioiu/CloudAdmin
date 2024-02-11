import React, { useState, useEffect } from 'react';
import axios from 'axios';
import AppItem from './AppItem';
import './MyApps.scss';
import { Agent } from 'https';
import certs from '../Certs/certs.js';

function MyApps() {
  const [apps, setApps] = useState([]);
  const [errorMessage, setErrorMessage] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [typeInput, setTypeInput] = useState('');
  const [sortQueryInput, setSortQueryInput] = useState('')
  const [timestampInput, setTimestampInput] = useState('');
  const [timestampOn, setTimeStampOn] = useState(false);
  const timeRanges = {
    "1 day": "1 day",
    "3 days": "3 day",
    "7 days": "7 day",
    "14 days": "14 day",
    "30 days": "30 day",
    "60 days": "60 day",
    "90 days": "90 day"
  };

  const handleUpload = async (isComplex) => {
    const selectedFiles = document.getElementById('input').files;

    if (selectedFiles) {
      const userInfo = JSON.parse(localStorage.getItem('userInfo'));
      const username = userInfo?.username;

      const config_app = {
        headers: {
          'Content-type': 'multipart/form-data',
          'USER-AUTH': userInfo?.role,
          'USER-UUID': userInfo?.user_id,
        },
        params: {
          username: username,
          is_complex: isComplex,
        },
      };

      const agent = new Agent({
        cert: certs.certFile,
        key: certs.keyFile,
      });

      const formData = new FormData();
      for (var i = 0; i < selectedFiles.length; i++) {
        formData.append("file", selectedFiles[i]);
      }

      try {
        await axios.post('https://localhost:9443/register/app', formData, config_app, { httpsAgent: agent });
      } catch (error) {
        setErrorMessage(`Failed to upload app. ${error.response?.data?.message}`);
      }
    }
  };

  const handleSearchApp = (event) => {
    event.preventDefault();
    fetchApps();
  };

  //TODO filtre update ciudat (actualizare sau ceva) si sort nu se updateaza automat
  const buildConfig = (userInfo, typeInput, timestampInput, sortQueryInput) => {
    const config = {
      headers: {
        'Content-type': 'application/json',
        'USER-AUTH': userInfo?.role,
        'USER-UUID': userInfo?.user_id,
      },
      params: {},
    };

    setTimeStampOn(typeInput === 'created_timestamp' || typeInput === 'updated_timestamp');

    if (typeInput === 'created_timestamp' || typeInput === 'updated_timestamp') {
      config.params.filter = `${typeInput}>=${timeRanges[timestampInput]}`;
    }

    if (sortQueryInput.length !== 0) {
      config.params.sort = sortQueryInput;
    }

    return config;
  };

  const buildAppConfig = (userInfo, query_my_apps, username) => ({
    headers: {
      'Content-type': 'application/json',
      'USER-AUTH': userInfo?.role,
      'USER-UUID': userInfo?.user_id,
    },
    params: {
      appnames: query_my_apps,
      username,
    },
  });

  const buildSearchConfig = (config_app, typeInput, searchInput) => {
    if (searchInput.length !== 0) {
      config_app.params = {
        ...config_app.params,
        [typeInput === 'custom_filter' ? 'filter' : 'appnames']: typeInput === 'name' ? searchInput : typeInput === 'custom_filter' ? searchInput : `${typeInput}=${searchInput}`,
      };
    }

    return config_app;
  };

  const fetchApps = async () => {
    const userInfo = JSON.parse(localStorage.getItem('userInfo'));
    const username = userInfo?.username;

    try {
      const agent = new Agent({
        rejectUnauthorized: false,
        cert: certs.certFile,
        key: certs.keyFile,
      });

      const responseUser = await axios.get(`https://localhost:9443/user/${username}`, buildConfig(userInfo, typeInput, timestampInput, sortQueryInput), { httpsAgent: agent });

      const my_apps = responseUser.data?.applications;

      if (my_apps !== undefined) {
        const query_my_apps = my_apps.join();
        let config_app = buildAppConfig(userInfo, query_my_apps, username);
        config_app = buildSearchConfig(config_app, typeInput, searchInput);

        const responseApps = await axios.get('https://localhost:9443/app', config_app, { httpsAgent: agent });
        setApps(responseApps.data.Response);
      }
    } catch (error) {
      setErrorMessage(`Could not retrieve your apps. /${error.response?.data?.message}`);
      setApps([]);
    }
  };

  useEffect(() => {
    fetchApps();
  }, []);

  const renderApps = () => {
    if (apps) {
      return apps.map((app, i) => <AppItem key={i} app={app} />);
    }
  };

  return (
    <div className='myapps_container'>
      <form onSubmit={handleSearchApp}>
        <div className='search_bar'>
          <input
            type="search"
            placeholder="Search apps here"
            onChange={(e) => setSearchInput(e.target.value)}
            value={searchInput}
          />
          <label>
            Pick filter:
            <select value={typeInput} onChange={(e) => setTypeInput(e.target.value)}>
              <option value="name">name</option>
              <option value="kname">name(keyword)</option>
              <option value="description">Description(keyword)</option>
              <option value="is_running">IsRunning</option>
              <option value="created_timestamp">CreatedTimestamp</option>
              <option value="updated_timestamp">UpdatedTimestamp</option>
              <option value="port">Port</option>
              <option value="ip_address">IPAddress</option>
              <option value="schedule_type">ScheduleType</option>
              <option value="custom_filter">CustomFilter</option>
            </select>
          </label>
          {timestampOn &&
            <label>
              Pick Range:
              <select value={timestampInput} onChange={(e) => setTimestampInput(e.target.value)}>
                <option value="1 day">1 day</option>
                <option value="3 days">3 days</option>
                <option value="7 days">7 days</option>
                <option value="14 days">14 days</option>
                <option value="30 days">30 days</option>
                <option value="60 days">60 days</option>
                <option value="90 days">90 days</option>
              </select>
            </label>
          }
          <label>
            Sorting Types:
            <select value={sortQueryInput} onChange={(e) => setSortQueryInput(e.target.value)}>
              <option value="name|asc">Sort names ascending</option>
              <option value="name|desc">Sort names descending</option>
              <option value="created_timestamp|asc">Sort by Created Timestamp ascending</option>
              <option value="created_timestamp|desc">Sort by Created Timestamp descending</option>
              <option value="updated_timestamp|asc">Sort by Last Updated ascending</option>
              <option value="updated_timestamp|desc">Sort by Last Updated descending</option>
            </select>
          </label>
          <button type="submit" className='button-3'>
            Submit
          </button>
        </div>
      </form>
      <div className="table-container">
        <table className="table">
          <thead>
            <tr>
              <th>App Name</th>
              <th>Description</th>
              <th>Status</th>
              <th>CreatedTimestamp</th>
              <th>UpdatedTimestamp</th>
              <th>ScheduleType</th>
              <th>Port</th>
              <th>IPAddress</th>
              <th>&nbsp;</th>
            </tr>
          </thead>
          <tbody>
            {renderApps()}
          </tbody>
        </table>
      </div>
      <form>
        <input type="file" id="input" multiple={true} />
        <button type="button" className='button-3' onClick={() => handleUpload(false)}>
          SubmitArchive
        </button>
        <button type="button" className='button-3' onClick={() => handleUpload(true)}>
          SubmitComplexArchive
        </button>
      </form>

      {errorMessage && <div style={{ backgroundColor: "red" }} className="error"> {errorMessage} </div>}<p>{errorMessage}</p>
    </div>

  );
}

export default MyApps;
