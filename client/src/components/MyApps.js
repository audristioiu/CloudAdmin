import React, { useState, useEffect } from 'react';
import axios from 'axios';
import AppItem from './AppItem';
import './MyApps.css';

function MyApps() {
  const [apps, setApps] = useState([]);
  const [errorMessage, setErrorMessage] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [typeInput, setTypeInput] = useState('');

  const handleUploadArchive = () => {
    const selectedFile = document.getElementById('input').files[0];
    if (selectedFile) {
      const userInfo = JSON.parse(localStorage.getItem('userInfo'));
      const username = userInfo?.username;

      const config_app = {
        headers: {
          'Content-type': 'multipart/form-data',
          Authorization: userInfo?.role,
          'USER-UUID': userInfo?.user_id,
        },
        params: {
          username: username,
        },
      };
      const formData = new FormData();
      formData.append('file', selectedFile);

      try {
        axios.post('http://localhost:8080/register/app', formData, config_app);
      } catch (error) {
        console.log(error);
        setErrorMessage(error);
      }
    }
  };

  const fetchApps = async () => {
    const userInfo = JSON.parse(localStorage.getItem('userInfo'));
    const username = userInfo?.username;

    const config = {
      headers: {
        'Content-type': 'application/json',
        Authorization: userInfo?.role,
        'USER-UUID': userInfo?.user_id,
      },
    };

    try {
      const response = await axios.get(`http://localhost:8080/user/${username}`, config);
      const my_apps = response.data?.applications;
      const query_my_apps = my_apps.join();

      let config_app = {
        headers: {
          'Content-type': 'application/json',
          Authorization: userInfo?.role,
          'USER-UUID': userInfo?.user_id,
        },
        params: {
          appnames: query_my_apps,
          username: username,
        },
      };

      if (searchInput.length !== 0) {
        if (typeInput.length === 0 || typeInput === 'name') {
          config_app = {
            ...config_app,
            params: {
              ...config_app.params,
              appnames: searchInput,
            },
          };
        } else {
          config_app = {
            ...config_app,
            params: {
              ...config_app.params,
              filter: typeInput + ':' + searchInput,
            },
          };
        }
      }

      const response_apps = await axios.get('http://localhost:8080/app', config_app);
      setApps(response_apps.data.Response);
    } catch (error) {
      console.log(error);
      setErrorMessage(error);
      setApps([]);
    }
  };

  useEffect(() => {
    fetchApps();
  }, [searchInput, typeInput]);

  const renderApps = () => {
    if (apps) {
      return apps.map((app, i) => <AppItem key={i} app={app} />);
    }
  };

  return (
    <div className='myapps_container'>
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
            <option value="description">Description(keyword)</option>
            <option value="is_running">IsRunning</option>
          </select>
        </label>
        <button type="button" className='button-3' onClick={fetchApps}>
          Submit
        </button>
      </div>
      <div className="form-style">
        <div className="list-items">{renderApps()}</div>
        <input type="file" id="input" multiple={false} />
        <button type="button" className='button-3' onClick={handleUploadArchive}>
          SubmitArchive
        </button>
      </div>
    </div>
  );
}

export default MyApps;
