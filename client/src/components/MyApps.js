import React, { useState, useEffect } from 'react';
import axios from 'axios';
import AppItem from './AppItem';
import './MyApps.css';

function MyApps() {
  const [apps, setApps] = useState([]);
  const [errorMessage, setErrorMessage] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [typeInput, setTypeInput] = useState('');
  const [timestampInput, setTimestampInput] = useState('');
  const [timestampOn, setTimeStampOn] = useState(false);
  const timeRanges = {
    "1 day" : "1 day",
    "3 days" : "3 day",
    "7 days" : "7 day",
    "14 days" : "14 day",
    "30 days" : "30 day",
    "60 days" : "60 day",
    "90 days" : "90 day"
  };

  

  const handleUploadArchive = () => {
    const selectedFiles = document.getElementById('input').files
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
        },
      };

      

      const formData = new FormData();
      for(var i=0;i<selectedFiles.length;i++){
        formData.append("file", selectedFiles[i]);
      }

      try {
        axios.post('http://localhost:8080/register/app', formData, config_app);
      } catch (error) {
        console.log(error);
        setErrorMessage(error);
      }
    }
  };
  //TODO filtre update ciudat (actualizare sau ceva)
  const fetchApps = async () => {
    const userInfo = JSON.parse(localStorage.getItem('userInfo'));
    const username = userInfo?.username;

    if (typeInput === "created_timestamp" || typeInput === "updated_timestamp") {
      setTimeStampOn(true);
    } else {
      setTimeStampOn(false);
    }

    const config = {
      headers: {
        'Content-type': 'application/json',
        'USER-AUTH': userInfo?.role,
        'USER-UUID': userInfo?.user_id,
      },
    };

    try {
      const response = await axios.get(`http://localhost:8080/user/${username}`, config);
      const my_apps = response.data?.applications;
      if (my_apps !== undefined) {
        const query_my_apps = my_apps.join();

        let config_app = {
          headers: {
            'Content-type': 'application/json',
            'USER-AUTH': userInfo?.role,
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
          } else if (typeInput === 'custom_filter') {
            
            config_app = {
              ...config_app,
              params: {
                ...config_app.params,
                filter: searchInput,
              },
            };
          } else {
            config_app = {
              ...config_app,
              params: {
                ...config_app.params,
                filter: typeInput + '=' + searchInput,
              },
            };
          }
        }

        if (typeInput === 'created_timestamp' || typeInput === 'updated_timestamp') {
          console.log(timeRanges[timestampInput]);
          config_app = {
            ...config_app,
            params: {
              ...config_app.params,
              filter: typeInput + '<=' + timeRanges[timestampInput],
            },
          };
        }
  
        const response_apps = await axios.get('http://localhost:8080/app', config_app);
        setApps(response_apps.data.Response);
      }
     
    } catch (error) {
      console.log(error);
      setErrorMessage(error);
      setApps([]);
    }
  };

  useEffect(() => {
   
    fetchApps();
  }, [searchInput, typeInput, timestampInput]);

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
            <option value="kname">name(keyword)</option>
            <option value="description">Description(keyword)</option>
            <option value="is_running">IsRunning</option>
            <option value="created_timestamp">CreatedTimestamp</option>
            <option value="updated_timestamp">UpdatedTimestamp</option>
            <option value ="custom_filter">CustomFilter</option>
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
        <button type="button" className='button-3' onClick={fetchApps}>
          Submit
        </button>
      </div>
      <div className="form-style">
        <div className="list-items">{renderApps()}</div>
        <input type="file" id="input" multiple={true} />
        <button type="button" className='button-3' onClick={handleUploadArchive}>
          SubmitArchive
        </button>
      </div>
      {errorMessage && <div style={{ backgroundColor: "red" }} className="error"> {errorMessage} </div>}<p>{errorMessage}</p>
    </div>
    
  );
}

export default MyApps;
