import React, { useState, useEffect } from 'react';
import axios from 'axios';
import AppItem from './AppItem.js';
import '../../assets/MyApps.scss';
import '../../assets/Error.scss';
import { Agent } from 'https';
import certs from '../../Certs/certs.js';
import ReactPaginate from 'react-paginate';

function MyApps() {
  const [apps, setApps] = useState([]);
  const [selectAll, setSelectAll] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [typeInput, setTypeInput] = useState('');
  const [sortQueryInput, setSortQueryInput] = useState('')
  const [timestampInput, setTimestampInput] = useState('');
  const [timestampOn, setTimeStampOn] = useState(false);
  const [selectedFilterType, setSelectedFilterType] = useState('normal');
  const [itemOffset, setItemOffset] = useState(0);
  const [pageCount, setPageCount] = useState(0);

  const timeRanges = {
    "1 day": "1day",
    "3 days": "3day",
    "7 days": "7day",
    "14 days": "14day",
    "30 days": "30day",
    "60 days": "60day",
    "90 days": "90day"
  };

  // pagination
  const itemsPerPage = 5;

  const handlePageClick = (event) => {
    const selectedPage = event.selected;
    const newOffset = selectedPage * itemsPerPage;
    setItemOffset(newOffset);
  };

  const toggleAppSelection = (appId, isSelected) => {
    if (appId === 'all') {
      setSelectAll(isSelected);
      setApps(prevApps =>
        prevApps.map(app => ({
          ...app,
          isSelected: isSelected
        }))
      );
    } else {
      setApps(prevApps =>
        prevApps.map(app =>
          app.name === appId ? { ...app, isSelected : isSelected} : app
        )
      );
    }
  };

  const toggleSelectAll = () => {
    setSelectAll(!selectAll);
    setApps(prevApps =>
      prevApps.map(app => ({
        ...app,
        isSelected: !selectAll
      }))
    );
  };

  const handleUpload = async (isComplex) => {
    const selectedFiles = document.getElementById('input').files;

    if (selectedFiles) {
      const userInfo = JSON.parse(localStorage.getItem('userInfo'));
      const username = userInfo?.username;

      const config_app = {
        headers: {
          'Content-type': 'multipart/form-data',
          "Accept-Encoding" : "gzip",
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
        setErrorMessage(`Failed to upload app. Error : ` +error.response.data.message);
      }
    }
  };

  const handleSearchApp = (event) => {
    event.preventDefault();
    fetchApps();
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

  const buildSearchConfig = (config_app, typeInput, searchInput, sortQueryInput) => {
    setTimeStampOn(typeInput === 'created_timestamp' || typeInput === 'updated_timestamp');

    if (selectedFilterType == 'normal') {
      if (typeInput === 'created_timestamp' || typeInput === 'updated_timestamp') {
        config_app.params.filter = `${typeInput}>='${timeRanges[timestampInput]}'`;
      } else {
        if (searchInput.length !== 0) {
          config_app.params.filter = `${typeInput}='${searchInput}'`
        }
      }
    } else {

      config_app.params = {
        ...config_app.params,
        'filter': searchInput,
      };
    }

    if (sortQueryInput.length !== 0) {
      config_app.params.sort = sortQueryInput;
    }

    return config_app;
  };

  const buildPaginationConfig = (config_app, limitInput, offsetInput) => {
    config_app.params.limit = limitInput
    config_app.params.offset = offsetInput
    return config_app
  }

  const fetchApps = async () => {
    const userInfo = JSON.parse(localStorage.getItem('userInfo'));
    const username = userInfo?.username;

    try {
      const agent = new Agent({
        rejectUnauthorized: false,
        cert: certs.certFile,
        key: certs.keyFile,
      });
      const userConfig = {
        headers: {
          'Content-type': 'application/json',
          "Accept-Encoding" : "gzip",
          'USER-AUTH': userInfo?.role,
          'USER-UUID': userInfo?.user_id,
        }
      };
      const responseUser = await axios.get(`https://localhost:9443/user/${username}`, userConfig, { httpsAgent: agent });

      const my_apps = responseUser.data?.applications;

      if (my_apps !== undefined) {
        const query_my_apps = my_apps.join();
        let config_app = buildAppConfig(userInfo, query_my_apps, username);
        config_app = buildSearchConfig(config_app, typeInput, searchInput, sortQueryInput);
        config_app = buildPaginationConfig(config_app, itemsPerPage, itemOffset)
        const responseApps = await axios.get('https://localhost:9443/app', config_app, { httpsAgent: agent });
        setApps(responseApps.data.Response);
        setPageCount(Math.ceil(responseApps.data.QueryInfo.total / itemsPerPage));
      }
    } catch (error) {
      setErrorMessage(`Could not retrieve your apps. Error : ` +error.response.data.message);
      setApps([]);
    }
  };

  useEffect(() => {
    fetchApps();
  }, [itemOffset, pageCount]);

  const renderApps = () => {
    if (apps) {
      return apps.map((app, i) => (
        <AppItem
        key={i}
        app={app}
        onSelect={toggleAppSelection}
        isSelected={app.isSelected || selectAll}
      />
      ));
    }
  };

  const renderNormalFilter = () => {
    return (
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
    );
  }

  const renderComplexFilter = () => {
    return (
      <form onSubmit={handleSearchApp}>
        <div className='search_bar'>
          <input
            type="search"
            placeholder="Build your filter query"
            onChange={(e) => setSearchInput(e.target.value)}
            value={searchInput}
          />
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
    );
  }

  const renderFilter = () => {
    if (selectedFilterType == 'normal') {
      return renderNormalFilter();
    } else {
      return renderComplexFilter();
    }
  }

  const deleteSelectedApps = async () => {
    const userInfo = JSON.parse(localStorage.getItem('userInfo'));
    const username = userInfo?.username;
    const appnames = apps.filter(app => app.isSelected).map(app => app.name );

    try {
      const agent = new Agent({
        rejectUnauthorized: false,
        cert: certs.certFile,
        key: certs.keyFile,
      });
      const appConfig = {
        headers: {
          'Content-type': 'application/json',
          'USER-AUTH': userInfo?.role,
          'USER-UUID': userInfo?.user_id,
        },
        params: {
          username,
          "appnames": appnames.join(',')
        }
      };
      await axios.delete(`https://localhost:9443/app`, appConfig, { httpsAgent: agent });
    } catch (error) {
      setErrorMessage(`Could not delete your apps.`);
    }
  }

  return (
    <div className='myapps_container'>
      <input
        type="checkbox"
        checked={selectAll}
        onChange={toggleSelectAll}
      />
      Select All
      <div className="search_bar filter_type_select">
        <label>
          Filter Type:
          <select name="filter_type" className="input-style filter-type" onChange={(e) => setSelectedFilterType(e.target.value)}>
            <option value="normal">Normal</option>
            <option value="complex">Complex</option>
          </select>
        </label>

      </div>
      {renderFilter()}

      <div className="table-container" id='container'>
        <table className="table">
          <thead>
            <tr>
            <th>&nbsp;</th>
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
        <ReactPaginate
          breakLabel="..."
          nextLabel="next >"
          onPageChange={(e) => handlePageClick(e)}
          pageCount={pageCount}
          previousLabel="< previous"
          renderOnZeroPageCount={null}
          activeClassName="item active-page"
          breakClassName='item break-me'
          containerClassName='pagination'
          disabledClassName='disabled-page'
          nextClassName='item next'
          previousClassName='item previous'
        />
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
      <button type="button" className='button-3' onClick={deleteSelectedApps} disabled={apps.length === 0}>
        Delete Apps
      </button>
      {errorMessage && <div className="error-message"> <span className="error-text">{errorMessage}</span> </div>}
    </div>

  );
}

export default MyApps;
