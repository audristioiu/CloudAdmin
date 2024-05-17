import { useState } from "react";
import axios from 'axios';
import { Agent } from 'https';
import certs from '../../Certs/certs.js';
import '../../assets/Error.scss';

function GetApp(props) {
  const { app } = props;
  const [appName, setAppName] = useState(app.name);
  const [podName, setPodName] = useState('');
  const [errorMessage, setErrorMessage] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();

    try {
      const userInfo = JSON.parse(localStorage.getItem('userInfo'));
      const username = userInfo?.username;
      const agent = new Agent({
        cert: certs.certFile,
        key: certs.keyFile,
      });

      const config = {
        headers: {
          "Content-type": "application/json",
          "Accept-Encoding": "gzip",
          "USER-AUTH": userInfo?.role,
          "USER-UUID": userInfo?.user_id,
        },
        params: {
          username,
        }
      };

      await axios.get(`https://localhost:9443/getresults`, {
        params: {
          pod_name: podName,
        },
        ...config,
        httpsAgent: agent,
      });

    } catch (error) {
      setErrorMessage('Failed to schedule APP. Please try again. /' + error.response.data.message);
    }
  };

  return (
    <div className="modal-container">
      <form onSubmit={handleSubmit}>
        <div className="modal-title">
          Get {appName} info
        </div>
        <div className="user-box">
          <label>
            Pod Name
            <input
              className='input-style app-description'
              type='text'
              value={podName}
              onChange={(e) => setPodName(e.target.value)}
            />
          </label>
        </div>
        <button type="submit" className='button-3'>
          Get App Stats
        </button>
      </form>
      {errorMessage && <div className="error-message"> <span className="error-text">{errorMessage}</span> </div>}
    </div>
  );
}

export default GetApp;
