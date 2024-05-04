import { useState } from "react";
import axios from 'axios';
import { Agent } from 'https';
import certs from '../../Certs/certs.js';
import '../../assets/Error.scss';

function GetApp(props) {
  const { app } = props.app;
  const [appName, setAppName] = useState(app.name);
  const [podName, setPodName] = useState('');
  const [errorMessage, setErrorMessage] = useState('');

  let handleSubmit = async (event) => {

    try {
      const userInfo = JSON.parse(localStorage.getItem('userInfo'));
      const username = userInfo?.username;
      const agent = new Agent({
        cert: certs.certFile,
        key: certs.keyFile,
      })

      const config = {
        headers: {
          "Content-type": "application/json",
          "USER-AUTH": userInfo?.role,
          "USER-UUID": userInfo?.user_id,
        },
        params: {
          "username": username,
        }
      };

      await axios.get(`https://localhost:9443/getresults`, {
        "pod_name": podName,
      }, config,
        { httpsAgent: agent },);

    } catch (error) {
      setErrorMessage('Failed to schedule APP. Please try again. /' +error.response.data.message);
    }
  };

  return (
    <div>
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


      <a type="submit" onClick={handleSubmit}>
        <span></span>
        <span></span>
        <span></span>
        <span></span>
        Update
      </a>
    </form>
    {errorMessage && <div className="error-message"> <span className = "error-text">{errorMessage}</span> </div>}
    </div>
  )
}


export default GetApp;