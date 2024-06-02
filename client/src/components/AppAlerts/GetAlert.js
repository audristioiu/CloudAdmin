import { useEffect, useState } from "react";
import axios from 'axios';
import { Agent } from 'https';
import certs from '../../Certs/certs.js';
import '../../assets/Error.scss';

function GetAlert(props) {
  const { app } = props;
  const [appName, setAppName] = useState(app.name);
  const [responseData, setResponseData] = useState('');
  const [errorMessage, setErrorMessage] = useState('');

  let handleSubmit = async (event) => {
    event.preventDefault();

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
          "Accept-Encoding": "gzip",
          "USER-AUTH": userInfo?.role,
          "USER-UUID": userInfo?.user_id,
        },
        params: {
          "username": username,
          "app_name": appName,
        },
        httpsAgent: agent,
      };

      const resp = await axios.get(`https://localhost:9443/grafana/alert_trigger`, config);
      setErrorMessage();
      console.log(resp);
      setResponseData(resp.data);
    } catch (error) {
      setErrorMessage('Failed to get alert status for APP. Please try again. /');
      setResponseData('');
    }
  };

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <div className="modal-title">
          Get alerts for {appName}
        </div>

        {responseData && <div className="response-data">
          <h3>Response:</h3>
          <pre>{JSON.stringify(responseData, null, 2)}</pre>
        </div>}

        <button type="submit" className='button-3'>
          Get Alert
        </button>
      </form>

      {errorMessage && <div className="error-message"> <span className="error-text">{errorMessage}</span> </div>}
    </div>
  )
}


export default GetAlert;