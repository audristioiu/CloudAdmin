import { useState } from "react";
import axios from 'axios';
import { Agent } from 'https';
import certs from '../../Certs/certs.js';
import '../../assets/Error.scss';

function GetAlert(props) {
  const { app } = props;
  const [appName, setAppName] = useState(app.name);
  const [appDescription, setAppDescr] = useState("");
  const [appFlagArguments, setAppFlags] = useState("");
  const [appParamArguments, setAppParams] = useState("");
  const [errorMessage, setErrorMessage] = useState('');

  let handleSubmit = async () => {

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
        }
      };

     const resp =  await axios.get(`https://localhost:9443/grafana/alert_trigger`, {
      }, config,
        { httpsAgent: agent },);
      setErrorMessage();  
      console.log(resp)
    } catch (error) {
      setErrorMessage('Failed to get alert status for APP. Please try again. /' + error.response.data.message);
    }
  };

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <div className="modal-title">
          Get alerts for {appName}
        </div>

        <a type="submit" onClick={handleSubmit}>
          <span></span>
          <span></span>
          <span></span>
          <span></span>
          Get Alert
        </a>
      </form>
      {errorMessage && <div className="error-message"> <span className="error-text">{errorMessage}</span> </div>}
    </div>
  )
}


export default GetAlert;