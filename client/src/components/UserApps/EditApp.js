import { useState } from "react";
import axios from 'axios';
import { Agent } from 'https';
import certs from '../../Certs/certs.js';
import '../../assets/Error.scss';

function EditApp(props) {
  const {app} = props.app;
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
          "Accept-Encoding" : "gzip",
          "USER-AUTH": userInfo?.role,
          "USER-UUID": userInfo?.user_id,
        },
        params: {
          "username": username,
        }
      };

      await axios.put(`https://localhost:9443/app`, {
        "name": appName,
        "description": appDescription,
        "flag_arguments": appFlagArguments,
        "param_arguments": appParamArguments
      }, config,
        { httpsAgent: agent },);

    } catch (error) {
      setErrorMessage('Failed to update APP. Please try again. /' +error.response.data.message);
    }
  };

  return (
    <div>
    <form onSubmit={handleSubmit}>
      <div className="modal-title">
        Edit {appName}
      </div>
      <div className="user-box">
        <label>Description
          <input
            className='input-style app-description'
            type='textarea'
            value={appDescription}
            onChange={(e) => setAppDescr(e.target.value)}
          />
        </label>

      </div>
      <div className="user-box">
        <label>Flag Arguments
          <input
            className='input-style app-description'
            type='textarea'
            value={appFlagArguments}
            onChange={(e) => setAppFlags(e.target.value)}
          />

        </label>

      </div>
      <div className="user-box">
        <label>Param Arguments
          <input
            className='input-style app-description'
            type='textarea'
            value={appParamArguments}
            onChange={(e) => setAppParams(e.target.value)}
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


export default EditApp;