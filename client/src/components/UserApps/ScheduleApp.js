import { useState } from "react";
import axios from 'axios';
import { Agent } from 'https';
import certs from '../../Certs/certs.js';
import '../../assets/Error.scss';

function ScheduleApp(props) {
  const { app } = props;
  const [appName, setAppName] = useState(app.name);
  const [appScheduleType, setAppScheduleType] = useState(app.schedule_type);
  const [appNrReplicas, setAppNrReplicas] = useState(0);
  const [appServerPort, setAppServerPort] = useState(0);
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
          "USER-AUTH": userInfo?.role,
          "USER-UUID": userInfo?.user_id,
        },
        params: {
          "username": username,
        }
      };

      await axios.get(`https://localhost:9443/schedule`, {
        "appnames": appName,
        "schedule_type": appScheduleType,
        "nr_replicas": appNrReplicas,
        "server_port": appServerPort
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
        Schedule {appName}
      </div>
      <div className="user-box">
        <label>
          Schedule Type:
          <select name="schedule_type" defaultValue={appScheduleType} className="input-style app-description">
            <option value="normal">Normal</option>
            <option value="random_scheduler">Random Scheduler</option>
            <option value="rr_sjf_scheduler">RR SJF Scheduler</option>
          </select>
        </label>

      </div>
      <div className="user-box">
        <label>
          Number of replicas
          <input
            className='input-style app-description'
            type='number'
            value={appNrReplicas}
            onChange={(e) => setAppNrReplicas(e.target.value)}
          />

        </label>

      </div>
      <div className="user-box">
        <label>
          Server Port
          <input
            className='input-style app-description'
            type='number'
            value={appServerPort}
            onChange={(e) => setAppServerPort(e.target.value)}
          />
        </label>

      </div>


      <a type="submit" onClick={handleSubmit}>
        <span></span>
        <span></span>
        <span></span>
        <span></span>
        Schedule App
      </a>
    </form>
    {errorMessage && <div className="error-message"> <span className = "error-text">{errorMessage}</span> </div>}
    </div>
  )
}


export default ScheduleApp;