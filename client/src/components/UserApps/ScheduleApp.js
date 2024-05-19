import { useEffect, useState } from "react";
import axios from 'axios';
import { Agent } from 'https';
import certs from '../../Certs/certs.js';
import '../../assets/Error.scss';

function ScheduleApp({ app }) {
  const [appName, setAppName] = useState(app.name);
  const [appScheduleType, setAppScheduleType] = useState("normal");
  const [appNrReplicas, setAppNrReplicas] = useState(1);
  const [appServerPort, setAppServerPort] = useState(0);
  const [errorMessage, setErrorMessage] = useState('');

  useEffect(() => {
    setAppName(app.name);
  }, [app]);

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
          appnames: appName,
          schedule_type: appScheduleType,
          nr_replicas: appNrReplicas,
          server_port: appServerPort,
        },
        httpsAgent: agent,
      };

      await axios.get(`https://localhost:9443/schedule`, config);
      setErrorMessage();
    } catch (error) {
      setErrorMessage('Failed to schedule APP. Please try again. /' + error.response.data.message);
    }
  };

  return (
    <div className="modal-container">
      <form onSubmit={handleSubmit}>
        <div className="modal-title">
          Schedule {appName}
        </div>
        <div className="user-box">
          <label>
            Schedule Type:
            <select name="schedule_type" value={appScheduleType} onChange={(e) => setAppScheduleType(e.target.value)} className="input-style app-description">
              <option value="normal">Normal</option>
              <option value="random_scheduler">Random Scheduler</option>
              <option value="rr_sjf_scheduler">RR SJF Scheduler</option>
            </select>
          </label>
        </div>
        <div className="user-box">
          <label>
            Number of replicas:
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
            Server Port:
            <input
              className='input-style app-description'
              type='number'
              value={appServerPort}
              onChange={(e) => setAppServerPort(e.target.value)}
            />
          </label>
        </div>
        <button type="submit" className='button-3'>
          Schedule App
        </button>
      </form>
      {errorMessage && <div className="error-message"> <span className="error-text">{errorMessage}</span> </div>}
    </div>
  );
}

export default ScheduleApp;
