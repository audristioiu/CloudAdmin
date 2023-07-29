import { useState } from "react";
import { useNavigate } from "react-router-dom";
import './MyApps.css';

function AppItem(app) {
  const [appName, setAppName] = useState(app.app.name);
  const [appDescription, setAppDescr] = useState(app.app.description);
  const [appRunningState, setAppRunning] = useState(app.app.is_running);
  const history = useNavigate();

  const editApp = () => {
    localStorage.setItem("appInfo", JSON.stringify({ "app_name": appName }));
    history('/editapp');
  }

  return (
    <div className="app-item">
      <span>App name
        <input
          className='input-style app-input'
          type='text'
          value={appName}
          onChange={(e) => setAppName(e.target.value)}
          required
          disabled
        />
      </span>

      <span>Description
        <input
          className='input-style app-description'
          type='textarea'
          value={appDescription}
          onChange={(e) => setAppDescr(e.target.value)}
          required
          disabled
        />
      </span>

      <span>IsRunning
        {appRunningState === "true" ? (
          <div class="led-box">
            <div class="led-green"></div>
            <p>Running</p>
          </div>
        ) : (
          <div class="led-box">
            <div class="led-red"></div>
            <p>Not Running</p>
          </div>
        )}
        <input
          className='input-style app-input'
          type='text'
          value={appRunningState}
          onChange={(e) => setAppRunning(e.target.value)}
          required
          disabled
          style={{ visibility: "hidden" }}

        />
      </span>

      <div className="edit_delete_section">
        <button className='button-3' onClick={editApp}>
          Edit App
        </button>

        <button className='button-3'>
          Delete App
        </button>
      </div>
    
    </div>
  );
};

export default AppItem;
