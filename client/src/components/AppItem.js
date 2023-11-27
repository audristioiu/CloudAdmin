import { useState } from "react";
import { useNavigate } from "react-router-dom";
import './MyApps.scss';

function AppItem(app) {
  const [appName, setAppName] = useState(app.app.name);
  const [appDescription, setAppDescr] = useState(app.app.description);
  const [appRunningState, setAppRunning] = useState(String(app.app.is_running));
  const history = useNavigate();

  const editApp = () => {
    localStorage.setItem("appInfo", JSON.stringify({ "app_name": appName }));
    history('/editapp');
  }

  return (
    <tr>
      <td>{appName}</td>
      <td>{appDescription}</td>
      <td className={"status"}>
        <span className={appRunningState ? ' active' : ' waiting'}> 
          {appRunningState ? "Active" : "Not running"}
        </span>
      </td>
      <td>
        <button className='button-3' onClick={editApp}>
          Edit App
        </button>

        <button className='button-3'>
          Delete App
        </button>
      </td>
    </tr>
  );
};

export default AppItem;
