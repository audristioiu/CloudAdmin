import { useState } from "react";
import { useNavigate } from "react-router-dom";
import './MyApps.scss';

function AppItem(app) {
  const [appName, setAppName] = useState(app.app.name);
  const [appDescription, setAppDescr] = useState(app.app.description);
  const [appRunningState, setAppRunning] = useState(String(app.app.is_running));
  const [appCreatedTimestamp, setAppCreatedTimestamp] = useState(new Date(app.app.created_timestamp).toDateString())
  const [appUpdatedTimestamp, setAppUpdateTimestamp] = useState(new Date(app.app.updated_timestamp).toDateString())
  const [appScheduleType, setAppScheduleType] = useState(app.app.schedule_type)
  const [appPort, setAppPort] = useState(app.app.port)
  const [appIPAddress, setAppIPAddress] = useState(app.app.ip_address)
  const history = useNavigate();

  const editApp = () => {
    localStorage.setItem("appInfo", JSON.stringify({ "app_name": appName }));
    history('/editapp');
  }

  const getStatusClass = () => (appRunningState ? ' active' : ' inactive');

  return (
    <tr>
      <td>{appName}</td>
      <td>{appDescription}</td>
      <td className={"status"}>
        <span className={getStatusClass()}> 
          {appRunningState ? "Active" : "Not running"}
        </span>
      </td>
      <td>{appCreatedTimestamp}</td>
      <td>{appUpdatedTimestamp}</td>
      <td>{appScheduleType}</td>
      <td>{appPort}</td>
      <td>{appIPAddress}</td>
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
