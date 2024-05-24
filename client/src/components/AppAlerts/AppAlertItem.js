import { useEffect, useState } from "react";
import Modal from 'react-modal';
import '../../assets/MyApps.scss';
import certs from '../../Certs/certs.js';
import axios from 'axios';
import GetAlert from "./GetAlert";
import { Agent } from 'https';

function AppAlertItem({ app, onSelect, isSelected }) {
  const [appName, setAppName] = useState(app.name);
  const [appDescription, setAppDescr] = useState(app.description);
  const [appRunningState, setAppRunning] = useState(String(app.is_running));
  const [appCreatedTimestamp, setAppCreatedTimestamp] = useState(new Date(app.created_timestamp).toDateString());
  const [appUpdatedTimestamp, setAppUpdateTimestamp] = useState(new Date(app.updated_timestamp).toDateString());
  const [appScheduleType, setAppScheduleType] = useState(app.schedule_type);
  const [appPort, setAppPort] = useState(app.port);
  const [appIPAddress, setAppIPAddress] = useState(app.ip_address);
  const [appAlertIDs, setAppAlertIDs] = useState(app.alert_ids);
  const [isGetAlertModalOpen, setIsGetAlertModalOpen] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const toggleSelection = () => {
    onSelect(app.name, !app.isSelected);
  };

  useEffect(() => {
    setAppName(app.name);
    setAppDescr(app.description);
    setAppRunning(String(app.is_running));
    setAppCreatedTimestamp(new Date(app.created_timestamp).toDateString());
    setAppUpdateTimestamp(new Date(app.updated_timestamp).toDateString());
    setAppScheduleType(app.schedule_type);
    setAppPort(app.port);
    setAppIPAddress(app.ip_address);
    setAppAlertIDs(app.alert_ids)
  }, [app]);

  const getStatusClass = () => (appRunningState == "true" ? 'active' : 'inactive');

  const handleOpenGetAppModal = () => {
    setIsGetAlertModalOpen(true);
  };

  const handleCloseGetAppModal = () => {
    setIsGetAlertModalOpen(false);
  };

  const handleCreateAlert = async () => {
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
          app_name: appName,
        }
      };

      await axios.get(`https://localhost:9443/grafana/alert`, {
        ...config,
        httpsAgent: agent,
      });
      setErrorMessage();
    } catch (error) {
      setErrorMessage('Failed to create alert for APP. Please try again. /' + error.response.data.message);
    }

	};

  const handleDeleteAlert = async () => {
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
          app_name: appName,
          alert_ids: appAlertIDs.join(),
        }
      };

      await axios.delete(`https://localhost:9443/grafana/alert`, {
        ...config,
        httpsAgent: agent,
      });
      setErrorMessage();
    } catch (error) {
      setErrorMessage('Failed to delete alert for APP. Please try again. /' + error.response.data.message);
    }
	};

  return (
    <tr>
      <td>
        <input
          type="checkbox"
          checked={isSelected}
          onChange={toggleSelection}
        />
      </td>
      <td>{appName}</td>
      <td>{appDescription}</td>
      <td className={"status"}>
        <span className={getStatusClass()}>
          {getStatusClass() == "active" ? "Active" : "Not running"}
        </span>
      </td>
      <td>{appCreatedTimestamp}</td>
      <td>{appUpdatedTimestamp}</td>
      <td>{appScheduleType}</td>
      <td>{appPort}</td>
      <td>{appIPAddress}</td>
      <td>
        <button className='button-3' onClick={handleCreateAlert}>
          Create Alert
        </button>

        <button className='button-3' onClick={handleDeleteAlert}>
          Delete Alert
        </button>

        <button className='button-3' onClick={handleOpenGetAppModal}>
          Get App Alerts
        </button>

        <Modal
          isOpen={isGetAlertModalOpen}
          contentLabel="onRequestClose Example"
          onRequestClose={handleCloseGetAppModal}
          className="Modal"
          overlayClassName="Overlay"
        >
          <GetAlert app={app} />
        </Modal>

      </td>
      {errorMessage && <div className="error-message"> <span className="error-text">{errorMessage}</span> </div>}
    </tr>
  );
}

export default AppAlertItem;
