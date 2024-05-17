import { useEffect, useState } from "react";
import Modal from 'react-modal';
import '../../assets/MyApps.scss';
import GetAlert from "./GetAlert";
import { useNavigate } from 'react-router-dom';

function AppAlertItem({ app, onSelect, isSelected }) {
  const [appName, setAppName] = useState(app.name);
  const [appDescription, setAppDescr] = useState(app.description);
  const [appRunningState, setAppRunning] = useState(String(app.is_running));
  const [appCreatedTimestamp, setAppCreatedTimestamp] = useState(new Date(app.created_timestamp).toDateString());
  const [appUpdatedTimestamp, setAppUpdateTimestamp] = useState(new Date(app.updated_timestamp).toDateString());
  const [appScheduleType, setAppScheduleType] = useState(app.schedule_type);
  const [appPort, setAppPort] = useState(app.port);
  const [appIPAddress, setAppIPAddress] = useState(app.ip_address);
  const [isGetAlertModalOpen, setIsGetAlertModalOpen] = useState(false);

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
  }, [app]);

  const getStatusClass = () => (appRunningState == "true" ? 'active' : 'inactive');

  const handleOpenGetAppModal = () => {
    setIsGetAlertModalOpen(true);
  };

  const handleCloseGetAppModal = () => {
    setIsGetAlertModalOpen(false);
  };

  const handleCreateAlert = async () => {
		
	};

  const handleDeleteAlert = async () => {
		
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
    </tr>
  );
}

export default AppAlertItem;
