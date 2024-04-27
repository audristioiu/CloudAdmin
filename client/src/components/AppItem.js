import { useEffect, useState } from "react";
import Modal from 'react-modal';
import '../assets/MyApps.scss';
import EditApp from "./EditApp";
import ScheduleApp from "./ScheduleApp";
import GetApp from "./GetApp";
import { useNavigate } from 'react-router-dom';

function AppItem(app) {
  const [appName, setAppName] = useState(app.app.name);
  const [appDescription, setAppDescr] = useState(app.app.description);
  const [appRunningState, setAppRunning] = useState(String(app.app.is_running));
  const [appCreatedTimestamp, setAppCreatedTimestamp] = useState(new Date(app.app.created_timestamp).toDateString());
  const [appUpdatedTimestamp, setAppUpdateTimestamp] = useState(new Date(app.app.updated_timestamp).toDateString());
  const [appScheduleType, setAppScheduleType] = useState(app.app.schedule_type);
  const [appPort, setAppPort] = useState(app.app.port);
  const [appIPAddress, setAppIPAddress] = useState(app.app.ip_address);

  const [isScheduleModalOpen, setIsScheduleModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isGetAppModalOpen, setIsGetAppModalOpen] = useState(false);

  const history = useNavigate();

  useEffect(() => {
    setAppName(app.app.name);
    setAppDescr(app.app.description);
    setAppRunning(String(app.app.is_running));
    setAppCreatedTimestamp(new Date(app.app.created_timestamp).toDateString());
    setAppUpdateTimestamp(new Date(app.app.updated_timestamp).toDateString());
    setAppScheduleType(app.app.schedule_type);
    setAppPort(app.app.port);
    setAppIPAddress(app.app.ip_address);
  }, [app]);

  const getDashboardCPU = () => {
    localStorage.setItem("appInfo", JSON.stringify({ "app_name": appName }));
    history('/grafana/cpu')
  }
  const getDashboardMemory = () => {
    localStorage.setItem("appInfo", JSON.stringify({ "app_name": appName }));
    history('/grafana/mem')
  }
  const getStatusClass = () => (appRunningState == "true" ? 'active' : 'inactive');

  const handleOpenScheduleModal = () => {
    setIsScheduleModalOpen(true);
  };

  const handleOpenEditModal = () => {
    setIsEditModalOpen(true);
  };

  const handleOpenGetAppModal = () => {
    setIsGetAppModalOpen(true);
  };

  const handleCloseScheduleModal = () => {
    setIsScheduleModalOpen(false);
  };

  const handleCloseEditModal = () => {
    setIsEditModalOpen(false);
  };

  const handleCloseGetAppModal = () => {
    setIsGetAppModalOpen(false);
  };

  return (
    <tr>
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
      <button className='button-3' onClick={handleOpenScheduleModal}>
          Schedule App
        </button>

        <Modal 
           isOpen={isScheduleModalOpen}
           contentLabel="onRequestClose Example"
           onRequestClose={handleCloseScheduleModal}
           className="Modal"
           overlayClassName="Overlay"
        >
          <ScheduleApp app={app} />
        </Modal>

        <button className='button-3' onClick={handleOpenEditModal}>
          Edit App
        </button>

        <Modal 
           isOpen={isEditModalOpen}
           contentLabel="onRequestClose Example"
           onRequestClose={handleCloseEditModal}
           className="Modal"
           overlayClassName="Overlay"
        >
          <EditApp app={app} />
        </Modal>

        <button className='button-3' onClick={handleOpenGetAppModal}>
          Get App Stats
        </button>

        <Modal 
           isOpen={isGetAppModalOpen}
           contentLabel="onRequestClose Example"
           onRequestClose={handleCloseGetAppModal}
           className="Modal"
           overlayClassName="Overlay"
        >
          <GetApp app={app} />
        </Modal>

        <button className='button-3'>
          Delete App
        </button>
        { (appRunningState == "true") &&
        (<div><button className='button-3' onClick={getDashboardCPU}>
          Get Dashboard CPU Usage
        </button>
        <button className='button-3' onClick={getDashboardMemory}>
          Get Dashboard Memory Usage
        </button></div>)}
      </td>
    </tr>
  );
}

export default AppItem;
