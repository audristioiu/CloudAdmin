import { useState } from "react";
import { useNavigate } from "react-router-dom";
import Modal from 'react-modal'; // Import the modal library
import '../assets/MyApps.scss';
import EditApp from "./EditApp";
import ScheduleApp from "./ScheduleApp";

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

  const getStatusClass = () => (appRunningState ? ' active' : ' inactive');

  const handleOpenScheduleModal = () => {
    setIsScheduleModalOpen(true);
  };

  const handleOpenEditModal = () => {
    setIsEditModalOpen(true);
  };

  const handleCloseScheduleModal = () => {
    setIsScheduleModalOpen(false);
  };

  const handleCloseEditModal = () => {
    setIsEditModalOpen(false);
  };

  console.log(app);

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

        <button className='button-3'>
          Delete App
        </button>
      </td>
    </tr>
  );
}

export default AppItem;
