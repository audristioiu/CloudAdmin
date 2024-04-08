import { useState } from "react";
import { useNavigate } from "react-router-dom";
import Modal from 'react-modal'; // Import the modal library
import '../assets/MyApps.scss';
import EditApp from "./EditApp";

function AppItem(app) {
  const [appName, setAppName] = useState(app.app.name);
  const [appDescription, setAppDescr] = useState(app.app.description);
  const [appRunningState, setAppRunning] = useState(String(app.app.is_running));
  const [appCreatedTimestamp, setAppCreatedTimestamp] = useState(new Date(app.app.created_timestamp).toDateString());
  const [appUpdatedTimestamp, setAppUpdateTimestamp] = useState(new Date(app.app.updated_timestamp).toDateString());
  const [appScheduleType, setAppScheduleType] = useState(app.app.schedule_type);
  const [appPort, setAppPort] = useState(app.app.port);
  const [appIPAddress, setAppIPAddress] = useState(app.app.ip_address);
  const history = useNavigate();

  const [isModalOpen, setIsModalOpen] = useState(false);

  const getStatusClass = () => (appRunningState ? ' active' : ' inactive');

  const handleOpenModal = () => {
    setIsModalOpen(true);
  };

  const handleCloseModal = () => {
    setIsModalOpen(false);
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
        <button className='button-3' onClick={handleOpenModal}>
          Edit App
        </button>

        <Modal 
           isOpen={isModalOpen}
           contentLabel="onRequestClose Example"
           onRequestClose={handleCloseModal}
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
