import React, { useState, useEffect } from 'react';
import axios from 'axios';
import user_photo from '../user.png';
import './Profile.scss';
import { Agent } from 'https';
import certs from '../Certs/certs';
import { useNavigate } from 'react-router-dom';

const styles = {
  heading3: `text-xl font-semibold text-gray-900 p-4 border-b`,
  heading4: `text-base text-ct-blue-600 font-medium border-b mb-2`,
  modalOverlay: `overflow-y-auto overflow-x-hidden fixed top-0 right-0 left-0 z-50 w-full md:inset-0 h-modal md:h-full`,
  orderedList: `space-y-1 text-sm list-decimal`,
  buttonGroup: `flex items-center py-6 space-x-2 rounded-b border-t border-gray-200 dark:border-gray-600`,
  buttonBlue: `text-white bg-blue-700 hover:bg-blue-800 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium rounded-lg text-sm px-5 py-2.5 text-center dark:bg-blue-600 dark:hover:bg-blue-700 dark:focus:ring-blue-800`,
  buttonGrey: `text-gray-500 bg-white hover:bg-gray-100 focus:ring-4 focus:outline-none focus:ring-blue-300 rounded-lg border border-gray-200 text-sm font-medium px-5 py-2.5 hover:text-gray-900 focus:z-10 dark:bg-gray-700 dark:text-gray-300 dark:border-gray-500 dark:hover:text-white dark:hover:bg-gray-600 dark:focus:ring-gray-600`,
  inputField: `bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-2/5 p-2.5`,
};


const ProfilePage = () => {
  const [jobRole, setJobRole] = useState('');
  const [nrAppsDeployed, setNrAppsDeployed] = useState(0);
  const [username, setUsername] = useState('');
  const [fullName, setFullName] = useState('');
  const [birthDate, setBirthDate] = useState('');
  const [joinedDate, setJoinedDate] = useState('');
  const [lastTimeOnline, setLastTimeOnline] = useState('');
  const [wantNotify, setWantNotify] = useState(false);
  const [twoFAEnabled, setTwoFAEnabled] = useState(false);
  const [userEmail, setUserEmail] = useState('')
  const [errorMessage, setErrorMessage] = useState('');
  const history = useNavigate()

  const setup2FA = async () => {
    generateQRCode()
    history("/otp/setup")
  }
  

  const disable2FA = async () => {
    const userInfo = JSON.parse(localStorage.getItem('userInfo'));
    try {
      const config = {
        headers: {
          "Content-type": "application/json",
          "USER-AUTH": userInfo?.role,
          "USER-UUID": userInfo?.user_id,
        },
      };
      const agent = new Agent({
        cert: certs.certFile,
        key: certs.keyFile,
      })
     await axios.post(
        "https://localhost:9443/otp/disable",
      {},config, { httpsAgent : agent },);
    } catch (error) {
      setErrorMessage("Could not disable otp /" + error.response.data.message);
    }
  }
  const generateQRCode = async () => {
    const userInfo = JSON.parse(localStorage.getItem('userInfo'));
    try {
      const config = {
        headers: {
          "Content-type": "application/json",
          "USER-AUTH": userInfo?.role,
          "USER-UUID": userInfo?.user_id,
        },
      };
      const agent = new Agent({
        cert: certs.certFile,
        key: certs.keyFile,
      })
      const response = await axios.post(
        "https://localhost:9443/otp/generate",
      {},config, { httpsAgent : agent },);
      if (response.status === 200) {
        localStorage.setItem("userOTP", JSON.stringify(response.data))
      }
    } catch (error) {
      setErrorMessage("Could not generate qr /" + error.response.data.message);
    }
  }



  useEffect(() => {
    const fetchDetails = async () => {
      try {

        const agent = new Agent({
          cert: certs.certFile,
          key: certs.keyFile,
        })
        const userInfo = JSON.parse(localStorage.getItem('userInfo'));
        const username = userInfo?.username;
        const password = localStorage.getItem('userPass')

        if (username) {


          //trigger last time online update
          await axios.post(
            "https://localhost:9443/login",
            { "username": username, "password": password },
            {
              headers: {
                "Content-type": "application/json",
              },
              params: {
                "old_password": false,
              },
            },
            { httpsAgent: agent },
          );
          const config = {
            headers: {
              "Content-type": "application/json",
              "USER-AUTH": userInfo?.role,
              "USER-UUID": userInfo?.user_id,
            },
          };

          const response = await axios.get(`https://localhost:9443/user/${username}`, config, { httpsAgent: agent },);
          const userJobRole = response.data?.job_role;
          const userNrAppsDeployed = response.data?.nr_deployed_apps
          const birth = response.data?.birth_date;
          const joined = response.data?.joined_date;
          const lastOnline = response.data?.last_time_online;
          const joined_date = new Date(joined.replace(' ', 'T'));
          const last_online = new Date(lastOnline.replace(' ', 'T'));
          const full_name = response.data?.full_name;
          const want_notify = response.data?.want_notify;
          const email = response.data?.email
          setJobRole(userJobRole);
          setNrAppsDeployed(userNrAppsDeployed)
          setUsername(username);
          setBirthDate(birth);
          setJoinedDate(joined_date.toUTCString());
          setLastTimeOnline(last_online.toUTCString());
          setFullName(full_name);
          setWantNotify(String(want_notify))
          setUserEmail(email);
          const otp_data = response.data?.otp_data
          if (otp_data.otp_enabled === true){
            setTwoFAEnabled(true)
          } else {
            setTwoFAEnabled(false)
          }
        }
      } catch (error) {
        setErrorMessage("Could not retrieve user details. /" + error.response.data.message);
      }
    };

    fetchDetails();
  }, []);

  return (
    <div className="profile-container">
      <h2>Profile Page</h2>
      <div className="user-details">
        <img src={user_photo} className="user-photo" alt="User" />
        <div className="user-info">
          <p>Username: {username}</p>
          <p>Email : {userEmail}</p>
          <p>Full Name: {fullName}</p>
          <p>Job Role: {jobRole}</p>
          <p>Birth Date: {birthDate}</p>
          <p>Joined Date: {joinedDate}</p>
          <p>Last Time Online: {lastTimeOnline}</p>
          <p>Nr of applications deployed : {nrAppsDeployed} </p>
          <p>Want Notifications: {wantNotify}</p>
        </div>
      </div>
      {!twoFAEnabled ? (
        <div>
      <button onClick={setup2FA} className={styles.buttonBlue}>
        Setup MFA 
      </button>
      </div>
      ) : (
        <div>
        <button onClick={disable2FA} className={styles.buttonBlue}>
        Disable MFA
        </button>
        </div>
      )}
      <a href="/editprofile">
        Edit Profile
      </a>
      {errorMessage && <div style={{ backgroundColor: "red" }} className="error"> {errorMessage} </div>}<p>{errorMessage}</p>
    </div>
  );
};

export default ProfilePage;
