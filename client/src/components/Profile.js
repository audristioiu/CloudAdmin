import React, { useState, useEffect } from 'react';
import axios from 'axios';
import user_photo from '../user.png';
import './Profile.scss';
import { Agent } from 'https';
import certs from '../Certs/certs';






const ProfilePage = () => {
  const [jobRole, setJobRole] = useState('');
  const [nrAppsDeployed, setNrAppsDeployed] = useState(0);
  const [username, setUsername] = useState('');
  const [fullName, setFullName] = useState('');
  const [birthDate, setBirthDate] = useState('');
  const [joinedDate, setJoinedDate] = useState('');
  const [lastTimeOnline, setLastTimeOnline] = useState('');
  const [wantNotify, setWantNotify] = useState(false);
  const [userEmail, setUserEmail] = useState('')
  const [errorMessage, setErrorMessage] = useState('');




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
            "https://localhost:443/login",
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

          console.log(userInfo)
          const config = {
            headers: {
              "Content-type": "application/json",
              "USER-AUTH": userInfo?.role,
              "USER-UUID": userInfo?.user_id,
            },
          };

          const response = await axios.get(`https://localhost:443/user/${username}`, config, { httpsAgent: agent },);
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
      <a href="/editprofile">
        Edit Profile
      </a>
      {errorMessage && <div style={{ backgroundColor: "red" }} className="error"> {errorMessage} </div>}<p>{errorMessage}</p>
    </div>
  );
};

export default ProfilePage;
