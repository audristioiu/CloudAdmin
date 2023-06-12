import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
import user_photo from '../user.png';
import './Profile.css';

const ProfilePage = () => {
  const [address, setAddress] = useState('');
  const [username, setUsername] = useState('');
  const [fullName, setFullName] = useState('');
  const [birthDate, setBirthDate] = useState('');
  const [joinedDate, setJoinedDate] = useState('');
  const [lastTimeOnline, setLastTimeOnline] = useState('');
  const [wantNotify, setWantNotify] = useState('');
  const [errorMessage, setErrorMessage] = useState('');

  useEffect(() => {
    const fetchDetails = async () => {
      try {
        const userInfo = JSON.parse(localStorage.getItem('userInfo'));
        const username = userInfo?.username;

        if (username) {
          const config = {
            headers: {
              "Content-type": "application/json",
              "Authorization": userInfo?.role,
              "USER-UUID": userInfo?.user_id,
            },
          };

          const response = await axios.get(`http://localhost:8080/user/${username}`, config);
          const userAddress = response.data?.city_address;
          const birth = response.data?.birth_date;
          const joined = response.data?.joined_date;
          const lastOnline = response.data?.last_time_online;
          const joined_date = new Date(joined.replace(' ', 'T'));
          const last_online = new Date(lastOnline.replace(' ', 'T'));
          const full_name = response.data?.full_name;
          const want_notify = response.data?.want_notify;
          setAddress(userAddress);
          setUsername(username);
          setBirthDate(birth);
          setJoinedDate(joined_date.toUTCString());
          setLastTimeOnline(last_online.toUTCString());
          setFullName(full_name);
          setWantNotify(want_notify);
        }
      } catch (error) {
        console.log('Error retrieving user details:', error);
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
          <p>Full Name: {fullName}</p>
          <p>Address: {address}</p>
          <p>Birth Date: {birthDate}</p>
          <p>Joined Date: {joinedDate}</p>
          <p>Last Time Online: {lastTimeOnline}</p>
          <p>Want Notifications: {wantNotify}</p>
        </div>
      </div>
      <a href="/editprofile">
        Edit Profile
      </a>
    </div>
  );
};

export default ProfilePage;
