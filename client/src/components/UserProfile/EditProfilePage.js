import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import user_photo from '../../user.png';
import { Agent } from 'https';
import certs from '../../Certs/certs.js';
import '../../assets/Error.scss';

const EditProfilePage = () => {
  const [jobRole, setJobRole] = useState('');
  const [fullName, setFullName] = useState('');
  const [birthDate, setBirthDate] = useState('');
  const [wantNotify, setWantNotify] = useState(false);
  const [password, setPassword] = useState('');
  const [oldPassword, setOldPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [userEmail, setUserEmail] = useState('')
  const [showPasswordFields, setShowPasswordFields] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  let errMsg = "";

  const navigate = useNavigate();

  const handleSubmit = async (event) => {
    event.preventDefault();
    try {
      const userInfo = JSON.parse(localStorage.getItem('userInfo'));
      const username = userInfo?.username;

      const agent = new Agent({
        cert: certs.certFile,
        key: certs.keyFile,
      })

      if (username) {
        const config = {
          headers: {
            "Content-type": "application/json",
            "Accept-Encoding" : "gzip",
            "USER-AUTH": userInfo?.role,
            "USER-UUID": userInfo?.user_id,
          },

        };

        const updatedData = {
          "username": username,
          "email": userEmail,
          "full_name": fullName,
          "job_role": jobRole,
          "birth_date": birthDate,
          "want_notify": wantNotify,
          "nr_deployed_apps": userInfo?.nr_deployed_apps,
        };

        if (showPasswordFields) {
          if (username) {
            try {
              const config = {
                headers: {
                  "Content-type": "application/json",
                  "Accept-Encoding" : "gzip",
                },
                params: {
                  "old_password": true,
                },
              };

              await axios.post(
                "https://localhost:9443/login",
                { "username": username, "password": oldPassword },
                config,
                { httpsAgent: agent },
              );
            } catch (error) {
              setErrorMessage("Wrong old password / " +error.response.data.message);
              return
            };

            updatedData["password"] = password;
            localStorage.setItem("userPass", password);
          }

          const response = await axios.put(`https://localhost:9443/user/`, updatedData, config, { httpsAgent: agent },);
          if (response.status === 200) {
            // Profile updated successfully, navigate back to profile page
            navigate('/profile');
          }
        } else {
          const response = await axios.put(`https://localhost:9443/user/`, updatedData, config, { httpsAgent: agent },);
          if (response.status === 200) {
            // Profile updated successfully, navigate back to profile page
            navigate('/profile');
          }
        }
      }
    } catch (error) {
      setErrorMessage('Error updating profile. Please try again. /' +error.response.data.message);
    }
  };

  return (
    <div className="login-box">
      <h2>Edit Profile</h2>
      <img src={user_photo} className="user-photo" />
      <form onSubmit={handleSubmit}>
        <div className="user-box">
          <input
            type="text"
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
          />
          <label>Full Name</label>
        </div>
        <div className="user-box">
          <input
            type="text"
            value={userEmail}
            onChange={(e) => setUserEmail(e.target.value)}
          />
          <label>Email</label>
        </div>
        <div className="user-box">
          <input
            type="text"
            value={jobRole}
            onChange={(e) => setJobRole(e.target.value)}
          />
          <label>Job Role(Optional)</label>
        </div>
        <div className="user-box">
          <input
            type="date"
            value={birthDate}
            onChange={(e) => setBirthDate(e.target.value)}
          />
          <label>Birth Date</label>
        </div>
        <label className="checkbox-container">
          Want Notifications
          <input
            type="checkbox"
            checked={wantNotify}
            onChange={(e) => setWantNotify(e.target.checked)}
          />
          <span class="checkmark"></span>
        </label>

        {showPasswordFields && (
          <div className='password-container'>
            <div className="user-box">
              <input
                type="password"
                value={oldPassword}
                onChange={(e) => setOldPassword(e.target.value)}
              />
              <label>Old Password</label>
            </div>
            <div className="user-box">
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <label>Password</label>
            </div>
            <div className="user-box">
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
              <label>Confirm Password</label>
            </div>
          </div>
        )}
        <a href="#" onClick={() => setShowPasswordFields(!showPasswordFields)}>
          <span></span>
          <span></span>
          <span></span>
          <span></span>
          {showPasswordFields ? "Hide Password Fields" : "Show Password Fields"}
        </a>

        <a href="/profile">
          <span></span>
          <span></span>
          <span></span>
          <span></span>
          Cancel
        </a>

        <a type="submit" onClick={handleSubmit} className='profile-submit'>
          <span></span>
          <span></span>
          <span></span>
          <span></span>
          Update
        </a>
      </form>
      {errorMessage && <div className="error-message"> <span className = "error-text">{errorMessage}</span> </div>}
    </div>
  );

};

export default EditProfilePage;
