import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import user_photo from '../user.png';

const EditProfilePage = () => {
  const [address, setAddress] = useState('');
  const [fullName, setFullName] = useState('');
  const [birthDate, setBirthDate] = useState('');
  const [wantNotify, setWantNotify] = useState('');
  const [password, setPassword] = useState('');
  const [oldPassword, setOldPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPasswordFields, setShowPasswordFields] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const navigate = useNavigate();

  const handleSubmit = async (event) => {
    event.preventDefault();
    try {
      const userInfo = JSON.parse(localStorage.getItem('userInfo'));
      const username = userInfo?.username;

      console.log(username);

      if (username) {
        const config = {
          headers: {
            "Content-type": "application/json",
            "Authorization": userInfo?.role,
            "USER-UUID": userInfo?.user_id,
          },
        };

        const updatedData = {
          "username": username,
          "full_name" : fullName,
          "city_address": address,
          "birth_date": birthDate,
          "want_notify": wantNotify.toString(),
        };        

        if (showPasswordFields) {
          if (password !== confirmPassword) {
            setErrorMessage('Passwords do not match.');
            return;
          }

          if (password.length < 8) {
            setErrorMessage('Password should be at least 8 characters long.');
            return;
          }

          if (username) {
            try {
              const config = {
                headers: {
                  "Content-type": "application/json",
                },
              };
              console.log({ "username": username, "password": oldPassword })
              await axios.post(
                "http://localhost:8080/login",
                { "username": username, "password": oldPassword },
                config
              );
            } catch (error) {
              console.log(error.response.data.message);
              setErrorMessage("Wrong old password")
              return
            };

            updatedData["password"] = password;
          }

        const response = await axios.put(`http://localhost:8080/user/`, updatedData, config);
        console.log(response)
        if (response.status === 200) {
          // Profile updated successfully, navigate back to profile page
          navigate('/profile');
        }
        } else {
          const response = await axios.put(`http://localhost:8080/user/`, updatedData, config);
        console.log(response)
        if (response.status === 200) {
          // Profile updated successfully, navigate back to profile page
          navigate('/profile');
        }
        }
      }
    } catch (error) {
      console.log('Error updating profile:', error);
      setErrorMessage('Error updating profile. Please try again.');
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
            value={address}
            onChange={(e) => setAddress(e.target.value)}
          />
          <label>Address</label>
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
      {errorMessage && <p>{errorMessage}</p>}
    </div>
  );
  
};

export default EditProfilePage;
