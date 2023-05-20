import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './Login.css';
import user_photo from '../user.png';

function Profile() {
  const [address, setAddress] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [wantNotify, setWantNotify] = useState('');
  const [errorMessage, setErrorMessage] = useState('');

  useEffect(() => {
    const fetchAddress = async () => {
      try {
        const userInfo = JSON.parse(localStorage.getItem('userInfo'));
        const username = userInfo?.username;

        if (username) {
          const config = {
            headers: {
              "Content-type": "application/json",
              "Access-Control-Allow-Origin": "localhost:3000",
              "Authorization": userInfo?.role,
              "USER-UUID": userInfo?.user_id,
            },
          };

          const response = await axios.get(`http://localhost:8080/user/${username}`);
          const userAddress = response.data?.city_address;
          setAddress(userAddress);
        }
      } catch (error) {
        // Handle error if the address retrieval fails
        console.log('Error retrieving user address:', error);
      }
    };
  
    fetchAddress();
  }, []);

  let errMsg = ""
  let handleSubmit = async (event) => {
    if (password.length > 0) {
      if (password.charAt(0) !== password.charAt(0).toUpperCase()){
        errMsg = 'Password must start with uppercase'
        setErrorMessage(errMsg)
        return

      }
      if (password.length < 8) {
        errMsg = 'Password is too short'
        setErrorMessage(errMsg)
        return

      }
    }

    try {
      // Make an API request to update the user's profile
      // Here, you can use axios or any other library for making HTTP requests
      // Pass the updated profile information in the request body

      const userInfo = JSON.parse(localStorage.getItem('userInfo'));
      const username = userInfo?.username;

      const response = await axios.put(`http://localhost:8080/user/`, {
        "username": username,
        "city_address": address,
        "password": password,
        "want_notify": wantNotify.toString(),
      });

      // Clear the form fields and display a success message
      setAddress('');
      setPassword('');
      setConfirmPassword('');
      setWantNotify('');
      setErrorMessage('Profile updated successfully!');
    } catch (error) {
      setErrorMessage('Failed to update profile. Please try again.');
    }
  };

  return (
    <div className="login-box">
      <h2>Profile</h2>
      <img src={user_photo} className='user-photo' />
      <form onSubmit={handleSubmit}>
        <div className="user-box">
          <input
            type="text"
            name="address"
            value={address}
            onChange={(event) => setAddress(event.target.value)}
            required
          />
          <label>Address</label>
        </div>
        <div className="user-box">
          <input
            type="password"
            name="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
          <label>Password</label>
        </div>
        <div className="user-box">
          <input
            type="password"
            name="confirm_password"
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)}
            required
          />
          <label>Confirm Password</label>
          </div>
        <div className="checkbox-input">
          <label>Do you want to receive notifications regarding your apps?</label>
          <input
            type="checkbox"
            name="want_notify"
            checked={wantNotify}
            onChange={(event) => setWantNotify(event.target.checked)}
            required
          />
        </div>
          <a type="submit" onClick={handleSubmit}>
            <span></span>
            <span></span>
            <span></span>
            <span></span>
            Update
          </a>
      </form>
      {errorMessage && <div style={{backgroundColor: "red"}} className="error"> {errorMessage} </div>}
    </div>
  );
}

export default Profile;