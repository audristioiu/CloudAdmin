import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './Login.css';
import user_photo from '../user.png';

function Profile() {
  const [address, setAddress] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const history = useNavigate();

  let errMsg = ""
  let handleSubmit = async (event) => {
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