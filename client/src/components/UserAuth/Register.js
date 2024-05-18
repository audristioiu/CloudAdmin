import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import '../../assets/Login.scss';
import '../../assets/Error.scss';
import PasswordStrengthBar from 'react-password-strength-bar';
import {Agent} from 'https';
import certs from '../../Certs/certs';

function Register() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [userEmail, setUserEmail] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const history = useNavigate();

  let errMsg = "";
  let handleSubmit = async (event) => {

    if (!username || !password || !confirmPassword || !userEmail) {
      errMsg = 'Please fill all the fields!';
      setErrorMessage(errMsg);
      return

    }


    event.preventDefault();
    // Implement login logic here
    if (password === confirmPassword) {
      try {
        // Passwords match, register 
        const config = {
          headers: {
            "Content-type": "application/json",
            "Accept-Encoding" : "gzip"
          },
        };
        const agent = new Agent({
          cert: certs.certFile,
          key: certs.keyFile,
        })
        await axios.post(
          "https://localhost:9443/register/user",
          { "username": username, "password": password, "email": userEmail },
          config,
          { httpsAgent: agent },
        );
        setErrorMessage();
        history('/login');
      } catch (error) {

        setErrorMessage('Register failed. Error : ' + error.response.data.message);
        return
      };

    } else {
      // Passwords don't match, show error message
      errMsg = 'Passwords do not match.';
      setErrorMessage(errMsg);
    }
  };


  return (
    <div className="login-box">
      <h2>Register</h2>
      <form onSubmit={handleSubmit}>
        <div className="user-box">
          <input
            type="text"
            name="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            required
          />
          <label>Username</label>
        </div>
        <div className="user-box">
          <input
            type="text"
            name="email"
            value={userEmail}
            onChange={(event) => setUserEmail(event.target.value)}
            required
          />
          <label>Email</label>
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
          <PasswordStrengthBar password={password} />
          <label>Confirm Password</label>
        </div>
        <a type="submit" onClick={handleSubmit}>
          <span></span>
          <span></span>
          <span></span>
          <span></span>
          Register
        </a>
      </form>
      {errorMessage && <div className="error-message"> <span className = "error-text">{errorMessage}</span> </div>}
    </div>
  );
}

export default Register;