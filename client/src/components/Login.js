import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import '../assets/Login.scss';
import '../assets/Error.scss';
import { Agent } from 'https';
import certs from '../Certs/certs.js';


function Login({ setAuth }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const history = useNavigate();

  const handleSubmit = async (event) => {
    event.preventDefault();
    // Implement login logic here
    try {
      // Passwords match, register 
      const config = {
        headers: {
          "Content-type": "application/json",
        },
      };

      const agent = new Agent({
        cert: certs.certFile,
        key: certs.keyFile,
      })

      const { data } = await axios.post(
        "https://localhost:9443/login",
        { "username": username, "password": password },
        config,
        { httpAgent: agent },
      );
      localStorage.setItem("userPass", password);
      localStorage.setItem("userInfo", JSON.stringify(data));
      setAuth(true);
      if (data.otp_data.otp_enabled) {
        history('/otp/validate');
      } else {
        history('/');
      }
     
    } catch (error) {
      setErrorMessage(error.response.data.message);
      return
    };
  };

  return (
    <div className="login-box">
      <h2>Login</h2>
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
            type="password"
            name="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
          <label>Password</label>
        </div>
        <a type="submit" onClick={handleSubmit}>
          <span></span>
          <span></span>
          <span></span>
          <span></span>
          Log in
        </a>
      </form>
      {errorMessage && <div className="error-message"> <span className = "error-text">{errorMessage}</span> </div>}
    </div>
  );
}

export default Login;