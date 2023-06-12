import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './Login.css';

function Register() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const history = useNavigate();

  let errMsg = ""
  let handleSubmit = async (event) => {

    if (!username || !password || !confirmPassword) {
      errMsg = 'Please fill all the fields!'
      setErrorMessage(errMsg)
      return

    }
    if (password.length > 0) {
      if (password.length < 8) {
        errMsg = 'Password is too short'
        setErrorMessage(errMsg)
        return

      }
      if (password.charAt(0) !== password.charAt(0).toUpperCase()) {
        errMsg = 'Password must start with an uppercase letter';
        setErrorMessage(errMsg);
        return;
      }
    } else {
      errMsg = "Password empty"
      setErrorMessage(errMsg)
    }


    event.preventDefault();
    console.log('Username:', username, 'Password:', password);
    // Implement login logic here
    if (password === confirmPassword) {
      try {
        // Passwords match, register 
        const config = {
          headers: {
            "Content-type": "application/json",
          },
        };

        const { data } = await axios.post(
          "http://localhost:8080/register/user",
          { "username": username, "password": password },
          config
        );

        console.log(data);
        console.log(`Registered user with username ${username} and password ${password}`);
        history('/login');
      } catch (error) {
        console.log(error.response.data.message);
        setErrorMessage("Wrong password")
        return
      };

    } else {
      // Passwords don't match, show error message
      console.error('Passwords do not match');
      errMsg = 'Passwords do not match'
      setErrorMessage(errMsg)
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
          Register
        </a>
      </form>
      {errorMessage && <div style={{ backgroundColor: "red" }} className="error"> {errorMessage} </div>}
    </div>
  );
}

export default Register;