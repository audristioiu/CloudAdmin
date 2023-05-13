import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './Login.css';

function Register() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showErrorMessage, setShowErrorMessage] = useState(false);
  const [isPasswordDirty, setisPasswordDirty] = useState(false);
  const history = useNavigate();

  let handleSubmit = async (event) => {
    if (!username || !password || !confirmPassword) {
      alert('Please fill all the fields!');
      return;
    }
    if (password.charAt(0) !== password.charAt(0).toUpperCase()){
      alert('Password should start with an uppercase')
      return;
    }
    if (password.length < 8) {
      alert('Password is too short')
      return;
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
          { "username": username,"password" : password },
          config
        );

        console.log(data);
        console.log(`Registered user with username ${username} and password ${password}`);
        history('/login');
      } catch (error) {
        setShowErrorMessage(true)
        alert(error.response.data.message);
        return
      };

    } else {
      // Passwords don't match, show error message
      console.error('Passwords do not match');
    }
  };
  useEffect(() => {
    if (isPasswordDirty) {
      if (password === confirmPassword) {
        setShowErrorMessage(false);
        setConfirmPassword('form-control is-valid')
      } else {
        setShowErrorMessage(true)
        setConfirmPassword('form-control is-invalid')
      }
    }
  }, [confirmPassword])

  // const handleConfirmPassword = (e) => {
  //   setConfirmPassword(e.target.value);
  //   setisPasswordDirty(true);
  // }

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
          </a>
          Register
      </form>
      {showErrorMessage && isPasswordDirty ? <div> Passwords did not match </div> : ''}
    </div>
  );
}

export default Register;