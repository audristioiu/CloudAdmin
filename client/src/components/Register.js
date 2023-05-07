import React, { useState } from 'react';
import './Login.css';

function LoginBox() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
  
    const handleSubmit = (event) => {
      event.preventDefault();
      console.log('Username:', username, 'Password:', password);
      // Implement login logic here
      if (password === confirmPassword) {
        // Passwords match, register user
        console.log(`Registered user with username ${username} and password ${password}`);
      } else {
        // Passwords don't match, show error message
        console.error('Passwords do not match');
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
          <a type="submit">
            <span></span>
            <span></span>
            <span></span>
            <span></span>
            Register
          </a>
        </form>
      </div>
    );
  }
  
  export default LoginBox;