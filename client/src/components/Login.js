import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './Login.css';

function Login({ setAuth }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const history = useNavigate();

  const handleSubmit = async (event) => {
    event.preventDefault();
    console.log('Username:', username, 'Password:', password);
    // Implement login logic here
    try {
      // Passwords match, register 
      const config = {
        headers: {
          "Content-type": "application/json",
        },
      };

      const { data } = await axios.post(
        "http://localhost:8080/login",
        { "username": username, "password": password },
        config
      );

      console.log(data);
      localStorage.setItem("userInfo", JSON.stringify(data));
      console.log(`Login user with username ${username} and password ${password}`);
      console.log(` Here is your role : ${data.role} and uuid : ${data.user_id}`)
      setAuth(true);
      history('/');
    } catch (error) {
      console.log(error.response.data.message);
      setErrorMessage("Wrong username or password")
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
      {errorMessage && <div style={{ backgroundColor: "red" }} className="error"> {errorMessage} </div>}<p>{errorMessage}</p>
    </div>
  );
}

export default Login;