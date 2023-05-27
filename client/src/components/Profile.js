import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './Login.css';
import user_photo from '../user.png';
import checkbox_photo from '../checkbox.png';

function Profile() {
  const [address, setAddress] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [birthDate, setBirthDate] = useState('');
  const [joinedDate, setJoinedDate] = useState('');
  const [lastTimeOnline, setLastTimeOnline] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [oldPassword, setOldPassword] = useState('');
  const [wantNotify, setWantNotify] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const [editMode, setEditMode] = useState(false)
  const [editableMode, setEditableMode] = useState(false)
  const [editableProfilePage, setEditableProfilePage] = useState(true)
  const [changePassMode, setChangePassMode] = useState(false)
  const [continuePassMode, setContinuePassMode] = useState(false)
  const [clicked, setClicked] = useState(true);
  //de adaugat si notificarile sa fie salvate


  const closeEditMode = () => {
    setEditMode(false)
    setClicked(false)
    setChangePassMode(false)
    setContinuePassMode(false)
    setEditableProfilePage(true)
  }

  const openEditMode = () => {

    setClicked(false)
    setEditableProfilePage(false)
    setEditableMode(true)

  }

  const openEditProfileMode = () => {
    setEditMode(true)
    setClicked(false)
    setEditableProfilePage(false)
  }

  const openPassMode = () => {
    setChangePassMode(true)
  }

  const onEditHandler = () => {
    closeEditMode();
  }



  useEffect(() => {
    const fetchDetails = async () => {
      try {
        const userInfo = JSON.parse(localStorage.getItem('userInfo'));
        const username = userInfo?.username;

        if (username) {
          const config = {
            headers: {
              "Content-type": "application/json",
              "Authorization": userInfo?.role,
              "USER-UUID": userInfo?.user_id,
            },
          };

          const response = await axios.get(`http://localhost:8080/user/${username}`, config);
          const userAddress = response.data?.city_address;
          const birth = response.data?.birth_date
          const joined = response.data?.joined_date
          const lastOnline = response.data?.last_time_online
          const joined_date = new Date(joined.replace(' ', 'T'));
          const last_online = new Date(lastOnline.replace(' ', 'T'))
          const full_name = response.data?.full_name
          const want_notify = response.data?.want_notify
          setAddress(userAddress);
          setUsername(username);
          setBirthDate(birth);
          setJoinedDate(joined_date.toUTCString());
          setLastTimeOnline(last_online.toUTCString());
          setFullName(full_name);
          setWantNotify(want_notify)
        }
      } catch (error) {
        // Handle error if the address retrieval fails
        console.log('Error retrieving user details:', error);
      }
    };

    fetchDetails();
  }, []);

  let errMsg = ""
  let handleCheckOldPass = async (event) => {
    console.log(oldPassword)
    console.log(oldPassword.length)
    if (oldPassword.length > 0) {

      if (oldPassword.length < 8) {
        errMsg = 'Old Password is too short'
        setErrorMessage(errMsg)

      }
      if (oldPassword.charAt(0) < 'A' || oldPassword.charAt(0) > 'Z') {
        errMsg = 'Old Password must start with uppercase'
        setErrorMessage(errMsg)
        return

      }

    } else {
      errMsg = "Password empty"
      setErrorMessage(errMsg)
    }
    const userInfo = JSON.parse(localStorage.getItem('userInfo'));
    const username = userInfo?.username;

    if (username) {
      try {
        // Passwords match, register 
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
        setErrorMessage("Wrong password")
        return
      };

      setContinuePassMode(true)
    }


  }
  let handleSubmit = async (event) => {
    if (password.length > 0) {


      if (password.length < 8) {
        errMsg = 'Password is too short'
        setErrorMessage(errMsg)
        return

      }
      if (password.charAt(0) < 'A' || password.charAt(0) > 'Z') {
        errMsg = 'Password must start with uppercase'
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

      const config = {
        headers: {
          "Content-type": "application/json",
          "Authorization": userInfo?.role,
          "USER-UUID": userInfo?.user_id,
        },
      };

      await axios.put(`http://localhost:8080/user/`, {
        "username": username,
        "city_address": address,
        "password": password,
        "want_notify": wantNotify.toString(),
        "birth_date": birthDate,
        "full_name" : fullName
      }, config);

      // Clear the form fields and display a success message
      setAddress('');
      setPassword('');
      setConfirmPassword('');
      setWantNotify('');
      setErrorMessage('Profile updated successfully!');
      setChangePassMode(false)
      setClicked(true)
      setContinuePassMode(false)
      setEditableProfilePage(true)
      setEditableMode(false)
      setEditMode(false)
    } catch (error) {
      setErrorMessage('Failed to update profile. Please try again.');
    }
  };

  return (

    <div class="container bootstrap snippets bootdey">
      {editableProfilePage && (
        <div class="row">
          <div class="main-content">

            <button type="submit" onClick={openEditProfileMode} className="button-edit-mode">
              <span></span>
              <span></span>
              <span></span>
              <span></span>
              EditProfile</button>



            <div class="tab-content profile-page">

              <div class="tab-pane profile active" id="profile-tab">
                <div class="row">
                  <div class="col-md-3">
                    <div class="user-info-left">
                      <img class="img-responsive" src={user_photo} alt="Profile Picture" />
                      <h2>{fullName} <i class="fa fa-circle blue-font online-icon"></i><sup class="sr-only">online</sup></h2>
                    </div>
                  </div>
                  <div class="col-md-9">
                    <div class="user-info-right">
                      <div class="basic-info">
                        <h3><i class="fa fa-square"></i> Basic Information</h3>
                        <p class="data-row">
                          <span class="data-name">Birth Date</span>
                          <span class="data-value">{birthDate}</span>
                        </p>
                        <p class="data-row">
                          <span class="data-name">Date Joined</span>
                          <span class="data-value">{joinedDate}</span>
                        </p>
                        <p class="data-row">
                          <span class="data-name">Last Time Online</span>
                          <span class="data-value">{lastTimeOnline}</span>
                        </p>
                      </div>
                      <div class="contact_info">
                        <h3><i class="fa fa-square"></i> Contact Information</h3>
                        <p class="data-row">
                          <span class="data-name">Email</span>
                          <span class="data-value">{username}</span>
                        </p>
                        <p class="data-row">
                          <span class="data-name">Address</span>
                          <span class="data-value">{address}</span>
                        </p>
                      </div>

                    </div>
                  </div>
                </div>
              </div>

            </div>
          </div>

        </div>
      )}

      {!editableProfilePage && (
        <><div>
        </div><div className="login-box">
            <h2>Profile</h2>
            <img src={user_photo} className='user-photo' />
            <form onSubmit={handleSubmit}>
              {editMode && (<div className="user-box">
                <input
                  type="text"
                  name="fullname"
                  value={fullName}
                  onChange={(event) => setFullName(event.target.value)}
                  required
                  readOnly={!editableMode} />

                <label>Full Name</label>
              </div>)}
              {editMode && (<div className="user-box">
                <input
                  type="date"
                  name="birthdate"
                  value={birthDate}
                  onChange={(event) => setBirthDate(event.target.value)}
                  required
                  readOnly={!editableMode} />

                <label>Birth Date</label>
              </div>)}
              {editMode && (<div className="user-box">
                <input
                  type="text"
                  name="address"
                  value={address}
                  onChange={(event) => setAddress(event.target.value)}
                  required
                  readOnly={!editableMode} />

                <label>Address</label>
              </div>)}
              {changePassMode && (<div className="user-box">
                <input
                  type="password"
                  name="old_password"
                  value={oldPassword}
                  onChange={(event) => setOldPassword(event.target.value)}
                  required
                  readOnly={!editableMode && changePassMode} />
                <label>Old Password </label>
              </div>)}
              {continuePassMode && (<div className="user-box">
                <input
                  type="password"
                  name="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                  readOnly={!editableMode && changePassMode && continuePassMode} />
                <label>Password </label>
              </div>)}
              {continuePassMode && (<div className="user-box">
                <input
                  type="password"
                  name="confirm_password"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  required
                  readOnly={!editableMode && changePassMode && continuePassMode} />
                <label>Confirm Password</label>
              </div>)}
              {editMode && (<div className="checkbox-input">
                <label>Do you want to receive notifications regarding your apps?</label>
                <input
                  type="checkbox"
                  name="want_notify"
                  checked={wantNotify}
                  onChange={(event) => setWantNotify(event.target.checked)}
                  required
                  disabled={!editableMode} />
              </div>)}
              <a type="submit" style={{ visibility: clicked ? "visible" : "hidden" }} onClick={handleSubmit}>
                <span></span>
                <span></span>
                <span></span>
                <span></span>
                Update
              </a>
            </form>
            {editableMode && !editableProfilePage ? (
              <div className="textfield--header-actions">
                 {(continuePassMode || editableMode) && (
                <a type="submit" onClick={closeEditMode} className="button-cancel-mode">
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                  Cancel</a>
                  )}
                {(continuePassMode || editableMode) && (
                  <a type="submit" onClick={onEditHandler} className="button-save-mode">
                    <span></span>
                    <span></span>
                    <span></span>
                    <span></span>
                    Save</a>
                )}

              </div>
            ) : (

              <a type="submit" onClick={openEditMode} className="button-edit-mode">
                <span></span>
                <span></span>
                <span></span>
                <span></span>
                Edit</a>

            )}
            {!changePassMode && editableMode && (
              <a type="submit" style={{ visibility: clicked ? "hidden" : "visible" }} onClick={openPassMode} className="button-change-password">
                <span></span>
                <span></span>
                <span></span>
                <span></span>
                ChangePassword</a>
            )}



            {!continuePassMode && changePassMode && (
              <button style={{ backgroundImage: `url(${checkbox_photo})`, backgroundSize: "cover", width: "40px", height: "40px" }} className="button-check-password" onClick={handleCheckOldPass}
              ></button>
            )}
            {errorMessage && <div style={{ backgroundColor: "red" }} className="error"> {errorMessage} </div>}
          </div></>
      )};

    </div>
  )
}


export default Profile;