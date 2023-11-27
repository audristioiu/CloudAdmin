import { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from 'axios';
import { Agent } from 'https';
import certs from '../Certs/certs.js';

function EditApp() {

  const app = JSON.parse(localStorage.getItem("appInfo"));
  const [appName, setAppName] = useState(app.app_name);
  const [appDescription, setAppDescr] = useState("");
  const [appFlagArguments, setAppFlags] = useState("");
  const [appParamArguments, setAppParams] = useState("");
  const [errorMessage, setErrorMessage] = useState('');
  const [editMode, setEditMode] = useState(false);
  const [clicked, setClicked] = useState(true);
  const [editableMode, setEditableMode] = useState(false);
  const history = useNavigate();



  const closeEditMode = () => {
    setEditMode(false);
    setClicked(true);

  }

  const openEditMode = () => {
    setClicked(false);
    setEditMode(true);
    setEditableMode(true);
  }

  const onEditHandler = () => {
    closeEditMode();
  }

  let handleSubmit = async (event) => {

    try {
      // Make an API request to update the app data
      // Here, you can use axios or any other library for making HTTP requests
      // Pass the updated app information in the request body

      const userInfo = JSON.parse(localStorage.getItem('userInfo'));
      const username = userInfo?.username;
      const agent = new Agent({
        cert: certs.certFile,
        key: certs.keyFile,
      })

      const config = {
        headers: {
          "Content-type": "application/json",
          "USER-AUTH": userInfo?.role,
          "USER-UUID": userInfo?.user_id,
        },
        params: {
          "username": username,
        }
      };

      await axios.put(`https://localhost:443/app`, {
        "name": appName,
        "description": appDescription,
        "flag_arguments": appFlagArguments,
        "param_arguments": appParamArguments
      }, config,
        { httpsAgent: agent },);

      // Clear the form fields and display a success message
      setAppDescr('');
      setAppName('');
      setAppFlags('');
      setAppParams('');
      setClicked(true);
      setEditableMode(false);
      history("/myapps");

    } catch (error) {
      setErrorMessage('Failed to update APP. Please try again. /' + error.response.data.message);
    }
  };


  return (
    <div className="login-box">
      <form onSubmit={handleSubmit}>
        <div className="user-box">
          <input
            type='text'
            value={appName}
            onChange={(e) => setAppName(e.target.value)}
            required
            disabled
          />


        </div>
        {editableMode && (<div className="user-box">
          <input
            className='input-style app-description'
            type='textarea'
            value={appDescription}
            onChange={(e) => setAppDescr(e.target.value)}
            required
          />

          <label>Description</label>

        </div>)}
        {editableMode && (<div className="user-box">
          <input
            className='input-style app-description'
            type='textarea'
            value={appFlagArguments}
            onChange={(e) => setAppFlags(e.target.value)}
            required
          />

          <label>Flag Arguments</label>

        </div>)}
        {editableMode && (<div className="user-box">
          <input
            className='input-style app-description'
            type='textarea'
            value={appParamArguments}
            onChange={(e) => setAppParams(e.target.value)}
            required
          />

          <label>Param Arguments</label>

        </div>)}


        <a type="submit" style={{ visibility: clicked ? "visible" : "hidden" }} onClick={handleSubmit}>
          <span></span>
          <span></span>
          <span></span>
          <span></span>
          Update
        </a>
      </form>
      {editMode ? (
        <div className="textfield--header-actions">
          {(editableMode) && (
            <a type="submit" onClick={closeEditMode} className="button-cancel-mode">
              <span></span>
              <span></span>
              <span></span>
              <span></span>
              Cancel</a>)}
          {(editableMode) && (
            <a type="submit" onClick={onEditHandler} className="button-save-mode">
              <span></span>
              <span></span>
              <span></span>
              <span></span>
              Save</a>)}

        </div>
      ) : (

        <a type="submit" onClick={openEditMode} className="button-edit-mode">
          <span></span>
          <span></span>
          <span></span>
          <span></span>
          Edit</a>

      )}
      {errorMessage && <div style={{ backgroundColor: "red" }} className="error"> {errorMessage} </div>}<p>{errorMessage}</p>
    </div>
  )
}


export default EditApp;