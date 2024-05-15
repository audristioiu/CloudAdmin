import axios from 'axios';
import React, { useState } from "react";
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {Agent} from 'https';
import certs from '../../Certs/certs';
import '../../assets/Profile.scss';
import '../../assets/Error.scss';
import styled from "styled-components";
import ReactInputVerificationCode from "react-input-verification-code";

const styles = {
    heading3: `text-xl font-semibold text-gray-900 p-4 border-b`,
    heading4: `text-base text-ct-blue-600 font-medium border-b mb-2`,
    modalOverlay: `overflow-y-auto overflow-x-hidden fixed top-0 right-0 left-0 z-50 w-full md:inset-0 h-modal md:h-full`,
    orderedList: `space-y-1 text-sm list-decimal`,
    buttonGroup: `flex items-center py-6 space-x-2 rounded-b border-t border-gray-200 dark:border-gray-600`,
    buttonBlue: `text-white bg-blue-700 hover:bg-blue-800 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium rounded-lg text-sm px-5 py-2.5 text-center dark:bg-blue-600 dark:hover:bg-blue-700 dark:focus:ring-blue-800`,
    buttonGrey: `text-gray-500 bg-white hover:bg-gray-100 focus:ring-4 focus:outline-none focus:ring-blue-300 rounded-lg border border-gray-200 text-sm font-medium px-5 py-2.5 hover:text-gray-900 focus:z-10 dark:bg-gray-700 dark:text-gray-300 dark:border-gray-500 dark:hover:text-white dark:hover:bg-gray-600 dark:focus:ring-gray-600`,
    inputField: `bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-2/5 p-2.5`,
  };
  const StyledReactInputVerificationCode = styled.div`
  display: flex;
  justify-content: center;

  --ReactInputVerificationCode-itemWidth: 40px;
  --ReactInputVerificationCode-itemHeight: 48px;
  --ReactInputVerificationCode-itemSpacing: 8px;

  .ReactInputVerificationCode__item {
    font-size: 16px;
    font-weight: 500;
    color: #fff;

    background: rgba(53, 67, 98, 1);
    border: 1px solid
    ${({ isInvalid }) => (isInvalid ? "#EF6C65" : "rgba(28, 30, 60, 0.4)")};
    border-radius: 4px;
    box-shadow: none;
  }

  .ReactInputVerificationCode__item.is-active {
    box-shadow: none;
    border: 1px solid #36c6d9;
  }
`;
const OneTimePasswordValidate = () => {

    const [codeData, setCodeData] = useState('')
    const [errorMessage, setErrorMessage] = useState('');
    const history = useNavigate();

    const closeModal=() => {
      history('/profile')
  }

    const validateOTP = async () => {
        if (codeData) {
          const userInfo = JSON.parse(localStorage.getItem('userInfo'));
          try {
            const config = {
              headers: {
                "Content-type": "application/json",
                "Accept-Encoding" : "gzip",
                "USER-AUTH": userInfo?.role,
                "USER-UUID": userInfo?.user_id,
              },
            };
            const agent = new Agent({
              cert: certs.certFile,
              key: certs.keyFile,
            })
            const response = await axios.post(
              "https://localhost:9443/otp/validate",
            {token: codeData},config, { httpsAgent : agent },);
             if (response.status === 200){
                history('/')
             }
          } catch (error) {
            setErrorMessage("Could not validate otp : " +error.response.data.message);
          }
         
      }
    }

return (
    <section className="bg-ct-blue-600 min-h-screen grid place-items-center">
      <div className="w-full">
        <h2  style={{"display": "flex","alignItems": "center", "justifyContent": "center"}} className="text-lg text-center mb-4 text-ct-dark-200">
          Verify the Authentication Code
        </h2>
          <h2  style={{"display": "flex","alignItems": "center", "justifyContent": "center"}} className="text-center text-3xl font-semibold text-[#142149]">
            Two-Factor Authentication
          </h2>
          <p  style={{"display": "flex","alignItems": "center", "justifyContent": "center"}} className="text-center text-sm">
            Open the two-step verification app on your mobile device to get your
            verification code.
          </p>
                  <StyledReactInputVerificationCode>
                  <ReactInputVerificationCode
                    type="text"
                    value={codeData}
                    placeholder={null}
                    length={6}
                    onChange={
                      (newValue)=> {
                        setCodeData(newValue)
                      if (newValue !== null) {
                        setErrorMessage(null)
                      }
                    }
                    }
                    className="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-2/4 p-2.5"
                  />
                  </StyledReactInputVerificationCode>
          <p className="mt-2 text-xs text-red-600">
          {errorMessage && <div className="error-message"> <span className = "error-text">{errorMessage}</span> </div>}
          </p>
          <div className={styles.buttonGroup}>
            <button
              type="button"
              onClick={closeModal}
              style={{display:"block", margin:"auto",marginLeft:40}}
              className={styles.buttonGrey}
            >
              Close
            </button>
            </div>
          <button
            className={styles.buttonBlue}
             style={{display:"block", margin:"auto"}}
            textColor="text-ct-blue-600"
            onClick={validateOTP}
          >
            Authenticate
          </button>
      </div>
    </section>
  );
};

export default OneTimePasswordValidate;
