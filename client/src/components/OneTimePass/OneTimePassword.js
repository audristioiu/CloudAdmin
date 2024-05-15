import QRCode from "qrcode";
import axios from 'axios';
import React, { useState } from "react";
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
import {Agent} from 'https';
import certs from '../../Certs/certs';
import '../../assets/Profile.scss';
import '../../assets/Error.scss';
import ReactInputVerificationCode from "react-input-verification-code";
const styles = {
    heading3: `text-xl font-semibold text-gray-900 p-4 border-b`,
    heading4: `text-base text-ct-blue-600 font-medium border-b mb-2`,
    modalOverlay: `overflow-y-auto overflow-x-hidden fixed top-0 right-0 left-0 z-50 w-full md:inset-0 h-modal md:h-full`,
    orderedList: `space-y-1 text-sm list-decimal`,
    buttonGroup: `flex items-center py-6 space-x-2 rounded-b border-t border-gray-200 dark:border-gray-600 allign:center`,
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

const OneTimePassword = () => {
    const [qrcodeUrl, setqrCodeUrl] = useState('');
    const [codeData, setCodeData] = useState('');
    const [showQR, setShowQR] = useState(false);
    const [showButton, setShowButton] = useState(true);
    const [errorMessage, setErrorMessage] = useState('');
    const history = useNavigate();


    const closeModal=() => {
        history('/profile')
    }

    const getQR=() => {
        QRCode.toDataURL(JSON.parse(localStorage.getItem('userOTP'))?.otp_auth_url).then(setqrCodeUrl)
        setShowQR(true)
        setShowButton(!showButton);
    }

    const verifyOTP = async () => {
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
              "https://localhost:9443/otp/verify",
            {"token": codeData},config, { httpsAgent : agent },);
            if (response.status === 200) {
                history('/profile')
            }
            
          } catch (error) {
            setErrorMessage("Could not verify otp : " +error.response.data.message);
          }
         
      }
    }


    useEffect(() =>{
    }, [])
   
    return (
        <div
          className="overflow-y-auto overflow-x-hidden fixed top-0 right-0 left-0 z-50 w-full md:inset-0 h-modal md:h-full bg-[#222] bg-opacity-50"
        >
          <div className="relative p-4 w-full max-w-xl h-full md:h-auto left-1/2 -translate-x-1/2">
            <div className="relative bg-white rounded-lg shadow">
              <h3 className={styles.heading3}>Two-Factor Authentication (2FA)</h3>
              {/* Modal body */}
              <div className="p-6 space-y-4">
                <h4 className={styles.heading4}>
                  Configuring Google Authenticator or Authy
                </h4>
                <div className={styles.orderedList}>
                  <li>
                    Press Get QR button to generate QR code.
                  </li>
                  <li>
                    Install Google Authenticator (IOS - Android) or Authy (IOS -
                    Android).
                  </li>
                  <li>In the authenticator app, select "+" icon.</li>
                  <li>
                    Select "Scan a barcode (or QR code)" and use the phone's camera
                    to scan this barcode.
                  </li>
                  <li>
                    If you want to close MFA setup, please press Close.
                  </li>
                </div>
                <div>
                  <h4  style={{"display": "flex","alignItems": "center", "justifyContent": "center"}} className={styles.heading4}>Scan QR Code</h4>
                  <div style={{"display": "flex","alignItems": "center", "justifyContent": "center"}} className="flex justify-center">
                    <img
                      className="block w-64 h-64 object-contain"
                      src= {showQR ? qrcodeUrl : qrcodeUrl}
                      alt="qrcode url"
                    />
                  </div>
                </div>
                <div>
                  <h4  style={{"display": "flex","alignItems": "center", "justifyContent": "center"}} className={styles.heading4}>Verify Code</h4>
                  <p style={{"display": "flex","alignItems": "center", "justifyContent": "center"}} className="text-sm">
                    For changing the setting, please verify the authentication code:
                  </p> 
                </div>
                {showButton && <button type="button" onClick={getQR} style={{display:"block", margin:"auto", marginTop:-110}} className={styles.buttonBlue}>
                        Get QR
                    </button>}
                {showQR && (

                <form>
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
                    <button  
                    type="button" onClick={verifyOTP} style={{display:"block", margin:"auto", marginTop:-30}} className={styles.buttonBlue}>
                      Verify & Activate
                    </button>
                  </div>
                </form>
                )}
              </div>
            </div>
          </div>
        </div>
      );
    };

export default OneTimePassword;
