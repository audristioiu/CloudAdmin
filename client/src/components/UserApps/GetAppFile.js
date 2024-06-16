import { useState } from "react";
import axios from 'axios';
import { Agent } from 'https';
import certs from '../../Certs/certs.js';
import '../../assets/Error.scss';

function GetAppFile(props) {
    const { app } = props;
    const [appName, setAppName] = useState(app.name);
    const [podName, setPodName] = useState('');
    const [fileName, setFileName] = useState('');
    const [errorMessage, setErrorMessage] = useState('');

    const handleSubmit = async (event) => {
        event.preventDefault();

        try {
            const userInfo = JSON.parse(localStorage.getItem('userInfo'));
            const username = userInfo?.username;
            const agent = new Agent({
                cert: certs.certFile,
                key: certs.keyFile,
            });

            const config = {
                headers: {
                    "Content-type": "application/json",
                    "Accept-Encoding": "gzip",
                    "USER-AUTH": userInfo?.role,
                    "USER-UUID": userInfo?.user_id,
                },
                params: {
                    username,
                    app_name: podName,
                    file_name: fileName,
                },
                httpsAgent: agent,
                responseType: 'blob',
            };

            const response = await axios.get(`https://localhost:9443/getpodfile`, config);
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', fileName); // Set the file name for download
            document.body.appendChild(link);
            link.click();

            link.remove(); // Clean up and remove the link
            window.URL.revokeObjectURL(url);  // Free up memory used by the blob
            setErrorMessage();
        } catch (error) {
            setErrorMessage('Failed to schedule APP. Please try again. /' + error.response.data.message);
        }
    };

    return (
        <div className="modal-container">
            <form onSubmit={handleSubmit}>
                <div className="modal-title">
                    Download file from {appName}
                </div>
                <div className="user-box">
                    <label>
                        Pod Name
                        <input
                            className='input-style app-description'
                            type='text'
                            value={podName}
                            onChange={(e) => setPodName(e.target.value)}
                        />
                    </label>
                </div>
                <div className="user-box">
                    <label>
                        File Name
                        <input
                            className='input-style app-description'
                            type='text'
                            value={fileName}
                            onChange={(e) => setFileName(e.target.value)}
                        />
                    </label>
                </div>
                <button type="submit" className='button-3'>
                    Download file
                </button>
            </form>
            {errorMessage && <div className="error-message"> <span className="error-text">{errorMessage}</span> </div>}
        </div>
    );
}

export default GetAppFile;
