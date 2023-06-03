import { useState } from "react";
import { useNavigate } from "react-router-dom";

function AppItem(app){
    const [appName, setAppName] = useState(app.app.name)
    const [appDescription, setAppDescr] = useState(app.app.description)
    const [appRunningState, setAppRunning] = useState(app.app.is_running)
    const history = useNavigate()
    
    const editApp = () => {
        console.log(appName)
        localStorage.setItem("appInfo", JSON.stringify({"app_name":appName}));
        history('/editapp')
    }

    return (
        <div className="app-item">
            <span>App name
                <input
                    className='input-style app-input'
                    type='text'
                    value={appName}
                    onChange={(e) => setAppName(e.target.value)}
                    required
                    disabled
                    />
            </span>
           

            <span>Description
                <input
                    className='input-style app-description'
                    type='textarea'
                    value={appDescription}
                    onChange={(e) => setAppDescr(e.target.value)}
                    required
                    disabled
                    />
            </span> 

            <span>IsRunning
                {appRunningState == "true" ? (
                     <div class="led-box">
                     <div class="led-green"></div>
                     <p>Running</p>
                        </div>
                ) : (
                    <div class="led-box">
                    <div class="led-red"></div>
                    <p>Not Running</p>
                  </div>
                )}
                <input
                    className='input-style app-input'
                    type='text'
                    value={appRunningState}
                    onChange={(e) => setAppRunning(e.target.value)}
                    required
                    disabled
                    style={{visibility: "hidden"}}

                    />
            </span>

            <span>
                <button className='edit-delete-button btn'
                onClick={editApp}
                  >Edit App
                    <span className='far fa-solid fa-pen-to-square'>

                    </span>
                </button>

                <button className='edit-delete-button btn'
                    >Delete App
                    <span className='far fa-solid fa-trash-can'></span>
                </button>
            </span>

        </div>
    );
};


export default AppItem;