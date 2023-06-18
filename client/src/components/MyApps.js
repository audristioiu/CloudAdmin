import React, { useState, useEffect } from 'react';
import axios from 'axios';
import AppItem from './AppItem';

function MyApps() {
    const [apps, setApps] = useState([]);
    const [errorMessage, setErrorMessage] = useState('');
    const [searchInput, setSearchInput] = useState("");
    const [typeInput, setTypeInput] = useState("")

    console.log(searchInput)
    console.log(typeInput)

    let handleUploadArchive = () => {
        const selectedFile = document.getElementById("input").files[0];
        if (selectedFile !== undefined) {
            const userInfo = JSON.parse(localStorage.getItem('userInfo'));
            const username = userInfo?.username;
    
            const config_app = {
                headers: {
                    "Content-type": "multipart/form-data",
                    "Authorization": userInfo?.role,
                    "USER-UUID": userInfo?.user_id,
                },
                params: {
                    "username": username,
                }
            }
            const formData = new FormData();
            formData.append('file',selectedFile)
    
            try {
                axios.post("http://localhost:8080/register/app", formData, config_app)
            } catch(error){
                console.log(error)
                setErrorMessage(error)
            }
    
        }
       


    }

    const fetchApps = async () => {

        console.log(typeInput)

        //debug filtru nu merge pe frontend
        const userInfo = JSON.parse(localStorage.getItem('userInfo'));
        const config = {
            headers: {
                "Content-type": "application/json",
                "Authorization": userInfo?.role,
                "USER-UUID": userInfo?.user_id,
            },
        };
        const username = userInfo?.username;
        try {
            const response = await axios.get(`http://localhost:8080/user/${username}`, config);
            const my_apps = response.data?.applications
            const query_my_apps = my_apps.join()
            if (searchInput.length !== 0) {
                if (typeInput.length === 0 || typeInput === "name") {
                    const config_app = {
                        headers: {
                            "Content-type": "application/json",
                            "Authorization": userInfo?.role,
                            "USER-UUID": userInfo?.user_id,
                        },
                        params: {
                            "appnames": searchInput,
                            "username": username,
                        }
                    }
                    const response_apps = await axios.get(`http://localhost:8080/app`, config_app);
                    console.log(response_apps)
                    setApps(response_apps.data.Response)
                } else {
                    const config_app = {
                        headers: {
                            "Content-type": "application/json",
                            "Authorization": userInfo?.role,
                            "USER-UUID": userInfo?.user_id,
                        },
                        params: {
                            "appnames": query_my_apps,
                            "username": username,
                            "filter": typeInput + ':' + searchInput,
                        }
                    }
                    const response_apps = await axios.get(`http://localhost:8080/app`, config_app);
                    console.log(response_apps)
                   setApps(response_apps.data.Response)
                }
               
            } else {
                const config_app = {
                    headers: {
                        "Content-type": "application/json",
                        "Authorization": userInfo?.role,
                        "USER-UUID": userInfo?.user_id,
                    },
                    params: {
                        "appnames": query_my_apps,
                        "username": username
                    }
                }

                const response_apps = await axios.get(`http://localhost:8080/app`, config_app);
                console.log(response_apps)
                setApps(response_apps.data.Response)
            }



        } catch (error) {
            console.log(error)
            setErrorMessage(error)
            console.log(errorMessage)
            //to fix wrong search error
            setApps([]) 
        };
    };

    useEffect(() => {
        fetchApps();
    }, apps);



    const renderApps = () => {
        console.log(apps)
        if (apps) {
            return apps.map((app, i) => {
                return <AppItem key={i} app={app} />
            })
        }

    };

    return (
        <>
             <input type="submit" value="Submit" onClick={fetchApps}/>
            <input
                type="search"
                placeholder="Search here"
                onChange={(e) => setSearchInput(e.target.value)}
                value={searchInput} />
            <label>
                Pick filter:
                <select
                    value={typeInput}
                    onChange={(e) => setTypeInput(e.target.value)}>
                    <option value="name">name</option>
                    <option value="description">Description(keyword)</option>
                    <option value="is_running">IsRunning</option>
                </select>
            </label>
            <div className='form-style'>
                <div className='list-items'>
                    {renderApps()}
                </div>
                <input type="file" id="input" multiple />
                <input type="submit" value="SubmitArchive" onClick={handleUploadArchive} />
            
            </div>
        
        </>
        
    )

}


export default MyApps;