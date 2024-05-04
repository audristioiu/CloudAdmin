import { useEffect, useState, React } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar/Navbar';
import Login from './components/UserAuth/Login';
import Register from './components/UserAuth/Register';
import Home from './components/Home';
import Main from './components/Main';
import ProfilePage from './components/UserProfile/Profile';
import EditProfilePage from './components/UserProfile/EditProfilePage';
import MyApps from './components/UserApps/MyApps';
import EditApp from './components/UserApps/EditApp';
import OneTimePassword from "./components/OneTimePass/OneTimePassword";
import OneTimePasswordValidate from "./components/OneTimePass/OneTimePasswordValidate";
import GrafanaPanelCPU from './components/D3Grafana/GrafanaPanelCPU';
import GrafanaPanelMem from './components/D3Grafana/GrafanaPanelMem';
import Form from './components/Form/Form';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(
    () => JSON.parse(localStorage.getItem('userInfo')) || false
  );

  const setAuth = (value) => {
    setIsAuthenticated(value);
  };

  useEffect(() => {
    localStorage.setItem("auth", JSON.stringify(isAuthenticated));
  }, [isAuthenticated]);

  return (
    <BrowserRouter>
      <Routes>
        <Route path='/login' element={<Login setAuth={setAuth} />} />
        <Route path='/register' element={<Register />} />
        <Route path='/otp/setup' element={<OneTimePassword />} />
        <Route path='/otp/validate' element={<OneTimePasswordValidate />} />
        <Route path='/' element={isAuthenticated ? <>
          <Navbar />
          <Home />
        </> : <Navigate to="/main" replace />} />
        <Route path='/home' element={<>
          <Navbar />
          <Home />
        </>} />
        <Route path='/profile' element={<>
          <Navbar />
          <ProfilePage />
        </>} />
        <Route path='/editprofile' element={<EditProfilePage />} />
        <Route path="/form" element={<Form />} />
        <Route path='/main' element={<Main />} />
        <Route path='/myapps' element={<>
          <Navbar />
          <MyApps />
        </>} />
        <Route path='/editapp' element={<EditApp />} />
        <Route path='/grafana/cpu' element={<GrafanaPanelCPU />} />
        <Route path='/grafana/mem' element={<GrafanaPanelMem />} />

      </Routes>
    </BrowserRouter>
  );
};

export default App;