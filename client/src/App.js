import { useEffect, useState, React } from 'react';
import { 
  BrowserRouter,
  Routes,
  Route,
  Navigate
} from 'react-router-dom';
import Login from './components/Login';
import Register from './components/Register';
import Home from './components/Home';
import Main from './components/Main';
import Profile from './components/Profile';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(
    () => JSON.parse(localStorage.getItem('userInfo')) || false
  );

  const setAuth = (value) => {
    setIsAuthenticated(value);
  };

  useEffect(()=>{
    localStorage.setItem("auth", JSON.stringify(isAuthenticated));
  }, [isAuthenticated]);

  return (
    <BrowserRouter>
      <Routes>
        <Route path='/login' element={<Login setAuth={setAuth}/>}/>
        <Route path='/register' element={<Register />}/>
        <Route path='/' element={isAuthenticated ? <Profile /> : <Navigate to="/main" replace />}/>
        <Route path='/home' element={<Home />}/>
        <Route path='/profile' element={<Profile />}/>
        <Route path='/main' element={<Main />}/>
      </Routes>
    </BrowserRouter>
  );
};

export default App;