import React from 'react';
import { useNavigate, NavLink } from 'react-router-dom';
import '../assets/Navbar.scss';
  
const Navbar = () => {
  const history = useNavigate();

  const logout = (event) => {
    event.preventDefault();

    localStorage.removeItem('userPass');
    localStorage.removeItem('userInfo');
    localStorage.setItem("auth", false)

    history('/main');
  };

  return (
    <>
      <div className='nav'>
        <div className='nav-menu'>
          <NavLink to='/home' activeclassname="active" className="nav-link">
            Home
          </NavLink>
          <NavLink to='/profile' activeclassname="active" className="nav-link">
            Profile
          </NavLink>
          <NavLink to='/myapps' activeclassname="active" className="nav-link">
            MyApps
          </NavLink>
          <button className='logout-btn' onClick={logout}>
            Logout
          </button>
        </div>
      </div>
    </>
  );
};
  
export default Navbar;