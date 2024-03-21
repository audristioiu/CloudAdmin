import React from 'react';
import {
  Nav,
  NavLink,
  Bars,
  NavMenu,
} from './NavbarElements';
import { useNavigate } from 'react-router-dom';
  
const Navbar = () => {
  const history = useNavigate();

  const logout = (event) => {
    event.preventDefault();

    localStorage.removeItem('userPass');
    localStorage.removeItem('userInfo');

    history('/main');
  };

  return (
    <>
      <Nav>
        <Bars />
        <NavMenu>
          <NavLink to='/home'>
            Home
          </NavLink>
          <NavLink to='/profile'>
            Profile
          </NavLink>
          <NavLink to='/myapps'>
            MyApps
          </NavLink>
          <button className='logout-btn' onClick={logout}>
            Logout
          </button>
        </NavMenu>
      </Nav>
    </>
  );
};
  
export default Navbar;