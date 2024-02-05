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

    history.push('/');
  };

  return (
    <>
      <Nav>
        <Bars />
        <NavMenu>
          <NavLink to='/home' activeStyle>
            Home
          </NavLink>
          <NavLink to='/profile' activeStyle>
            Profile
          </NavLink>
          <NavLink to='/myapps' activeStyle>
            MyApps
          </NavLink>
          <button className='logout-btn' onClick={logout}>
            Logout
          </button>
          {/* cred ca trebuie un logout + cele de schedule si dashboards*/}
          {/* <NavLink to='/logout' activeStyle>
            Teams
          </NavLink>
          <NavLink to='/blogs' activeStyle>
            Blogs
          </NavLink>
          <NavLink to='/sign-up' activeStyle>
            Sign Up
          </NavLink> */}
          {/* Second Nav */}
          {/* <NavBtnLink to='/sign-in'>Sign In</NavBtnLink> */}
        </NavMenu>
      </Nav>
    </>
  );
};
  
export default Navbar;