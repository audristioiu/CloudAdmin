import { Link } from 'react-router-dom';
import './Login.scss';

function Main() {
  return (
    <div className="login-box">
      <h1>Welcome to Cloud Admin!</h1>
      <p>Please log in or register:</p>
      <nav>
        <ul>
          <li>
            <Link to="/login">
              Log in
            </Link>
          </li>
          <li><Link to="/register">Register</Link></li>
        </ul>
      </nav>
    </div>

  );
}

export default Main;