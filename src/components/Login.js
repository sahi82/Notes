// File: components/Login.js
import React, { useState } from 'react';
import { 
  getAuth, 
  GoogleAuthProvider, 
  FacebookAuthProvider, 
  signInWithPopup 
} from 'firebase/auth';
import '../styles/Login.css';

function Login() {
  const [error, setError] = useState('');
  const auth = getAuth();

  const handleGoogleSignIn = async () => {
    try {
      const provider = new GoogleAuthProvider();
      await signInWithPopup(auth, provider);
    } catch (error) {
      setError(error.message);
      console.error("Google Sign-in Error:", error);
    }
  };

  const handleFacebookSignIn = async () => {
    try {
      const provider = new FacebookAuthProvider();
      await signInWithPopup(auth, provider);
    } catch (error) {
      setError(error.message);
      console.error("Facebook Sign-in Error:", error);
    }
  };

  return (
    <div className="login-container">
      <h1>Welcome</h1>
      <p>Sign in to continue</p>
      
      {error && <div className="error-message">{error}</div>}
      
      <div className="auth-buttons">
        <button 
          className="google-button"
          onClick={handleGoogleSignIn}
        >
          <i className="google-icon"></i>
          Sign in with Google
        </button>
        
        <button 
          className="facebook-button"
          onClick={handleFacebookSignIn}
        >
          <i className="facebook-icon"></i>
          Sign in with Facebook
        </button>
      </div>
    </div>
  );
}

export default Login;
