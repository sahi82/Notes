// File: components/Dashboard.js
import React from 'react';
import { getAuth, signOut } from 'firebase/auth';
import '../styles/Dashboard.css';

function Dashboard() {
  const auth = getAuth();
  const user = auth.currentUser;
  
  const handleSignOut = async () => {
    try {
      await signOut(auth);
    } catch (error) {
      console.error("Sign out error:", error);
    }
  };

  return (
    <div className="dashboard-container">
      <nav className="dashboard-nav">
      <div className="brand">Secure Notes App</div>
        <button className="logout-button" onClick={handleSignOut}>
          Sign Out
        </button>
      </nav>
      
      <div className="dashboard-content">
        <div className="user-profile">
          {user?.photoURL && (
            <img 
              src={user.photoURL} 
              alt="Profile" 
              className="profile-image" 
            />
          )}
          <h2>Welcome, {user?.displayName || 'User'}</h2>
          <p>{user?.email}</p>
        </div>
        
        <Notes />
      </div>
    </div>
  );
}

export default Dashboard;
