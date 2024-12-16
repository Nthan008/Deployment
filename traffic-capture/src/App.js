import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

  const captureTraffic = async () => {
    setLoading(true);
    setMessage(''); // Clear previous messages
  
    try {
      const response = await axios.post('http://localhost:5000/capture-traffic', {}, {
        headers: { 'Content-Type': 'application/json' },
      });
      setMessage(response.data.message || 'Network traffic captured successfully.');
    } catch (error) {
      setMessage('Error capturing network traffic.');
    }
  
    setLoading(false);
  };
  

  return (
    <div className="app-container">
      {/* Navigation Bar */}
      <header className="navbar">
        <div className="logo">AI Malware Detection</div>
        <nav>
          <a href="#home" className="active">Home</a>
          <a href="#about">About</a>
        </nav>
        <div className="profile">
          <img src="https://via.placeholder.com/40" alt="Profile" className="profile-img" />
        </div>
      </header>

      {/* Hero Section */}
      <section className="hero">
        <h1>Android Malware Detection System</h1>
        <p>
          Detect malicious activity by analyzing network traffic in real-time.
        </p>

        {/* Capture Traffic Button */}
        <div className="capture-traffic">
          <img
            src={loading ? '/img/on.png' : '/img/off.png'}
            alt={loading ? 'Tracking On' : 'Tracking Off'}
            className="capture-btn"
            onClick={!loading ? captureTraffic : undefined} // Only clickable when not loading
            style={{ cursor: !loading ? 'pointer' : 'not-allowed' }}
          />
        </div>

        {/* Status Message */}
        {message && <p className="status-message">{message}</p>}
      </section>
    </div>
  );
}

export default App;
