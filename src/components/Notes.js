// File: components/Notes.js (Updated for server-side encryption)
import React, { useState, useEffect } from 'react';
import { getAuth } from 'firebase/auth';
import '../styles/Notes.css';

function Notes() {
  const [note, setNote] = useState('');
  const [savedNotes, setSavedNotes] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const auth = getAuth();
  const user = auth.currentUser;

  // API base URL (should be configured in environment variables)
  const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'https://your-azure-app-service.azurewebsites.net';
  
  useEffect(() => {
    // Load notes when component mounts
    if (user) {
      loadNotes();
    }
  }, [user]);

  const loadNotes = async () => {
    try {
      setLoading(true);
      
      // Fetch notes from the server API
      const response = await fetch(`${API_BASE_URL}/api/notes/${user.uid}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${await user.getIdToken()}`
        }
      });
      
      if (!response.ok) {
        throw new Error('Failed to fetch notes');
      }
      
      // Notes are already decrypted by the server
      const notesData = await response.json();
      setSavedNotes(notesData);
    } catch (err) {
      setError('Error loading notes: ' + err.message);
      console.error('Error loading notes:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSaveNote = async () => {
    if (!note.trim()) {
      setError('Note cannot be empty');
      return;
    }
    
    try {
      setLoading(true);
      setError('');
      
      // Send the plaintext note to the server for encryption and storage
      const response = await fetch(`${API_BASE_URL}/api/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${await user.getIdToken()}`
        },
        body: JSON.stringify({
          userId: user.uid,
          content: note
        })
      });
      
      if (!response.ok) {
        throw new Error('Failed to save note');
      }
      
      const savedNote = await response.json();
      
      // Reload notes to get the latest data
      await loadNotes();
      
      // Clear the input
      setNote('');
    } catch (err) {
      setError('Error saving note: ' + err.message);
      console.error('Error saving note:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="notes-container">
      <h2>Encrypted Notes</h2>
      <p className="notes-description">
        Your notes are securely encrypted on the server using Azure Key Vault.
      </p>
      
      {error && <div className="error-message">{error}</div>}
      
      <div className="note-input-container">
        <textarea
          className="note-input"
          placeholder="Type your note here..."
          value={note}
          onChange={(e) => setNote(e.target.value)}
          rows={6}
        />
        
        <button 
          className="save-note-button"
          onClick={handleSaveNote}
          disabled={loading}
        >
          {loading ? 'Saving...' : 'Save Note'}
        </button>
      </div>
      
      <div className="saved-notes">
        <h3>Your Notes</h3>
        {loading && <p>Loading notes...</p>}
        
        {savedNotes.length === 0 && !loading ? (
          <p className="no-notes">No saved notes yet</p>
        ) : (
          <div className="notes-list">
            {savedNotes.map((note) => (
              <div key={note.id} className="note-item">
                <p className="note-content">{note.content}</p>
                <p className="note-date">
                  {new Date(note.createdAt).toLocaleString()}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default Notes;