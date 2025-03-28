// File: server/api/notes.js (Revised with server-side encryption)
const express = require('express');
const router = express.Router();
const admin = require('firebase-admin');
const { SecretClient } = require("@azure/keyvault-secrets");
const { DefaultAzureCredential } = require("@azure/identity");
const crypto = require('crypto');
const { CryptographyClient, KeyClient } = require("@azure/keyvault-keys");

// Initialize Firestore database
const db = admin.firestore();

// Azure Key Vault configuration
const keyVaultName = process.env.KEY_VAULT_NAME;
const keyVaultUrl = `https://${keyVaultName}.vault.azure.net`;
const secretName = process.env.ENCRYPTION_KEY_NAME;

// Middleware to verify Firebase auth token
const authenticateUser = async (req, res, next) => {
  try {
    const idToken = req.headers.authorization?.split('Bearer ')[1];
    if (!idToken) {
      return res.status(401).json({ error: 'Unauthorized: No token provided' });
    }
    
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
};

const generateAndStoreAESKey = async (userId) => {
  try {
    // Step 1: Check if the AES key already exists for the user
    const userKeyDoc = await db.collection("userKeys").doc(userId).get();
    if (userKeyDoc.exists) {
      console.log(`AES key already exists for user: ${userId}`);
      return; // Exit the function if the key already exists
    }

    // Step 2: Generate a unique AES key
    const aesKey = crypto.randomBytes(32); // 256-bit AES key

    // Step 3: Encrypt the AES key with an RSA key from Azure Key Vault
    const credential = new DefaultAzureCredential();
    const cryptoClient = new CryptographyClient(`${keyVaultUrl}/keys/${secretName}`, credential);

    const encryptResult = await cryptoClient.encrypt("RSA-OAEP", aesKey);

    // Step 4: Store the encrypted AES key in Firestore
    await db.collection("userKeys").doc(userId).set({
      encryptedAESKey: encryptResult.result.toString("base64"), // Store as base64 string
      createdAt: new Date().toISOString(),
    });

    console.log(`AES key generated and stored for user: ${userId}`);
  } catch (err) {
    console.error("Error generating and storing AES key:", err);
    throw new Error("Failed to generate and store AES key");
  }
};

// Retrieve and decrypt AES key for a user
const getAESKeyForUser = async (userId) => {
  try {
    // Step 1: Retrieve the encrypted AES key from Firestore
    const userKeyDoc = await db.collection("userKeys").doc(userId).get();
    if (!userKeyDoc.exists) {
      throw new Error("No AES key found for user");
    }

    const encryptedAESKey = Buffer.from(userKeyDoc.data().encryptedAESKey, "base64");

    // Step 2: Decrypt the AES key with the RSA key from Azure Key Vault
    const credential = new DefaultAzureCredential();
    const cryptoClient = new CryptographyClient(`${keyVaultUrl}/keys/${secretName}`, credential);

    const decryptResult = await cryptoClient.decrypt("RSA-OAEP", encryptedAESKey);

    return decryptResult.result; // Return the decrypted AES key as a Buffer
  } catch (err) {
    console.error("Error retrieving and decrypting AES key:", err);
    throw new Error("Failed to retrieve and decrypt AES key");
  }
};

// Get encryption key from Azure Key Vault
/* const getEncryptionKey = async () => {
  try {
    // Using Managed Identity for authentication with Azure
    const credential = new DefaultAzureCredential();
    const secretClient = new SecretClient(keyVaultUrl, credential);
    
    // Get the encryption key from Azure Key Vault
    const keySecret = await secretClient.getSecret(secretName);
    return keySecret.value;
  } catch (err) {
    console.error('Error accessing Key Vault:', err);
    throw new Error('Could not access encryption key');
  }
}; */

// Encrypt data using AES-256-GCM
const encryptData = async (text, key) => {
  try {
    // const key = await getEncryptionKey();
    // Create a buffer from the key (using SHA-256 to ensure proper key length)
    const keyBuffer = crypto.createHash('sha256').update(key).digest();
    // Generate a random initialization vector
    const iv = crypto.randomBytes(16);
    // Create cipher
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
    // Encrypt the data
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    // Get authentication tag
    const authTag = cipher.getAuthTag().toString('hex');
    // Return the IV, encrypted data, and auth tag
    return {
      iv: iv.toString('hex'),
      encryptedData: encrypted,
      authTag
    };
  } catch (err) {
    console.error('Encryption error:', err);
    throw new Error('Failed to encrypt data');
  }
};

// Decrypt data using AES-256-GCM
const decryptData = async (encryptedData, iv, authTag, key) => {
  try {
    // const key = await getEncryptionKey();
    // Create a buffer from the key (using SHA-256 to ensure proper key length)
    const keyBuffer = crypto.createHash('sha256').update(key).digest();
    // Convert hex strings to buffers
    const ivBuffer = Buffer.from(iv, 'hex');
    const authTagBuffer = Buffer.from(authTag, 'hex');
    // Create decipher
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, ivBuffer);
    decipher.setAuthTag(authTagBuffer);
    // Decrypt the data
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    console.error('Decryption error:', err);
    throw new Error('Failed to decrypt data');
  }
};

// POST endpoint to create a new note
router.post('/notes', authenticateUser, async (req, res) => {
  try {
    const { userId, content } = req.body;
    
    // Verify the requesting user matches the userId in the request
    if (req.user.uid !== userId) {
      return res.status(403).json({ error: 'Forbidden: User ID mismatch' });
    }
    
    // Ensure the AES key exists for the user
    await generateAndStoreAESKey(userId);

    // Step 2: Retrieve and decrypt the AES key
    const aesKey = await getAESKeyForUser(userId);

    // Encrypt the note content on the server
    const encrypted = await encryptData(content, aesKey);
    
    // Create a new note document in Firestore
    const noteRef = await db.collection('notes').add({
      userId,
      encryptedData: encrypted.encryptedData,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
      createdAt: new Date().toISOString()
    });
    
    // Get the created note ID
    const noteDoc = await noteRef.get();
    
    res.status(201).json({
      id: noteDoc.id,
      createdAt: noteDoc.data().createdAt
    });
  } catch (error) {
    console.error('Error creating note:', error);
    res.status(500).json({ error: 'Failed to create note' });
  }
});

// GET endpoint to retrieve all notes for a user
router.get('/notes/:userId', authenticateUser, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Verify the requesting user matches the userId in the request
    if (req.user.uid !== userId) {
      return res.status(403).json({ error: 'Forbidden: User ID mismatch' });
    }
    
    // Step 1: Retrieve and decrypt the AES key
    const aesKey = await getAESKeyForUser(userId);

    // Query notes for the specified user
    const notesSnapshot = await db
      .collection('notes')
      .where('userId', '==', userId)
      .orderBy('createdAt', 'desc')
      .get();
    
    // Format and decrypt the notes data
    const notes = [];
    for (const doc of notesSnapshot.docs) {
      const noteData = doc.data();
      try {
        // Decrypt the note content
        const decryptedContent = await decryptData(
          noteData.encryptedData,
          noteData.iv,
          noteData.authTag,
          aesKey
        );
        
        notes.push({
          id: doc.id,
          content: decryptedContent,
          createdAt: noteData.createdAt
        });
      } catch (decryptError) {
        console.error(`Error decrypting note ${doc.id}:`, decryptError);
        // Add the note with an error message instead of content
        notes.push({
          id: doc.id,
          content: "[Decryption failed]",
          createdAt: noteData.createdAt
        });
      }
    }
    
    res.status(200).json(notes);
  } catch (error) {
    console.error('Error fetching notes:', error);
    res.status(500).json({ error: 'Failed to fetch notes' });
  }
});

// DELETE endpoint to delete a note by ID
router.delete('/notes/:noteId', authenticateUser, async (req, res) => {
  try {
    const { noteId } = req.params;

    // Retrieve the note document
    const noteDoc = await db.collection('notes').doc(noteId).get();

    // Check if the note exists
    if (!noteDoc.exists) {
      return res.status(404).json({ error: 'Note not found' });
    }

    // Verify the requesting user matches the userId in the note
    const noteData = noteDoc.data();
    if (req.user.uid !== noteData.userId) {
      return res.status(403).json({ error: 'Forbidden: User ID mismatch' });
    }

    // Delete the note
    await db.collection('notes').doc(noteId).delete();

    res.status(200).json({ message: 'Note deleted successfully' });
  } catch (error) {
    console.error('Error deleting note:', error);
    res.status(500).json({ error: 'Failed to delete note' });
  }
});

module.exports = router;