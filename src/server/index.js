const express = require('express');
const http = require('http');
const https = require('https'); // Import the https module
const admin = require('firebase-admin');
const { DefaultAzureCredential } = require('@azure/identity');
const { SecretClient } = require('@azure/keyvault-secrets');
const { CertificateClient } = require('@azure/keyvault-certificates');
const app = express();

/*
// Decode the Base64-encoded Firebase credentials
const firebaseCredentialsBase64 = process.env.FIREBASE_SERVER_CREDENTIALS;
if (!firebaseCredentialsBase64) {
  throw new Error('FIREBASE_CREDENTIALS environment variable is not set');
}

const firebaseCredentials = JSON.parse(Buffer.from(firebaseCredentialsBase64, 'base64').toString('utf8'));

// Initialize Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(firebaseCredentials),
  databaseURL: "https://notes-c0856.firebaseio.com"
}); */

const keyVaultName = process.env.KEY_VAULT_NAME;
const keyVaultUrl = `https://${keyVaultName}.vault.azure.net`;
const certificateName = process.env.SSL_CERT_NAME; // Name of the certificate in Key Vault

// Function to retrieve Firebase credentials from environment variable or fallback to Key Vault
const getFirebaseCredentials = async () => {
    try {
      // Attempt to retrieve the credentials from the environment variable
      const firebaseCredentialsBase64 = process.env.FIREBASE_SERVER_CREDENTIALS;
      if (firebaseCredentialsBase64) {
        console.log('Firebase credentials retrieved from environment variable');
        return JSON.parse(Buffer.from(firebaseCredentialsBase64, 'base64').toString('utf8'));
      }
  
      // If not found in the environment variable, retrieve from Key Vault
      console.warn('FIREBASE_SERVER_CREDENTIALS not found in environment. Attempting to retrieve from Key Vault...');
      const credential = new DefaultAzureCredential();
      const secretClient = new SecretClient(keyVaultUrl, credential);
  
      const secret = await secretClient.getSecret(firebaseSecretName);
      console.log('Firebase credentials retrieved from Key Vault');
      return JSON.parse(Buffer.from(secret.value, 'base64').toString('utf8'));
    } catch (error) {
      console.error('Failed to retrieve Firebase credentials:', error);
      throw new Error('Firebase credentials are not available in environment or Key Vault');
    }
  };

  // Function to retrieve the certificate from Azure Key Vault
  const getSSLCertificate = async () => {
    try {
        const credential = new DefaultAzureCredential();
        const certificateClient = new CertificateClient(keyVaultUrl, credential);
    
        // Retrieve the certificate with the private key
        const certificateWithPolicy = await certificateClient.getCertificate(certificateName);
        const privateKeySecretName = certificateWithPolicy.keyId.split('/').pop();
        const secretClient = new SecretClient(keyVaultUrl, credential);
    
        // Retrieve the private key as a PEM-encoded secret
        const privateKeySecret = await secretClient.getSecret(privateKeySecretName);
        const privateKeyPem = privateKeySecret.value;
    
        // Improved certificate formatting
        const publicCertificate = certificateWithPolicy.cer;
        const publicCertificatePem = Buffer.from(publicCertificate).toString('base64');
        const formattedCertificatePem = `-----BEGIN CERTIFICATE-----\n${publicCertificatePem.replace(/(.{64})/g, '$1\n')}\n-----END CERTIFICATE-----`;
        const formattedPrivateKeyPem = `-----BEGIN PRIVATE KEY-----\n${privateKeyPem.replace(/(.{64})/g, '$1\n')}\n-----END PRIVATE KEY-----`;
    
        return {
            key: formattedPrivateKeyPem,
            cert: formattedCertificatePem,
        };
    } catch (error) {
        console.error('Error retrieving SSL certificate from Key Vault:', error);
        throw new Error('Failed to retrieve SSL certificate');
    }
};

/* const cors = require('cors');
app.use(cors());

const notesRouter = require('./api/notes'); 

const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());

// Use the notes router
app.use('/api', notesRouter); */

// Start the server
/* app.listen(PORT, () => {
  console.log(`Server is running on https://localhost:${PORT}`);
}); */

(async () => {
    try {
      const firebaseCredentials = await getFirebaseCredentials();

      // Initialize Firebase Admin SDK
      admin.initializeApp({
        credential: admin.credential.cert(firebaseCredentials),
        databaseURL: "https://notes-c0856.firebaseio.com"
      });

      // Middleware to redirect HTTP to HTTPS
      /* app.use((req, res, next) => {
        if (!req.secure) {
          // Redirect to HTTPS
          return res.redirect(`https://${req.headers.host}${req.url}`);
        }
        next();
      }); */

      const cors = require('cors');
      app.use(cors());

      const notesRouter = require('./api/notes'); 

      // const HTTPS_PORT = process.env.PORT || 443; // HTTPS port (Azure will use the PORT environment variable)
      const HTTP_PORT = process.env.PORT || 8080; // HTTP port for debugging or local use

      // Middleware
      app.use(express.json());

      // Use the notes router
      app.use('/api', notesRouter);

      /* const sslOptions = await getSSLCertificate();
      https.createServer(sslOptions, app).listen(HTTPS_PORT, () => {
        console.log(`Server is running on https://localhost:${HTTPS_PORT}`);
      });*/

      // Start HTTP server for redirection
      http.createServer(app).listen(HTTP_PORT, () => {
        console.log(`HTTP Server is running on http://localhost:${HTTP_PORT}`);
      });
    } catch (error) {
      console.error('Failed to start HTTPS server:', error);
    }
  })();