import React, { useState, useEffect, useCallback } from 'react';
import { initializeApp } from 'firebase/app';
import { getAuth, signInAnonymously, signInWithCustomToken, onAuthStateChanged } from 'firebase/auth';
import { getFirestore, collection, doc, setDoc, getDocs, deleteDoc, onSnapshot } from 'firebase/firestore';

// Helper function to convert ArrayBuffer to Base64 string
const arrayBufferToBase64 = (buffer) => {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
};

// Helper function to convert Base64 string to ArrayBuffer
const base64ToArrayBuffer = (base64) => {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
};

// Main App Component
const App = () => {
  const [website, setWebsite] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [savedPasswords, setSavedPasswords] = useState([]);
  const [message, setMessage] = useState('');
  const [db, setDb] = useState(null);
  const [auth, setAuth] = useState(null);
  const [userId, setUserId] = useState(null);
  const [isAuthReady, setIsAuthReady] = useState(false);
  const [showConfirmDelete, setShowConfirmDelete] = useState(false);
  const [passwordToDelete, setPasswordToDelete] = useState(null);

  // Firebase initialization and authentication
  useEffect(() => {
    try {
      const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';
      const firebaseConfig = typeof __firebase_config !== 'undefined' ? JSON.parse(__firebase_config) : {};

      if (Object.keys(firebaseConfig).length === 0) {
        setMessage('Firebase configuration not found. Cannot initialize app.');
        return;
      }

      const app = initializeApp(firebaseConfig);
      const firestoreDb = getFirestore(app);
      const firebaseAuth = getAuth(app);

      setDb(firestoreDb);
      setAuth(firebaseAuth);

      const unsubscribe = onAuthStateChanged(firebaseAuth, async (user) => {
        if (user) {
          setUserId(user.uid);
        } else {
          // Sign in anonymously if no user is authenticated
          try {
            if (typeof __initial_auth_token !== 'undefined') {
              await signInWithCustomToken(firebaseAuth, __initial_auth_token);
            } else {
              await signInAnonymously(firebaseAuth);
            }
            setUserId(firebaseAuth.currentUser?.uid || crypto.randomUUID()); // Fallback for anonymous
          } catch (error) {
            console.error("Error signing in:", error);
            setMessage(`Authentication error: ${error.message}`);
            setUserId(crypto.randomUUID()); // Use a random ID if auth fails
          }
        }
        setIsAuthReady(true);
      });

      return () => unsubscribe();
    } catch (error) {
      console.error("Error initializing Firebase:", error);
      setMessage(`Firebase initialization error: ${error.message}`);
    }
  }, []);

  // Fetch passwords when auth is ready and userId is available
  useEffect(() => {
    if (isAuthReady && db && userId) {
      const passwordsCollectionRef = collection(db, `artifacts/${__app_id}/users/${userId}/passwords`);
      const unsubscribe = onSnapshot(passwordsCollectionRef, (snapshot) => {
        const passwordsList = snapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data()
        }));
        setSavedPasswords(passwordsList);
      }, (error) => {
        console.error("Error fetching passwords:", error);
        setMessage(`Error fetching passwords: ${error.message}`);
      });

      return () => unsubscribe();
    }
  }, [isAuthReady, db, userId]);

  // Function to derive key from passphrase
  const getKeyFromPassphrase = useCallback(async (passphrase, salt) => {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(passphrase),
      { name: "PBKDF2" },
      false,
      ["deriveBits", "deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }, []);

  // Function to encrypt password
  const encryptPassword = useCallback(async (text, passphrase) => {
    if (!passphrase) {
      throw new Error("Passphrase is required for encryption.");
    }
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16)); // Generate a unique salt for each encryption
    const iv = crypto.getRandomValues(new Uint8Array(12)); // Generate a unique IV for each encryption

    const key = await getKeyFromPassphrase(passphrase, salt);
    const encrypted = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      key,
      enc.encode(text)
    );
    return {
      encryptedData: arrayBufferToBase64(encrypted),
      iv: arrayBufferToBase64(iv),
      salt: arrayBufferToBase64(salt)
    };
  }, [getKeyFromPassphrase]);

  // Function to decrypt password
  const decryptPassword = useCallback(async (encryptedData, iv, salt, passphrase) => {
    if (!passphrase) {
      throw new Error("Passphrase is required for decryption.");
    }
    try {
      const key = await getKeyFromPassphrase(passphrase, base64ToArrayBuffer(salt));
      const decrypted = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: base64ToArrayBuffer(iv),
        },
        key,
        base64ToArrayBuffer(encryptedData)
      );
      const dec = new TextDecoder();
      return dec.decode(decrypted);
    } catch (error) {
      console.error("Decryption failed:", error);
      throw new Error("Decryption failed. Check your passphrase.");
    }
  }, [getKeyFromPassphrase]);

  // Handle saving a password
  const handleSavePassword = async () => {
    if (!website || !username || !password || !passphrase) {
      setMessage('Please fill in all fields (Website, Username, Password, Passphrase).');
      return;
    }
    if (!db || !userId) {
      setMessage('Database not ready. Please wait.');
      return;
    }

    try {
      setMessage('Encrypting and saving...');
      const { encryptedData, iv, salt } = await encryptPassword(password, passphrase);

      const passwordsCollectionRef = collection(db, `artifacts/${__app_id}/users/${userId}/passwords`);
      await setDoc(doc(passwordsCollectionRef), { // Use setDoc with a new doc() to auto-generate ID
        website,
        username,
        encryptedPassword: encryptedData,
        iv,
        salt,
        createdAt: new Date().toISOString()
      });
      setMessage('Password saved successfully!');
      setWebsite('');
      setUsername('');
      setPassword('');
      // Keep passphrase in state for convenience or clear it based on UX preference
    } catch (error) {
      console.error("Error saving password:", error);
      setMessage(`Error saving password: ${error.message}`);
    }
  };

  // Handle retrieving/displaying a password
  const handleRetrievePassword = async (entry) => {
    if (!passphrase) {
      setMessage('Please enter your passphrase to decrypt passwords.');
      return;
    }
    try {
      setMessage('Decrypting...');
      const decryptedPass = await decryptPassword(entry.encryptedPassword, entry.iv, entry.salt, passphrase);
      // Update the specific entry in the state to show the decrypted password
      setSavedPasswords(prevPasswords =>
        prevPasswords.map(p =>
          p.id === entry.id ? { ...p, decryptedPassword: decryptedPass, showPassword: true } : p
        )
      );
      setMessage('Password decrypted.');
    } catch (error) {
      console.error("Error retrieving password:", error);
      setMessage(`Error retrieving password: ${error.message}`);
      // Clear the decrypted password if decryption fails
      setSavedPasswords(prevPasswords =>
        prevPasswords.map(p =>
          p.id === entry.id ? { ...p, decryptedPassword: '', showPassword: false } : p
        )
      );
    }
  };

  // Handle hiding a decrypted password
  const handleHidePassword = (entry) => {
    setSavedPasswords(prevPasswords =>
      prevPasswords.map(p =>
        p.id === entry.id ? { ...p, decryptedPassword: '', showPassword: false } : p
      )
    );
  };

  // Show confirmation dialog for delete
  const confirmDelete = (passwordEntry) => {
    setPasswordToDelete(passwordEntry);
    setShowConfirmDelete(true);
  };

  // Handle deleting a password
  const handleDeletePassword = async () => {
    if (!passwordToDelete) return;

    if (!db || !userId) {
      setMessage('Database not ready. Cannot delete.');
      return;
    }

    try {
      setMessage('Deleting password...');
      const docRef = doc(db, `artifacts/${__app_id}/users/${userId}/passwords`, passwordToDelete.id);
      await deleteDoc(docRef);
      setMessage('Password deleted successfully!');
      setShowConfirmDelete(false);
      setPasswordToDelete(null);
    } catch (error) {
      console.error("Error deleting password:", error);
      setMessage(`Error deleting password: ${error.message}`);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center p-4 font-sans">
      <div className="bg-white p-8 rounded-xl shadow-lg w-full max-w-2xl">
        <h1 className="text-3xl font-bold text-center text-gray-800 mb-6">Secure Password Manager</h1>

        {userId && (
          <div className="mb-4 text-sm text-gray-600 text-center">
            Your User ID: <span className="font-mono bg-gray-200 px-2 py-1 rounded-md break-all">{userId}</span>
          </div>
        )}

        <div className="mb-6">
          <label htmlFor="website" className="block text-gray-700 text-sm font-bold mb-2">Website/Service:</label>
          <input
            type="text"
            id="website"
            className="shadow appearance-none border rounded-lg w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={website}
            onChange={(e) => setWebsite(e.target.value)}
            placeholder="e.g., Google, Facebook"
          />
        </div>

        <div className="mb-6">
          <label htmlFor="username" className="block text-gray-700 text-sm font-bold mb-2">Username/Email:</label>
          <input
            type="text"
            id="username"
            className="shadow appearance-none border rounded-lg w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="e.g., your_email@example.com"
          />
        </div>

        <div className="mb-6">
          <label htmlFor="password" className="block text-gray-700 text-sm font-bold mb-2">Password:</label>
          <input
            type="password"
            id="password"
            className="shadow appearance-none border rounded-lg w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter password to encrypt"
          />
        </div>

        <div className="mb-6">
          <label htmlFor="passphrase" className="block text-gray-700 text-sm font-bold mb-2">Encryption Passphrase (Important!):</label>
          <input
            type="password"
            id="passphrase"
            className="shadow appearance-none border rounded-lg w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="Enter a strong passphrase (remember this!)"
          />
          <p className="text-xs text-gray-500 mt-1">
            This passphrase is used to encrypt/decrypt your passwords. If you forget it, your passwords cannot be recovered.
          </p>
        </div>

        <button
          onClick={handleSavePassword}
          className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50 w-full transition duration-300 ease-in-out transform hover:scale-105"
        >
          Save Encrypted Password
        </button>

        {message && (
          <p className={`mt-4 text-center ${message.startsWith('Error') ? 'text-red-600' : 'text-green-600'}`}>
            {message}
          </p>
        )}

        <div className="mt-8">
          <h2 className="text-2xl font-bold text-gray-800 mb-4">Saved Passwords</h2>
          {savedPasswords.length === 0 ? (
            <p className="text-gray-600">No passwords saved yet.</p>
          ) : (
            <ul className="space-y-4">
              {savedPasswords.map((entry) => (
                <li key={entry.id} className="bg-gray-50 p-4 rounded-lg shadow-sm border border-gray-200">
                  <div className="flex justify-between items-center mb-2">
                    <p className="text-lg font-semibold text-gray-800">{entry.website}</p>
                    <button
                      onClick={() => confirmDelete(entry)}
                      className="text-red-500 hover:text-red-700 focus:outline-none"
                      title="Delete Password"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm6 0a1 1 0 11-2 0v6a1 1 0 112 0V8z" clipRule="evenodd" />
                      </svg>
                    </button>
                  </div>
                  <p className="text-gray-700"><strong>Username:</strong> {entry.username}</p>
                  <div className="flex items-center mt-2">
                    <p className="text-gray-700 mr-2"><strong>Password:</strong></p>
                    {entry.showPassword ? (
                      <span className="font-mono bg-gray-200 px-2 py-1 rounded-md flex-grow break-all">{entry.decryptedPassword}</span>
                    ) : (
                      <span className="font-mono bg-gray-200 px-2 py-1 rounded-md flex-grow">***********</span>
                    )}
                    {entry.showPassword ? (
                      <button
                        onClick={() => handleHidePassword(entry)}
                        className="ml-2 bg-yellow-500 hover:bg-yellow-700 text-white text-sm py-1 px-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:ring-opacity-50 transition duration-300 ease-in-out"
                      >
                        Hide
                      </button>
                    ) : (
                      <button
                        onClick={() => handleRetrievePassword(entry)}
                        className="ml-2 bg-green-500 hover:bg-green-700 text-white text-sm py-1 px-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-opacity-50 transition duration-300 ease-in-out"
                      >
                        Decrypt
                      </button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Confirmation Modal for Delete */}
        {showConfirmDelete && (
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white p-6 rounded-lg shadow-xl max-w-sm w-full text-center">
              <h3 className="text-lg font-bold mb-4">Confirm Deletion</h3>
              <p className="mb-6">Are you sure you want to delete the password for <span className="font-semibold">{passwordToDelete?.website}</span>?</p>
              <div className="flex justify-center space-x-4">
                <button
                  onClick={() => setShowConfirmDelete(false)}
                  className="bg-gray-300 hover:bg-gray-400 text-gray-800 font-bold py-2 px-4 rounded-lg focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-opacity-50 transition duration-300"
                >
                  Cancel
                </button>
                <button
                  onClick={handleDeletePassword}
                  className="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-opacity-50 transition duration-300"
                >
                  Delete
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default App;
