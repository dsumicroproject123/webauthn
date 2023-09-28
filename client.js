document.addEventListener('DOMContentLoaded', () => {
  const registrationForm = document.getElementById('registration-form');
  const registerButton = document.getElementById('register-button');

  const loginForm = document.getElementById('login-form');
  const loginButton = document.getElementById('login-button');

  // Check for WebAuthn support
  if (!window.PublicKeyCredential) {
    console.error('WebAuthn is not supported in this browser.');
    return;
  }

  // Register a user
  registerButton.addEventListener('click', async () => {
    const username = document.getElementById('username').value;
    const displayName = document.getElementById('display_name').value;

    const publicKeyCredentialCreationOptions = {
      challenge: new Uint8Array(32), // You should generate a proper challenge on the server
      rp: {
        name: "WebAuthn Registration and Login",
        id: "dsumicroproject.github.io", // Update with your Flask server URL
      },
      user: {
        id: new Uint8Array(32), // Generate a user ID
        name: username,
        displayName: displayName,
      },
      pubKeyCredParams: [{ alg: -7, type: "public-key" }],
      authenticatorSelection: {
        authenticatorAttachment: "cross-platform",
      },
      timeout: 60000,
      attestation: "none"
    };

    try {
      const response = await fetch('/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(publicKeyCredentialCreationOptions),
      });

      if (response.ok) {
         const data = await response.json(); // Parse JSON response
    alert(data.message); // Display a success message
  } else {
    const data = await response.json(); // Parse JSON error response
    alert(`Registration error: ${data.message}`);
  }
} catch (error) {
      alert(`Registration error: ${error.message}`);
    }
  });

  loginButton.addEventListener('click', async () => {
    const loginUsername = document.getElementById('login_username').value;

    try {
      const response = await fetch('/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ login_username: loginUsername }),
      });

      if (response.ok) {
        alert('Login successful!');
      } else {
        const data = await response.json();
        alert(`Login error: ${data.message}`);
      }
    } catch (error) {
      alert(`Login error: ${error.message}`);
    }
  });
});
