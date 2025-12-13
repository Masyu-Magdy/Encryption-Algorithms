document.addEventListener("DOMContentLoaded", function () {
  let currentAlgorithm = "playfair";
  let currentAction = "encrypt";

  const algorithmCards = document.querySelectorAll(".algorithm-card");
  const actionButtons = document.querySelectorAll(".action-btn");
  const algorithmInfoElement = document.getElementById("algorithm-info");
  const inputLabel = document.getElementById("input-label");
  const inputText = document.getElementById("input-text");
  const keyInput = document.getElementById("key");
  const processBtn = document.getElementById("process-btn");
  const resultElement = document.getElementById("result");

  const algorithmInfo = {
    playfair: {
      description:
        "A classic encryption algorithm based on a 5x5 matrix containing the encryption key. It encrypts pairs of letters (bigrams) instead of single letters.",
      keyPlaceholder: "Enter a keyword (letters only, e.g., 'MONARCHY')",
      textPlaceholder: {
        encrypt: "Enter text to encrypt (letters only, no spaces)",
        decrypt: "Enter ciphertext to decrypt",
      },
    },
    rsa: {
      description:
        "A public-key cryptosystem widely used for secure data transmission. It uses asymmetric key encryption where the public key encrypts data and a private key decrypts it.",
      keyPlaceholder: "Enter key size (512, 1024, or 2048) for key generation",
      textPlaceholder: {
        encrypt: "Enter text to encrypt with RSA",
        decrypt: "Enter ciphertext to decrypt with RSA",
      },
    },
    aes: {
      description:
        "Advanced Encryption Standard (AES) is a symmetric encryption algorithm widely used across the globe. It's fast, secure, and used by governments and security systems.",
      keyPlaceholder:
        "Enter 16, 24, or 32 character key (e.g., 'MySecretKey123456')",
      textPlaceholder: {
        encrypt: "Enter text to encrypt with AES",
        decrypt: "Enter Base64 ciphertext to decrypt with AES",
      },
    },
    des: {
      description:
        "Data Encryption Standard (DES) is an older symmetric-key algorithm that uses a 56-bit key. It's now considered insecure for many applications but was historically important.",
      keyPlaceholder: "Enter 8 character key (e.g., '12345678')",
      textPlaceholder: {
        encrypt: "Enter text to encrypt with DES",
        decrypt: "Enter Base64 ciphertext to decrypt with DES",
      },
    },
  };

  updateAlgorithmInfo();
  updatePlaceholders();

  // Algorithm card selection
  algorithmCards.forEach((card) => {
    card.addEventListener("click", function () {
      // Remove active class from all cards
      algorithmCards.forEach((c) => c.classList.remove("active"));

      // Add active class to clicked card
      this.classList.add("active");

      // Update current algorithm
      currentAlgorithm = this.dataset.algorithm;

      // Update UI
      updateAlgorithmInfo();
      updatePlaceholders();
      clearResult();
    });
  });

  // Action button selection
  actionButtons.forEach((btn) => {
    btn.addEventListener("click", function () {
      // Remove active class from all buttons
      actionButtons.forEach((b) => b.classList.remove("active"));

      // Add active class to clicked button
      this.classList.add("active");

      // Update current action
      currentAction = this.dataset.action;

      // Update UI
      updatePlaceholders();
      updateProcessButton();
      clearResult();
    });
  });

  // Process button click
  processBtn.addEventListener("click", processOperation);

  // Function to update algorithm information
  function updateAlgorithmInfo() {
    const info = algorithmInfo[currentAlgorithm];
    algorithmInfoElement.innerHTML = `
            <p><strong>${currentAlgorithm.toUpperCase()}:</strong> ${
      info.description
    }</p>
        `;
  }

  // Function to update placeholders
  function updatePlaceholders() {
    const info = algorithmInfo[currentAlgorithm];

    // Update input label
    inputLabel.textContent =
      currentAction === "encrypt" ? "Plaintext" : "Ciphertext";

    // Update textarea placeholder
    inputText.placeholder = info.textPlaceholder[currentAction];

    // Update key input placeholder
    keyInput.placeholder = info.keyPlaceholder;
  }

  // Function to update process button text
  function updateProcessButton() {
    const actionText =
      currentAction === "encrypt" ? "Encryption" : "Decryption";
    processBtn.innerHTML = `<i class="fas fa-play-circle"></i> Execute ${actionText} Operation`;
  }

  // Function to clear result
  function clearResult() {
    resultElement.textContent =
      "The result will appear here after executing the operation...";
    resultElement.style.color = "";
  }

  // Function to display result
  function displayResult(result, isError = false) {
    resultElement.textContent = result;
    resultElement.style.color = isError ? "#e74c3c" : "#27ae60";
  }

  // Function to validate input
  function validateInput() {
    const text = inputText.value.trim();
    const key = keyInput.value.trim();

    if (!text) {
      displayResult("Please enter some text to process.", true);
      return false;
    }

    if (!key) {
      displayResult("Please enter a key.", true);
      return false;
    }

    return true;
  }

  // Main processing function
  async function processOperation() {
    if (!validateInput()) return;

    const text = inputText.value.trim();
    const key = keyInput.value.trim();

    try {
      let result;

      switch (currentAlgorithm) {
        case "playfair":
          result =
            currentAction === "encrypt"
              ? playfairEncrypt(text, key)
              : playfairDecrypt(text, key);
          break;

        case "rsa":
          if (currentAction === "encrypt") {
            result = await rsaEncrypt(text, key);
          } else {
            result = await rsaDecrypt(text, key);
          }
          break;

        case "aes":
          if (currentAction === "encrypt") {
            result = aesEncrypt(text, key);
          } else {
            result = aesDecrypt(text, key);
          }
          break;

        case "des":
          if (currentAction === "encrypt") {
            result = desEncrypt(text, key);
          } else {
            result = desDecrypt(text, key);
          }
          break;

        default:
          throw new Error("Unknown algorithm");
      }

      displayResult(result);
    } catch (error) {
      displayResult(`Error: ${error.message}`, true);
      console.error(error);
    }
  }

  // Playfair Cipher Implementation
  function playfairEncrypt(text, key) {
    // Prepare text: remove spaces, convert to uppercase, handle J/I
    text = text
      .toUpperCase()
      .replace(/[^A-Z]/g, "")
      .replace(/J/g, "I");

    // Prepare key: remove duplicates and non-alphabetic characters
    key = key.toUpperCase().replace(/[^A-Z]/g, "");

    // Create Playfair matrix
    const matrix = createPlayfairMatrix(key);

    // Prepare text for encryption (add X between double letters, add X if odd length)
    let preparedText = "";
    for (let i = 0; i < text.length; i += 2) {
      const first = text[i];
      const second = text[i + 1] || "X";

      if (first === second) {
        preparedText += first + "X";
        i--; // Adjust index to process second character again
      } else {
        preparedText += first + second;
      }
    }

    // Ensure even length
    if (preparedText.length % 2 !== 0) {
      preparedText += "X";
    }

    // Encrypt pairs
    let result = "";
    for (let i = 0; i < preparedText.length; i += 2) {
      const pair = preparedText.substr(i, 2);
      const encryptedPair = encryptPlayfairPair(pair, matrix);
      result += encryptedPair;
    }

    return result;
  }

  function playfairDecrypt(text, key) {
    text = text.toUpperCase().replace(/[^A-Z]/g, "");
    key = key.toUpperCase().replace(/[^A-Z]/g, "");
    const matrix = createPlayfairMatrix(key);

    let result = "";
    for (let i = 0; i < text.length; i += 2) {
      const pair = text.substr(i, 2);
      const decryptedPair = decryptPlayfairPair(pair, matrix);
      result += decryptedPair;
    }

    // Remove any trailing X
    if (result.endsWith("X")) {
      result = result.slice(0, -1);
    }

    return result;
  }

  function createPlayfairMatrix(key) {
    const alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // J is omitted
    let matrixString = "";

    // Add key characters (without duplicates)
    for (const char of key) {
      const letter = char === "J" ? "I" : char;
      if (!matrixString.includes(letter)) {
        matrixString += letter;
      }
    }

    // Add remaining alphabet characters
    for (const letter of alphabet) {
      if (!matrixString.includes(letter)) {
        matrixString += letter;
      }
    }

    // Convert to 5x5 matrix
    const matrix = [];
    for (let i = 0; i < 5; i++) {
      matrix[i] = matrixString.substr(i * 5, 5).split("");
    }

    return matrix;
  }

  function encryptPlayfairPair(pair, matrix) {
    const [row1, col1] = findPosition(pair[0], matrix);
    const [row2, col2] = findPosition(pair[1], matrix);

    let encryptedPair = "";

    if (row1 === row2) {
      // Same row: shift right
      encryptedPair += matrix[row1][(col1 + 1) % 5];
      encryptedPair += matrix[row2][(col2 + 1) % 5];
    } else if (col1 === col2) {
      // Same column: shift down
      encryptedPair += matrix[(row1 + 1) % 5][col1];
      encryptedPair += matrix[(row2 + 1) % 5][col2];
    } else {
      // Rectangle: swap columns
      encryptedPair += matrix[row1][col2];
      encryptedPair += matrix[row2][col1];
    }

    return encryptedPair;
  }

  function decryptPlayfairPair(pair, matrix) {
    const [row1, col1] = findPosition(pair[0], matrix);
    const [row2, col2] = findPosition(pair[1], matrix);

    let decryptedPair = "";

    if (row1 === row2) {
      // Same row: shift left
      decryptedPair += matrix[row1][(col1 + 4) % 5];
      decryptedPair += matrix[row2][(col2 + 4) % 5];
    } else if (col1 === col2) {
      // Same column: shift up
      decryptedPair += matrix[(row1 + 4) % 5][col1];
      decryptedPair += matrix[(row2 + 4) % 5][col2];
    } else {
      // Rectangle: swap columns
      decryptedPair += matrix[row1][col2];
      decryptedPair += matrix[row2][col1];
    }

    return decryptedPair;
  }

  function findPosition(letter, matrix) {
    for (let row = 0; row < 5; row++) {
      for (let col = 0; col < 5; col++) {
        if (matrix[row][col] === letter) {
          return [row, col];
        }
      }
    }
    return [0, 0];
  }

  // RSA Implementation - Works with any key or size
  async function rsaEncrypt(text, key) {
    const keyInput = key.trim();

    // Check if input is a valid key size
    const validKeySizes = ["512", "1024", "2048"];

    if (validKeySizes.includes(keyInput)) {
      // User entered a key size - generate keys and encrypt
      return await rsaEncryptWithGeneratedKeys(text, parseInt(keyInput));
    }

    // Check if input looks like a public key
    if (keyInput.includes("PUBLIC KEY") || keyInput.includes("RSA PUBLIC")) {
      // User entered a public key
      try {
        const encrypt = new JSEncrypt();

        // Try to set the public key
        const success = encrypt.setPublicKey(keyInput);

        if (!success) {
          // If it doesn't work as-is, try adding proper headers
          let formattedKey = keyInput;
          if (!formattedKey.includes("-----BEGIN")) {
            formattedKey = `-----BEGIN PUBLIC KEY-----\n${formattedKey}\n-----END PUBLIC KEY-----`;
          }

          encrypt.setPublicKey(formattedKey);
        }

        const encrypted = encrypt.encrypt(text);

        if (encrypted) {
          return `RSA Encrypted:\n${encrypted}`;
        } else {
          throw new Error("Failed to encrypt with provided public key");
        }
      } catch (error) {
        throw new Error(`Invalid public key: ${error.message}`);
      }
    }

    // If it's not a key size and not a public key, use demo mode
    return await rsaEncryptWithGeneratedKeys(text, 2048);
  }

  async function rsaEncryptWithGeneratedKeys(text, keySize) {
    try {
      // Generate RSA key pair
      const encrypt = new JSEncrypt({ default_key_size: keySize.toString() });

      // Get public key
      const publicKey = encrypt.getPublicKey();

      // Create new encryptor with the public key
      const encryptor = new JSEncrypt();
      encryptor.setPublicKey(publicKey);

      const encrypted = encryptor.encrypt(text);

      if (encrypted) {
        return `RSA Encrypted (${keySize}-bit):\n${encrypted}\n\nPublic Key:\n${publicKey}`;
      } else {
        throw new Error("Encryption failed");
      }
    } catch (error) {
      throw new Error(`RSA ${keySize}-bit encryption failed: ${error.message}`);
    }
  }

  async function rsaDecrypt(ciphertext, key) {
    const keyInput = key.trim();

    // Remove any prefix if present
    const cleanCiphertext = ciphertext
      .replace(/^RSA Encrypted.*:\n?/, "")
      .replace(/^RSA Decrypted.*:\n?/, "")
      .trim();

    // Check if input looks like a private key
    if (keyInput.includes("PRIVATE KEY") || keyInput.includes("RSA PRIVATE")) {
      try {
        const decrypt = new JSEncrypt();

        // Try to set the private key
        const success = decrypt.setPrivateKey(keyInput);

        if (!success) {
          // If it doesn't work as-is, try adding proper headers
          let formattedKey = keyInput;
          if (!formattedKey.includes("-----BEGIN")) {
            formattedKey = `-----BEGIN RSA PRIVATE KEY-----\n${formattedKey}\n-----END RSA PRIVATE KEY-----`;
          }

          decrypt.setPrivateKey(formattedKey);
        }

        const decrypted = decrypt.decrypt(cleanCiphertext);

        if (decrypted) {
          return `RSA Decrypted: ${decrypted}`;
        } else {
          throw new Error("Failed to decrypt with provided private key");
        }
      } catch (error) {
        throw new Error(`Invalid private key: ${error.message}`);
      }
    }

    // Try common private key formats
    try {
      const decrypt = new JSEncrypt();

      // Try multiple key formats
      const keyFormats = [
        keyInput,
        `-----BEGIN RSA PRIVATE KEY-----\n${keyInput}\n-----END RSA PRIVATE KEY-----`,
        `-----BEGIN PRIVATE KEY-----\n${keyInput}\n-----END PRIVATE KEY-----`,
      ];

      for (const format of keyFormats) {
        try {
          if (decrypt.setPrivateKey(format)) {
            const decrypted = decrypt.decrypt(cleanCiphertext);
            if (decrypted) {
              return `RSA Decrypted: ${decrypted}`;
            }
          }
        } catch (e) {
          // Try next format
        }
      }

      throw new Error("Could not decrypt with provided key");
    } catch (error) {
      throw new Error(`RSA decryption failed: ${error.message}`);
    }
  }

  // AES Implementation with hex support
  function aesEncrypt(text, key) {
    // Normalize key to hex format
    let keyHex;

    if (/^[0-9A-Fa-f]+$/.test(key)) {
      // Key is already in hex
      keyHex = key.toLowerCase();
    } else {
      // Convert text key to hex
      keyHex = CryptoJS.enc.Utf8.parse(key).toString(CryptoJS.enc.Hex);
    }

    // Ensure key is 32, 48, or 64 hex chars (16, 24, or 32 bytes)
    if (![32, 48, 64].includes(keyHex.length)) {
      throw new Error(
        "Key must be 16, 24, or 32 bytes (32, 48, or 64 hex characters)"
      );
    }

    // Normalize text to hex format
    let textHex;

    if (/^[0-9A-Fa-f]+$/.test(text)) {
      // Text is already in hex
      textHex = text.toLowerCase();
    } else {
      // Convert text to hex
      textHex = CryptoJS.enc.Utf8.parse(text).toString(CryptoJS.enc.Hex);
    }

    // Ensure text is multiple of 32 hex chars (16 bytes = AES block size)
    if (textHex.length % 32 !== 0) {
      // Pad with zeros to make it multiple of 32
      textHex = textHex.padEnd(Math.ceil(textHex.length / 32) * 32, "0");
    }

    // Convert hex strings to CryptoJS format
    const keyBytes = CryptoJS.enc.Hex.parse(keyHex);
    const textBytes = CryptoJS.enc.Hex.parse(textHex);

    // Encrypt using AES ECB mode (as in your example)
    const encrypted = CryptoJS.AES.encrypt(textBytes, keyBytes, {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.NoPadding,
    });

    // Return hex result
    return encrypted.ciphertext.toString();
  }

  function aesDecrypt(ciphertext, key) {
    // Validate ciphertext is hex
    if (!/^[0-9A-Fa-f]+$/.test(ciphertext)) {
      throw new Error("Ciphertext must be in hexadecimal format");
    }

    // Normalize key to hex format
    let keyHex;

    if (/^[0-9A-Fa-f]+$/.test(key)) {
      // Key is already in hex
      keyHex = key.toLowerCase();
    } else {
      // Convert text key to hex
      keyHex = CryptoJS.enc.Utf8.parse(key).toString(CryptoJS.enc.Hex);
    }

    // Ensure key is 32, 48, or 64 hex chars
    if (![32, 48, 64].includes(keyHex.length)) {
      throw new Error(
        "Key must be 16, 24, or 32 bytes (32, 48, or 64 hex characters)"
      );
    }

    // Convert hex strings to CryptoJS format
    const keyBytes = CryptoJS.enc.Hex.parse(keyHex);
    const cipherBytes = CryptoJS.enc.Hex.parse(ciphertext);

    // Decrypt using AES ECB mode
    const decrypted = CryptoJS.AES.decrypt(
      {
        ciphertext: cipherBytes,
      },
      keyBytes,
      {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.NoPadding,
      }
    );

    // Return hex result
    return decrypted.toString(CryptoJS.enc.Hex);
  }

  // DES Implementation - Direct and simple
  function desEncrypt(text, key) {
    // Prepare inputs
    const plaintext = text.toLowerCase();
    const keyStr = key.toLowerCase();

    // Validate key
    if (!/^[0-9a-f]{16}$/.test(keyStr) && keyStr.length !== 8) {
      throw new Error("DES key must be 16 hex digits or 8 characters");
    }

    // Convert key to hex if needed
    let keyHex = keyStr;
    if (keyStr.length === 8) {
      keyHex = "";
      for (let i = 0; i < 8; i++) {
        keyHex += keyStr.charCodeAt(i).toString(16);
      }
    }

    // Validate plaintext
    if (!/^[0-9a-f]+$/.test(plaintext)) {
      throw new Error("Plaintext must be in hexadecimal format");
    }

    // Pad plaintext if needed
    let paddedPlaintext = plaintext;
    while (paddedPlaintext.length % 16 !== 0) {
      paddedPlaintext += "0";
    }

    // Convert to CryptoJS format
    const keyParsed = CryptoJS.enc.Hex.parse(keyHex);
    const plaintextParsed = CryptoJS.enc.Hex.parse(paddedPlaintext);

    // Encrypt
    const encrypted = CryptoJS.DES.encrypt(plaintextParsed, keyParsed, {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.NoPadding,
    });

    // Convert to hex string
    const ciphertext = encrypted.ciphertext;
    let result = "";

    for (let i = 0; i < ciphertext.sigBytes; i++) {
      const byte = ciphertext.words[i >>> 2] >>> (24 - (i % 4) * 8);
      result += (byte & 0xff).toString(16).padStart(2, "0");
    }

    return result;
  }

  function desDecrypt(ciphertext, key) {
    // Similar implementation for decryption
    const cipher = ciphertext.toLowerCase();
    const keyStr = key.toLowerCase();

    if (!/^[0-9a-f]{16}$/.test(keyStr) && keyStr.length !== 8) {
      throw new Error("DES key must be 16 hex digits or 8 characters");
    }

    if (!/^[0-9a-f]+$/.test(cipher)) {
      throw new Error("Ciphertext must be in hexadecimal format");
    }

    let keyHex = keyStr;
    if (keyStr.length === 8) {
      keyHex = "";
      for (let i = 0; i < 8; i++) {
        keyHex += keyStr.charCodeAt(i).toString(16);
      }
    }

    const keyParsed = CryptoJS.enc.Hex.parse(keyHex);
    const cipherParsed = CryptoJS.enc.Hex.parse(cipher);

    const decrypted = CryptoJS.DES.decrypt(
      {
        ciphertext: cipherParsed,
      },
      keyParsed,
      {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.NoPadding,
      }
    );

    let result = "";
    const words = decrypted.words;
    const sigBytes = decrypted.sigBytes;

    for (let i = 0; i < sigBytes; i++) {
      const byte = words[i >>> 2] >>> (24 - (i % 4) * 8);
      result += (byte & 0xff).toString(16).padStart(2, "0");
    }

    return result;
  }

  // Initialize process button text
  updateProcessButton();
});
