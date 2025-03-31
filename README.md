# StegoAuth

## Table of Contents

1. [Introduction](#introduction)
2. [Cryptographic Architecture Overview](#cryptographic-architecture-overview)
3. [Algorithms and Techniques](#algorithms-and-techniques)

4. [RSA Key Pair Generation](#rsa-key-pair-generation)
5. [Digital Signatures](#digital-signatures)
6. [Hashing Functions](#hashing-functions)
7. [Steganography Implementation](#steganography-implementation)

8. [Authentication and Key Management](#authentication-and-key-management)

9. [Key Generation](#key-generation)
10. [Key Storage](#key-storage)
11. [Key Usage](#key-usage)

12. [Security Considerations](#security-considerations)

13. [Known Vulnerabilities](#known-vulnerabilities)
14. [Mitigation Strategies](#mitigation-strategies)

15. [Tools and Libraries](#tools-and-libraries)
16. [Compliance and Standards](#compliance-and-standards)
17. [Future Enhancements](#future-enhancements)
18. [Code Examples](#code-examples)

19. [Complete Implementation Examples](#complete-implementation-examples)
20. [Usage Examples](#usage-examples)

21. [References](#references)

## Introduction

Stegoauth is a secure image watermarking application that combines cryptographic techniques with steganography to embed invisible, cryptographically signed watermarks into digital images. This document provides a comprehensive overview of the cryptographic logic within the application, detailing the design choices, algorithms, and security considerations.

The core security premise of Stegoauth rests on two fundamental cryptographic pillars:

1. **Asymmetric Cryptography (RSA)**: Used for creating digital signatures that verify the authenticity and ownership of watermarked images.
2. **Steganography**: Employed to invisibly embed this cryptographic data within images without visibly altering their appearance.

## Cryptographic Architecture Overview

Stegoauth implements a security model based on public-key cryptography where:

1. Each user has a unique RSA key pair (public and private keys)
2. When creating a watermark, the application:

3. Constructs a payload containing user identification and timestamp
4. Signs this payload with the user's private key
5. Embeds both the payload and signature into the image using steganography

6. When verifying a watermark, the application:

7. Extracts the embedded data from the image
8. Verifies the signature using the purported creator's public key
9. Displays the verification result and embedded metadata

This architecture ensures that:

- Only the image owner (who possesses the private key) can create valid watermarks
- Anyone with access to the creator's public key can verify the authenticity of watermarked images
- The watermark remains invisible to casual observation

## Algorithms and Techniques

### RSA Key Pair Generation

#### Algorithm Description

RSA (Rivest–Shamir–Adleman) is an asymmetric cryptographic algorithm that uses a mathematically linked pair of keys: a public key that can be freely shared and a private key that must be kept secret. The mathematical relationship between these keys enables the following critical operations:

- Content signed with a private key can be verified using the corresponding public key
- Content encrypted with a public key can only be decrypted using the corresponding private key

The security of RSA relies on the computational difficulty of factoring the product of two large prime numbers. Modern RSA implementations typically use key lengths of 2048 or 4096 bits to ensure adequate security against factoring attacks.

#### Implementation Details

In the current implementation, RSA key pair generation is handled through a dedicated function that generates a 2048-bit RSA key pair:

```typescript
export async function generateRSAKeyPair(): Promise<{
  publicKey: string;
  privateKey: string;
}> {
  // In a production environment, this would use the Web Crypto API
  // The current implementation returns placeholder keys for demonstration
  return {
    publicKey: `-----BEGIN PUBLIC KEY-----...`,
    privateKey: `-----BEGIN PRIVATE KEY-----...`,
  };
}
```

In a production environment, this would be replaced with an implementation using the Web Crypto API:

```typescript
export async function generateRSAKeyPair(): Promise<{
  publicKey: string;
  privateKey: string;
}> {
  // Generate an RSA key pair
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: "SHA-256",
    },
    true, // Whether the key is extractable
    ["encrypt", "decrypt"] // Key usages
  );

  // Export the public key to PEM format
  const publicKeyBuffer = await window.crypto.subtle.exportKey(
    "spki",
    keyPair.publicKey
  );
  const publicKeyBase64 = arrayBufferToBase64(publicKeyBuffer);
  const publicKeyPEM = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64}\n-----END PUBLIC KEY-----`;

  // Export the private key to PEM format
  const privateKeyBuffer = await window.crypto.subtle.exportKey(
    "pkcs8",
    keyPair.privateKey
  );
  const privateKeyBase64 = arrayBufferToBase64(privateKeyBuffer);
  const privateKeyPEM = `-----BEGIN PRIVATE KEY-----\n${privateKeyBase64}\n-----END PRIVATE KEY-----`;

  return {
    publicKey: publicKeyPEM,
    privateKey: privateKeyPEM,
  };
}

// Helper function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const binary = String.fromCharCode(...new Uint8Array(buffer));
  return window
    .btoa(binary)
    .match(/.{1,64}/g)!
    .join("\n");
}
```

### Digital Signatures

#### Algorithm Description

Digital signatures provide three essential security services:

- **Authentication**: Verification that the message was created by a known sender
- **Non-repudiation**: The sender cannot deny having sent the message
- **Integrity**: The message was not altered in transit

In the context of Stegoauth, digital signatures are crucial for proving the authenticity of watermarks. When a user creates a watermark, they sign a payload containing their identity and a timestamp using their private key. This signature can later be verified using their public key, confirming that the watermark was indeed created by them.

#### Implementation Details

The current implementation includes two key functions:

```typescript
/**
 * Signs data with a private key
 * @param data The data to sign
 * @param privateKey The private key to use for signing
 * @returns Promise resolving to the signature
 */
export async function signData(
  data: string,
  privateKey: string
): Promise<string> {
  // Simple hash-based signature for demo purposes
  return `signature-${hashData(data)}`;
}

/**
 * Verifies a signature with a public key
 * @param data The original data
 * @param signature The signature to verify
 * @param publicKey The public key to use for verification
 * @returns Promise resolving to a boolean indicating if the signature is valid
 */
export async function verifySignature(
  data: string,
  signature: string,
  publicKey: string
): Promise<boolean> {
  // Simple hash-based verification for demo purposes
  return signature === `signature-${hashData(data)}`;
}
```

In a production environment, these would be replaced with implementations using the Web Crypto API:

```typescript
/**
 * Signs data with a private key using RSA-PSS
 * @param data The data to sign
 * @param privateKeyPEM The PEM-encoded private key
 * @returns Promise resolving to the base64-encoded signature
 */
export async function signData(
  data: string,
  privateKeyPEM: string
): Promise<string> {
  // Convert PEM private key to CryptoKey
  const privateKey = await importPrivateKey(privateKeyPEM);

  // Convert data to ArrayBuffer
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);

  // Sign the data
  const signature = await window.crypto.subtle.sign(
    {
      name: "RSA-PSS",
      saltLength: 32, // Recommended salt length for security
    },
    privateKey,
    dataBuffer
  );

  // Convert signature to base64
  return arrayBufferToBase64(signature);
}

/**
 * Verifies a signature with a public key
 * @param data The original data
 * @param signature The base64-encoded signature
 * @param publicKeyPEM The PEM-encoded public key
 * @returns Promise resolving to a boolean indicating if the signature is valid
 */
export async function verifySignature(
  data: string,
  signature: string,
  publicKeyPEM: string
): Promise<boolean> {
  try {
    // Convert PEM public key to CryptoKey
    const publicKey = await importPublicKey(publicKeyPEM);

    // Convert data to ArrayBuffer
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);

    // Convert base64 signature to ArrayBuffer
    const signatureBuffer = base64ToArrayBuffer(signature);

    // Verify the signature
    const isValid = await window.crypto.subtle.verify(
      {
        name: "RSA-PSS",
        saltLength: 32,
      },
      publicKey,
      signatureBuffer,
      dataBuffer
    );

    return isValid;
  } catch (error) {
    console.error("Signature verification error:", error);
    return false;
  }
}

// Helper functions for key import/export and base64 conversion
async function importPrivateKey(pemKey: string): Promise<CryptoKey> {
  // Remove PEM header/footer and decode base64
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = pemKey
    .replace(pemHeader, "")
    .replace(pemFooter, "")
    .replace(/\s/g, "");

  const binaryDer = base64ToArrayBuffer(pemContents);

  return window.crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    {
      name: "RSA-PSS",
      hash: { name: "SHA-256" },
    },
    false,
    ["sign"]
  );
}

async function importPublicKey(pemKey: string): Promise<CryptoKey> {
  // Remove PEM header/footer and decode base64
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const pemContents = pemKey
    .replace(pemHeader, "")
    .replace(pemFooter, "")
    .replace(/\s/g, "");

  const binaryDer = base64ToArrayBuffer(pemContents);

  return window.crypto.subtle.importKey(
    "spki",
    binaryDer,
    {
      name: "RSA-PSS",
      hash: { name: "SHA-256" },
    },
    false,
    ["verify"]
  );
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const binary = String.fromCharCode(...new Uint8Array(buffer));
  return window.btoa(binary);
}
```

### Hashing Functions

#### Algorithm Description

Cryptographic hash functions are one-way functions that transform input data of arbitrary size into a fixed-size output (a hash value or digest) with the following key properties:

- **Deterministic**: The same input always produces the same output
- **Quick Computation**: The hash value can be calculated efficiently
- **Pre-image Resistance**: It is computationally infeasible to reverse the function
- **Small Changes, Big Effects**: A small change in input produces a significantly different output
- **Collision Resistance**: It is difficult to find two different inputs that produce the same hash

In Stegoauth, hashing is used within the signature process and for creating unique identifiers.

#### Implementation Details

The current implementation uses a simple hash function:

```typescript
/**
 * Hashes data using a simple algorithm
 * @param data The data to hash
 * @returns The hash as a hex string
 */
export function hashData(data: string): string {
  // Simple hash function for demo purposes
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    const char = data.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash).toString(16);
}
```

In a production environment, this would be replaced with a standard cryptographic hash function using the Web Crypto API:

```typescript
/**
 * Hashes data using SHA-256
 * @param data The data to hash
 * @returns Promise resolving to the hash as a hex string
 */
export async function hashData(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);

  const hashBuffer = await window.crypto.subtle.digest("SHA-256", dataBuffer);

  // Convert hash to hex string
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
```

### Steganography Implementation

#### Algorithm Description

Steganography is the practice of concealing information within other non-secret data or a physical object to avoid detection. In Stegoauth, steganography is used to hide watermark data within image files without visibly altering their appearance.

The specific technique employed is Least Significant Bit (LSB) steganography, which works by replacing the least significant bits of pixel color values with bits from the data to be hidden. Since changing the least significant bit of a color value causes only a tiny, typically imperceptible change to the color, this allows data to be hidden with minimal visual impact on the image.

#### Implementation Details

The steganography implementation consists of several key functions:

1. `createWatermark`: Creates a watermark for an image by signing user data and embedding it
2. `verifyWatermark`: Extracts and verifies a watermark from an image
3. `embedDataInImage`: Embeds data in an image using LSB steganography
4. `extractDataFromImage`: Extracts embedded data from an image

The LSB steganography algorithm works as follows:

```typescript
/**
 * Embeds data in an image using a simple but robust method
 * This method uses a fixed pattern to embed data, making it more reliable
 * @param ctx The canvas context
 * @param data The string data to embed
 */
function embedDataInImage(ctx: CanvasRenderingContext2D, data: string): void {
  // Get image data
  const imageData = ctx.getImageData(0, 0, ctx.canvas.width, ctx.canvas.height);
  const pixels = imageData.data;

  // Convert data to binary
  const binaryData = stringToBinary(data);

  // Store the length of the binary data as a 32-bit header
  const lengthBinary = binaryData.length.toString(2).padStart(32, "0");

  // Embed the length header first (32 bits)
  for (let i = 0; i < 32; i++) {
    // Calculate position - use a fixed pattern for reliability
    // We'll use the first 32 pixels, modifying the least significant bit of the red channel
    const pixelIndex = i * 4; // Each pixel has 4 values (RGBA)

    // Embed the bit in the red channel
    pixels[pixelIndex] =
      (pixels[pixelIndex] & 0xfe) | Number.parseInt(lengthBinary[i], 2);
  }

  // Now embed the actual data
  for (let i = 0; i < binaryData.length; i++) {
    // Calculate position - use a fixed pattern that's easy to reproduce
    // Start after the header (32 pixels) and use every 4th byte (red channel only)
    const pixelIndex = (i + 32) * 4;

    if (pixelIndex >= pixels.length) {
      if (DEBUG)
        console.log(
          `Warning: Reached end of image data at bit ${i}/${binaryData.length}`
        );
      break;
    }

    // Embed the bit in the red channel
    pixels[pixelIndex] =
      (pixels[pixelIndex] & 0xfe) | Number.parseInt(binaryData[i], 2);
  }

  // Put the modified image data back to the canvas
  ctx.putImageData(imageData, 0, 0);
}

/**
 * Extracts embedded data from an image
 * @param ctx The canvas context
 * @returns The extracted string data or null if no data found
 */
function extractDataFromImage(ctx: CanvasRenderingContext2D): string | null {
  // Get image data
  const imageData = ctx.getImageData(0, 0, ctx.canvas.width, ctx.canvas.height);
  const pixels = imageData.data;

  // First, extract the 32-bit length header
  let lengthBinary = "";

  for (let i = 0; i < 32; i++) {
    // Calculate position - same pattern as embedding
    const pixelIndex = i * 4;

    if (pixelIndex >= pixels.length) {
      if (DEBUG) console.log("Image too small to contain a watermark");
      return null;
    }

    // Extract the bit from the red channel
    lengthBinary += (pixels[pixelIndex] & 1).toString();
  }

  // Convert binary length to decimal
  const dataLength = Number.parseInt(lengthBinary, 2);

  if (dataLength <= 0 || dataLength > pixels.length) {
    if (DEBUG) console.log(`Invalid data length: ${dataLength}`);
    return null;
  }

  // Now extract the actual data
  let extractedBinary = "";

  for (let i = 0; i < dataLength; i++) {
    // Calculate position - same pattern as embedding
    const pixelIndex = (i + 32) * 4;

    if (pixelIndex >= pixels.length) {
      if (DEBUG)
        console.log(
          `Warning: Reached end of image data at bit ${i}/${dataLength}`
        );
      break;
    }

    // Extract the bit from the red channel
    extractedBinary += (pixels[pixelIndex] & 1).toString();
  }

  // Convert binary data back to text
  try {
    const extractedText = binaryToString(extractedBinary);
    return extractedText;
  } catch (error) {
    if (DEBUG) console.error("Error converting binary to text:", error);
    return null;
  }
}
```

## Authentication and Key Management

### Key Generation

In Stegoauth, each user is assigned a unique RSA key pair during account creation. The generation process occurs client-side using the browser's cryptographic capabilities, and both the public and private keys are stored in the user's profile.

```typescript
const register = async (username: string, password: string) => {
  // ...

  // Generate RSA key pair
  const { publicKey, privateKey } = await generateRSAKeyPair();

  // Create new user
  const newUser = {
    id: crypto.randomUUID(),
    username,
    password, // In a real app, this would be hashed
    publicKey,
    privateKey,
  };

  // ...
};
```

### Key Storage

In the current implementation, keys are stored in the browser's localStorage:

```typescript
// Save user to "database"
users.push(newUser);
localStorage.setItem("stegoauth-users", JSON.stringify(users));

// Set user in state and localStorage
setUser(userWithoutPassword);
localStorage.setItem("stegoauth-user", JSON.stringify(userWithoutPassword));
```

This approach is suitable for demonstration but has serious security limitations for a production environment. In production, the following approach would be recommended:

1. **Private Keys**:

1. Should be encrypted before storage using a key derived from the user's password
1. Ideally should never leave the client except in encrypted form
1. Consider using the Web Crypto API's `subtle.wrapKey` for additional protection

1. **Public Keys**:

1. Can be stored server-side in a secure database
1. Should be retrievable only by authenticated users

### Key Usage

Keys are used for two primary purposes:

1. **Watermark Creation**: The user's private key signs the watermark payload, which includes user identity information and a timestamp.
2. **Watermark Verification**: The purported creator's public key is used to verify the digital signature of the watermark.

## Security Considerations

### Known Vulnerabilities

1. **Client-Side Key Storage**:

1. The current implementation stores keys in localStorage, which is vulnerable to XSS attacks
1. Private keys stored on the client are vulnerable to theft if the device is compromised

1. **Plain-Text Password Storage**:

1. The current implementation stores passwords in plain text, which is a significant security risk

1. **Basic Steganography Algorithm**:

1. The current LSB algorithm uses a predictable pattern (consecutive pixels)
1. Only uses the red channel, making detection easier
1. Does not include error correction, making it vulnerable to image modifications

1. **Limited Signature Algorithm**:

1. The placeholder signature algorithm is not cryptographically secure
1. Does not use standard algorithms like RSA-PSS or ECDSA

### Mitigation Strategies

1. **Improved Key Storage**:

1. Encrypt private keys with a key derived from the user's password
1. Consider using hardware security if available (e.g., WebAuthn)
1. Store keys in more secure storage options (IndexedDB with proper encryption)

1. **Password Security**:

1. Implement proper password hashing using bcrypt or Argon2
1. Support multi-factor authentication

1. **Enhanced Steganography**:

1. Use a pseudo-random pattern for embedding data
1. Distribute data across all color channels
1. Implement error correction codes (Reed-Solomon)
1. Add resistance to common image modifications

1. **Robust Signature Algorithms**:

1. Implement standard signature algorithms (RSA-PSS)
1. Use appropriate key sizes (2048 bits minimum for RSA)
1. Consider Elliptic Curve algorithms for better performance

## Tools and Libraries

The current implementation uses primarily native browser APIs, but a production version would benefit from the following tools and libraries:

1. **Web Crypto API**

1. Purpose: Native browser API for cryptographic operations
1. Version: Determined by browser support (widely available in modern browsers)
1. Usage: Key generation, digital signatures, hashing

1. **Subtle Crypto**

1. Purpose: Part of Web Crypto API for low-level cryptographic operations
1. Usage: RSA key operations, signature creation and verification

1. **Node.js Crypto (Server-Side)**

1. Purpose: Cryptographic operations on the server
1. Version: Latest stable
1. Usage: Password hashing, additional server-side cryptographic operations

1. **bcrypt or Argon2**

1. Purpose: Secure password hashing
1. Version: Latest stable
1. Usage: Hashing user passwords before storage

1. **Reed-Solomon Libraries**

1. Purpose: Error correction for steganography
1. Usage: Making watermarks more robust against image modifications

## Compliance and Standards

A production version of Stegoauth should adhere to the following standards and best practices:

1. **NIST Recommendations**

1. Key Sizes: RSA keys should be at least 2048 bits (NIST SP 800-57)
1. Hash Functions: SHA-256 or stronger (NIST FIPS 180-4)
1. Signature Algorithms: RSA-PSS or ECDSA (NIST FIPS 186-4)

1. **OWASP Security Guidelines**

1. Follow OWASP Top 10 web application security risks
1. Implement proper authentication and authorization
1. Protect against common web vulnerabilities (XSS, CSRF)

1. **General Data Protection Regulation (GDPR)**

1. Implement proper consent mechanisms for data collection
1. Provide data portability options
1. Implement right to be forgotten

1. **FIPS 140-2/3**

1. For applications requiring high security, consider FIPS-compliant cryptographic modules

## Future Enhancements

1. **Blockchain Integration**

1. Store watermark records on a blockchain for immutable proof of creation
1. Implement smart contracts for licensing and usage tracking

1. **Zero-Knowledge Proofs**

1. Allow verification of watermark authenticity without revealing the entire watermark data

1. **Quantum-Resistant Algorithms**

1. Prepare for quantum computing threats by implementing post-quantum cryptographic algorithms

1. **Advanced Steganography Techniques**

1. Explore frequency-domain steganography (DCT, DWT) for greater robustness
1. Implement adaptive steganography that considers image content

## Code Examples

### Complete Implementation Examples

#### Production-Ready RSA Key Generation

```typescript
export async function generateRSAKeyPair(): Promise<{
  publicKey: string;
  privateKey: string;
}> {
  try {
    // Generate an RSA key pair
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]), // 65537
        hash: "SHA-256",
      },
      true, // Whether the key is extractable
      ["encrypt", "decrypt"] // Key usages
    );

    // Export the public key to PEM format
    const publicKeyBuffer = await window.crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey
    );
    const publicKeyBase64 = arrayBufferToBase64(publicKeyBuffer);
    const publicKeyPEM = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64}\n-----END PUBLIC KEY-----`;

    // Export the private key to PEM format
    const privateKeyBuffer = await window.crypto.subtle.exportKey(
      "pkcs8",
      keyPair.privateKey
    );
    const privateKeyBase64 = arrayBufferToBase64(privateKeyBuffer);
    const privateKeyPEM = `-----BEGIN PRIVATE KEY-----\n${privateKeyBase64}\n-----END PRIVATE KEY-----`;

    return {
      publicKey: publicKeyPEM,
      privateKey: privateKeyPEM,
    };
  } catch (error) {
    console.error("Error generating RSA key pair:", error);
    throw new Error("Failed to generate RSA key pair");
  }
}

// Helper function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const binary = String.fromCharCode(...new Uint8Array(buffer));
  return window
    .btoa(binary)
    .match(/.{1,64}/g)!
    .join("\n");
}
```

#### Secure Private Key Storage

```typescript
import {
  pbkdf2Sync,
  randomBytes,
  createCipheriv,
  createDecipheriv,
} from "crypto";

// Encrypt a private key with a password
export function encryptPrivateKey(
  privateKey: string,
  password: string
): { encryptedKey: string; salt: string; iv: string } {
  // Generate a random salt
  const salt = randomBytes(16).toString("hex");

  // Derive a key from the password
  const derivedKey = pbkdf2Sync(password, salt, 100000, 32, "sha256");

  // Generate a random initialization vector
  const iv = randomBytes(16);

  // Create a cipher
  const cipher = createCipheriv("aes-256-gcm", derivedKey, iv);

  // Encrypt the private key
  let encryptedKey = cipher.update(privateKey, "utf8", "hex");
  encryptedKey += cipher.final("hex");

  // Get the auth tag
  const authTag = cipher.getAuthTag().toString("hex");

  // Return the encrypted key, salt, and iv
  return {
    encryptedKey: encryptedKey + authTag, // Append auth tag to encrypted key
    salt,
    iv: iv.toString("hex"),
  };
}

// Decrypt a private key with a password
export function decryptPrivateKey(
  encryptedData: { encryptedKey: string; salt: string; iv: string },
  password: string
): string {
  // Derive the key from the password
  const derivedKey = pbkdf2Sync(
    password,
    encryptedData.salt,
    100000,
    32,
    "sha256"
  );

  // Extract the auth tag (last 32 chars of hex string = 16 bytes)
  const authTag = Buffer.from(encryptedData.encryptedKey.slice(-32), "hex");
  const encryptedKey = encryptedData.encryptedKey.slice(0, -32);

  // Create a decipher
  const decipher = createDecipheriv(
    "aes-256-gcm",
    derivedKey,
    Buffer.from(encryptedData.iv, "hex")
  );

  // Set the auth tag
  decipher.setAuthTag(authTag);

  // Decrypt the private key
  let decrypted = decipher.update(encryptedKey, "hex", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}
```

### Usage Examples

#### Creating a Watermark

```typescript
async function watermarkImage(
  imageFile: File,
  user: { id: string; username: string; privateKey: string },
  message: string = ""
): Promise<HTMLCanvasElement> {
  // Read the image file
  const dataUrl = await readImageAsDataURL(imageFile);
  const img = await createImageFromDataURL(dataUrl);

  // Create a canvas from the image
  const canvas = createScaledCanvas(img, 1200, 1200);

  // Create the watermark
  const watermarkedCanvas = await createWatermark(
    canvas,
    {
      id: user.id,
      username: user.username,
      privateKey: user.privateKey,
    },
    message
  );

  return watermarkedCanvas;
}
```

#### Verifying a Watermark

```typescript
async function verifyImageWatermark(
  imageFile: File,
  publicKey: string
): Promise<{
  isValid: boolean;
  data?: {
    userId: string;
    username: string;
    timestamp: number;
    message: string;
  };
}> {
  // Read the image file
  const dataUrl = await readImageAsDataURL(imageFile);
  const img = await createImageFromDataURL(dataUrl);

  // Create a canvas from the image
  const canvas = createScaledCanvas(img, 1200, 1200);

  // Verify the watermark
  const result = await verifyWatermark(canvas, publicKey);

  return result;
}
```

## References

1. NIST Special Publication 800-57 Part 1 Revision 5: Recommendation for Key Management
2. FIPS PUB 186-4: Digital Signature Standard (DSS)
3. Web Crypto API: [https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
4. OWASP Top Ten: [https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)

---
