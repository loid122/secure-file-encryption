# secure-file-encryption
Secure encryption of files using both RSA and AES (hybrid encryption).

A Python-based secure file encryption tool that uses a hybrid encryption scheme combining AES-GCM for fast, secure file encryption and RSA for protecting the AES key.

# Features

Hybrid Encryption: Encrypts file contents with AES-GCM and secures the AES key using RSA encryption.

Data Integrity: Uses AES-GCM for authenticated encryption to ensure integrity and confidentiality.

Asymmetric Key Protection: RSA encryption safeguards the AES key for secure transmission and storage.

Flexible Key Management: Supports generating new RSA key pairs or using existing ones.

# Technologies Used

Language: Python

Encryption: AES-GCM (symmetric) and RSA (asymmetric) via cryptography package
