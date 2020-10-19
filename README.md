# Encrypt Field REDCap External Module

This external module allows you to encrypt certain fields in surveys, using mixed encryption with openssl (RSA + AES-256 in CBC mode), thus making it impossible for hackers or system administrators to read these fields (Only a public key is stored on the server).

## Instructions

1. Install the EM as usual.
2. Enable at least 1 instrument as survey in REDCap.
3. Enable 1 or more of this/these survey(s) for encryption in the module's project options.
4. Generate an RSA SSL key pair and export public and private keys in pem format (Google on how to do this if needed).
5. Paste the public key in the module's project options.
6. Assign the @ENCRYPT\_FIELD smart tag to the fields you want to encrypt (Only text and notes are currently supported).

## How does it works

1. Encryption is performed in PHP similarly to [https://github.com/CodeReaper/unsealed-secrets](https://github.com/CodeReaper/unsealed-secrets), however it uses a stronger cypher, AES-256 in CBC mod instead of RC4.
2. The encrypted text is a json string.

## Limitations

1. There is currently no decryption in REDCap which means also that the responses cannot be edited.
2. Some R functions are provided to decrypt individual field values or a cvs file exported by REDCap, using your private key.
3. Implementation in other languages are possible, including javascript.