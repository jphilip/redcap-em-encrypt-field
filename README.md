## Instructions

1. Install the EM as usual.
2. Enable at least 1 instrument as survey in REDCap.
3. Enable 1 or more of these surveys for encryption in the module's project options.
4. Generate an RSA key pair and export public and private keys in pem format (>= 2048 bits is recommended).
Google on how to do this if needed, e.g. on Windows 10: [https://phoenixnap.com/kb/generate-ssh-key-windows-10](https://phoenixnap.com/kb/generate-ssh-key-windows-10).
Make sure you do not use the demo keys provided in this repository, you need to generate your own.
5. Paste the public key in the module's project options.
6. Assign the @ENCRYPT\_FIELD smart tag to the fields you want to encrypt (Only text and notes are currently supported).
7. Some R functions are provided in the package to decrypt individual field values or a cvs file exported by REDCap, using your private key. Implementations in other languages are easy to implement using the examples from the repository: [https://github.com/CodeReaper/unsealed-secrets](https://github.com/CodeReaper/unsealed-secrets)
8. A basic REDCap project is provided in the package to test the functionality.

## How it works

1. Encryption is performed in PHP similarly to: [https://github.com/CodeReaper/unsealed-secrets](https://github.com/CodeReaper/unsealed-secrets), however it uses a stronger cypher, AES-256 in CBC mode instead of RC4.
2. The encrypted text is a json string however, when you open the form in REDCap, encrypted fields will be displayed as "Encrypted field (cannot be modified)" and they will be readonly, but the other fields can be modified and saved. The logs though will display the encrypted json string.

## Limitations

1. The encryption currently only works in surveys.
2. There is currently no decryption in REDCap which means also that the responses cannot be edited. Therefore, you cannot have encryption and the Save and return later, e-consent framework or One section per page without hiding back button option, enabled in a survey using the encrypt field module.
4. The private key is not stored on the server. This means that you cannot decrypt the data if you lose the private key, so make sure you keep copies of the private key and/or copies of the decrypted data in safe places.
5. Mixed encryption at the field level largely increases the amount of space required for storage, therefore this solution would not be recommended for a large number of fields and a large number of records. A typical use case is when you have PHIs in a public survey, e.g. consent/registration form, and encrypt those, but not the analytical research data in other forms.