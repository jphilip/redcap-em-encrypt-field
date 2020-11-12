This external module allows you to encrypt certain fields in surveys, using mixed encryption with openssl (RSA + AES-256 in CBC mode), thus making it impossible for hackers or malicious system administrators to read these fields (Only a public key is stored on the server).

## Version history
- 0.1.0 Initial developement version.
- 0.2.0 Added a SHA256 hash to the payload to allow verification of the integrity of each field upon decryption.

## Instructions

1. Install the EM as usual.
2. Enable at least 1 instrument as survey in REDCap.
3. Enable 1 or more of these surveys for encryption in the module's project options.
4. Generate an RSA key pair and export public and private keys in pem format (>= 2048 bits is recommended).
Google on how to do this if needed, e.g. [http://lunar.lyris.com/help/lm_help//11.3/Content/generating_public_and_private_keys.html](http://lunar.lyris.com/help/lm_help//11.3/Content/generating_public_and_private_keys.html).
Make sure you do not use the demo keys provided in this repository for your own projects, you need to generate your own keys.
5. Paste the public key in the module's project options.
6. Assign the @ENCRYPT\_FIELD smart tag to the fields you want to encrypt (Only text and notes are currently supported).
7. Some R functions are provided in the package to decrypt individual field values or a cvs file exported by REDCap, using your private key. Implementations in other languages are easy to implement using the examples from the repository: [https://github.com/CodeReaper/unsealed-secrets](https://github.com/CodeReaper/unsealed-secrets)
8. A basic REDCap project in XML format is provided in the Github package to demonstrate the functionality. Note that the EM project settings are not part of the XML so you will have to set them: To get started, open project setttings and only enable encryption in the consent instrument and load the public key located in the example folder. The demo data has already been extracted to the EncryptDemo.csv file and decrypted to the decrypted_EncryptDemo.csv file.  
To do your own decryption, open the decrypt.R file in R or RStudio and execute line by line to follow the flow.  
You can add records by filling new surveys, then extract the data to a new csv file and decrypt similarly in R.

## How it works

1. Encryption is performed in PHP similarly to: [https://github.com/CodeReaper/unsealed-secrets](https://github.com/CodeReaper/unsealed-secrets), however it uses a stronger cypher, AES-256 in CBC mode instead of RC4.
2. The encrypted text is a json string, however when you open the form in REDCap, encrypted fields will be displayed as "Encrypted field (cannot be modified)" and they will be readonly, but the other fields can be modified and saved. The logs though will display the encrypted json string.

## Limitations

1. The encryption currently only works in surveys.
2. There is currently no decryption in REDCap which means also that the responses cannot be edited. Therefore, you cannot have encryption and the Save and return later, e-consent framework or One section per page without hiding back button option, enabled in a survey using the encrypt field module.
4. The private key is not stored on the server. This means that you cannot decrypt the data if you lose the private key, so make sure you keep copies of the private key and/or copies of the decrypted data in safe places.
5. Mixed encryption at the field level largely increases the amount of space required for storage, therefore this solution would not be recommended for a large number of fields and a large number of records. A typical use case is when you have PHIs in a public survey, e.g. consent/registration form, and encrypt those, but not the analytical research data in other forms.