SPSA 2018 - OpenSSL / YAO
------------------------------------------

This program:
1) generates RSA Keys
2) generates DSA Keys
3) read a file containing a YAO's garbled circuit description
4) encrypts the file using RSA Public Key
5) signs the file using DSA Private Key
6) verifies the signature file using DSA Public Key
7) decrypts the file using RSA Private Key
8) evaluates the circuit

Programming Language: C
Required External Library: OpenSSL

**** ATTENTION ****
Configure your folders to be able to execute the program, to read and write files.
You should have the following folders (asis): 
- /KEYS/RSA
- /KEYS/DSA
- /CIT/
- /SIGN/

------------------------------------------
Made by Angelo Sirica
