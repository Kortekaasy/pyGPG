# pyGPG
A GPG like application in python, but with lattice based encryption.

# How to use pyGPG
In the dist directory you can find two different executables: "pygpg" and "pygpg.exe".
The pygpg.exe executable is build for windows environments, and the pygpg executable is build
for posix environments. There are three basic commands available, which you can find beneath:
---
The following command will generate a new keypair. During generation you will be asked to specifiy
a security level and a password to protect your private key.
```
$ ./pygpg -g [key id]
```
---
The following command will encrypt a file. In order to encrypt a file you will need to specify
a public key, that needs to be in the key database.
```
$ ./pygpg -e [key id] [path/to/file.ext]
```
---
The following command will decrypt a file. The only supported file format is .pygpg files.
During the decryption operation you will be asked to enter the password that you chose to
protect your private key.
```
$ ./pygpg -d [path/to/file.pygpg]
```
