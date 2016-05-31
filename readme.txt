Christopher Nelson
christopher.w.nelso@wsu.edu

-description-
PublicKeyCrypt is a program that implements a public-key cryptosystem. It can generate keys and
encrypt/decrypt ASCII text files of any length. It also requires a "ptext.txt" file to perform
encryption on. For key generation, the user provides a random number to seed a random number
generator. It then generates a 33-bit prime that is used to create the public and private keys.
For encryption, the program encrypts the "ptext.txt" file in 32-bit blocks using the "pubkey.txt"
file. For decryption, the program decrypts the cipher text file that it creates.

To run the program, run the wsu_crypt.java file in an IDE such as Eclipse, or compile and 
run it. To compile the code, type javac PublicKeyCrypt.java in the command prompt. Then
type java PublicKeyCrypt to run it.

-list of files-
readme.txt 		Readme file
PublicKeyCrypt.java	Source code file