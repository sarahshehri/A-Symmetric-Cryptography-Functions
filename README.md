# A-Symmetric-Cryptography-Functions
(We did it programmatically with a one class(symmetricCryptoFunction), and it was categorized by methods)

(inputFilePathForEncrypting, inputFilePathForDecrypting, inputFolderForEncrypting, inputFolderForDecrypting, inputFilePathForHashing)
•	We have defined 5 variables of type string. These variables storing the path of the file and folder for encrypt/decrypt a file and folder and hashing a file. The user is required to save files and folders in the same path with the specified type of extension.


getFunction(choice,inputFilePath,inputFolderPath)
•	We have implemented a method(getFunction) that implements user selection of our system(symmetric crypto system)Encryption or Hashing or Exit.


getMenu()
•	We have implemented a (getMenu) method that displays the main menu of our system to the user.


static void getEncryption(choice,inputFilePath,inputFolderPath)
•	We've created a method (getEncryption) that allows the user to select our system's encryption (encrypts or decrypts (the user chooses between AES and DES algorithm) or returns to the main menu).
1.	Encrypt Methods 
It converts the plaintext(file\folder) into ciphertext(file\folder) using the algorithm selected by the user.
2.	Decrypt Methods 
It converts the ciphertext(file\folder) into plaintext(file\folder) using the algorithm selected by the user.


Hashing Method 
•	We developed a method (Hashing) that allows users to choose between the SHA256 and SHA512 algorithms. To convert plaintext (file) into a hashed format.

o	Implement a symmetric cryptographic system 
	Encrypt Process 
	Make sure the path(file)is correct-.txt then save it as a project route-.
	Make sure the file/folder name is correct-file/folder-.
	Make sure your key verify )DES:8 digits|AES:24 digest).

	Decrypt Process 
	Make sure the path(file/folder)is correct-.txt.encrypted then save it as a project route-.
	Make sure the file/folder name is correct-file/folder-.
	Make sure your key verify )DES:8 digits|AES:24 digest)


o	Implement a one-way hash function 
	Hashing Process 
	Make sure the path(file)is correct-.txt then save it as a project route-.
	Make sure the file name is correct-file-.
