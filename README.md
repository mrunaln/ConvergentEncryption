ConvergentEncryption
====================

Privacy Enhanced Cloud Storage Admitting Deduplication
Cloud storage : Dropbox

Pre-requisite : Dropbox account

Features : 
1. Encrypt file contents (mp3, mp4, ico, txt, png, jpg, html)
2. Upload file on cloud (dropbox)
3. Download file and key.
4. Decrypt the file contents.
5. Share file with friend Bob.
6. Bob downloads and decrypts the file contents.


Setup : 
1. Download and uncompress python sdk for Dropbox
2. Login to dropbox account
3. Create new dropbox platform app.
4. Use the app key and app secret in the file encryptionDeduplication.py
5. Install python
6. Download pycrypto library from https://github.com/dlitz/pycrypto
7. Install pycrypto.


User Manual : 
Use Case 1 : Authenticate the application.
1. cd ConvergentEncryption/src/
2. Run the program using command - python encryptionDeduplication.py
3. The program prompts a url to authenticate the user. Access the url in a browser.
4. You may need to login to your dropbox account.
5. Dropbox will prompt you to authenticate yourself.Click on Allow button.
6. Copy the authentication code from browser and paste it in the IDE used.
7. In case of error, the response will be printed on the console.

Use Case 2  : Encrypt and upload
1. Place the content that you want to encrypt, upload on dropbox account inside  	    ConvergentEncryption/content/
2. Open ConvergentEncryption/src/encryptionDeduplication.py enter the file_name 
   you want to encrypt, upload on dropbox account, decrypt and download. 
   By default file_name mentioned in the program will be uploaded. 
3. The file will be encrypted and uploaded to :
	 <your_dropbox_account>/Apps/<your_new_dropbox_platform_app>/<file_name_dir>/file_name
4. Server side de-duplication will be performed i.e if the file is already present     
   then it will not be uploaded again( timestamp will be updated)


Use case 3 : Download and decrypt	 
1. Downloading the file will be done to location:
	/Users/mrunalnargunde/Desktop/Development/fall2014/appliedCrypt/ConvergentEncryption/downloads/<file_name_dir>
	You can change this location by setting global variable download_file_path
2. You can open the file at the specified location.


Use Case 4 : File Sharing
Assumption : File is shared with Bob only. No other user profiles present.
1. The file which is currently uploaded/downloaded by the application is shared with  
   Bob.
2. The files shared are stored at location : 
   ConvergentEncryption/sharedFile/downloads/ForBob/
3. You can view the files present at that location.