ConvergentEncryption
====================

Privacy Enhanced Cloud Storage Admitting Deduplication
Cloud storage : Dropbox

Pre-requisite : Dropbox account

Setup : 
1. Download and uncompress python sdk for Dropbox
2. Login to dropbox account
3. Create new dropbox platform app.
4. Use the app key and app secret in the file encryptionDeduplication.py
5. Install python
6. Download pycrypto library from https://github.com/dlitz/pycrypto
7. Install pycrypto.


User Manual : 
1. cd ConvergentEncryption/src/
2. Place the content that you want to encrypt, upload on dropbox account, decrypt and 	 download inside ConvergentEncryption/content/
3. Open ConvergentEncryption/src/encryptionDeduplication.py enter the file_name 
   you want to encrypt, upload on dropbox account, decrypt and download. 
   By default file_name mentioned in the program will be uploaded.
4. Run the program using command - python encryptionDeduplication.py
5. The program prompts a url to authenticate the user. Access the url in a browser.
6. You may need to login to your dropbox account.
7. Dropbox will prompt you to authenticate yourself.Click on Allow button.
8. Copy the authentication code from browser and paste it in the IDE used.
9. The file will be encrypted and uploaded to :
	 <your_dropbox_account>/Apps/<your_new_dropbox_platform_app>/<file_name_dir>/file_name
10. Downloading the file will be done to location:
	/Users/mrunalnargunde/Desktop/Development/fall2014/appliedCrypt/ConvergentEncryption/downloads/<file_name_dir>
	You can change this location by setting global variable download_file_path
11. In case of error, the response will be printed on the console.