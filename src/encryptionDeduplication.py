'''

Privacy Enhanced Cloud Storage Admitting Deduplication
by Mrunal Nargunde

'''

import os
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
import Crypto.Cipher.AES as AES
from os import urandom
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
import dropbox
from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# this is used to create a counter.
# We have padded data in bytes.
# So we want the counter also to be in bytes
global nonce
nonce = get_random_bytes(8)
global app_key
global app_secret

# Storing the file_name to read from local machine and 
# upload with the file with the same filename with encrypted contents on dropbox
global file_name
global local_filePath
global packageDirectory

local_filePath = "../content/"
file_name = "mrunal.txt"
packageDirectory = file_name.split(".")

#Store the encrypted key on dropbox with the following filename
global key_file_name
key_file_name = "/mrunalEncryptedKey"+file_name

# Location of the file downloaded on local machine
global download_file_path
download_file_path = "/Users/mrunalnargunde/Desktop/Development/fall2014/appliedCrypt/ConvergentEncryption/downloads/" + packageDirectory[0]
# If the directory does not exists then create one.
if not os.path.exists(download_file_path):
    os.makedirs(download_file_path )


# pad function - converts the data into hexadecimal format in bytes
# content: Data inside the user defined file
# Also equal chunks of block_size are created.
def pad(content):
  return content + b"\0" * (AES.block_size - len(content) % AES.block_size)
 
# striping the padded data
def unpad(content):
  return content.rstrip(b'\0')

def readFile():
    #fileName = "working-draft.txt
    with open(local_filePath + file_name) as in_file:
      content =  in_file.readlines()
    
    stringContent = ''.join(content)

    # Always length should be 32 so no need of padding
    # Encrypt this key with public key and store it on the cloud   
    secretKey = SHA256.new(stringContent).digest()
    return stringContent, secretKey


 # DONE 27 Oct 2014 : 
    # RSA will be used to create pair of public key and pvt key.
    # Using that public key I will encrypt secret key to store on the cloud.
    # Now only my paired secret from RSA can decrypt the data.
def generate_Rsa_Key_Pair(secretKey):
    keys = RSA.generate(1024)
    f = open('../keyManager/my_pvt_rsa_key.pem','w')
    f.write(keys.exportKey('PEM'))
    f.close()

    f = open('../keyManager/my_public_rsa_key.pem','w')
    f.write(keys.publickey().exportKey('PEM'))
    f.close()
    f = open('../keyManager/my_public_rsa_key.pem','r')
    publickey = RSA.importKey(f.read())
    
    encryptedSecretKey = publickey.encrypt(pad(secretKey), None)
    return publickey, encryptedSecretKey

def encrypt():
  stringContent, secretKey = readFile();
  paddedContent   = pad(stringContent)
  # Note that - In counter mode no iv, but they use nonce + counter check wiki diagram
  # nonce is 8 bytes , and counter of 64 bytes, and create 64 * 8 = 512 bytes 
  # 512 bytes is the block size of AES blocks
  ctr = Counter.new(64,nonce)
  aes = AES.new(secretKey, AES.MODE_CTR,counter=ctr)
  ciphertext = aes.encrypt(paddedContent)
  #print "Encypted Content = " + ciphertext
  
  # Here used iv to randomize the data to greater extend.
  iv = Random.new().read(AES.block_size);
  return  iv+ciphertext, secretKey

def decrypt(ciphertext, secretKey):
  if len(ciphertext) <= AES.block_size:
    raise Exception ("Invalid ciphertext")
  
  ciphertext = ciphertext[AES.block_size:]
  ctr = Counter.new(64,nonce)
  aes = AES.new(secretKey, AES.MODE_CTR , counter=ctr)
  original_data = aes.decrypt(ciphertext)
  
  return unpad(original_data)

def authenticateApp():
  # TO DO : Enter your app key and App secret.
  app_key = 'osa0wcmmglq7xwg'
  app_secret = 'vw40uc9sbw7rez2'
  # Get your app key and secret from the Dropbox developer website
  flow = dropbox.client.DropboxOAuth2FlowNoRedirect(app_key, app_secret)

  # Have the user sign in and authorize this token
  authorize_url = flow.start()
  print '1. Go to: \n' + authorize_url
  print '2. Click "Allow" (you might have to log in first)'
  print '3. Copy the authorization code.'
  code = raw_input("Enter the authorization code here: ").strip()

  # This will fail if the user enters an invalid authorization code
  access_token, user_id = flow.finish(code)
  client = dropbox.client.DropboxClient(access_token)
  return access_token, client

def upload_File_And_Key_And_Get_Metadata(ciphertext, encryptedSecretKey, access_token, client):

  try:
    #deduplication part => overwrite = True 
    response = client.put_file("/" + packageDirectory[0] + "/"+file_name, ciphertext,True)
    stringEncryptedKey = " ".join(encryptedSecretKey)
    responseFromKey = client.put_file(packageDirectory[0] + "/"+ key_file_name, stringEncryptedKey,True)
    print "Alice, your encrypted file has been successfully uploaded !\n"
  except dropbox.rest.ErrorResponse as e : 
    print "Alice - Error occured while uploading the file- " 
    print dropbox.rest.ErrorResponse    
  #print 'uploaded: ', response
  return access_token
  


def downloadFile(access_token):
  client = dropbox.client.DropboxClient(access_token)
  #folder_metadata = client.metadata('/')
  #print 'metadata: ', folder_metadata
  
  
  f1, metadata = client.get_file_and_metadata(packageDirectory[0] + "/" + key_file_name)
  
  f2 = open('../keyManager/my_pvt_rsa_key.pem','r')
  pvtkey = RSA.importKey(f2.read())
  decrypted = pvtkey.decrypt(f1.read()) 

  f, metadata = client.get_file_and_metadata("/" + packageDirectory[0] + "/"+ file_name)
  out = open(download_file_path + "/" + file_name, 'wb')
  out.write(decrypt(ciphertext, secretKey))
  out.close()


def bob_generate_Rsa_Key_Pair():

    keys = RSA.generate(1024)
    f = open('../keyManager/bob/bob_pvt_rsa_key.pem','w')
    f.write(keys.exportKey('PEM'))
    f.close()

    f = open('../keyManager/bob/bob_public_rsa_key.pem','w')
    f.write(keys.publickey().exportKey('PEM'))
    f.close()

def alice_shares_with_bob():
  '''
  Alice gets her own encrypted key from dropbox
  decrypts the key
  '''
  client = dropbox.client.DropboxClient(access_token)
  f1, metadata = client.get_file_and_metadata(packageDirectory[0] + "/" + key_file_name)
  f2 = open('../keyManager/my_pvt_rsa_key.pem','r')
  pvtkey = RSA.importKey(f2.read())
  decryptedKey = pvtkey.decrypt(f1.read())

  '''
  Re-seal this decrypted key with bobs_public_key
  '''
  f = open('../keyManager/bob/bob_public_rsa_key.pem','r')
  publickey = RSA.importKey(f.read())
  encryptedSecretKeyForBob = publickey.encrypt(pad(decryptedKey), None)
  return encryptedSecretKeyForBob;

def printStatus(msg):
  print msg


print "* * * * * * * * * * * * * * * * * * * * * * * * * * * * \n"
print "Privacy Enhanced Cloud Storage Admitting De-duplication\n\n" 
printStatus (" Hi I am Alice,  I want to use file : " + file_name + " for encryption, de-duplication, uploading, decrypting data & downloading file")
print "* * * * * * * * * * * * * * * * * * * * * * * * * * * * \n"


printStatus("Data encryption in progress ")
ciphertext, secretKey = encrypt()
printStatus("Alice, your data is encrypted successfully!\n")

printStatus("Generating RSA key pair for Alice\n")
rsa_public_key, encryptedSecretKey = generate_Rsa_Key_Pair(secretKey);

printStatus("Alice, Can you please authenticate your app ? \n");
access_token, client = authenticateApp()
print "Authentication successful ! \n " 

printStatus ("File upload in progress . . . ")
access_token = upload_File_And_Key_And_Get_Metadata(ciphertext,encryptedSecretKey, access_token, client)

while(1):
  print "\n What do you want to do next . . .\n 1. Download the file \n 2. Share the file with friend\n 3. Exit\n"
  featureChoice=int (input("Enter your choice here : "))
  if featureChoice == 1:
      print "\n \n D O W N L O A D F I L E   F E A T U R E \n"
      printStatus("Downloading the file - " + file_name + " \n Download location - " + download_file_path)
      # First download the encrypted key file mrunalEncryptedKey.txt
      # Read its contents
      # Decrypt that secret key using the pvtkey from rsa
      # Use the secret key from decryption process to decrypt content from the mrunal.txt
      downloadFile(access_token);
      printStatus("Download successfully complete !")

  elif featureChoice == 2:
      print "\n \n F I L E   S H A R E   F E A T U R E \n"
      print "Alice wants to share a file with Bob\n\n"

      print "Hello Alice!\n You can share this file with the following friends : \n 1. Bob \n 2. Chris\n"
      friendId = int(input("Enter the friend id here : "))

      if(friendId == 1):
        bob_generate_Rsa_Key_Pair()
        printStatus("Hi, I am Alice!")
        printStatus("I am re-sealing this key with Bobs public key")

        encryptedSecretKeyForBob = alice_shares_with_bob()

        # Assume bob is notified ciphertext and encryptedSecretKeyForBob
        printStatus("\n Let us assume: Alice notifies Bob with key and cipher text ! \n");

        download_file_path = "/Users/mrunalnargunde/Desktop/Development/fall2014/appliedCrypt/ConvergentEncryption/sharedFiles/downloads" + "/ForBob/" + packageDirectory[0]
        if not os.path.exists(download_file_path):
          os.makedirs(download_file_path )

        printStatus("Done ! Let me share this cryptic file and key with Bob\n\n")
        access_token = upload_File_And_Key_And_Get_Metadata(ciphertext, encryptedSecretKeyForBob, access_token, client)

        printStatus("Hi, I am Bob !")
        printStatus("Oh I received something from Alice !");

        printStatus(" Downloading the file - " + file_name + " \n Download location - " + download_file_path)
        downloadFile(access_token)
        printStatus("Download successfully complete !  Lets check !")
        # end of if freind Id == 1

  elif featureChoice == 3:
      break;
  else:
    print "Incorrect entry ! :("




