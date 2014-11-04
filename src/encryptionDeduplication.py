'''

Privacy Enhanced Cloud Storage Admitting Deduplication
by Mrunal Nargunde

'''

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


global file_name = "/mrunal.txt"
global key_file_name = "/mrunalEncryptedKey.txt"
global download_file_path = "/Users/mrunalnargunde/Desktop/Development/fall2014/appliedCrypt/1_Assignment/downloads"


# content: Data inside the user defined file
# pad function - converts the data into hexadecimal format in bytes
# Also equal chunks of block_size are created.
def pad(content):
  return content + b"\0" * (AES.block_size - len(content) % AES.block_size)
 
# striping the padded data
def unpad(content):
  return content.rstrip(b'\0')

def readFile():
    #fileName = "working-draft.txt"
    with open(file_name) as in_file:
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
def generateRsaKeyPair(secretKey):
    keys = RSA.generate(1024)
    f = open('mykey.pem','w')
    f.write(keys.exportKey('PEM'))
    f.close()

    f = open('mykeypublic.pem','w')
    f.write(keys.publickey().exportKey('PEM'))
    f.close()
    f = open('mykeypublic.pem','r')
    publickey = RSA.importKey(f.read())
    
    encryptedSecretKey = publickey.encrypt(pad(secretKey), None)
    return publickey, encryptedSecretKey

def encrypt():
  print "E N C R Y P T "
  stringContent, secretKey = readFile();
  paddedContent   = pad(stringContent)
  # Note that - In counter mode no iv, but they use nonce + counter check wiki diagram
  # nonce is 8 bytes , and counter of 64 bytes, and create 64 * 8 = 512 bytes 
  # 512 bytes is the block size of AES blocks
  ctr = Counter.new(64,nonce)
  aes = AES.new(secretKey, AES.MODE_CTR,counter=ctr)
  ciphertext = aes.encrypt(paddedContent)
  print "Encypted Content = " + ciphertext
  
  # Here used iv to randomize the data to greater extend.
  iv = Random.new().read(AES.block_size);
  return  iv+ciphertext, secretKey

def decrypt(ciphertext, secretKey):
  print "D E C R Y P T  "
  if len(ciphertext) <= AES.block_size:
    raise Exception ("Invalid ciphertext")
  
  ciphertext = ciphertext[AES.block_size:]
  print AES.block_size
  ctr = Counter.new(64,nonce)
  aes = AES.new(secretKey, AES.MODE_CTR , counter=ctr)
  original_data = aes.decrypt(ciphertext)
  
  return unpad(original_data)



def upload_File_And_Key_And_Get_Metadata(ciphertext, encryptedSecretKey):
  # TO DO : Enter your app key and App secret.
  app_key = 'osa0wcmmglq7xwg'
  app_secret = 'vw40uc9sbw7rez2'
  # Get your app key and secret from the Dropbox developer website
  flow = dropbox.client.DropboxOAuth2FlowNoRedirect(app_key, app_secret)

  # Have the user sign in and authorize this token
  authorize_url = flow.start()
  print '1. Go to: ' + authorize_url
  print '2. Click "Allow" (you might have to log in first)'
  print '3. Copy the authorization code.'
  code = raw_input("Enter the authorization code here: ").strip()

  # This will fail if the user enters an invalid authorization code
  access_token, user_id = flow.finish(code)

  client = dropbox.client.DropboxClient(access_token)
  #print 'linked account: ', client.account_info()

  f = open('/Users/mrunalnargunde/Desktop/Development/fall2014/appliedCrypt/1_Assignment/working-draft.txt', 'rb')
  try:
    #deduplication part => overwrite = True 
    response = client.put_file(file_name, ciphertext,True)
    stringEncryptedKey = " ".join(encryptedSecretKey)
    responseFromKey = client.put_file(key_file_name, stringEncryptedKey,True)
  except dropbox.rest.ErrorResponse as e : 
    print "Mrunal - Error occured while uploading the file- " 
    print dropbox.rest.ErrorResponse    

  #print 'uploaded: ', response
  return access_token
  


def downloadFile(access_token):
  print "In downloadFile function "
  client = dropbox.client.DropboxClient(access_token)
  #folder_metadata = client.metadata('/')
  #print 'metadata: ', folder_metadata
  
  
  f1, metadata = client.get_file_and_metadata(key_file_name)  
  f2 = open('mykey.pem','r')
  pvtkey = RSA.importKey(f2.read())
  decrypted = pvtkey.decrypt(f1.read()) 
    
  f, metadata = client.get_file_and_metadata(file_name)
  #out = open('/Users/mrunalnargunde/Desktop/Development/fall2014/appliedCrypt/1_Assignment/downloads/mrunal.txt', 'wb')
  out = open(download_file_path + file_name, 'wb')

  out.write(decrypt(ciphertext, secretKey))
  #print decrypt(ciphertext, secretKey)
  out.close()
  






ciphertext, secretKey = encrypt()
rsa_public_key, encryptedSecretKey = generateRsaKeyPair(secretKey);
access_token = upload_File_And_Key_And_Get_Metadata(ciphertext,encryptedSecretKey)

# First download the encrypted key file mrunalEncryptedKey.txt
# Read its contents
# Decrypt that secret key using the pvtkey from rsa
# Use the secret key from decryption process to decrypt content from the mrunal.txt
downloadFile(access_token);

