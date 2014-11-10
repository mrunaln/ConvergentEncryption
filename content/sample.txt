Computer networks assignment -  Python

Learning - client server communication over HTTP/1.1

* Implementing Get request and Put request

  Assumptions :
  
  HTTPclientServer is the directory where all the program files and resources are stored.

  HTTPclientServer/src/server.py is simple http server implemented using python

  HTTPclientServer/src/client.py is simple client making get or put request to the server.
  
  HTTPclientServer/WebContent directory contains all the resources that client can access and send or recieve from server.

  HTTPclientServer/WebContent/serverPut directory where server stores all the put resouces obtained from client.


  Execution : 

* Run server from command line using:
   > python server.py 60002

* To run make the request from client use : 
    > python client.py localhost 60002 Get /sample.html
    > python client.py localhost 60002 Put /sample.mp4

  Supports file types :

    Images -
    png, jpg [Displayed in browser]

    Audio files -
    mp3 [Downloads audio and can be played from the new location]

    Video -
    mp4 [Plays the video in browser]

    Text -
    plain text,html [Printed]
