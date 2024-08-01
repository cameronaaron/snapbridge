
#!/bin/bash

docker build -t snapchat-bridge .

docker run -d -p 8080:8080 --name snapchat-bridge snapchat-bridge
