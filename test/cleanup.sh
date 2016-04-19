#!/bin/bash

docker ps -a | egrep -v CONTAINER | awk '{print $1}' | xargs -I {} docker kill {}
docker ps -a | egrep -v CONTAINER | awk '{print $1}' | xargs -I {} docker rm {}
docker images | fgrep lnmp_ | awk '{print $3}' | xargs -I {} docker rmi {}
