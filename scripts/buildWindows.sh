#!/bin/bash

CMD=${*:-make exec}

DOCKER_IMAGE=${DOCKER_IMAGE:-lion.fritz.box:32323/my/go-win:latest}
docker run --rm -it -u $(id -u):$(id -g) --platform linux/amd64 -e HOME=/opt/xxx -v `pwd`/x/passwd:/etc/passwd -v `pwd`:/data -v `pwd`/x:/opt/xxx/ -v $HOME/.ssh:/opt/xxx/.ssh -w /data ${DOCKER_IMAGE} ${CMD}
#-v /data:`pwd`:rw,z 
