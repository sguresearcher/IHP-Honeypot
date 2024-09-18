#!/bin/bash

for container_id in $( docker ps | grep conpot | awk '{print $1}'); do
    docker restart $container_id
done

