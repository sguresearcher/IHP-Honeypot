#!/bin/bash

for container_id in $(docker ps -q); do
    docker restart $container_id
done

