#!/bin/bash

sudo docker rm -f $(sudo docker ps -a -q)
sudo docker volume rm $(sudo docker volume ls -q)


sudo docker volume create cowrie-var
sudo docker volume create cowrie-etc
sudo mkdir /var/lib/docker/volumes/rdpy /var/lib/docker/volumes/rdpy/_data
sudo mkdir /var/lib/docker/volumes/elasticpot /var/lib/docker/volumes/elasticpot/_data

sudo docker run -p 22:22/tcp -p 23:23/tcp -v cowrie-etc:/cowrie/cowrie-git/etc -v cowrie-var:/cowrie/cowrie-git/var -d --cap-drop=ALL --read-only --restart unless-stopped 103.175.218.193:5000/cowrie
sudo docker run -it -p 21:21 -p 42:42 -p 69:69/udp -p 80:80 -p 135:135 -p 443:443 -p 445:445 -p 1433:1433 -p 1723:1723 -p 1883:1883 -p 3306:3306 -p 5060:5060 -p 5060:5060/udp -p 5061:5061 -p 11211:11211 -v dionaea:/opt/dionaea -d --restart unless-stopped 103.175.218.193:5000/dionaea
sudo docker run -it -p 3389:3389 -v rdpy:/var/log -d --restart unless-stopped 103.175.218.193:5000/rdpy /bin/sh -c 'python /rdpy/bin/rdpy-rdphoneypot.py -l 3389 /rdpy/bin/1 >> /var/log/rdpy.log'
sudo docker run -it -p 9200:9200/tcp -v elasticpot:/elasticpot/log -d --restart unless-stopped 103.175.218.193:5000/elasticpot /bin/sh -c 'cd elasticpot; python3 elasticpot.py'
sudo docker run -it -p 2222:2222 -p 8545:8545 -p 5900:5900 -p 25:25 -p 5037:5037 -p 631:631 -p 389:389 -p 6379:6379 -v honeytrap:/home -d --restart unless-stopped 103.175.218.193:5000/honeytrap
sudo docker run -d --restart always -v conpot:/data -p 8000:8800 -p 10201:10201 -p 5020:5020 -p 16100:16100/udp -p 47808:47808/udp -p 6230:6230/udp -p 2121:2121 -p 6969:6969/udp -p 44818:44818 103.175.218.193:5000/conpot

# sudo kill -HUP $(ps aux | grep 'fluentd -c' | awk '{print $2}'| head -1)
pgrep -f 'fluentd -c' | head -1 | xargs sudo kill -HUP

sudo rm -rf ewsposter_data
mkdir ewsposter_data ewsposter_data/log ewsposter_data/spool ewsposter_data/json
