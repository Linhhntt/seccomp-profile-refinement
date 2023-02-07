docker exec -it testtt ./run.sh nginx
docker exec -it testtt ./run.sh httpd.apr 
docker exec -it testtt ./run.sh memcached.libevent
docker exec -it testtt ./run.sh redis-server
docker exec -it testtt ./run.sh lighttpd
docker exec -it testtt ./run.sh bind.libuv