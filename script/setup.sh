#static_analysis
cd ../static_analysis
STATIC_DIR=$(pwd)
mkdir -p test-results
# run static-analyzer container
docker run -d --name static-analyzer --volume $STATIC_DIR/test-results:/results taptipalit/temporal-specialization-artifacts:1.0

#copy into container

docker cp $STATIC_DIR/callgraphs/callgraphs.test/. static-analyzer:/debloating-vol/temporal-specialization-artifacts/callgraphs
docker cp $STATIC_DIR/docker-build/run.sh static-analyzer:/debloating-vol/temporal-specialization-artifacts
docker cp $STATIC_DIR/library-debloating/piecewise.py static-analyzer:/debloating-vol/temporal-specialization-artifacts/library-debloating
docker cp $STATIC_DIR/createSyscallStats.py static-analyzer:/debloating-vol/temporal-specialization-artifacts
docker cp $STATIC_DIR/python-utils/util.py static-analyzer:/debloating-vol/temporal-specialization-artifacts/python-utils/util.py
docker exec -it static-analyzer chmod +x /debloating-vol/temporal-specialization-artifacts/run.sh
