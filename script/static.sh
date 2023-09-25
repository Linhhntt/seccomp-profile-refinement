# please input appname
if [ $# -ne 2 ]; then
    echo "Usage: ./static.sh <bc_file_name> <version>"
    exit 1
fi

APP=$1
VERSION=$2
APP_PART=$(echo $APP | cut -f1 -d"." | cut -f1 -d"-")

cd ../static_analysis
STATIC_DIR=$(pwd)
echo $STATIC_DIR
# docker exec -it static-analyzer rm -rf /debloating-vol/temporal-specialization-artifacts/bitcodes/*
docker cp $STATIC_DIR/bitcodes/$APP_PART/$VERSION/. static-analyzer:/debloating-vol/temporal-specialization-artifacts/bitcodes/

#dynamic_analysis
cd ../dynamic_analysis
cd version-output
DYNOUT_DIR=$(pwd)
echo $DYNOUT_DIR
#copy binaries from dynamic analysis to static analysis
# docker exec -it static-analyzer rm -rf ./binaries/*
docker cp $DYNOUT_DIR/$APP_PART/$VERSION/. static-analyzer:/debloating-vol/temporal-specialization-artifacts/binaries/$APP_PART/

# # run static-analysis
docker exec -it static-analyzer ./run.sh $APP 

#static_analysis result link
cd ../../static_analysis/test-results
# STATIC_DIR=$(pwd)
docker cp static-analyzer:/debloating-vol/temporal-specialization-artifacts/outputs/$APP_PART.syscall.out .

#create seccomp profiles from whitelist
cd ../../seccomp
mkdir -p test-output
python3.7 handler.py -a $APP_PART -o ./test-output
