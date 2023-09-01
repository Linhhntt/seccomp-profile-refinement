# please input appname
if [ $# -ne 1 ]; then
    echo "Usage: ./static.sh <bc_file_name>"
    exit 1
fi

APP=$1
APP_PART=$(echo $APP | cut -f1 -d"." | cut -f1 -d"-")

#dynamic_analysis
cd ../dynamic_analysis
cd example-output
DYNOUT_DIR=$(pwd)

#copy binaries from dynamic analysis to static analysis
docker cp $DYNOUT_DIR/. static-analyzer:/debloating-vol/temporal-specialization-artifacts/binaries

# # run static-analysis
docker exec -it static-analyzer ./run.sh $APP 

# #static_analysis result link
# cd ../../static_analysis/test-results
# # STATIC_DIR=$(pwd)
# docker cp static-analyzer:/debloating-vol/temporal-specialization-artifacts/outputs/$APP_PART.syscall.out .

# #create seccomp profiles from whitelist
# cd ../../seccomp
# mkdir -p test-output
# python3.7 handler.py -a $APP_PART -o ./test-output
