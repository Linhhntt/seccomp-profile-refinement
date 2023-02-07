#
# CRASH ANALYSIS
#
# longnv
#

SECCOMP_PROFILE_PATH=/home/longnv/test/linh-test.json
IMAGE_TAG=nginx:latest
PORT_OUT=8081
PORT_IN=80


res=`docker run --rm -it -p$PORT_OUT:$PORT_IN --security-opt seccomp=$SECCOMP_PROFILE_PATH $IMAGE_TAG`
#IFS=$'\n'
arr=($(cat syscalls.txt))
echo $res



# loop thru array of syscalls
# for each syscall, see if it belongs to the crash log
# add it to the seccomp profile
# single quote protects the variable inside sed statement
for syscall in ${arr[@]}; do 
    if grep -q $syscall  <<< $res; then
        echo "***FOUND******$syscall*******"
        sed  -i '/\"names\"/a  \
        "'$syscall'",' $SECCOMP_PROFILE_PATH 
    fi
done



#if printf '%s\0' "${arr[@]}" | grep -Fxqz -- 'myvalue'; then
#    # ...
#fi
