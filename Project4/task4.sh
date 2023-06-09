#!/bin/bash

# check for valid input
if ! [ $# -ge 1 ]; then
    echo "Usage: ./task4.sh PATH_OF_IMAGE"
    exit 1
fi

image_path=$1

offset=`grep -obUaP "\x50\x4b\x03\x04" $image_path | awk -F':' {'print $1'}`
dd if=$image_path of=temp skip=$offset bs=1 status=none
unzip -q temp
cat flag.txt | grep FLAG | awk {'print $2'}
rm temp flag.txt