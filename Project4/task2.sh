#!/bin/bash

# check for valid input
if ! [ $# -ge 1 ]; then
    echo "Usage: ./task2.sh PATH_OF_STRING"
    exit 1
fi

string_path=$1

# find all base64 encoded strings in the binary
encoded_strings=`strings -f $string_path | awk {'print $2'} | grep -E "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$"`

# iterate through the encoded strings
for str in $encoded_strings; do
    decoded_str=`echo $str | base64 -d | tr -d '\0'`
    # print out the string satisfy the format FLAG{xxx} after base64 decoded
    if [[ $decoded_str =~ ^FLAG\{.*\}$ ]]; then
        echo $decoded_str
    fi
done