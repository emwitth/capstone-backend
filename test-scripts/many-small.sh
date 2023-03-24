#!/bin/bash

echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "Many Small Script - nc connects to nc google.com 80 28 times"
echo "                  - for checking ability to handle many of same program"
printf "begin script? (y/n):"
read input
if [ $input != 'y' ]; then
    echo "script skipped"
    exit 0;
else
    echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    for ((i = 0; i < 20; i++)); do
        echo "echo -e \"f\\n\\n\" | nc google.com 80 ----------------------------"
        echo -e "f\n\n" | nc google.com 80
        sleep 3
    done
    echo "FINISHED MANY SMALL SCRIPT ---------------------------------------------"
fi
