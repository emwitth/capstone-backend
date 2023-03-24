#!/bin/bash

echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "IP List Script - Checks that one ip can share multiple names"
printf "begin script? (y/n):"
read input
if [ $input != 'y' ]; then
    echo "script skipped"
    exit 0
else
    echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    echo "ping example.com -c 3 -------------------------------------------------"
    ping example.com -c 3
    sleep 1
    echo "ping example.net -c 3 -------------------------------------------------"
    ping example.net -c 3
    echo "FINISHED IP LIST SCRIPT -----------------------------------------------"
fi
