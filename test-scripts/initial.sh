#!/bin/bash

echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "Initial Script - Diverse checks for simple graph check"
printf "begin script? (y/n):"
read input
if [ $input != 'y' ]; then
    echo "script skipped"
    exit 0
else
    echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    ping 8.8.8.8 -c 10
    sleep 3
    echo "wget google.com -------------------------------------------------"
    wget google.com
    sleep 15
    echo "wget www.flyn.org -----------------------------------------------"
    wget www.flyn.org
    sleep 15
    echo "wget www.flyn.org/courses/ --------------------------------------"
    wget www.flyn.org/courses/
    sleep 15
    echo "wget www.aquinas.dev --------------------------------------------"
    wget www.aquinas.dev
    sleep 15
    echo "ping google.com -c 10 -------------------------------------------"
    ping google.com -c 10
    sleep 5
    echo "cleaning up -----------------------------------------------------"
    echo "rm -f index.html*"
    rm -f index.html*
    echo "FINISHED INITIAL SCRIPT -----------------------------------------"
fi
