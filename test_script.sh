#!/bin/bash
# Simple test script that does some work
for i in {1..1000}; do
    echo "Processing $i" > /dev/null
    sleep 0.001
done
