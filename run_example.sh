#!/bin/sh

python grade.py ./example/gt.csv ./example/submissions output.csv
echo "Example done, deleting output.csv"
rm -f output.csv
