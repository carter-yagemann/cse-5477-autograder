#!/bin/sh

python grade.py ./example/gt.csv ./example/submissions scores.csv transcripts
echo "Example done, see scores.csv and transcripts directory"
