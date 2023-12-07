#!/bin/bash
inotifywait -q -e modify,moved_to -m detections/validated/ detections/failed/ |  while read -r directory events filename path; do python3 ./development/custom_validation.py $filename $(pwd)/$directory$filename$path $events;done
