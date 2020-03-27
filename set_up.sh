#!/usr/bin/env bash
input="$1"

while true; do
  if [ "$input" = "0" ] || [ "$input" = "pbft" ]; then
    echo docker-compose -f consensus/sawtooth-default-pbft.yaml up
    docker-compose -f consensus/sawtooth-default-pbft.yaml up
    break
  elif [ "$input" = "1" ] || [ "$input" = "poet" ]; then
    echo docker-compose -f consensus/sawtooth-default-poet.yaml up
    docker-compose -f consensus/sawtooth-default-poet.yaml up
    break
  else
    echo Do you want to run pbft "(0)" or poet "(1)"
    read -r input
  fi
done
