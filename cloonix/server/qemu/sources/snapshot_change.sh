#!/bin/bash

if (( ${#} != 2 )); then
  echo num old and num new.
  exit 1
fi
OLD_SNAPSHOT=$1
NEW_SNAPSHOT=$2

if [ ! -e qemu-${NEW_SNAPSHOT}.tar.gz ]; then
  echo qemu-${NEW_SNAPSHOT}.tar.gz not found
  exit 1
fi

for i in patched_create; do
  if [ "$(grep $OLD_SNAPSHOT $i)" == "" ]; then 
    echo $OLD_SNAPSHOT not found in $i
    exit 1
  fi
done

for i in mkpatch patched_create; do
  sed -i s"/${OLD_SNAPSHOT}/${NEW_SNAPSHOT}/" $i
done

