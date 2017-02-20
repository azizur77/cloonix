#!/bin/bash
HERE=`pwd`
rm -rf spice
rm -f spice.tar.gz
git clone git://anongit.freedesktop.org/spice/spice
cd spice
patch -p1 < ../compile_in_centos.patch
./autogen.sh
cd $HERE
rm -rf ./spice/autom4te.cache
rm -rf ./spice/spice-common/autom4te.cache
rm -rf ./spice/.git
rm -rf ./spice/spice-common/.git
tar zcvf spice.tar.gz spice
rm -rf spice
