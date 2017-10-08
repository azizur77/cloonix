#!/bin/bash
HERE=`pwd`
rm -rf virglrenderer
rm -f virglrenderer.tar.gz
git clone git://anongit.freedesktop.org/virglrenderer
cd virglrenderer
./autogen.sh
cd $HERE
rm -rf ./virglrenderer/autom4te.cache
rm -rf ./virglrenderer/.git
tar zcvf virglrenderer.tar.gz virglrenderer 
rm -rf virglrenderer

