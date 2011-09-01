#!/bin/sh
OSX_VER=`sw_vers -productVersion`
if test ${OSX_VER:0:4} = "10.5"; then
	arch -i386 ${0%.sh} "$@"
else
	${0%.sh} "$@"
fi
