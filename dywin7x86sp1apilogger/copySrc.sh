#!/bin/sh

rm res/*
rm *.cpp
rm *.h
rm Makefile

# cp /media/sf_vbox-sharedfolder/SguProjects/Sources/panda/apidblib/*.cpp .
# cp /media/sf_vbox-sharedfolder/SguProjects/Sources/panda/apidblib/*.h .
cp /media/sf_vbox-sharedfolder/SguProjects/Sources/panda/src/dywin7x86sp1apilogger/*.cpp .
cp /media/sf_vbox-sharedfolder/SguProjects/Sources/panda/src/dywin7x86sp1apilogger/Makefile .
cp /media/sf_vbox-sharedfolder/SguProjects/Sources/panda/src/dywin7x86sp1apilogger/*.h .
cp /media/sf_vbox-sharedfolder/SguProjects/Sources/panda/src/dywin7x86sp1apilogger/res/*.csv res
rm main.cpp
