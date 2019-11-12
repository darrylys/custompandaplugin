#!/bin/sh

rm *.h
rm *.cpp
rm Makefile

cp /media/sf_vbox-sharedfolder/SguProjects/Sources/panda/src/dyremoteprocwrite/*.h .
cp /media/sf_vbox-sharedfolder/SguProjects/Sources/panda/src/dyremoteprocwrite/*.cpp .
cp /media/sf_vbox-sharedfolder/SguProjects/Sources/panda/src/dyremoteprocwrite/Makefile .

rm main.cpp
