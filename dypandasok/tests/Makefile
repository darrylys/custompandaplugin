
XTCFLAGS=-DRUNTEST -std=c++11
#XTINCLUDES=-I../include
#XTLIBDIRS=-L../lib
XTLIBS=

# list of all sources
# this must be manually listed because in case of PANDA, 
# this Makefile is for "unit testing" purpose, and so, must
# exclude all sources that are connected to PANDA/QEMU
# Only add the sources that are self-contained, can be compiled and executed as a separate unit.
XTSOURCEDIR:= ../api_filter.cpp \
	../pp_range.cpp \
	../Tracer.cpp \
	../tests/main.cpp \
	../AnalysisEngine.cpp

include ../../testmakefile.mak

