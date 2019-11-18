
XTCFLAGS=-DRUNTEST
#XTINCLUDES=-I../include
#XTLIBDIRS=-L../lib
XTLIBS=

# list of all sources
# this must be manually listed because in case of PANDA, 
# this Makefile is for "unit testing" purpose, and so, must
# exclude all sources that are connected to PANDA/QEMU
# Only add the sources that are self-contained, can be compiled and executed as a separate unit.
XTSOURCEDIR:=../StructMetaData.cpp \
	../utils.cpp \
	../LiteralMetaData.cpp \
	../ZeroTerminatedStringData.cpp \
	../ISerializer.cpp \
	../LengthSpecifiedStringData.cpp \
	../StructData.cpp \
	../WinTypes.cpp \
	../LiteralData.cpp \
	../CommonData.cpp \
	../CommonMetaData.cpp \
	../tests/LiteralTypeTest.cpp \
	../tests/UtilsTest.cpp \
	../tests/StringTypeTest.cpp \
	../tests/CsvReaderTest.cpp \
	../tests/main.cpp \
	../tests/WinTypeData2JsonSerializerTest.cpp \
	../tests/WinApisTest.cpp \
	../tests/JsonSerializerTest.cpp \
	../JsonSerializer.cpp \
	../StringMetaData.cpp \
	../DummyEnv.cpp \
	../WinApis.cpp \
	../WinTypeData2JsonSerializer.cpp \
	../CsvReader.cpp

include ../../testmakefile.mak

