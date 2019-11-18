#
# 'make depend' uses makedepend to automatically generate dependencies 
#               (dependencies are added to end of Makefile)
# 'make'        build executable file 'mycc'
# 'make clean'  removes all .o and executable files
#

# define the C compiler to use
CXX = g++

# define any compile-time flags
CXXFLAGS += -O3 -Wall -g $(XTCFLAGS)

# define any directories containing header files other than /usr/include
#
INCLUDES = -I../ $(XTINCLUDES)

# define library paths in addition to /usr/lib
#   if I wanted to include libraries not in /usr/lib I'd specify
#   their path using -Lpath, something like:
LFLAGS = -L/home/newhall/lib  -L../lib $(XTLIBDIRS)

# define any libraries to link into executable:
#   if I want to link in libraries (libx.so or libx.a) I use the -llibname 
#   option, something like (this will link in libmylib.so and libm.so:
#   -lm is required: https://stackoverflow.com/questions/1033898/why-do-you-have-to-link-the-math-library-in-c
#   for historical reasons, it seems.
#LIBS = -lmylib -lm
LIBS = -lm $(XTLIBS)
#SOURCEDIR = ../

# define the C source files
#SRCS = emitter.c error.c init.c lexer.c main.c symbol.c parser.c
SRCS = $(XTSOURCEDIR)
#SRCS := $(shell find $(SOURCEDIR) -name '*.cpp')

# define the C object files 
#
# This uses Suffix Replacement within a macro:
#   $(name:string1=string2)
#         For each word in 'name' replace 'string1' with 'string2'
# Below we are replacing the suffix .c of all words in the macro SRCS
# with the .o suffix
#
OBJS = $(SRCS:.cpp=.o)

# define the executable file 
MAIN = testexec

#
# The following part of the makefile is generic; it can be used to 
# build any executable just by changing the definitions above and by
# deleting dependencies appended to the file from 'make depend'
#

.PHONY: depend clean

# the [tab] at the beginning of the second line of "all:" is required.
# Makefile is VERY PICKY about this. It has to be a tab character.
all:	$(MAIN)
	@echo  Simple compiler named mycc has been compiled

$(MAIN):	$(OBJS) 
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $(MAIN) $(OBJS) $(LFLAGS) $(LIBS)

# this is a suffix replacement rule for building .o's from .c's
# it uses automatic variables $<: the name of the prerequisite of
# the rule(a .c file) and $@: the name of the target of the rule (a .o file) 
# (see the gnu make manual section about automatic variables)
.cpp.o:
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $<  -o $@

clean:
	$(RM) *.o ../*.o *~ ../*~ $(MAIN)

depend: $(SRCS)
	makedepend $(INCLUDES) $^

# DO NOT DELETE THIS LINE -- make depend needs it

