Q = @
CC = gcc

TARGET_ARCH = 

CFLAGS = 
CPPFLAGS = -fPIC -shared 
OUTPUT_OPTION = -O2 -g -Wall -Werror -Wextra -pedantic -o $@ 

LDFLAGS = -fPIC -shared 
LDLIBS = -lconfig -lcrypto -lmariadb -largon2 
LOADLIBES =  

SRCDIR = src/
BUILDDIR = build/

VPATH = $(SRCDIR):$(BUILDDIR)

SRC = $(wildcard $(SRCDIR)*.c)
BUILD = $(patsubst $(SRCDIR)%, $(BUILDDIR)%, $(patsubst %.c, %.o, $(SRC)))
OUTLIB = plugin.so

.PHONY: all clean help

help:
	@ echo ""
	@ echo "The help section is not ready yet. Come back later! :)" 
	@ echo "Not to myself : Need to create the makefile help section"
	@ echo ""

all: $(OUTLIB)

#$(TEST): $(BUILD) $(TEST_BUILD)
#	@ echo "LD	$@"
#	$(Q)

$(OUTLIB): $(BUILD)
	@ echo "LINK	$@"
	$(Q) $(LINK.o) $^ -o $@ $(LOADLIBES) $(LDLIBS) 

$(BUILDDIR)%.o: %.c
	@ echo "CC	$(patsubst $(BUILDDIR)%,%,$@)"
	$(Q) $(COMPILE.c) $(OUTPUT_OPTION) $< 
	
clean:
	rm -f $(OUTLIB) $(BUILDDIR)*.o


