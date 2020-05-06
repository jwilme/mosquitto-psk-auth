Q = @
CC = gcc

TARGET_ARCH = 

CFLAGS = 
CPPFLAGS = -fPIC -shared
OUTPUT_OPTION = -o $@ 

LDFLAGS =
LDLIBS = 
LOADLIBES =

SRCDIR = src/
BUILDDIR = build/

VPATH = $(SRCDIR):$(BUILDDIR)

SRC = $(wildcard $(SRCDIR)*.c)
BUILD = $(patsubst $(SRCDIR)%, $(BUILDDIR)%, $(patsubst %.c, %.o, $(SRC)))
OUTLIB = auth_plugin.so

.PHONY: all clean

all: $(OUTLIB)

$(OUTLIB) : $(BUILD)
	$(Q) $(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@
	@ echo "AR	$@"

$(BUILDDIR)%.o: %.c
	$(Q) $(COMPILE.c) $(OUTPUT_OPTION) $< 
	@ echo "CC	$(patsubst $(BUILDDIR)%,%,$@)"
	
clean:
	rm -f $(OUTLIB) $(BUILDDIR)*.o


