# Edit the two following variables to define the path to the directories containing the JNI headers and libjvm.so.

# Define the directories containing the JNI header files jni.h and jni_md.h.
JNI_HEADERS_DIRS := /usr/lib/jvm/java-6-sun/include /usr/lib/jvm/java-6-sun/include/linux

# Define the directory containing libjvm.so.
LIBJVM_SO_DIR := /usr/lib/jvm/java-6-sun/jre/lib/amd64/server

# Set the maximum heap space size (-Xmx) for the invoked JVM in MiB
#MAXHEAP := 512

# Set CFLAGS
#CFLAGS := -Os


# Editing below should be not necessery
MAXHEAP ?= 512
CFLAGS ?= -g -Wall
IFLAGS :=
IFLAGS += $(foreach dir, $(JNI_HEADERS_DIRS), -I$(dir))
LDFLAGS :=
LDFLAGS += -L$(LIBJVM_SO_DIR) -Wl,-rpath $(LIBJVM_SO_DIR)

CFLAGS += -DMAXHEAP='"$(MAXHEAP)"'
CFLAGS += $(IFLAGS)
LDFLAGS += -lnids -ljvm

all: pcap2sql

pcap2sql: main.o
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f main.o pcap2sql

.PHONY: all clean test
