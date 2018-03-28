CC=gcc
vpath %.c src
vpath %.h include

OBJS=main.o analyze.o utilitys.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g -Wall -I include
LDLIBS=-lpcap
TARGET=main
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

.PHONY: clean remove run
clean:
	@rm *.o
remove:
	@rm main

run:
	@./main in.pcap
