CC=gcc

OBJS=main.o utilitys.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g -Wall
LDLIBS=-lpcap
TARGET=main
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

.PHONY: clean remove
clean:
	@rm *.o
remove:
	@rm main
