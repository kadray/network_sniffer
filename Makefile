# Compiler and flags
CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpcap -lncurses -lpthread

# Files
SRCS = sniffer.c
OBJS = $(SRCS:.c=.o)
TARGET = sniffer

# Default target
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build files
clean:
	rm -f $(OBJS) $(TARGET)
