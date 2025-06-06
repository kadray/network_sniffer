CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpcap -lncurses -lpthread

TARGET = packet_viewer
SRC = main.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)
