CC = gcc
CFLAGS = -Wall -g
LIBS = -lpcap

OBJS = main.o interface.o sniffer.o parser.o storage.o 
TARGET = cshark

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJS) $(TARGET)
