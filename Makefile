CC = gcc
CFLAGS = -Wall -Wextra -g -O2
LDFLAGS = -lpthread
TARGET = modbus-multiplexer
SRC = modbus-multiplexer.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

debug: CFLAGS += -DDEBUG -g3
debug: $(TARGET)

clean:
	rm -f $(TARGET)

indent: $(SRC)
	indent $(SRC) -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4 \
		-cli0 -d0 -di1 -nfc1 -i8 -ip0 -l100 -lp -npcs -nprs -npsl -sai \
		-saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1

.PHONY: all clean debug indent
