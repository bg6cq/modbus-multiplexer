all: modbus-multiplexer

modbus-multiplexer: modbus-multiplexer.c
	gcc -o modbus-multiplexer -Wall -g modbus-multiplexer.c -lpthread


indent: modbus-multiplexer.c
	indent modbus-multiplexer.c -nbad -bap \
		-nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4  \
                -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l100 -lp -npcs -nprs -npsl -sai \
                -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1

