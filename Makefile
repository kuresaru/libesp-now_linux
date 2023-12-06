INC = -Iinc
OPT = $(INC) -Wall

all: libesp-now_linux.so

libesp-now_linux.so: src/protocol.o src/raw_socket.o
	gcc -shared -fPIC $(OPT) -o $@ $^

%.o: %.c
	gcc -c $(OPT) -o $@ $<

clean:
	rm -f src/*.o libesp-now_linux.so
