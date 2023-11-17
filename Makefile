OPT = -Wall

espnow2tcp: main.o protocol.o raw_socket.o
	gcc $(OPT) -o $@ $^

%.o: %.c
	gcc -c $(OPT) -o $@ $<

clean:
	rm -f *.o espnow2tcp
