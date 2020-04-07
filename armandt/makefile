main: main.o armandt.o michelle.o
	gcc -static main.o armandt.o michelle.o -o main

main.o: main.c armandt.h michelle.h
	gcc -c main.c

armandt.o: armandt.c armandt.h
	gcc -c armandt.c

michelle.o: michelle.c michelle.h
	gcc -c michelle.c

run:
	./main

clean:
	rm -f main armandt.o michelle.o main.o