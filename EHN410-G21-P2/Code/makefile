main: main.o CipherModes.o AES.o
	gcc -static main.o CipherModes.o AES.o -o main

main.o: main.c CipherModes.h AES.h
	gcc -c main.c

CipherModes.o: CipherModes.c CipherModes.h
	gcc -c CipherModes.c

AES.o: AES.c AES.h
	gcc -c AES.c

run:
	./main

clean:
	rm -f main CipherModes.o AES.o main.o