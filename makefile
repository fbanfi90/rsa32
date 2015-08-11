CC = g++
CFLAGS = -std=c++11 -O2

all: RSA

RSA: main.o RSA.o
	$(CC) main.o RSA.o $(CFLAGS) -o rsa

main.o: main.cpp
	$(CC) -c main.cpp $(CFLAGS)

RSA.o: RSA.cpp
	$(CC) -c RSA.cpp $(CFLAGS)

clean:
	rm -rf *o rsa
