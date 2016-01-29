# Defer rules to makefile in the parent directory

all: libpharos.a

objects = $(wildcard *.cpp)

libpharos.a: ../Makefile
	make -C .. libpharos/$@ 

%.o: %.cpp
	make -C .. libpharos/$@

clean:
	rm -f *.o libpharos.a
