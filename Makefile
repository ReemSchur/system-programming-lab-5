all: loader

loader: loader.o startup.o start.o linking_script
	ld -m elf_i386 -o loader \
		loader.o startup.o start.o \
		-L/usr/lib32 -lc \
		-T linking_script \
		-dynamic-linker /lib32/ld-linux.so.2

loader.o: loader.c
	gcc -m32 -Wall -Wextra -g -c loader.c -o loader.o

startup.o: startup.s
	nasm -f elf32 startup.s -o startup.o

start.o: start.s
	nasm -f elf32 start.s -o start.o

clean:
	rm -f loader.o startup.o start.o loader
