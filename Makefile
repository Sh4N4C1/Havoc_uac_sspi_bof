BOFNAME := sspi_uac
COMINCLUDE := -I ./include
LIBINCLUDE := -lsecur32
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
CC=x86_64-w64-mingw32-clang

all:
	$(CC_x64) -o ./bin/$(BOFNAME).x64.o $(COMINCLUDE) -Os -c ./src/Uac.c -DBOF
