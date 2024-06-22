LLVM_BUILD_DIR=/opt/llvm-project/llvm-build
CC=$(LLVM_BUILD_DIR)/bin/my-clang
CXX=$(LLVM_BUILD_DIR)/bin/my-clang++
export LLVM_COMPILER=clang
export LLVM_COMPILER_PATH=/opt/llvm-project/llvm-build/bin
CFLAGS=place -O0 -g
CXXFLAGS=place -O0 -g
LDFLAGS=place -O0 -g

all: test1 test2


test1 : test1.o
#       $(CC) $(LDFLAGS) test1.o -o test1

test2 : test2.o

%.o : %.c
		$(CC) -c $(CFLAGS) $< -o $@


clean:
		rm -f *.o
