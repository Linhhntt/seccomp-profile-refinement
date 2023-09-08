# Clang+LLVM INSTALLATION ON A LOCAL MACHINE

## 1. Goals
- This document describes some issues that may happen when we install LLVM compiler.
- Using LLVM we can generate bitcodes of applications with multiple specific versions.

## 2. How to install Clang+LLVM
- The original ways to install LLVM-7 please refer to this [document](https://github.com/shamedgh/temporal-specialization/blob/master/INSTALL.md#2-llvm-passes)

## 3. Problems
- Before doing build inside LLVM, we need to export some dependences as gcc, g++
```
    $ whereis g++
    $ export g++=/usr/bin/g++
    $ whereis gcc 
    $ export gcc=/usr/bin/gcc
```
- In the original guide, the command line:
```
cmake -G "Unix Makefiles" -DLLVM_BINUTILS_INCDIR=/path/to/binutils/include -DLLVM_TARGETS_TO_BUILD="X86" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../install ../
```
Following this command, LLVM and clang will be installed under -DCMAKE_INSTALL_PREFIX, we should change `../install` by `/usr/local/` so that system can understand.

- For the `make -j<number_of_cores> && make install` command, we have to use the root permission.

- After run all commands, we should check whether LLVM+Clang are installed successfully or not by log files. Especially, in the `cmake` step 
