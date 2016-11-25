# C Runtime Library

## Description

Modern compilers provide C runtime libraries designed to aid the compiler in
performing certain tasks (for GCC, this is the crtstuff.c in libgcc).
Three different functions that most of these libraries perform:
- Global Construction (executing functions defined in the ".ctors" and ".init_array" section)
- Global Destruction (executing functions defined in the ".dtors" and ".fini_array" section)
- Register Exception Framework Section (".eh_frame" section)

Although it is possible for the ELF loader to do these tasks for an executable,
from a security / containment perspective, it's better for the executable
itself to perform these tasks in its own isolated environment. Bareflank,
like everything else, needs to perform these same tasks, and thus performs
them in the context of the VMM, but can also use this code within a VM if
needed. For Bareflank, all of the C++ objects that are globally defined, have
constructors / destructors that need to be executed from a global perspective.
Each ".eh_frame" section in the ELF binary also needs to be registered with
the unwinder code to provide exception support.

## How It's Used

Each cross compiled shared library is compiled using the bareflank-gcc-wrapper.

[bareflank-gcc-wrapper](https://raw.githubusercontent.com/Bareflank/hypervisor/master/tools/scripts/bareflank-gcc-wrapper)

If you look at a GCC compiler (and even Clang/LLVM), both compilation
and linking is done with GCC. When linking is required, GCC calls LD (the
linker) on your behalf, and adds ctrbegin.o and crtend.o to your
executable (which it gets from crtstuff.c). These additional object files
provide the above described functionality. There are 4 different ELF sections
that need to be executed here:
- ctors
- dtors
- init_array
- fini_array

These sections are all the same; a list of void (*func)(void)
function pointers. When each module is loaded, the CTORS/init_array functions
all need to be executed, while during destruction, DTORS/fini_array functions
need to be executed. Finally, each ELF module has a ".eh_frame" section (even
for C code sometimes), that contains stack unwinding information that is
needed by the unwinder. The ELF loader gathers the location and size
of each of these sections, which in turn is used by the CRT library to
setup/teardown a module:

[ELF loader](https://github.com/Bareflank/hypervisor/blob/master/bfelf_loader/src/bfelf_loader.c#L1039)

To make all of this work, Bareflank's wrapper script acts like
GCC and Clang. When "-c" is provided, the code is compiled, and when
no "-c" is provided, the code is linked.

The Bareflank drivers (also referred to as the driver entry points, located in
the bfdrivers folder), are responsible for loading each cross compiled module
from the bfvmm folder into memory using the ELF loader. Once everything is
loaded / relocated, the driver then locates the local_init function and executes 
it for each shared librariy.

[common.c](https://raw.githubusercontent.com/Bareflank/hypervisor/master/bfdrivers/src/common.c)

This causes the global constructors to get executed, and registers the
".eh_frame" for the module (to support exception handling). When the driver
is "unloading" the VMM, the local_fini function is in turn executed, calling
global destructors.
