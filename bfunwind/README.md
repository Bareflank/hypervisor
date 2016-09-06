# Unwind Library

## Description

The unwind library is used by C++ to provide exception support. When an exception is thrown in C++, an exception object is created (the object that will be thrown; which is usually something that inherits std::exception), and the stack is unwound until a catch(xxx) statement is found that matches the exception object that was thrown, or the end of the stack is reached in which case std::terminate is called (which in our case results in a call to abort). The code that "unwinds" the stack is the unwind library. On Linux, there are several unwind libraries that can be used with GCC and Clang/LLVM. The three main unwind libraries are libgcc (provided by the GCC compiler), libunwind, and (given the same name) Apple's libunwind that is now part of the LLVM project.

[libgcc](https://github.com/gcc-mirror/gcc/tree/master/libgcc) <br>
[libunwind (Savannah)](http://www.nongnu.org/libunwind/) <br>
[libunwind (Apple)](https://github.com/llvm-mirror/libunwind) <br>

All of these unwind libraries are tightly coupled to user space, and in some cases even require pthread support to work. For this reason, Bareflank provides it's own unwind library capable of being executed in the kernel, with thread-safety, but with no external dependencies (i.e. not even libc is needed).

## How It is Used

When the "throw" keyword is used in C++, the compiler actually replaces this with a call to \_\_cxa_allocate, and \_\_cxa_throw. The allocate function allocates the exception object, and the throw performs the stack unwinding. These functions are provided by the C++ ABI. In GCC this would normally be libsupc++. Bareflank currently uses libc++, and thus uses libc++abi instead of libsupc++. The C++ ABI handles most of the C++ specifics, but eventually makes a call to \_\_Unwind\_RaiseException which is a IA64 C++ ABI specific function call (with it's own specification) that must be provided by an "unwind" library.

[call to \_\_Unwind\_RaiseException](https://github.com/llvm-mirror/libcxxabi/blob/master/src/cxa_exception.cpp#L195)

This library is very specific to the architecture as it usually has to have some raw assembly to perform the "jump" into the function that contains the catch statement (as the registers have to be restored). Currently, Bareflank has support for x86_64, but will eventually have support for ARM 64bit as well.

Since "throw" statements in C++ code generate \_\_cxa_xxx function calls, there is no needed to link the unwind library to every single module as they contain symbols for \_\_cxa_xxx and not \_\_Unwind\_RaiseException. Instead, the unwind library needs to be linked to the libc++abi, and the libc++abi needs to be available at load time. Currently, libc++abi is statically linked to libc++.so, which is loaded by the driver / ELF loader with the rest of the VMM. In future version of Bareflank, libc.so, libc++.so and libc++abi.so will all be loaded by the driver / ELF loader separately and the unwind library will be statically linked to libc++abi.so only.

The code in the unwind library is organized by the spec that each file implements (since there are multiple specs to get unwinding to work). Generally speaking, when an exception is thrown, the \_\_Unwind\_RaiseException function is called which is located here:

[ia64_cxx_abi](https://github.com/Bareflank/hypervisor/blob/master/bfunwind/src/ia64_cxx_abi.cpp)

The \_\_Unwind\_RaiseException function saves the register state, and then uses the program counter (i.e. rip for Intel x86_64), and looks up the FDE assocaited with the PC. The FDEs are stored in the ".eh_frame" section in each ELF module. The following code is used to get the FDE:

[eh_frame](https://github.com/Bareflank/hypervisor/blob/master/bfunwind/src/eh_frame.cpp)

Once the FDE is located, this code parses the FDE and then uses the DWARF 4 code to decode the stack instructions which unwind the stack for the stack frame the FDE describes. The DWARF code is located here:

[dwarf4](https://github.com/Bareflank/hypervisor/blob/master/bfunwind/src/dwarf4.cpp)

The stack is unwound using the DWARF code, and control is handed back to the ia64_cxx_abi which calls a personality function located in the ".text" section in each ELF module which tells the ia64_cxx_abi code if it should continue to unwind, or stop. This process continues until the code is told to stop, in which case the CPU state is updated to reflect the unwound state. For more information and detail on this process, read each header file as it contains a lot more specifics.

## Limitations

Currently the unwind library only has support for x86_64, and has only been tested on Intel (although it's unlikely changes are needed to support AMD64).

## Notes

During the development of this code, one bug was found that is worth mentioning here. In the System V spec, the register order is rax, _rdx_, rcx, rbx, etc..., not rax, _rbx_, rcx, rdx. When you read the code, you will see this reflected in the source, and it is by design, as this is how the spec is written, if you change the order of these reigsters to reflect the Intel Manual, the code will not work properly.
