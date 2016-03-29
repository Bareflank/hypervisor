
# Unwind Library

## Description

The unwind library is used by C++ to provide exception support. When an exception is thrown in C++, an exception object is created (the object that will be thrown; which is usually something that inherits std::exception), and the stack is unwound until a catch(xxx) statement is found that matches the exception object that was thrown, or the end of the stack is reached in which case std::terminate is called (which in our case results in a call to abort). The code that "unwinds" the stack is the unwind library. On Linux, there are several unwind libraries that can be used with GCC and Clang/LLVM. The three main unwind libraries are libgcc (provided by the GCC compiler), libunwind, and (given the same name) Apple's libunwind that is now part of the LLVM project. All of these unwind libraries are tightly coupled to user space, and in some cases even require pthread support to work. For this reason, Bareflank provides it's own unwind library capable of being executed in the kernel, with thread-safety, but with no external dependencies (i.e. not even libc is needed). 

## How It is Used

When the "throw" keyword is used in C++, the compiler actually replaces this with a call to \_\_cxa_allocate, and \_\_cxa_throw. The allocate function allocates the exception object, and the throw performs the stack unwinding. These functions are provided by the C++ ABI. In GCC this would normally be libsupc++. Bareflank currently uses libc++, and thus uses libc++abi instead of libsupc++. The C++ ABI handles most of the C++ specifics, but eventually makes a call to \_\_UnwindRaiseException which is a IA64 C++ ABI specific function call (with it's own specification) that must be provided by an "unwind" library. This library is very specific to the architecture as it usually has to have some raw assembly to perform the "jump" into the function that contains the catch statement (as the registers have to be restored). Currently, Bareflank has support for x86_64, but will eventually have support for ARM 64bit as well. 

Since "throw" statements in C++ code generate \_\_cxa_xxx function calls, there is no needed to link the unwind library to every single module as they contain symbols for \_\_cxa_xxx and not \_\_UnwindRaiseException. Instead, the unwind library needs to be linked to the libc++abi, and the libc++abi needs to be available at load time. Currently, libc++abi is statically linked to libc++.so, which is loaded by the driver / ELF loader with the rest of the VMM. In future version of Bareflank, libc.so, libc++.so and libc++abi.so will all be loaded by the driver / ELF loader separately and the unwind library will be statically linked to libc++abi.so only. 

## Limitations

Currently the unwind library only has support for x86_64, and has only been tested on Intel (although it's unlikely changes are needed to support AMD64). The unwind library also does not have support for DWARF expressions. Currently expression support has not been needed, but if GCC generates code that does in fact use DWARF expressions, a thrown exception would fail in the unwinder with a call to abort if it's available. Like the rest of Bareflank, the unwinder assumes that if allocations fail, the system will be halted (i.e. there is no support for gracefully failing an out-of-memory error). 

## Notes

Since Bareflank makes heavy use of C++ exceptions for handling error conditions, "state" must be handled appropriately. Like other error handling schemes, if an error occurs in the middle of committing state (i.e. writing to member variables, writing to a database, etc...), state changes must be rolled back to provide an all or nothing commit. In C based kernel logic, it's typical to see a lot of "goto" statements to unroll changes that must be cleaned up if an error occurs. In C++, RAII is used instead (if that term is new to you, google it as it's an important C++ pattern). To provide automatic rollback logic in the presence of exceptions, a "commit_or_rollback" class is provided in /include. 

The commit_or_rollback code allows you to create a class that will execute a function intended to rollback an operation if that class is not "committed" prior to it's destruction. A good example of how this works is in the VMXON code:

<link to VMXON code>

When the VMXON code creates the VMXON region, state has been created. Just prior to creating this region, a commit_or_rollback  (COR) class is created, with a rollback lambda function that releases the region. The last thing the function does it commit the COR. If an error occurs (such as an exception is thrown), the commit function will never be executed, thus when the COR is destroyed, it will execute the rollback function, automatically releasing the VMXON region. These commit_or_rollback function classes will be seen through out the code to ensure that state is handled properly in the event of an error, and can be used by a user of Bareflank to provided similar state guarantees. 
