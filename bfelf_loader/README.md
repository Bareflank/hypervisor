# ELF Loader

## Description

When source code is compiled, the compiler must compile the source into a format the OS knows how to load (unless a "flat" binary is being constructed which is outside the scope of this document). On Windows or UEFI the format that is used is PE/COFF, while on Linux, the format is ELF.

[ELF64 spec](https://uclibc.org/docs/elf-64-gen.pdf)

The entire VMM is a set of shared libraries (also called dynamically linked libraries in Windows), that are compiled to the ELF format using GCC or Clang/LLVM. In fact, the VMM has no "binary" executable like a typical application; everything is a shared library. To load and execute the VMM modules, Bareflank provides a custom ELF loader that can be used in the kernel (currently Linux is supported, but Windows and UEFI support is coming).

## How It is Used

Although the bulk of the VMM is actually executed in the context of the host OS's kernel (i.e. the Linux kernel, or UEFI, etc...), the only kernel specific code exists in the /bfdrivers folder which contains Bareflank's driver entry points.

[driver entries](https://github.com/Bareflank/hypervisor/tree/master/bfdrivers/src)

Each driver provided by Bareflank provides just enough code to execute Bareflank's custom ELF loader to load and execute the VMM. Once the VMM is bootstrapped and executed, everything else is done within the VMM, and should be considered an isolated environment. This architecture provides code reuse, while also providing a cross-platform method for writing a hypervisor that can be executed in different host OS kernels (which share pretty much nothing in common).

The ELF format provides a ton of information that can be used to better understand what the compiled code should be doing, how to load the code, etc... In the case of Bareflank, the ELF loader needs to be able to load each VMM module into memory, relocate each module (position independent code is heavily used by Bareflank), and then execute it. To better understand how the ELF loader API works, please see the following:

[test_bfelf_loader_resolve_symbol_real_test](https://github.com/Bareflank/hypervisor/blob/master/bfelf_loader/test/test_loader_resolve_symbol.cpp#L463)

How the ELF loader is actually used can be seen in the common.c code for the driver entry points:

[common.c](https://github.com/Bareflank/hypervisor/blob/master/bfdrivers/src/common.c)

A summarized explanation of how the VMM is loaded / started is as follows:
- Create an bfelf_file_t for each module that must be loaded and initialize it.
- Allocate memory for each program segment defined by ELF in the module (ELF tells you how much memory to allocate, and what permissions the memory needs; there is likely at least a segment for read/execute, and a segment for read/write for each module).
- Add the initialized ELF file to a bfelf_loader_t.
- Once all ELF files have been added to a loader, relocate. This step processes each symbol in the ELF file's Global Offset Table (GOT) and makes sure that each symbol is relocated in memory, and has a valid address
- Execute the local_init from the C runtime (see /bfcrt code provided by Bareflank)
- Execute init_vmm()
- Execute start_vmm()

When the VMM needs to be stopped / unloaded this process is simply reversed.

The ELF loader is used in other places within Bareflank as well. For example, the ELF loader is used in the unwind library's unit test to get access to the unit test's own ".eh_frame" section, which contains information needed to perform stack unwinding.

[unwind unit test](https://github.com/Bareflank/hypervisor/blob/master/bfunwind/test/test.cpp)

Like other Bareflank libraries, the ELF loader doesn't have any external dependencies making it easy to integrate into any kernel but is also capable of being used anywhere ELF is needed.

## Limitations

The ELF loader is currently specific to x86_64 for Intel, but will later be extended to support ARM 64bit (a task that might be as simple as relaxing some sanity checks). The loader is currently designed for loading the VMM, but will later be extended if needed to support loading applications into a "VM".

## Notes

The ELF loader has been extensively tested, and was one of the original pieces of code that was developed on this project. In general it can take a lot of abuse, but will crash if you provide an uninitialized structure to it's APIs. For example, attempting to provide the loader with an ELF file that has not had it's init function called, and has not been zero'd will result in a crash. The same applies to attempting to use a loader without first zeroing it's memory. In general, if you create a structure that is used by the ELF loader, you should run memset on that struct (minus the ELF file itself which is zero'd by it's init function).

When working with ELF files, if a problem occurs, learning how to use GCC's readelf command can save you a lot of time (same goes for objdump if things really get out of control). Some typical problems occur when:
- A symbol is missing (ooppsss)
- Duplicate symbols exist, something this ELF loader will not warn you about as duplicate symbols are leveraged so handle with care
- A symbol is mangled differently than you might have anticipated (don't forget that C++ mangles symbol names while C does not, so you might be missing an export "C" call, or your symbol has a different signature than your expecting).
- Each module has it's own GOT, so in most cases you will be working with your local GOT reference, and not the one from a different module, so symbol overwriting (as used by Hippomocks) can be tricky

Finally, it should be noted that there was one code modification made to the ELF loader to support C++ exceptions. When an exception is thrown, libc++abi.so must use std::type_info to figure out if a catch block should actually catch the exception, or tell the unwinder to continue unwinding. In GCC and Clang/LLVM this is done using a pointer comparison (whereas a string compare could and is used on Windows). The pointer comparison is a lot faster, but has the issue that each module will likely have it's own pointer for each symbol (even if the symbol is the same), thus preventing pointer comparisons from working. To overcome this issue, the IA64 C++ ABI specification, in a small, paragraph, left all by itself to never be heard from again, states that symbols defined as weak should always be given the same address, even across modules. So, C++ exception logic relies on this, and marks all std::type_info symbols as weak. It is then assumed the ELF loader will make sure that all weak symbols have the same pointer across all modules. To support this the Bareflank ELF loader always processes the modules in the same order, and once a symbol is marked weak, a global search is always performed. If the symbol is left marked weak throughout the search, the first address found is used. If a strong reference is found, the search stops, and that address is used instead. This provides the ability to still use the weak / strong relationship, but also provide the same address for all weak references if they occur.
