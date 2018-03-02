# Bareflank Hypervisor 1.0 Roadmap

## Summary

Version 1.0 of the Bareflank hypervisor will provide the project with basic, type 2 support for launching an Intel based VT-x hypervisor. Although the hypervisor will only be capable of launching the hypervisor, and continue execution of the host operating system, this first version will lay the ground work for future versions. 

## Goals

* Provide basic type 2 hypervisor with support for Windows and Linux. 
* Hypervisor compiled as a separate, cross-compiled ELF binary
* Support for dynamically loading modules within the hypervisor
* Basic debugging facilities
* Basic VT-x exit handler
* No outside dependencies
* Hypervisor written in C++
* Initial support for Intel’s x86_64. 

## Compilation

Although support for clang / LLVM would be preferred, version 1.0 will be compiled using a GCC cross-compiler to simplify the build process. 

* The hypervisor and all of it’s modules will be compiled using the ELF file format 
* Since the hypervisor only supports 64bit, x86_64-elf will be used as the cross-compile target. 
* Host OS support libraries (like the ELF loader) will be written in C, and will contain as few dependencies as possible, providing optimal cross-platform support
* The hypervisor will be written in C++, and thus, the compilation environment will need to support C and C++ 

## Bootstrap Process

Unlike previous type 2 hypervisors, the Bareflank hypervisor will be cross-compiled as a separate ELF formatted binary. For this reason, the driver entry points for each host operating system will only contain the bare minimum needed to read the hypervisor from disk, load it into memory (using an ELF loader), and then begin execution of the hypervisor itself. The bulk of the driver entry points (including he ELF loader) will be written as cross-platform C code, which will be shared to reduce the overall differences between each host specific driver. 

<figure><img src="https://raw.githubusercontent.com/Bareflank/hypervisor/master/doc/roadmap/v1.0/type2_init.png" alt=“type2_init”></figure>

Since the hypervisor will be cross-compiled, it would be possible to compile the hypervisor on Windows, and use it on a Linux based host operating system. Once the hypervisor is loaded, it will perform the bootstrapping of the hypervisor itself which will include:

* Compatibility checks
* Enabling VT-x
* Initializing the host operating system’s VMCS
* Launching the hypervisor

## ELF vs PE/COFF

Extensible Firmware Interface (EFI) uses the Portable Executable (PE, or PE/COFF) format to structure it’s binary executables. Since future versions of this hypervisor will require a PE/COFF loader, initially, PE/COFF was considered as the file format of choice to simplify the amount of work that would be required. Instead, however, ELF was chosen as the binary format. 

ELF has a couple of advantages over PE/COFF:

* Since ELF is the primary file format for Linux, most of the open source toolchains today support ELF. Few support PE/COFF
* Most EFI implementations do not support loading PE/COFF modules. Therefore, a second stage bootloader will be needed for the hypervisor to boot. If this is needed, an existing ELF loader can be used as this second stage boot loader
* Documentation on PE/COFF is limited, while documentation on ELF is more available.  

## Host OS Components

The goal is to keep the host operating system driver entry points as minimal as possible. Furthermore, the code used by the driver entry points will be shared to the greatest extent possible, minimizing the amount of code that must be written specifically for a given operating system. 

The host operating system components specifically be limited to:
* Platform support functions (e.g. memory allocation, file loading, etc…). 
* ELF loader
* Driver scaffolding

It should be noted that since the hypervisor will be executing in it’s own environment, it will not have access to the host operating system’s debugging environment (i.e. debugging printing). All of the components of the driver entry points that can be tested from user space will be. 

## Hypervisor Components

The hypervisor will be cross-compiled as a self-contained, ELF formatted binary. It will consist of:

* Debugging facilities
* VT-x facilities (including VMCS loading)
* Exit handler

The entire hypervisor will be written as a set of modules that will be loaded by the host operating system during initialization. Each library will be provided via the LGPL v2.1 license, providing a means for users of the project to replace specific components of the hypervisor with proprietary alternatives. 

Each module will be written in C++, and unit tested via user-space support applications to the greatest extent possible, providing a means to enable test driven development. Since the hypervisor will be written as a set of modules, mock modules can be provided that simulate various inputs to validate that each module gracefully handles error cases. For example, all of the VT-x functions can reside in their own module, while logic that uses the VT-x functions (e.g. the VMCS facilities) can use this module to perform it’s tasks. During unit testing, a mock VT-x module can be used instead providing a means to simulate error conditions, as well as test from user space. 

The exit handler for the hypervisor will only contain the bare minimum to resume execution back to the host operating system. Future version of the Bareflank hypervisor will provide more advanced exit handlers. 

### Position Independent Code (PIC)  
  
Since the hypervisor only supports x86_64, it will be compiled using “-fPIC” which causes the compiler to produce position independent code (PIC). This has a couple of advantages:

* Loading the hypervisor in a lot of ways is easier because it can be loaded anywhere in the host operating system’s memory space. 
* There is no need for complicated linker scripts to locate the hypervisor in memory
* Future versions of the hypervisor can support ASLR from within the hypervisor itself.   

The main disadvantage is the ELF loader will be more complicated as it needs to populate the global offset table in each module, vs. statically linked binaries can simply be placed in memory and executed. 

## Tasks

The following defines the high level tasks that this project would prefer to see in version 1.0. These tasks are in no particular order (i.e. they may be completed in any order), and some of these tasks may be pushed to future released if needed. 

### Required Tasks for Version 1.0

* ~~Makefile build environment~~ (Rian Quinn)
* ~~Linux cross-compiler script~~ (Brendan Kerrigan)
* ~~Unit test framework~~ (Rian Quinn)
* ~~ELF loader~~ (Rian Quinn)
* ~~Linux driver entry point~~ (Rian Quinn)
* Serial debugging facilities (Brendan Kerrigan)
* PCI debugging facilities (Brendan Kerrigan)
* VMCS facilities (Rian Quinn)
* Linux VMCS initialization (Rian Quinn)
* Exit handler (Rian Quinn)
* ELF loader documentation (Rian Quinn)
* Driver entry point documentation (Rian Quinn)
* Linux cross-compiler documentation (Brendan Kerrigan)  
* Serial debugging documentation (Brendan Kerrigan)
* PCI debugging documentation (Brendan Kerrigan)
* VMCS documentation (Rian Quinn)
* Linux Usage documentation (Rian Quinn)
* Linux compilation documentation (Rian Quinn)
* Linux installation documentation (Rian Quinn)
* API documentation (Rian Quinn / Brendan Kerrigan)

### Stretch Goals

* OS X cross-compiler script (Rian Quinn)
* Windows cross-compiler script (Brendan Kerrigan)
* ELF PLT lazy loader (Brendan Kerrigan)
* Window driver entry point (Brendan Kerrigan)
* OS X driver entry point (Rian Quinn)
* Windows VMCS initialization (Brendan Kerrigan)
* OS X VMCS initialization (Rian Quinn)
* CPUID emulation (Brendan Kerrigan)
* ELF PLT loader documentation (Brendan Kerrigan)
* OS X cross-compiler documentation (Rian Quinn)
* Windows cross-compiler documentation (Brendan Kerrigan)
* Windows Usage documentation (Brendan Kerrigan)
* OS X Usage documentation (Rian Quinn)
* Windows compilation documentation (Brendan Kerrigan)
* OS X compilation documentation (Rian Quinn)
* Windows installation documentation (Brendan Kerrigan)
* OS X installation documentation (Rian Quinn)

## Schedule

High Level Milestones
* Development: October 2015 - December 2015
* Feature Freeze: Mid December 2015
* Final Release: January 2015

Finer Grained Milestones
* Milestone (2 November 2015): ELF Loader Complete
* Milestone (16 November 2015): Driver Entry Point Complete 
* Milestone (7 December 2015): VMCS Complete
* Milestone (14 December 2015): Exit Handler Complete
* Milestone (1 January 2015): Documentation Complete
