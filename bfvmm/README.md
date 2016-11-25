# Virtual Machine Monitor (VMM)

## Description

The VMM is the part of the hypervisor that monitors each virtual machine. The term "hypervisor" can mean a lot of things. Generally speaking, it should refer to the piece of code that maintains control of the supervisor, but instead generally refers to everything within a hypervisor's project including the drivers and userspace code (e.g. the Xen hypervisor is made up of everything from the actual hypervisor itself, but also its hypercall libraries, libXL, etc...). Thus, the Bareflank hypervisor describes the entire project, while the VMM is the piece of code that oversees the management of each virtual machine, and the "exit handler" is the actual piece of code that maintains control over the supervisor. The exit handler is contained within the VMM, and the VMM is contained within the hypervisor.

## How It Is Used

The VMM itself is made up of a set of shared libraries, is loaded into memory by the driver entry point, and is executed from different points of view. When starting / stopping, the VMM is executed in ring 0 along side the host OS kernel. When a VM exit occurs, the VMM is executed with so called "ring -1" privileges in the form of the exit handler, and is responsible for emulating the offending instruction.

Since the VMM is relatively isolated it must provide its own execution environment. This includes support for memory management (i.e. malloc / free), debugging, and STL support via libc++.so.

The bootstrapping process starts with the driver entry loading all of the VMM modules into memory and relocating each symbol. From there, the driver entry calls local_init to execute all of the global constructors (e.g. std::cout is initialized here). Once all of the global constructors are executed, the driver entry calls into the VMM's memory manager to add memory descriptors to the memory manager. These descriptors tell the VMM what the virtual -> physical memory mappings are, that the VMM will later use to configure itself and its associated VMs. Serial is initialized the first time it's executed as it's defined as a static "singleton-ish" class. Finally, the driver entry will execute start_vmm found in the "entry" module.

The entry module guards the host OS kernel from the VMM by doing two things: catching all exceptions that bubble up to the entry functions, and provide a custom stack. Most of the errors in the VMM are designed to be caught by the entry code. If an error should occur, gsl::final_act classes are added to the code to automatically rollback changes to the VMM, and the exception will eventually be picked up by the top level catch all provided by the entry module. This code will tell the developer what the error was, and then hand control back to the host OS indicating that an error occurred. In addition, a custom stack is provided as some host OSes provide very small stacks (e.g. Linux).

The entry code then calls into the vCPU manager which in turn sets up each vCPU. A lot of the VMM code is designed to work with both Intel and ARM. The vCPU however is designed to be architecture specific, and this is where ARM support will be added later on in the future. Currently the only vCPU that's provided is the Intel x64 vCPU, which has its intrinsics class (raw assembly functions), its VMXON class, VMCS class and Exit Handler class. The rest of the process is right out of the Intel Software Developers Manual. VMXON is started and initialized, then the VMCS. Once the VMM is started, and a VM exit occurs, execution is handed to the exit handler to be emulated.

## Limitations

Currently the VMM is Intel specific. It's designed specifically to be able to be extended with ARM support in the future. Once this process begins, it's likely some things will have to change to support this added functionality, so keep an eye on the project as changes to the interfaces might occur if needed to support other architectures.

The VMM has its own memory pool which is static. Future versions will likely work to make the management of this memory pool easier but it's likely to remain a statically compiled resource for the foreseeable future. If you end up with an std::bad_alloc error, you will need to modify the amount of memory that is provided to the VMM in the constants.h file.

We do not support anything in libc/libc++ that relies on floating point functions. Furthermore, some STL functionality makes no sense in the kernel, like std::fstream, which we obviously do not support. Our goal is to use the STL to ease development of things that the kernel would normally use, not to provide generic support for the STL. The use of the STL in the kernel is already pretty controversial, lets not push it.

## Notes

Since the VMM is compiled using System V compilers (i.e. GCC or Clang/LLVM), a System V specific issue must be addressed. The System V spec states that leaf functions do not need to move the stack pointer, providing an optimization (called the red zone) that actually has a pretty dramatic improvement on performance (since each leaf function can avoid at least 2 instructions per call). The problem is, in kernel code this optimization does not work as interrupts use the existing stack pointer as their execution stack, which results in a corrupt stack if an interrupt fires while a leaf function is executing (a bug that was not fun to track down). Great care must be taken to ensure that all code that will execute in the VMM is compiled using the -mno-red-zone. For more information, please see the following:

[red zone](http://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64/)

Currently the VMM does not link against libgcc. Most articles on osdev.org would tell you that not linking against libgcc is a big "no-no". In our case, it's fine. Libgcc mainly provides 64bit instruction support on 32bit systems, as well as the C++ unwinder. Bareflank does not support 32bit systems, and it provides its own C++ unwinder, thus has no reason to add support for libgcc. If libgcc is needed in the future, a patch would have to be made to GCC to tell it to compile libgcc without red zone support (a patch this project does not want to maintain if it can be avoided). If support is needed in the future, it will manifest itself as a missing symbol while trying to load the VMM.

