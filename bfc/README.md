# C Library
## Present
Bareflank uses [newlib](https://sourceware.org/newlib/) for it's libc implementation. Currently Bareflank provides it's own implementations of:
- malloc (and friends)
- init / fini
- pthreads
- syscall functions

The VMM's memory manger provides support for malloc and friends and can be found [here](https://github.com/Bareflank/hypervisor/blob/master/bfvmm/src/memory_manager/src/memory_manager_x64.cpp). Malloc provided by newlib assumes newlib is in userspace, and thus has the ability to extend the size of the memory pool via paging. Since Bareflank executes both from within the Host OS kernel, and ring -1, we don't have the ability to easily extend the virtual memory space used by the memory manager, and thus we provide our own static memory allocation. The init / fini functions that newlib provides assumes linker scripts are used to located each of the ctor/dtor sections. It also doesn't provide registration functions for exception support. Therefore, Bareflank provides it's own init/fini functions [here](https://github.com/Bareflank/hypervisor/tree/master/bfcrt). Currently we use our own pthread library, but in future versions we hope to leverage the existing implementation found in newlib. Most of the syscalls that newlib depends on, plus the pthread library can be found [here](https://github.com/Bareflank/libbfc). In future versions we plan to remove this repo and place the code that remains in this folder so that the code is tracked with the main repo. 

## Future

Today newlib is provided as a support library for libcxx. All of libc is available for use if you prefer libc functions over libcxx versions however. In the future, Bareflank extensions will provide guest support, and libc will also be needed to provide generic application support. When this occurs, Bareflank's modifications of libc will be generalized to support both the hypervisor, but also guest virtual machines provided by other repos / extensions. 
