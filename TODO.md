Misc:
- create a custom PPA for Travic CI that contains our cross-compiler. Needs to
  support more than one version of GCC, and should install GCC in it's own
  directory to prevent the native GCC from being removed
- We need to go through all of the error codes, and map out blocks for each
  module, driver, elf error, etc... This way, when an error bubbles through
  the system, it's easy to identify
- Destructors for statically created classes are not being called. This should
  be resolved at some point. Likely this problem will go away once we have a 
  custom libc, as atexit registers the destructor, but is never executed since
  we cannot use _exit() at the moment. 
- Add support for clang/LLVM
- Add DWARF4 expression support in the unwinder (this could go away if 
  Clang/LLVM doesn't need it either). 
- Add support for Intel's MPX. This doesn't look like a huge amount of work, but 
  would require a custom libmpx designed for the kernel in a cross platform 
  fashion. Might not be possible until the new libc is developed with basic 
  pthread mutex support. 
- Modify the common.c code in the driver entry to handle memory protections 
  properly. Specifically, we want to make sure that we are respecting the 
  read/execute and read/write memory protections that are labeled by the 
  ELF program loader. This isn't useful until we break apart libc++.so such
  that it's not marked r/w/x (likely to be solved with the new libc)
- We use our own stack, and the memory for this stack comes from .bss, as it 
  allocated using make_unique. We need to ensure that this memory is marked 
  read/write and not read/execute (likely it is, but we should verify).

Version 1.0 TODO:
- Add exception support to debug ring
- Add exception support to exit handler
- Add exception support to memory manager
- Add exception support to vcpu
- Add exception support to vmcs
- Add exception support to vmm
- Need to have all of the VMCS checks implemented and unit tested
- Need to have all of the remaining unit tests completed (i.e. all of the
  VMM modules need their unit tests completed including serial)
- Everything should be using the new debug.h instead of manually calling
  std::cout
- Provide support for Debian, Fedora, CentOS

Version 1.1 TODO:
- Need to have a completely isolated exit handler. It should have it's own
  CR3, IDT, and GDT.
- Need MultiCore support
- Need a simple means for subclassing, at a minimum, the VMCS and exit handler.
  Ideally, the entire VCPU class should be able to be subclassed so that it
  can be customized.
- Need to rename the VCPU logic as it's really specific to Intel.
- Add Windows support
- Once we have our own GDT/IDT, part of the "promote" process needs to restore
  the GDT/IDT which is not being done. The segment registers are swapped, but
  we are not doing a sgdt or sidt to swap these.
- CS, SS and TR need to be restored properly when promoting. This will be
  really important once a new GDT is used in the host.
- Provide APIs within the VMCS for setting / clearing traps to MSRs and IO
- Create custom libc. This first step should be to provide equvilant 
  functionality to newlib. Once this is done, the next step should be to break
  apart libc++.so into libc.so, libcxxabi.so (statically linked with the 
  unwinder), and libc++.so. 

Version 2.0 TODO:
- Type 1 and Type 2 support
- Multiple guest support running http://www.includeos.org/

Documenttion:
- Update cross compiler documentation to include how to setup sysroot
- Problem with reusing CR3 from IOCTL
- Red-zone: http://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64/
- Statics using the stack and the crash we saw with the memory manager
- The build system could use a document that explains how it works and the
  various different features that it has
- ctors / dtors
