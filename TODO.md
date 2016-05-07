
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
  ELF program loader.
- Add system beep code for additional debugging
- Add support for the PCI debugger
- Trigger a rebuild if bfcrt changes
- Trigger a rebuild of libcxx is bfunwind changes
- Some scripts use "-" while others use "_", we should be consistent

Version 1.1 TODO:
- Need to have a completely isolated exit handler. It should have it's own
  CR3, IDT, and GDT.
- Need MultiCore support
- Add Windows support
- Once we have our own GDT/IDT, part of the "promote" process needs to restore
  the GDT/IDT which is not being done. The segment registers are swapped, but
  we are not doing a sgdt or sidt to swap these.
- CS, SS and TR need to be restored properly when promoting. This will be
  really important once a new GDT is used in the host.
- Create custom libc. This first step should be to provide equvilant
  functionality to newlib. Once this is done, the next step should be to break
  apart libc++.so into libc.so, libcxxabi.so (statically linked with the
  unwinder), and libc++.so.
- ELF loader has some C++ comments in it. Make sure in general that C/C++
  comments are done properly.
- Clean up the VMCS checks so that they can be unit tested better, and then
  complete the unit tests
- All structs used in C++ only should have constructors
- the debug.h code should use std::cerr were needed
- per-core debugging should be done
- #define for line endings for bfendl
- Uses the following as our default flags to match Clear Linux: -g2 -O3 -pipe
  -fexceptions -fstack-protector -m64 -march=westmere -mtune=native
  -malign-data=abi
- Fix issue with dwarf4.cpp. The encoding / decoding logic has been updated
  to fix issue with the -1 << shift, which we should also be fixing.

Version 1.2 TODO:
- UEFI Support (i.e. type 1)
- Multiple guest support running http://www.includeos.org/ or some other
  unikernel. Note that the actual guest support will likely be in a different
  repo, but Bareflank itself will need some changes to support this (for
  example, some organizational changes to the vcpu to run a guest).
- Hyperkernel support
- Provide a means to extend BFM and the drivers

Known Issues:
- Kernels that have CONFIG_DEBUG_STACKOVERFLOW enabled will kernel oops when
  do_IRQ is called because Bareflank uses it's own stack, and this triggers
  the oops as stack_overflow_check thinks the stack has been overrun. The
  oops can be safely ignored, but the best solution at the moment is to
  disable this check from executing or don't use a kernrel with this enabled.
  This is seen on Fedora as installing the kernel source enables a debug kernel
  by default with this enabled.
