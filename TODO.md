
Misc:
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
- Need MultiCore support
- Add Windows support
- Create custom libc. This first step should be to provide equvilant
  functionality to newlib. Once this is done, the next step should be to break
  apart libc++.so into libc.so, libcxxabi.so (statically linked with the
  unwinder), and libc++.so.
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
- Once we have our own custom C, we should print a backtrace in the unwind
  logic when an exception is throw so that we can see what lead up to the
  exception. This is really important as std::exceptions do not have
  contextual information about where the exception occured.

Version 1.2 TODO:
- UEFI Support (i.e. type 1)
- Multiple guest support running http://www.includeos.org/ or some other
  unikernel. Note that the actual guest support will likely be in a different
  repo, but Bareflank itself will need some changes to support this (for
  example, some organizational changes to the vcpu to run a guest).
- Hyperkernel support
- Provide a means to extend BFM and the drivers

Version 1.3 TODO:
- We should consider running a static analysis tool on the code to identify
  issues with the source before moving onto a 2.0. Basically, once we have
  support for all of the platforms we wish to target, and the C++ environment
  is relatively stable, we should take some time to cleanup any issues
  with reliability and security before moving onto more features.

Version 2.0 TODO:
- If possible we should implement C++ GSL. Just depends on whether or not
  the GSL is available as well as a checking tool by then.

Known Issues:
- Kernels that have CONFIG_DEBUG_STACKOVERFLOW enabled will kernel oops when
  do_IRQ is called because Bareflank uses it's own stack, and this triggers
  the oops as stack_overflow_check thinks the stack has been overrun. The
  oops can be safely ignored, but the best solution at the moment is to
  disable this check from executing or don't use a kernrel with this enabled.
  This is seen on Fedora as installing the kernel source enables a debug kernel
  by default with this enabled.
