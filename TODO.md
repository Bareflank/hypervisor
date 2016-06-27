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
- Add Windows support
- Create custom libc. This first step should be to provide equvilant
  functionality to newlib. Once this is done, the next step should be to break
  apart libc++.so into libc.so, libcxxabi.so (statically linked with the
  unwinder), and libc++.so.
- ELF loader has some C++ comments in it. Make sure in general that C/C++
  comments are done properly.
- Clean up the VMCS checks so that they can be unit tested better, and then
  complete the unit tests
- All structs used in C++ only should have constructors
- Uses the following as our default flags to match Clear Linux: -g2 -O3 -pipe
  -fexceptions -fstack-protector -m64 -march=westmere -mtune=native
  -malign-data=abi
- Once we have our own custom C, we should print a backtrace in the unwind
  logic when an exception is throw so that we can see what lead up to the
  exception. This is really important as std::exceptions do not have
  contextual information about where the exception occured.

Version 1.2 TODO:
- Move to JSON. Once we need to be able to start a guest, we have a lot of
  information that needs to be parsed (image, ram, number vcpus). We can
  then move the module_file to json as well.
- UEFI Support (i.e. type 1)
- Multiple guest support running http://www.includeos.org/ or some other
  unikernel. Note that the actual guest support will likely be in a different
  repo, but Bareflank itself will need some changes to support this (for
  example, some organizational changes to the vcpu to run a guest).
- Hyperkernel support
- Provide a means to extend BFM and the drivers
- When we add hyperkernel support, the vcpuid will take on a different form
  than it has today. Specifically, we will need to standardize how we plan
  to decompose the vcpuid. For example, maybe 16bits go to the guest, 16bits
  go to the vcpu, and 16bits go to the physical cpu. Once this is done,
  code in the driver will need to strip out the physical cpu part so that
  it knows what core to be talking to
- For the hyperkernel, we will need to map out the different use cases,
  and figure out how we want to add, start and stop a guest. There are some
  issues here. For example, in a type 2 situation, there is no hypervisor to
  vmcall too so that code cannot be a vmcall. In a type 1 where the host OS
  is UEFI and Windows / Linux has been booted, we don't have a driver
  that can talk to the hypervisor like a type 2 (maybe we can register a
  UEFI runtime service?)

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
