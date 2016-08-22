Misc:
- Add support for clang/LLVM
- Add support for Intel's MPX. This doesn't look like a huge amount of work, but
  would require a custom libmpx designed for the kernel in a cross platform
  fashion. Might not be possible until the new libc is developed with basic
  pthread mutex support.
- Add system beep code for additional debugging
- Add support for the PCI debugger
- Add support for https://coveralls.io
- Re-write the common.c code such that, the ELF loader is not compiled in
  the driver itself, but instead, the ELF loader is compiled as a flat
  binary and executed, which then starts the VMM. This will evenutally provide
  a better starting point for a dynamic root-of-trust in the future if so
  desired.
- Speed up linking time by adding -fvisibility=hidden. It was stated that
  this could effect C++ so we need to find an exmaple of what to do, if
  anything (might be taken care of by libc++). Also... will need to add
  visibility macros if we enable this option, and should disable the GCC
  flags for BFM and windows for export all.

Version 1.2 TODO:
- Clean up the VMCS checks so that they can be unit tested better, and then
  complete the unit tests
- Add a make install / uninstall and provide a Windows installer for the 
  drivers.
- Create custom libc. This first step should be to provide equvilant
  functionality to newlib. Once this is done, the next step should be to break
  apart libc++.so into libc.so, libcxxabi.so (statically linked with the
  unwinder), and libc++.so.
- Destructors for statically created classes are not being called. This should
  be resolved at some point. Likely this problem will go away once we have a
  custom libc, as atexit registers the destructor, but is never executed since
  we cannot use _exit() at the moment.
- UEFI Support (i.e. type 1)
- Multiple guest support running http://www.includeos.org/ or some other
  unikernel. Note that the actual guest support will likely be in a different
  repo, but Bareflank itself will need some changes to support this (for
  example, some organizational changes to the vcpu to run a guest).
- Hyperkernel support
- Fully unittest C++ inside the VMM to verify which portions of C++ we plan
  to support actually work. 
