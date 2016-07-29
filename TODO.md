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

Version 1.1 TODO:
- Add Windows support
- Trigger a rebuild if bfcrt changes
- The vcpuid needs to be figured out. Since we need to be able to move VMCS
  structures from core to core to handle rescheduling a task on a different
  CPU, there is probably no need to make this complicated. Just need to make
  sure that the vcpuid is a uint64 everywhere.
- The IOCTLs for Windows are too permissive
- The IOCTLs for Windows do not share the same #'s as Linux

Version 1.2 TODO:
- Clean up the VMCS checks so that they can be unit tested better, and then
  complete the unit tests
- Create custom libc. This first step should be to provide equvilant
  functionality to newlib. Once this is done, the next step should be to break
  apart libc++.so into libc.so, libcxxabi.so (statically linked with the
  unwinder), and libc++.so.
- Destructors for statically created classes are not being called. This should
  be resolved at some point. Likely this problem will go away once we have a
  custom libc, as atexit registers the destructor, but is never executed since
  we cannot use _exit() at the moment.
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
- Missing ctrl checks for entry / exit

Version 1.3 TODO:
- We should consider running a static analysis tool on the code to identify
  issues with the source before moving onto a 2.0. Basically, once we have
  support for all of the platforms we wish to target, and the C++ environment
  is relatively stable, we should take some time to cleanup any issues
  with reliability and security before moving onto more features.

Version 2.0 TODO:
- If possible we should implement C++ GSL. Just depends on whether or not
  the GSL is available as well as a checking tool by then.
