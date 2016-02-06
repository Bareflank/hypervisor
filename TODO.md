Misc:
- create a custom PPA for Travic CI that contains our cross-compiler. Needs to
  support more than one version of GCC, and should install GCC in it's own
  directory to prevent the native GCC from being removed
- We need to go through all of the error codes, and map out blocks for each
  module, driver, elf error, etc... This way, when an error bubbles through
  the system, it's easy to identify
- Add support for weak / strong symbols in the ELF loader as this could get us
  in trouble at some point.
- Destructors for statically created classes are not being called. This should
  be resolved at some point.
- Add support for clang/LLVM

Version 1.0 TODO:
- Need to be able to start / stop a basic VM
- Need to have all of the VMCS checks implemented and unit tested
- Need to have all of the remaining unit tests completed (i.e. all of the
  VMM modules need their unit tests completed including serial)
- remove the "valid" flag in the elf loader as it it meaning less and each
  function should be able to live on it's own.
- redo the elf_loader unit test to use hippo mocks. Doing so will allow us to
  mock up a function's dependencis, allowing us to test each function's tasks
  better
- cleanup the elf_loader as it has newlines for function calls in the header,
  which was abandoned.
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

Version 2.0 TODO:
- Type 1 and Type 2 support
- Multiple guest support running http://www.includeos.org/

Documenttion:
- Problem with reusing CR3 from IOCTL
- Red-zone
- Statics using the stack and the crash we saw with the memory manager
- The build system could use a document that explains how it works and the
  various different features that it has
- ctors / dtors
