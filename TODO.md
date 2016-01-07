- create a custom PPA for Travic CI that contains our cross-compiler. Needs to
  support more than one version of GCC, and should install GCC in it's own
  directory to prevent the native GCC from being removed
- redo the elf_loader unit test to use hippo mocks. Doing so will allow us to
  mock up a function's dependencis, allowing us to test each function's tasks
  better
- cleanup the elf_loader as it has newlines for function call in the header,
  which was abandoned.
- should provide the ability to have both a static target, and a shared target
  for the native compiler and the cross compiler so that tests like the BFM
  can be statically linked if needed (i.e. to support overriding C functions)
- We need to go through all of the error codes, and map out blocks for each
  module, driver, elf error, etc... This way, when an error bubbles through
  the system, it's easy to identify

Version 1.0 TODO:
- BFM needs the ability to load / unload the VMM as well as start / stop the
  VMM
- Need to be able to start / stop a basic VM
- Need to have all of the VMCS checks implemented and unit tested
- Need to have all of the remaining unit tests completed (i.e. all of the
  VMM modules need their unit tests completed including serial)
- Turn on all warnings, and error no warnings to verify that the code is clean
  and ready to go
- All of the "C" interfaces should use the int64_t/uint64_t types instead of
  long lon int / unsigned long long int.

Version 1.1 TODO:
- Need to have a completely isolated exit handler. It should have it's own
  CR3, IDT, and GDT.
- Need MultiCore support
- Need a simple means for subclassing, at a minimum, the VMCS and exit handler.
  Ideally, the entire VCPU class should be able to be subclassed so that it
  can be customized.
- Need to rename the VCPU logic as it's really specific to Intel.
- Add Windows support

