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

