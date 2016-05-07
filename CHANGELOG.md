# Change Log

## [Unreleased]
### Added
- New GDT class that provides a cleaner abstraction of the GDT
- New IDT class that provides a cleaner abstraction of the IDT
- New VMCS state classes that organize the creation of the VMM's state, as
  well as the Host VM's state. Future versions will also add a Guest VM
  state as well
- New state save logic for the exit handler to support multi-core. The state
  save area is placed in "GS" allowing the exit handler to access CPU specific
  state logic in a reentrant, thread-safe manner without the need for lookups
  or APIC logic.
- Added TSS structure to intrinsics code. This structure is used by the
  custom GDT for the VMM, but is not actually used.
- The VMM now uses it's own GDT instead of the GDT provided by the Host OS.
- The VMM now uses it's own IDT instead of the IDT provided by the Host OS.
- The VMM now uses it's own CR0 instead of the CR0 provided by the Host OS.
- The VMM now uses it's own CR4 instead of the CR4 provided by the Host OS.
- The VMM now uses it's own RFLAGS instead of the RFLAGS provided by the Host OS.
- The VMM now uses it's own EFER MSR instead of the EFER MSR provided by the Host OS.

### Changed
- The VMCS state classes are now shared by pointer (i.e. shared_ptr)
  instead of my reference. This was done to support inheritance.

### Fixed
- If a VM-entry failured occured, the exit handler would incorrectly read
  the error as unknown because it was not filtering the VM-entry failure
  bit
- Some of the macros in the intrinsics file were causing unsigned intergers
  because they hit touched bit 31. The macros have been expanded to 64bits
  to prevent this

### Removed
- The old GDT logic that was in the intrinsics_x64 has been removed. Please
  use the new GDT class as it has the same functionality, but more.
- The old IDT logic that was in the intrinsics_x64 has been removed. Please
  use the new IDT class as it has the same functionality, but more.
- The old vmcs_intel_x64_state class has been removed in favor of inheritance
  to better support different state types (VMM, Host VM and Guest VM). Please
  use the subclasses instead, or inherit manually
- The vCPU dispatch, halt and promote functions have been removed as they
  were specific to Intel.

## [1.0.0] - 2016-27-04
### Added
- Linux support
- Single core support (core 0)
- Custom C runtime library for constructor / destructor support and registering
  exception handlers
- Custom driver entry logic for loading the VMM
- Custom ELF loader for loading the VMM modules
- Userspace managament application (BFM) for starting / stopping the
  hypervisor
- Custom kernel-safe unwind library for adding exception support to the VMM
- Basic VMM with support for Intel x86_64. The VMM places the Host OS into
  a virtual machine and back out. Currently can be extended to provide
  additional functionality
- Custom build environment
- Complete set of unit tests
- Documentation
- Scripts for setting up Unbuntu, Debian and Fedora build environments.
