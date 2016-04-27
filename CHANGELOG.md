# Change Log

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
