
<img src="https://raw.githubusercontent.com/Bareflank/hypervisor/master/doc/images/logo-black.png" width="501">

## Description

The Bareflank Hypervisor is an open source, lightweight hypervisor, lead by
Assured Information Security, Inc. that provides the scaffolding needed to
rapidly prototype hypervisor technologies. To ease development, Bareflank
is written in C++, and includes support for exceptions and the C++ Standard
Template Library (STL) via libc++. With the C++ STL, users can leverage
shared pointers, complex data structures (e.g. hash tables, maps, lists,
etc…), and several other modern C++ features. Existing open source
hypervisors that are written in C are difficult to modify, and spend a
considerable amount of time re-writing similar functionality instead of
focusing on what matters most: hypervisor technologies. Furthermore, users
can leverage inheritance to extend every part of the hypervisor to provide
additional functionality above and beyond what is already provided.

To this end, Bareflank's primary goal is to remain simple, and
minimalistic, providing only the scaffolding needed
to construct more complete/complicated hypervisors including:
- Type 1 Hypervisors (like Xen)
- Type 2 Hypervisors (like VirtualBox)
- Host-Only Hypervisors (commonly used by anti-virus and rootkits)

The core business logic will remain in the hypervisors that extend
Bareflank, and not in Bareflank itself.

To support Bareflank's design approach, the entire project is licensed
under the GNU Lesser General Public License v2.1 (LGPL), specifically
enabling users of the project to both contribute back to the project, but
also create proprietary extensions if so desired.

In addition to Bareflank’s lightweight, modular design, the entire
hypervisor has been written using test driven development. As such, all
of Bareflank’s code comes complete with a set of unit tests to validate
that the provided code works as expected.

![](https://travis-ci.org/Bareflank/hypervisor.svg?branch=master)

## Demo

Checkout the latest demo for how to compile, use and extend the
Bareflank Hypervisor

[![Bareflank Demonstration Video](http://img.youtube.com/vi/adesFxQ741c/0.jpg)](https://www.youtube.com/watch?v=adesFxQ741c)

## Compilation Instructions

Before you can compile, you must have both a native GCC compiler, as well as a
GCC cross-compiler. If you are running on one of the supported platforms,
setting up the cross compiler is as simple as:

```
./tools/scripts/setup-<platform>.sh
```

The setup-\<platform\>.sh script not only creates the cross compiler, but
it also sets up the libc and libc++ environment, creating a sysroot that will
be used by the Bareflank Hypervisor. Once you have your cross compiler setup
based on the script, you should be able to run the following:

```
make
make unittest
```

To run the hypervisor, you need to first compile, and load one of the driver
entry points. Bareflank uses the driver entry point to gain kernel level
access to the system to load the hypervisor. On Linux, this is as simple as:

```
make linux_load
make load
make start
```

to reverse this:

```
make stop
make unload
make linux_unload
```

to get status information, use the following:

```
make status
make dump
```

For more detailed instructions please read the following (based on which OS your using):

[Driver Entry Documentation](https://github.com/Bareflank/hypervisor/tree/master/bfdrivers/src/arch)

## Example Extensions

To provide examples of how you might extend Bareflank to provide your own custom
functionality, we have provided a couple of examples:

[Enable VPID](https://github.com/Bareflank/hypervisor_example_vpid) <br>
[CPUID Count](https://github.com/Bareflank/hypervisor_example_cpuidcount)

## Roadmap (updated 3-19-2016)

### Version 1.0

Target: April 2016

* ~~ELF Loader~~
* ~~Userspace Managment Application (bfm)~~
* ~~Unwinder~~
* ~~Initial C++ Environment~~
* ~~Linux Driver Entry~~
* Basic VMM
* ~~Testing (Ubuntu, Debian, Fedora, CentOS)~~

### Version 1.1

Target: September 2016

* Multi-Core Support
* Windows Support
* Updated C++ Environment
* Isolated VMM

### Version 1.2

Target: Janurary 2017

* UEFI Support (i.e. type 1)

## Contributing

We are always looking for feedback, feature requests, bug reports, and
help with writing the code itself. If you would like to participate in 
this project, the following Wiki page provides more information on how 
to do so:

https://github.com/Bareflank/hypervisor/wiki/Contributing

## License

The Bareflank Hypervisor is licensed under the GNU Lesser General Public License
v2.1 (LGPL).

## Related

If your interested in Bareflank, you might also be interested in the following
hypervisor projects:

**MoRE:** <br>
https://github.com/ainfosec/MoRE

**SimpleVisor:**  <br>
https://github.com/ionescu007/SimpleVisor
