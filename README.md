
# Bareflank Hypervisor

![](https://travis-ci.org/Bareflank/hypervisor.svg?branch=master)

## Description

The bareflank hypervisor is an open source, lightweight hypervisor, lead by
Assured Information Security, Inc. designed specifically to enable hypervisor
based research. To support any style of research, bareflank comes complete with:
- a generic virtual machine monitor (VMM),
- a user mode application to manage the hypervisor.
- a set of driver entries to launch the VMM from various host operating systems
  (e.g. Linux, Windows, UEFI)

In addition, the entire bareflank project is licensed under the
GNU Lesser General Public License v2.1 (LGPL), providing a means for users of
the project to both contribute back to the project, but also create proprietary
extensions if so desired.

To ease the development of the VMM, bareflank has partial support for C++,
including Exception support and the C++ Standard Template Library (STL) 
via libc++. With the C++ STL, users can quickly prototype new technologies as
bareflank has access to shared pointers, complex data structures
(e.g. hash tables, maps, lists, etc…), and several other modern C++ features.
Most of these features are “header only”, meaning only the parts of the STL
that are used are included, providing a convenient means to keep the VMM as
small as possible. Existing open source hypervisors that are written in C
spend a considerable amount of time re-writing similar functionality instead of
focusing on what matters most: hypervisor technologies.

Since the goal of the project is to provide a lightweight hypervisor for
research, the VMM only provides the bare minimum support to launch a VMM.
As bareflank is written in C++, users can leverage
inheritance to extend every part of the hypervisor to provide additional
functionality above and beyond what is already provided.

In addition to bareflank’s lightweight, modular design, the entire hypervisor
has been written using test driven development. As such, all of bareflank’s
code comes complete with a set of unit tests to validate that the provided
code works as expected.

## Demo

Checkout the latest demo for how to compile, use and extend the 
bareflank hypervisor

[![Bareflank Demonstration Video](http://img.youtube.com/vi/adesFxQ741c/0.jpg)](https://www.youtube.com/watch?v=adesFxQ741c)

## Compilation Instructions

Before you can compile, you must have both a native GCC compiler, as well as a
GCC cross-compiler. If you are running on one of the supported platforms 
(Ubuntu 12.04, 14.04, 15.04, 15.10, Debian Jessie, Fedora 22, 23), 
setting up the cross compiler is as simple as:

```
./tools/scripts/setup-<platform>.sh
```

The setup-\<platform\>.sh script not only creates the cross compiler, but
it also sets up the libc and libc++ environment, creating a sysroot that will
be used by the bareflank hypervisor. Once you have your cross compiler setup
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
make quick
```

and to reverse this:

```
make linux_unload
```

and to get status information, use the following:

```
make status
make dump
```

For more detailed instructions please read the following (based on which OS your using):

[Driver Entry Documentation](https://github.com/Bareflank/hypervisor/tree/master/driver_entry/src/arch)

## Example Extensions

To provide examples of how you might extend bareflank to provide your own custom
functionality, we have provided a couple of examples:

[CPUID Count](https://github.com/Bareflank/hypervisor_example_cpuidcount) <br>
[Enable VPID](https://github.com/Bareflank/hypervisor_example_vpid)

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

Note: The first version only supports Linux in a type 2 configuration. The
hypervisor itself doesn't do much other than hoist Linux into a virtual
machine and continue execution. 

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

If you would like to participate in the development of this project, the
following Wiki page provides more information on how to do so:

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
