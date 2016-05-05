
<img src="https://raw.githubusercontent.com/Bareflank/hypervisor/master/doc/images/logo-black.png" width="501">

## Description

The Bareflank Hypervisor is an open source, lightweight hypervisor, lead by
Assured Information Security, Inc. that provides the scaffolding needed to
rapidly prototype new hypervisors. To ease development, Bareflank
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
- Bare Metal Hypervisors (also known as type 1, like [Xen](http://www.xenproject.org))
- Late Launch Hypervisors (also known as type 2, like [VirtualBox](https://www.virtualbox.org))
- Host-Only Hypervisors (no guests, like [MoRE](https://github.com/ainfosec/MoRE))

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

## Motivation

Most people think that hypervisors are meant to virtualize servers and
provide a means to run Windows on a Mac, but there is a whole field
of research were hypervisors are used without guest virtual
machines. Since a hypervisor is capable of controlling the host OS
running underneath it, (so called "ring -1"), hypervisors have been
used for introspection, reverse engineering, anti-virus, containerization,
diversity, and even architectural research like the
[MoRE](https://github.com/ainfosec/MoRE) hypervisor. All of these use
cases start the same way, by spending months standing up the hypervisor
itself before you can start working on your actual project. Existing open
source hypervisors are so focused on supporting virtual machines and
burdened with legacy support that they are painful to work with when
conducting less traditional hypervisor research.

Bareflank's goal is to provide the scaffolding needed to create any type of
hypervisor. To support this, Bareflank leverages C++ not only to provide
a clear method for extending the hypervisor via inheritance, but also to
provide access to the C++ STL to reduce the time it takes to prototype and
implement new technologies. For example, suppose your writing an
introspection hypervisor that needs to store the different system calls that
are being made in a hash table for fast lookups. Doing this in an existing C
based hypervisor might require you to create your own hash table implementation.
This same implementation is trivial with the STL's existing data structures.
With Bareflank's design, you can focus on the goal of your project, and less
on implementing the foundation needed to support your project.

Bareflank will always maintain the "bare minimum" needed to stand up a
hypervisor. Future repositories/projects will be created that extend
the hypervisor to add additional API support for common research tasks (e.g.
VT-x APIs, LibVMI APIs, and even guest support APIs). Long term, it is our
hope that others will leverage Bareflank to create hypervisors
capable of competing with existing type 1 and type 2 open source hypervisors,
but Bareflank itself will remain focused on the bare minimum scaffolding.

## Website

[Bareflank Hypervisor Website](http://bareflank.github.io/hypervisor/)

## Demo

Checkout the latest demo for how to compile, use and extend the
Bareflank Hypervisor

[![Bareflank Demonstration Video](http://img.youtube.com/vi/YgQdECPzDkQ/0.jpg)](https://www.youtube.com/watch?v=YgQdECPzDkQ)

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

## Roadmap (updated 4-27-2016)

### Version 1.0

Released: April 27, 2016 <br>
[[link](https://github.com/Bareflank/hypervisor/releases/tag/v1.0.0)]

* ~~ELF Loader~~
* ~~Userspace Managment Application (bfm)~~
* ~~Unwinder~~
* ~~Initial C++ Environment~~
* ~~Linux Driver Entry~~
* ~~Basic VMM~~
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
* Basic Guest Support
* BFM / Driver Extension Support

### Version 1.3

Target: June 2017

* 64bit ARM Support
* Intel Nested Virtualization Support

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
