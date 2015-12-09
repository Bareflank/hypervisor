# Bareflank Hypervisor

## Description

The Bareflank Hypervisor aims to provide a platform for performing hypervisor
research. Some highlights include:

- Reduced legacy support (e.g. requires 64bit, no support for BIOS, etc...)
- Written in C++
- Cross Platform
- Developed using Test Driven Development
- Few external dependencies
- LGPL v2.1

In addition to simplified architecture, the Bareflank hypervisor has been
licensed under the LGPL v2.1. The entire Bareflank hypervisor is a collection
of cross-compiled libraries. Users of the Bareflank hypervisor are welcome
to replace any or all of the open source libraries with proprietary versions,
enabling the development of internal hypervisor based research, while
sharing the core portions of the hypervisor that don't usually change (for
example, starting and stopping an Intel VT-x based hypervisor is the same
whether it's KVM, Xen, VMWare, VIrtualBox or Bareflank).

In return we ask that users contribute back to the project to enhance
and maintain the open source portions of the hypervisor, such that all users
can benefit.

## Compilation Instructions

Before you can compile, you must have a native GCC installer, as well as a
GCC cross-compiler. For instructions on how to setup a GCC cross-compiler,
please see the following:

[Cross Compilers](https://github.com/Bareflank/hypervisor/tree/master/doc/cross_compilers)

If you are running on one of the supported platforms, setting up the cross
compiler is as simple as:

```
./tools/scripts/<platform>-cross-compiler.sh
```

Once you have your cross compiler setup based on the script, or instructions,
you should be able to run the following

```
make
make unittest
```

To run the hypervisor, you need to first compile, and load one of the driver
entry points. Bareflank uses the driver entry point to gain kernel level
access to the system to load the hypervisor. To see the instructions for
how to load the hypervisor, please read the following:

[Driver Entry Documentation](https://github.com/Bareflank/hypervisor/tree/master/driver_entry/src/arch)

To clean up the source directory, run:

```
make clean
```

## Contributing

If you would like to participate in the development of this project, the
following Wiki page provides more information on how to do so:

https://github.com/Bareflank/hypervisor/wiki/Contributing

## License

The Bareflank Hypervisor is licensed under the GNU Lesser General Public License
v2.1 (LGPL).
