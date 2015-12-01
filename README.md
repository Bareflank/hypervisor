# Bareflank Hypervisor

## Description

The Bareflank Hypervisor aims to provide a platform for performing hypervisor
research. Some highlights include:

- Reduced legacy support (e.g. requires 64bit, no support for BIOS, etc...)
- Written in C++
- Cross Platform
- Few external dependencies

In addition to simplied archiecture, the Bareflank hypervisor has been
licensed under the v2.1 LGPL. The entire Bareflank hypervisor is a collection
of cross-compiled libraries. Users of the Bareflank hypervisor are welcome
to repalce any or all of the open source libraries with proprietary versions,
enabling the development of internal hypevisor based research, while
sharing the core portions of the hypervisor that don't usually change (for
example, starting and stopping an Intel VT-x based hypervisor is the same
whether it's KVM, Xen, VMWare, VIrtualBox or Bareflank).

In return we ask that users contribute back to the project to enhance
and maitain the open source portions of the hypervisor, such that all users
can benefit.

## Compilation Instructions

Before you can compile, you must have a native GCC installer, as well as a
GCC cross-compiler. For instructions on how to setup a GCC cross-compiler,
please see the following:

https://github.com/Bareflank/hypervisor/tree/master/doc/cross_compilers

These instructions setup a cross-compiler for this project in
~/opt/cross/bin/x86_64-elf-XXX. Assuming you followed these instructions,
you should be able to run:

```
make
make clean
```

## Contributing

If you would like to participate in the development of this project, the
following Wiki page provides more information on how to do so:

https://github.com/Bareflank/hypervisor/wiki/Contributing

## License

The Bareflank Hypervisor is licensed under the GNU Lesser General Public License
v2.1 (LGPL).
