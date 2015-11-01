# Bareflank Hypervisor

## Description

The Bareflank Hypervisor aims to provide a platform for performing hypervisor research. Some highlights include:

- Zero legacy support (e.g. requires 64bit)
- Written in C++
- Cross Platform
- Few external dependencies

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

If you placed the cross-compiler into a different directory, simply do the
following (replace the path with yours);

```
export CROSS_CC=~/opt/cross/bin/x86_64-elf-gcc
export CROSS_CXX=~/opt/cross/bin/x86_64-elf-g++
export CROSS_LD=~/opt/cross/bin/x86_64-elf-ld
make -e
make -e clean
```

## Contributing

If you would like to participate in the development of this project, the
following Wiki page provides more information on how to do so:

https://github.com/Bareflank/hypervisor/wiki/Contributing

## License

The Bareflank Hypervisor is licensed under the GNU Lesser General Public License
v2.1 (LGPL).
