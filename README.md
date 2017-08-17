![Bareflank](https://raw.githubusercontent.com/Bareflank/hypervisor/master/doc/images/bareflank_logo.jpg)
<br>
<br>
<br>
[![GitHub version](https://badge.fury.io/gh/bareflank%2Fhypervisor.svg)](https://badge.fury.io/gh/bareflank%2Fhypervisor)
[![Build Status](https://travis-ci.org/Bareflank/hypervisor.svg?branch=master)](https://travis-ci.org/Bareflank/hypervisor)
[![Build status](https://ci.appveyor.com/api/projects/status/r82c37nc634tnsv9/branch/master?svg=true)](https://ci.appveyor.com/project/rianquinn/hypervisor-13oyg/branch/master)
[![Coverage Status](https://coveralls.io/repos/github/Bareflank/hypervisor/badge.svg?branch=master)](https://coveralls.io/github/Bareflank/hypervisor?branch=master)
<a href="https://scan.coverity.com/projects/bareflank-hypervisor">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/9857/badge.svg"/>
</a>
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/325/badge)](https://bestpractices.coreinfrastructure.org/projects/325)
[![Join the chat at https://gitter.im/Bareflank-hypervisor/Lobby](https://badges.gitter.im/Bareflank-hypervisor/Lobby.svg)](https://gitter.im/Bareflank-hypervisor/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

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
- Host-Only Hypervisors (no guests, like [MoRE](https://github.com/ainfosec/MoRE), [SimpleVisor](https://github.com/ionescu007/SimpleVisor) and [HyperPlatform](https://github.com/tandasat/HyperPlatform))

The core business logic will remain in the hypervisors that extend
Bareflank, and not in Bareflank itself.

To support Bareflank's design approach, the entire project is licensed
under the GNU Lesser General Public License v2.1 (LGPL), specifically
enabling users of the project to both contribute back to the project, but
also create proprietary extensions if so desired.

In addition to Bareflank’s lightweight, modular design, the entire
hypervisor has been written using test driven development. As such, all
of Bareflank’s code comes complete with a set of unit tests to validate
that the provided code works as expected. These tests are validated using
[Coveralls](https://coveralls.io/github/Bareflank/hypervisor), and
[Travis CI](https://travis-ci.org/Bareflank/hypervisor) has been setup to
test styling via
[Astyle](http://astyle.sourceforge.net), and static / dynamic analysis
via [Coverity](https://scan.coverity.com/projects/bareflank-hypervisor),
[Clang Tidy](http://clang.llvm.org/extra/clang-tidy/), and [Google's
Sanitizers](https://github.com/google/sanitizers). In addition, we adhere
to the
[CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/325),
and the
[C++ Core Guidelines](https://github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md)
including support for the [Guideline Support Library](https://github.com/Microsoft/GSL).

Currently we have support for the following 64bit host operating systems on
Intel _SandyBridge_ and above hardware:
- Ubuntu 16.10, 17.04
- Windows 10
- Windows 8.1

Although not officially supported, Bareflank has also been tested with the
following Linux distributions:
- Debian
- Fedora
- OpenSUSE
- Arch Linux

In the future, we would also like to support:
- macOS
- BSD
- UEFI
- ARM (64bit)

## Motivation

Most people think that hypervisors are meant to virtualize servers and
provide a means to run Windows on a Mac, but there is a whole field
of research where hypervisors are used without guest virtual
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
implement new technologies. For example, suppose you’re writing an
introspection hypervisor that needs to store the different system calls that
are being made in a data structure for fast lookups. Doing this in an existing C
based hypervisor might require you to create your own data structure.
This same implementation is trivial with the STL's existing data structures.
With Bareflank's design, you can focus on the goal of your project, and less
on implementing the foundation needed to support your project.

Bareflank will always maintain the "bare minimum" needed to stand up a
hypervisor. Additional repositories like the
[Extended APIs](https://github.com/Bareflank/extended_apis) repo and the
[Hyperkernel](https://github.com/Bareflank/hyperkernel) repo have been created
that extend the hypervisor to add additional API support for common research tasks (e.g.
VT-x / VT-d APIs and guest support APIs). Long term, it is our
hope that others will leverage Bareflank to create hypervisors
capable of competing with existing type 1 and type 2 open source hypervisors,
but Bareflank itself will remain focused on the bare minimum scaffolding.

## Links

[Bareflank Hypervisor Website](http://bareflank.github.io/hypervisor/) <br>
[Bareflank Hypervisor API Documentation](http://bareflank.github.io/hypervisor/html/)

## Demo

Checkout the latest demo for how to compile, use and extend the
Bareflank Hypervisor

[![Bareflank Demonstration Video](http://img.youtube.com/vi/YgQdECPzDkQ/0.jpg)](https://www.youtube.com/watch?v=YgQdECPzDkQ)

## Additional Videos

CppCon 2016: Making C++ and the STL Work in the Linux / Windows Kernels <br>

[![CppCon 2016](http://img.youtube.com/vi/uQSQy-7lveQ/mq1.jpg)](https://www.youtube.com/watch?v=uQSQy-7lveQ)

## Dependencies

Although Bareflank can be made to run on most systems, the following are the
supported platforms and their dependencies:

#### Ubuntu 16.10 (or Higher):
```
sudo apt-get install git build-essential linux-headers-$(uname -r) nasm clang cmake
```

#### Windows (Cygwin):
```
setup-x86_64.exe -q -P git,make,gcc-core,gcc-g++,nasm,clang,clang++,cmake
```

#### Windows (Bash):
TBD

## Compilation Instructions

The hypervisor is a collection of several different repos and external
dependencies. The main repos are as follows:
- [bfsdk](https://github.com/bareflank/bfsdk.git)
- [bfsysroot](https://github.com/bareflank/bfsysroot.git)
- [bfelf\_loader](https://github.com/bareflank/bfelf_loader.git)
- [bfm](https://github.com/bareflank/bfm.git)
- [bfvmm](https://github.com/bareflank/bfvmm.git)
- [bfdriver](https://github.com/bareflank/bfdriver.git)

To compile, run the following commands:

```
cd ~/
git clone -b dev https://github.com/bareflank/hypervisor.git
mkdir ~/hypervisor/build
cd ~/hypervisor/build
export PATH="$PWD/../bfprefix/bin:$PATH"
cmake ..
make
make driver_build
```

If your making changes to the hypervisor itself, we highly recommend using a
working directory. This will allow you maintain your own forks of each repo
and modify / commit as needed. Each repo that is needed must be present in
your working directory, otherwise CMake will complain.
- `-DWORKING_PATH=<path to dir>`

Also, if your modifying the hypervisor, we also highly recommend enabling
dev mode. This will enable the various different tools that are needed to
pass all of our CI tests.
- `-DENABLE_DEV_MODE=ON`

One this is enabled, you can run the following commands before submitting a
PR:
- `make test`
- `make format`
- `make tidy`

You can also direct the build system to use your own forked repos in-place of
the main repos. To do this, add any of the following CMake variables with
links to the repo of your choice:
- `-DBFSDK\_URL=<url>`
- `-DBFSYSROOT\_URL=<url>`
- `-DBFELF\_LOADER\_URL=<url>`
- `-DBFM\_URL=<url>`
- `-DBFVMM\_URL=<url>`
- `-DBFDRIVER\_URL=<url>`

Alternatively, if you have cloned your own local repositories without,
a working directory you can set the following:
- `BFSDK\_PATH=<path to repo>`
- `BFSYSROOT\_PATH=<path to repo>`
- `BFELF\_LOADER\_PATH=<path to repo>`
- `BFM\_PATH=<path to repo>`
- `BFVMM\_PATH=<path to repo>`
- `BFDRIVER\_PATH=<path to repo>`

If you wish to enable the extended APIs, you can do so using the following.
If you have a working directory, ensure the extended APIs repo is present in
your working directory first:

- `-DENABLE_EXTENDED_APIS=ON`

## Usage Instructions

To use the hypervisor, run the following commands:

```
make driver_quick
make quick
```

to get status information, use the following:

```
make status
make dump
```

to reverse this:

```
make unload
make driver_unload
```
to clean-up:

```
make super-clean
```

to preform a more comprehensive clean:

```
make dist-clean
rm -Rf *
```

## Extended APIs / Hyperkernel

Since Bareflank only provides the bare minimum implementation, we have created
two other repositories that extend Bareflank to provide additional
capabilities that you might find useful. The Extended APIs repo provides
additional APIs around Intel's VT-x / VT-d. Likely most users of Bareflank will
find these APIs useful. The Hyperkernel leverages the Extended APIs and
Bareflank to provide guest support. If your project requires guest support,
you might also find this repo useful as well.

**Extended APIs:**<br>
https://github.com/Bareflank/extended_apis

**Hyperkernel:**<br>
https://github.com/Bareflank/hyperkernel

## Example Extensions

To provide examples of how you might extend Bareflank to provide your own custom
functionality, we have provided a couple of examples:

**Enable VPID:**<br>
https://github.com/Bareflank/hypervisor_example_vpid

**CPUID Count:**<br>
https://github.com/Bareflank/hypervisor_example_cpuidcount

**MSR Bitmap:**<br>
https://github.com/Bareflank/hypervisor_example_msr_bitmap

**Extended APIs EPT Hook:**<br>
https://github.com/Bareflank/extended_apis_example_hook

## Roadmap

The project roadmap can be located [here](https://github.com/Bareflank/hypervisor/projects)

## License

The Bareflank Hypervisor is licensed under the GNU Lesser General Public License
v2.1 (LGPL).

## Related

If you’re interested in Bareflank, you might also be interested in the
following hypervisor projects:

**MoRE:** <br>
https://github.com/ainfosec/MoRE

**SimpleVisor:**  <br>
https://github.com/ionescu007/SimpleVisor

**HyperPlatform:**  <br>
https://github.com/tandasat/HyperPlatform
