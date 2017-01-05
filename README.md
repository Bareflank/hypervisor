<img src="https://raw.githubusercontent.com/Bareflank/hypervisor/master/doc/images/bareflank_logo.jpg" width="501">
<br>
<br>
<br>
[![GitHub version](https://badge.fury.io/gh/bareflank%2Fhypervisor.svg)](https://badge.fury.io/gh/bareflank%2Fhypervisor)
[![Build Status](https://travis-ci.org/Bareflank/hypervisor.svg?branch=master)](https://travis-ci.org/Bareflank/hypervisor)
[![Build Status](https://ci.appveyor.com/api/projects/status/r82c37nc634tnsv9?svg=true)](https://ci.appveyor.com/project/rianquinn/hypervisor-13oyg)
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

Currently we have support for the following 64bit host operating systems on Intel _SandyBridge_ and above hardware:
- Ubuntu 16.10, 16.04, 14.04
- Debian Stretch
- Fedora 25, 24, 23
- OpenSUSE Leap 42.2
- Windows 10
- Windows 8.1

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

## Compilation Instructions

NOTE: Our master branch is our working, experimental branch and might be
unstable. If you would like to use Bareflank, we recommend using a tagged
release which has been more thoroughly tested. Of course if you happen to
find a bug, please let us know
[here](https://github.com/Bareflank/hypervisor/issues). These instructions
might vary from release to release, so if something doesn't work, please
refer to the instructions provided in the tagged version.

Before you can compile, the build environment must be present. If you are on
a supported Windows platform, you must first install cygwin, and run a cygwin
terminal with admin rights. You must also copy the setup-x86_64.exe to
"c:\cygwin64\bin". If you are on a supported Linux platform, all you need
is a terminal. Once your setup, you should be able to run the following:

```
cd ~/
git clone https://github.com/bareflank/hypervisor.git
cd ~/hypervisor
git checkout -b rc1.1.0

./tools/scripts/setup_<platform>.sh
```

If you are on Windows, there is one additional step that must be taken
to turn on test signing. This step can be skipped if you plan to sign
the driver with your own signing key.

```
bcdedit.exe /set testsigning ON
<reboot>
```

If you are not on a supported platform, you are more than welcome to modify
an existing setup_\<platform\>.sh script to suite your needs. Its likely
the hypervisor will work assuming you can get it to compile. Once you have
the cross compilers you can run:

```
make
make test
```

To run the hypervisor, you need to first compile, and load one of the driver
entry points. Bareflank uses the driver entry point to gain kernel level
access to the system to load the hypervisor. On Windows and Linux, this
is as simple as:

```
make driver_load
make load
make start
```

to get status information, use the following:

```
make status
make dump
ARGS="versions 1" make vmcall
```

to reverse this:

```
make stop
make unload
make driver_unload
```

For more detailed instructions please read the following (based on which OS you are using):

[Driver Entry Documentation](https://github.com/Bareflank/hypervisor/tree/master/bfdrivers/src/arch)

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

**HyperBone:**  <br>
https://github.com/DarthTon/HyperBone
