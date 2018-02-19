![Bareflank](https://raw.githubusercontent.com/Bareflank/hypervisor/master/doc/images/bareflank_logo.jpg)
<br>
<br>
<br>
[![GitHub Version](https://badge.fury.io/gh/bareflank%2Fhypervisor.svg)](https://badge.fury.io/gh/bareflank%2Fhypervisor)
[![Build Status](https://travis-ci.org/Bareflank/hypervisor.svg?branch=master)](https://travis-ci.org/Bareflank/hypervisor)
[![Build Status](https://ci.appveyor.com/api/projects/status/r82c37nc634tnsv9/branch/master?svg=true)](https://ci.appveyor.com/project/rianquinn/hypervisor-13oyg/branch/master)
[![Coverage Status](https://coveralls.io/repos/github/Bareflank/hypervisor/badge.svg?branch=master)](https://coveralls.io/github/Bareflank/hypervisor?branch=master)
[![Codacy Status](https://api.codacy.com/project/badge/Grade/28ec616803cb4800a4b727b70a3b112f)](https://www.codacy.com/app/rianquinn/hypervisor?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=Bareflank/hypervisor&amp;utm_campaign=Badge_Grade)
[![Coverity Scan Status](https://scan.coverity.com/projects/9857/badge.svg)](https://scan.coverity.com/projects/bareflank-hypervisor)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/325/badge)](https://bestpractices.coreinfrastructure.org/projects/325)
[![Join the chat at https://gitter.im/Bareflank-hypervisor/Lobby](https://badges.gitter.im/Bareflank-hypervisor/Lobby.svg)](https://gitter.im/Bareflank-hypervisor/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## Description

The Bareflank Hypervisor is an open source, lightweight hypervisor, led by
Assured Information Security, Inc., that provides the scaffolding needed to
rapidly prototype new hypervisors. To ease development, Bareflank
is written in C++, and includes support for exceptions and the C++ Standard
Template Library (STL) via libc++. With the C++ STL, users can leverage
shared pointers, complex data structures (e.g. hash tables, maps, lists,
etc…), and several other modern C++ features. Existing open source
hypervisors that are written in C are difficult to modify, and require a
considerable amount of time re-writing similar functionality instead of
focusing on what matters most: hypervisor technologies. Furthermore, users
can leverage inheritance to extend every part of the hypervisor to provide
additional functionality above and beyond what is already provided.

To this end, Bareflank's primary goal is to remain simple and
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
via
[Coverity Scan](https://scan.coverity.com/projects/bareflank-hypervisor),
[Clang Tidy](http://clang.llvm.org/extra/clang-tidy/),
[Codacy](https://www.codacy.com),
and
[Google's Sanitizers](https://github.com/google/sanitizers). In addition, we adhere
to the
[CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/325),
and the
[C++ Core Guidelines](https://github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md)
including support for the
[Guideline Support Library](https://github.com/Microsoft/GSL).

Currently we have support for the following 64bit host operating systems on
Intel _Sandy Bridge_ and above hardware:
- Arch Linux
- Debian 9.x+
- Ubuntu 17.04+
- Windows 10
- Windows 8.1
- Windows 7

In the future, we would also like to support:
- macOS
- BSD
- UEFI (currently under development)
- ARM64 (currently under development)

## Motivation

Most people think that hypervisors are meant to virtualize servers and
provide a means to run Windows on a Mac, but there is a whole field
of research where hypervisors are used without guest virtual
machines. Since a hypervisor is capable of controlling the host OS
running underneath it (so called "ring -1"), hypervisors have been
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

#### Arch Linux:
```
sudo pacman -S linux-headers nasm cmake base-devel
git clone https://aur.archlinux.org/package-query.git
git clone https://aur.archlinux.org/yaourt.git
pushd package-query
makepkg --install --syncdeps --needed
popd
pushd yaourt
makepkg --install --syncdeps --needed
popd
sudo yaourt -S downgrade
sudo downgrade clang clang-tools-extra llvm-libs  # select 4.0.*
sudo ln -s /usr/share/clang/run-clang-tidy.py /usr/bin/run-clang-tidy-4.0.py
sudo ln -s /usr/bin/clang-tidy /usr/bin/clang-tidy-4.0
```

#### Ubuntu 17.04 (or Higher):
```
sudo apt-get install git build-essential linux-headers-$(uname -r) nasm clang cmake
```

#### Windows (Cygwin):
Visual Studio 2017 doesn't support building drivers, but the WDK 10 doesn't
compile drivers without Visual Studio 2017 installed, so you must install
both Visual Studio 2017 and 2015 to get a complete environment. Also note that
these packages must be installed in the following order:
- [Visual Studio 2015](https://go.microsoft.com/fwlink/?LinkId=615448&clcid=0x409)
  - Check "Visual C++"
- [Visual Studio 2017](https://www.visualstudio.com/thank-you-downloading-visual-studio/?sku=Community&rel=15#)
  - Check "Desktop development with C++"
  - Check "C++ CLI / Support"
- [Visual Studio WDK 10](https://go.microsoft.com/fwlink/p/?LinkId=845980)
- [Cygwin](https://www.cygwin.com/setup-x86_64.exe)

To install Cygwin, simply install using all default settings, and then copy
setup-x86\_64.exe to C:\\cygwin64\\bin. From there, open a Cygwin terminal and
run the following:

```
setup-x86_64.exe -q -P git,make,gcc-core,gcc-g++,nasm,clang,clang++,cmake,python,gettext,bash-completion
```

After installing the the above packages you must enable test signing mode.
This can be done from a command prompt with admin privileges:
```
bcdedit.exe /set testsigning ON
<reboot>
```
## Compilation Instructions

To compile with default settings for your host environment, run the following commands:

```
git clone -b dev https://github.com/bareflank/hypervisor.git
mkdir build; cd build
cmake ../hypervisor
make -j<# cores + 1>
```

For more detailed build instuctions and configurations, see the
[detailed build instructions](scripts/docs/build_instructions.md).
For instructions on building and creating Bareflank extensions, see the
[extension build instructions](scripts/docs/extension_instructions.md)

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
to clean up:

```
make distclean
```

## Serial Instructions

On Windows, serial output might not work. If this is the case, disbale the
default Serial device using the following:
```
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Serial" /f /v "start" /t REG_DWORD /d "4"
```

## Cygwin SSH Instructions

You might find it useful to setup SSH if you are using Cygwin. The instructions
for setting up SSH on Cygwin are as follows:

```
setup-x86_64.exe -q -P getent,cygrunsrv,openssl,openssh

ssh-host-config -y
<password>
<password>

net start sshd
netsh advfirewall firewall add rule name='SSH Port' dir=in action=allow protocol=TCP localport=22
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
