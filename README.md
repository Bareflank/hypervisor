![Bareflank](https://github.com/Bareflank/hypervisor/blob/gh-pages/bareflank_logo.jpg?raw=true)

<br>

[![GitHub Version](https://badge.fury.io/gh/bareflank%2Fhypervisor.svg)](https://badge.fury.io/gh/bareflank%2Fhypervisor)
[![Build Status](https://travis-ci.org/Bareflank/hypervisor.svg?branch=master)](https://travis-ci.org/Bareflank/hypervisor)
[![Build Status](https://ci.appveyor.com/api/projects/status/r82c37nc634tnsv9/branch/master?svg=true)](https://ci.appveyor.com/project/rianquinn/hypervisor-13oyg/branch/master)
[![codecov](https://codecov.io/gh/Bareflank/hypervisor/branch/master/graph/badge.svg)](https://codecov.io/gh/Bareflank/hypervisor)
[![Codacy Status](https://api.codacy.com/project/badge/Grade/28ec616803cb4800a4b727b70a3b112f)](https://www.codacy.com/app/rianquinn/hypervisor?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=Bareflank/hypervisor&amp;utm_campaign=Badge_Grade)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/325/badge)](https://bestpractices.coreinfrastructure.org/projects/325)
[![Join the chat at https://gitter.im/Bareflank-hypervisor/Lobby](https://badges.gitter.im/Bareflank-hypervisor/Lobby.svg)](https://gitter.im/Bareflank-hypervisor/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## Description

The Bareflank Hypervisor is an open source, hypervisor Software Development Toolkit (SDK), led by
Assured Information Security, Inc. (AIS), that provides a set of APIs needed to
rapidly prototype and create new hypervisors. To ease development, Bareflank
is written in C/C++, and includes support for C++ exceptions, JSON, the GSL and the C++ Standard
Template Library (STL).

The Bareflank Hypervisor uses a layered, modular approach.
- [hypervisor](https://github.com/Bareflank/hypervisor): provides a minimal, hypervisor
implementation, the build system, and architecture specific intrinsics.
- [extended_apis](https://github.com/Bareflank/extended_apis): adds hardware virtualization extension
APIs to the hypervisor.
- [hyperkernel](https://github.com/Bareflank/hyperkernel): adds guest support APIs to the
hypervisor.
- [pv_interface](https://github.com/Bareflank/pv_interface): adds a hypercall API/ABI and
PV interface to the hypervisor.

To support Bareflank's design approach, the hypervisor is licensed
under the GNU Lesser General Public License v2.1 (LGPL), specifically
enabling users of the project to both contribute back to the project, but
also create proprietary extensions of the VMM if so desired.

In addition, the project comes complete with a set of unit tests to validate
that the provided SDK works as expected. These tests are checked for completeness using
[Codecov](https://codecov.io/gh/Bareflank/hypervisor). Furthermore,
[Travis CI](https://travis-ci.org/Bareflank/hypervisor) has been setup to
test source code formatting via
[Astyle](http://astyle.sourceforge.net), and static / dynamic analysis
via
[Clang Tidy](http://clang.llvm.org/extra/clang-tidy/),
[Codacy](https://www.codacy.com),
and
[Google's Sanitizers](https://github.com/google/sanitizers). Finally, we adhere
to the
[CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/325),
the
[High Integrity C++ Guidelines](http://www.codingstandard.com/)
and the
[C++ Core Guidelines](https://github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md)
including support for the
[Guideline Support Library](https://github.com/Microsoft/GSL).

Currently we have support for the following 64bit host operating systems on
Intel _Sandy Bridge_ and above hardware:
- Arch Linux
- Ubuntu 17.10+
- Windows 10
- Windows 7
- UEFI

In the future, we would also like to support:
- macOS
- BSD
- ARM64 (currently under development)

## Motivation

Most people think that hypervisors are meant to virtualize servers and provide a means to run Windows on a Mac, but there is a whole field of research where hypervisors without guest virtual machines. Since a hypervisor is capable of controlling the host OS running underneath it (so-called "ring -1"), host-only hypervisors support introspection, reverse engineering, anti-virus, containerization, diversity, and even architectural research like [MoRE](https://github.com/ainfosec/MoRE). All of these use cases start the same way, by spending months standing up the hypervisor itself before you can start working on your actual project. Existing open source hypervisors are burdened with legacy support and unnecessary complexity that make them painful to work with when conducting hypervisor research.

## Links

[Bareflank Hypervisor Website](http://bareflank.github.io/hypervisor/) <br>
[Bareflank Hypervisor API Documentation](http://bareflank.github.io/hypervisor/html/)

## Demo

Checkout the latest demo for how to compile, use and extend the
Bareflank Hypervisor

[![Bareflank Demonstration Video](http://img.youtube.com/vi/YgQdECPzDkQ/0.jpg)](https://www.youtube.com/watch?v=YgQdECPzDkQ)

## Additional Videos

[![CppCon 2017](https://i.imgur.com/bLnrVon.png)](https://www.youtube.com/watch?v=KdJhQuycD78)
[![CppCon 2016](https://i.imgur.com/MLoOLmM.png)](https://www.youtube.com/watch?v=uQSQy-7lveQ)

## Dependencies

Although Bareflank can be made to run on most systems, the following are the
supported platforms and their dependencies:

#### Arch Linux:
```
sudo pacman -S linux-headers nasm cmake base-devel clang
```

#### Ubuntu 17.10 (or Higher):
```
sudo apt-get install git build-essential linux-headers-$(uname -r) nasm clang cmake libelf-dev
```

#### Windows (Cygwin):
- [Visual Studio 2017 / WDK 10](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
  - Check "Desktop development with C++"
  - Check "C++ CLI / Support"
- [Cygwin](https://www.cygwin.com/setup-x86_64.exe)

To install Cygwin, simply install using all default settings, and then copy
setup-x86\_64.exe to C:\\cygwin64\\bin. From there, open a Cygwin terminal and
run the following:

```
setup-x86_64.exe -q -P git,make,gcc-core,gcc-g++,nasm,clang,clang++,cmake,python,gettext,bash-completion
git config --global core.autocrlf false
```

After installing the the above packages and disabling auto CRLF (which breaks
bash scripts) you must enable test signing mode. This can be done from a
command prompt with admin privileges:
```
bcdedit.exe /set testsigning ON
<reboot>
```

## Compilation Instructions

To compile with default settings for your host environment, run the following commands:

```
git clone https://github.com/bareflank/hypervisor.git
mkdir build; cd build
cmake ../hypervisor
make -j<# cores + 1>
```

For more detailed build instructions, see the
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

## UEFI:
A UEFI application version of Bareflank may be compiled on either Linux or 
Cygwin (Visual Studio is currently not supported). To compile for UEFI, add the 
following to CMake when configuring:
```
-DENABLE_BUILD_EFI=ON
```
It should be noted that unit tests must be disabled, and static builds are currently
required (the example config provides an example of how to configure Bareflank as 
needed for more complex builds). The resulting UEFI application can be found here:
```
build/prefixes/x86_64-efi-pe/bin/bareflank.efi
```
Place this binary in your EFI partition (e.g., on Ubuntu this is 
/boot/efi/EFI/BOOT/bareflank.efi) and execute it like any other EFI application. 
Once Bareflank is running, if you wish to boot Windows or Linux, the Extended APIs 
are needed (as additional emulation is needed to succesfully boot an OS). Also
note that utilities like "make dump" do not work when using EFI as the driver 
doesn't have access to the debug ring. 

## Serial Instructions

On Windows, serial output might not work, and on systems (e.g. Intel NUC),
may prevent Bareflank from starting at all. If this is the case, disable the
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

## Additional Layers

*** **WARNING** *** <br>
The master branch is our development branch and should be considered unstable.
It is possible these additional projects might not compile with master. If you
need a stable branch that works with these repos, please use a tagged release.

Since the main, hypervisor repo only provides the a minimal implementation,
we have created other repositories that extend Bareflank to provide additional
capabilities that you might find useful.

**Extended APIs:**<br>
https://github.com/Bareflank/extended_apis

**Hyperkernel:**<br>
https://github.com/Bareflank/hyperkernel

**PV Interface:**<br>
https://github.com/Bareflank/pv_interface

## Example Extensions

*** **WARNING** *** <br>
The master branch is our development branch and should be considered unstable.
It is possible these additional projects might not compile with master. If you
need a stable branch that works with these repos, please use a tagged release.

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
v2.1 (LGPL). The Windows and EFI drivers are licensed under the MIT License. The
Linux driver is licensed under the General Public License v2.0 (GPL) License.

## Related

If you’re interested in Bareflank, you might also be interested in the
following hypervisor projects:

**MoRE:** <br>
https://github.com/ainfosec/MoRE

**SimpleVisor:**  <br>
https://github.com/ionescu007/SimpleVisor

**HyperPlatform:**  <br>
https://github.com/tandasat/HyperPlatform
