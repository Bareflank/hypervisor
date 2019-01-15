![Bareflank](https://github.com/Bareflank/hypervisor/raw/gh-pages/logo.png)

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
- [boxy](https://github.com/Bareflank/boxy): leverages the Bareflank SDK to provide a
fully functional hypervisor with guest support.

To support Bareflank's design approach, the hypervisor is licensed
under MIT, specifically
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
- ARM64 (still under development)

## Motivation

Most people think that hypervisors are meant to virtualize servers and provide a means to run Windows on a Mac, but there is a whole field of research where hypervisors are used without guest virtual machines. Since a hypervisor is capable of controlling the host OS running underneath it (so-called "ring -1"), host-only hypervisors support introspection, reverse engineering, anti-virus, containerization, diversity, and even architectural research like [MoRE](https://github.com/ainfosec/MoRE). All of these use cases start the same way, by spending months standing up the hypervisor itself before you can start working on your actual project. Existing open source hypervisors are burdened with legacy support and unnecessary complexity that make them painful to work with when conducting hypervisor research.

## Links

[Bareflank Hypervisor Website](http://bareflank.github.io/hypervisor/) <br>
[Bareflank Hypervisor API Documentation](http://bareflank.github.io/hypervisor/html/)

## Demo

Checkout the latest demo for how to compile and use the Bareflank Hypervisor on Ubuntu 18.04:

[![Bareflank Demonstration Video](http://img.youtube.com/vi/fNLXxtdkhLg/maxresdefault.jpg)](https://www.youtube.com/watch?v=fNLXxtdkhLg)

## Additional Videos

Checkout our [YouTube Channel](https://www.youtube.com/channel/UCH-7Pw96K5V1RHAPn5-cmYA) for more great content as well as
the following videos at [CppCon](https://www.youtube.com/user/CppCon) below:

[![CppCon 2017](https://i.imgur.com/bLnrVon.png)](https://www.youtube.com/watch?v=KdJhQuycD78)
[![CppCon 2016](https://i.imgur.com/MLoOLmM.png)](https://www.youtube.com/watch?v=uQSQy-7lveQ)

## Dependencies

Although Bareflank can be made to run on most systems, the following are the
supported platforms and their dependencies:

#### Arch Linux:
```
sudo pacman -S git base-devel linux-headers nasm clang cmake
```

#### Ubuntu 17.10 (or Higher):
```
sudo apt-get install git build-essential linux-headers-$(uname -r) nasm clang cmake libelf-dev
```

#### Windows (Visual Studio):
- [Visual Studio 2017 / WDK 10](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
  - Check "Desktop development with C++"
  - Check "C++ CLI / Support"
  - Check "VC++ 2017 version xxx Libs for Spectre (ARM)"
  - Check "VC++ 2017 version xxx Libs for Spectre (ARM64)"
  - Check "VC++ 2017 version xxx Libs for Spectre (x86 and x64)"

After installing the the above packages you must enable test signing mode. This can be done from a
command prompt with admin privileges:
```
bcdedit.exe /set testsigning ON
<reboot>
```

Once the build environment is set up, Bareflank can be configured using the following
instead of the cmake configure commands listed below which assume Linux:
```
cmake -G "Visual Studio 15 2017 Win64" -DENABLE_BUILD_VMM=OFF ..
```

Note that this version of Bareflank cannot be used to compile hypervisor as Visual Studio currently
cannot build the needed ELF files that Bareflank relies on. This build environment also relys on
msbuild, which doesn't support any of the build targets so compiling the drivers must be done
manually. This environment however will compile the userspace applications natively which is
needed for deployment to remove dependencies on Cygwin.

#### Windows (Cygwin):
- All of the Windows (Visual Studio) instructions
- [Cygwin](https://www.cygwin.com/setup-x86_64.exe)

To install Cygwin, simply install using all default settings, and then copy
setup-x86\_64.exe to C:\\cygwin64\\bin. From there, open a Cygwin terminal and
run the following:

```
setup-x86_64.exe -q -P git,make,gcc-core,gcc-g++,nasm,clang,clang++,cmake,python,gettext,bash-completion
```

This build environment provides a complete toolchain for building and running Bareflank. Most
developers using Bareflank on Windows will need Cygwin for this reason. The remaining compilation
instructions follow below.

#### Windows (WSL):
- Ubuntu 18.04 LTS (Windows Store)

In a powershell terminal with admin right, run the following:

```
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
```

Then run the following in the WSL command prompt that is created:

```
sudo apt-get update
sudo apt-get install git build-essential nasm clang cmake libelf-dev
```

Do not attempt to access the Linux file system from Windows. Instead, you should access the
Windows file system from Linux which can be found here:

```
/mnt/c/
```

Note that the WSL cannot be used to compile the Windows drivers or start/stop the hypervisor.
It can, however, be used to compile the hypervisor including the UEFI version without the
need for Cygwin. If this is paired with the Visual Studio build environment, and you manually
compile the drivers, you can piece together a complete build enviornment for Windows without the
need for Cygwin. Developers are advised not to use this however as it is cumbersome and instead
should use the Cygwin environment. The WSL is only supported for deployment purposes.

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
A UEFI application version of Bareflank may be compiled on Linux and used to boot
both Linux and Windows if you also include the Extended APIs. The followinging
describes how to build and execute Bareflank with EFI. For additional information,
please see the following YouTube [video](https://www.youtube.com/watch?v=FuEyjDqA53M&t=4s)

To compile for UEFI, add the following to CMake when configuring:
```
-DBUILD_EFI=ON
```
It should be noted that unit tests must be disabled, and static builds are currently
required (the example config provides an example of how to configure Bareflank as
needed for more complex builds).

To boot Windows or Linux with the Extended APIs you will need to provide your own
extension that enables EPT. To see an example of this type of extension, please
see the following integration test:
```
https://github.com/Bareflank/extended_apis/blob/master/bfvmm/integration/arch/intel_x64/efi/test_efi.cpp
```
Once you have your own extension, the example config is required to tell the build
system which VMM and target to use. The example config can be found here:
```
https://github.com/Bareflank/hypervisor/blob/master/scripts/cmake/config/example_config.cmake
```
Our front page video on YouTube explains how to use this config, and the instructions
are also in the config itself. To enable EFI, turn on the build Extended APIs and EFI
flags. You will also need to set the following:
```
set(OVERRIDE_VMM <name>)
set(OVERRIDE_VMM_TARGET <name>)
```
If for example you are using the integration test listed above, these setting would
be as follows:
```
set(OVERRIDE_VMM eapis_integration_intel_x64_efi_test_efi)
set(OVERRIDE_VMM_TARGET eapis_integration)
```
The first variable defines the VMM's name and the second variable defines the target
that builds this VMM (which tells the buid system what dependency EFI has). From
there build as normal.

The resulting UEFI application can be found here:
```
build/prefixes/x86_64-efi-pe/bin/bareflank.efi
```
Place this binary in your EFI partition (e.g., on Ubuntu this is
/boot/efi/EFI/BOOT/bareflank.efi) and execute it like any other EFI application.
Once Bareflank is running, you can start Windows or Linux if you included the
above. Also note that utilities like "make dump" do not work when using EFI as
the driver doesn't have access to the debug ring. You can however use
"make ack" if you are using the Extended APIs to get the hypervisor to say "hi".

## Serial Instructions

On Windows, serial output might not work, and on some systems (e.g. Intel NUC),
the default Windows serial device may prevent Bareflank from starting at all.
If this is the case, disable the default serial device using the following:
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

The Bareflank Hypervisor is licensed under the MIT License.

## Related

If you’re interested in Bareflank, you might also be interested in the
following hypervisor projects:

**MoRE:** <br>
https://github.com/ainfosec/MoRE

**SimpleVisor:**  <br>
https://github.com/ionescu007/SimpleVisor

**HyperPlatform:**  <br>
https://github.com/tandasat/HyperPlatform
