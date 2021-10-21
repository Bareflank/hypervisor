![Bareflank](https://github.com/Bareflank/hypervisor/raw/master/.github/images/hypervisor_logo.png)

## Description
The Bareflank Hypervisor is an open source hypervisor Software Development Toolkit (SDK) for Rust and C++, led by Assured Information Security, Inc. (AIS), that provides the tools needed to rapidly prototype and create your own hypervisor on 64bit versions of Intel and AMD (ARMv8 CPUs, RISC-V and PowerPC also planned). The Bareflank SDK is intended for instructional/research purposes as it only provides enough virtualization support to start/stop a hypervisor. Bareflank can also be used as the foundation to create your own, fully functional hypervisor as it uses the MIT license, includes 100% unit test coverage and compliance for AUTOSAR. If you are looking for a complete hypervisor (and not an SDK), please see [MicroV](https://github.com/Bareflank/microv). If you are looking for a minimal SDK for education or to perform research, this is the project for you. If you are simply looking for a reference hypervisor, please see [SimpleVisor](https://github.com/ionescu007/SimpleVisor).

Bareflank uses a layered, modular approach, that lets you pick just how much complexity you need in your project when creating your own custom hypervisor:
- [BSL](https://github.com/Bareflank/bsl): provides a header-only, AUTOSAR
  compliant implementation of a subset of the C++ Standard Library, used to
  implement Bareflank's C++ components ensuring Bareflank and projects built
  using Bareflank can support critical systems applications.
- [LLVM](https://github.com/Bareflank/llvm-project): provides our custom
  implementation of the LLVM Clang-Tidy static analysis tool to ensure
  compliance with AUTOSAR.
- [PAL](https://github.com/Bareflank/pal): provides auto-generated intrinsics
  APIs for Intel, AMD and ARM on any combination of OS and language.
- [hypervisor](https://github.com/Bareflank/hypervisor): provides the base SDK
  including the loader, the Bareflank microkernel and support applications.
  Although this repo is labeled "hypervisor", this repo only provides the base
  scaffolding for creating your own hypervisor. If you are in education or
  performing research and do not want to deal with the complexity of a fully
  functional hypervisor, this repo would be your starting point. By itself, the
  code in this repo only implements enough virtualization to start/stop a
  hypervisor.
- [MicroV](https://github.com/Bareflank/microv): This is the project led by
  Assured Information Security, Inc. (AIS) the provides a fully functional
  hypervisor that uses the Bareflank SDK as it's foundation. If you are looking
  for an actual hypervisor and not an SDK, this is the project you are looking
  for.

## **Quick start**
![GitHub release (latest by date)](https://img.shields.io/github/v/release/bareflank/hypervisor?color=brightgreen)

Get the latest version of the Bareflank Hypervisor SDK from GitHub:

```bash
git clone https://github.com/bareflank/hypervisor
mkdir hypervisor/build && cd hypervisor/build
cmake ..
make
```

Enjoy:
```
make driver_quick
make start
make dump
make stop
```

## Interested In Working For AIS?
Check out our [Can You Hack It?®](https://www.canyouhackit.com) challenge and test your skills! Submit your score to show us what you’ve got. We have offices across the country and offer competitive pay and outstanding benefits. Join a team that is not only committed to the future of cyberspace, but to our employee’s success as well.

<p align="center">
  <a href="https://www.ainfosec.com/">
    <img src="https://github.com/Bareflank/hypervisor/raw/master/.github/images/ais.png" alt="ais" height="100" />
  </a>
</p>

## Demo
Check out the latest demo for how to compile and use the Bareflank Hypervisor on Ubuntu 20.04:

## Additional Videos
Check out our [YouTube Channel](https://www.youtube.com/channel/UCH-7Pw96K5V1RHAPn5-cmYA) for more great content as well as
the following videos at [CppCon](https://www.youtube.com/userCon) below:

[![CppCon 2019](https://i.imgur.com/hjZg0pf.png)](https://www.youtube.com/watch?v=bKPN-CGhEC0)
[![CppCon 2017](https://i.imgur.com/nBFD6uA.png)](https://www.youtube.com/watch?v=KdJhQuycD78)
[![CppCon 2016](https://i.imgur.com/fwmlOiJ.png)](https://www.youtube.com/watch?v=uQSQy-7lveQ)

## **Important Tips**
Before attempting to use Bareflank, please review the following tips as they can make a huge difference in your initial experience:
- Make sure you are running on a system with a serial port. Which serial port
  Bareflank uses can be configured by setting HYPERVISOR_SERIAL_PORT on x86
  or HYPERVISOR_SERIAL_PORTH and HYPERVISOR_SERIAL_PORTL on ARMv8. Cables like
  [these](https://www.amazon.com/USB-Serial-Adapter-Modem-9-pin/dp/B008634VJY/ref=sr_1_1_sspa?crid=P21N96MOCMDS&dchild=1&keywords=usb+null+modem+cable&qid=1622226200&sprefix=usb+null+mo%2Caps%2C201&sr=8-1-spons&psc=1&spLa=ZW5jcnlwdGVkUXVhbGlmaWVyPUEzNzBLRUcxVzRNOE8zJmVuY3J5cHRlZElkPUEwMTA1Nzg4U0IyM1RPU0NTRjROJmVuY3J5cHRlZEFkSWQ9QTA3OTM4MjVFMzlNSEQ3T1E2MEwmd2lkZ2V0TmFtZT1zcF9hdGYmYWN0aW9uPWNsaWNrUmVkaXJlY3QmZG9Ob3RMb2dDbGljaz10cnVl)
  work great. Bareflank uses the following settings (115200 baud rate, 8 data
  bits, no parity bits, one stop bit).
- Using PCI serial addon cards will not work with UEFI. These cards need to be
  initialized by the OS, logic that Bareflank does not currently contain.
  If you are using Bareflank directly from Windows/Linux, these cards will work
  fine, but from UEFI, you need a serial port provided on the motherboard.
- The serial output might contain a lot of ANSI color codes if you are using
  a terminal that doesn't support ANSI color. To remove these, configure CMake
  with -DENABLE_COLOR=OFF.
- Windows Subsystem For Linux v2 is not supported. When this is turned on,
  Windows runs under HyperV, which currently does not support nested
  virtualization. Furthermore, if you have ever enabled the WSL2, you must
  turn HyperV off using `bcdedit /set hypervisorlaunchtype off` as HyperV will
  continue to run even if you are no longer using the WSL2.
- When running under Windows, driver issues can be seen by using
  [DbgView](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview).
  This tool must be run with Admin rights, and you need to turn on kernel
  output. Once this is working, you will see error messages coming from the
  Windows driver if needed.
- Nested virtualization (i.e., attempting to run Bareflank inside a VM) is
  not officially supported, but does work if you know what you are doing.
  Specifically, a headless version of Linux 20.04 or higher in VMWare works
  with the proper configuration. VirtualBox does not work due to a lack of
  supported features and KVM may or may not work (your milage may vary). In
  general, you should be using real hardware.
- If you need to compile Bareflank on older versions of Linux, it is possible,
  but you will need to update the build tools manually including LLVM 10+ and
  CMake 3.13+.

## **Build Requirements**
Currently, the Bareflank hypervisor only supports the Clang/LLVM 10+ compiler. This, however, ensures that the hypervisor can be natively compiled on Windows including support for cross-compiling. Support for other C++20 compilers can be added if needed, just let us know if that is something you need.

### **Windows**
To compile the BSL on Windows, you must first disable UEFI SecureBoot and enable test signing mode. Note that this might require you to reinstall Windows (**you have been warned**). This can be done from a command prompt with admin privileges:
```
bcdedit.exe /set testsigning ON
<reboot>
```

Next, install the following:
- [Visual Studio](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16) (Enable "Desktop development with C++")
- [WDK](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
- [LLVM 10+](https://github.com/llvm/llvm-project/releases)
- [CMake 3.13+](https://cmake.org/download/)
- [Ninja](https://github.com/ninja-build/ninja/releases)
- [Git](https://git-scm.com/downloads)

Visual Studio is needed as it contains Windows specific libraries that are needed during compilation. Instead of using the Clang/LLVM project that natively ships with Visual Studio, we use the standard Clang/LLVM binaries provided by the LLVM project which ensures we get all of the tools including LLD, Clang Tidy and Clang Format. Also note that you must put Ninja somewhere
in your path (we usually drop into CMake's bin folder). Finally, **make sure you follow all of the instructions when installing the WDK**. These instructions change frequently, and each step must be installed correctly and in the order provided by the instructions. Skipping a step, or installing a package in the wrong order will result in a WDK installation that doesn't work.

To compile the BSL, we are going to use Bash. There are many ways to start Bash including opening a CMD prompt and typing "bash". Once running bash, make sure you add the following to your PATH:
- MSBuild
- devcon
- certmgr

For example, in your .bashrc, you might add the following (depending on where Visual Studio put these files):
```bash
export PATH="/c/Program Files (x86)/Microsoft Visual Studio/2019/Community/MSBuild/Current/Bin:/c/Program Files (x86)/Windows Kits/10/Tools/x64:/c/Program Files (x86)/Windows Kits/10/bin/10.0.19041.0/x64:$PATH"
```

Finally, run the following from Bash:
```bash
git clone https://github.com/bareflank/hypervisor
mkdir hypervisor/build && cd hypervisor/build
cmake ..
ninja info
ninja
```

### **Ubuntu Linux**
To compile the BSL on Ubuntu (20.04 or higher) you must first install the following dependencies:
```bash
sudo apt-get install -y clang cmake lld
```

To compile the BSL, use the following:
```bash
git clone https://github.com/bareflank/hypervisor
mkdir hypervisor/build && cd hypervisor/build
cmake ..
make info
make
```

### **UEFI**
To compile for UEFI, simply follow the steps for your OS above, but add the following to the cmake:
```cmake
-DHYPERVISOR_BUILD_EFI=ON
```

You can then build the hypervisor as normal and the UEFI loader will be compiled for you automatically. Once the kernel, extensions and UEFI loader are compiled, you can copy them to your UEFI FS0 partition. **Note that all binaries must be copied to your FS0 partition, and on some systems, this might be a USB stick**. To aid in this copy process, the build system includes the following command:
```bash
make copy_to_efi_partition
```

By default this uses the EFI partition, but it can be relocated using:
```cmake
-DHYPERVISOR_EFI_FS0=<path to FS0>
```

Some systems require you to provide the UEFI shell, and so Bareflank contains a copy of this shell which will be copied along with the kernel, extensions and UEFI loader. Once you have rebooted into the UEFI shell, you can start the hypervisor using
```
start_bareflank.efi
```

Note that by default, the hypervisor is not able to boot an OS. You must either use a non-default example that provides more complete UEFI support, or provide your own extension that is capable of successfully booting an OS. Finally, we currently *do not* provide any of the other vmmctl functions like stop or dump.

## Usage Instructions
The Bareflank Hypervisor SDK consists of the following main components:
- vmmctl
- loader
- kernel
- extension

The "extension" is where you put your code. It is a ring 3 application that runs on top of our microkernel in so called "ring -1" or VMX root. The "kernel" is the aformentioned microkernel, and it is responsible for executing all of the hypervisor applications that actually implement the hypervisor. In other words, all of the hypervisor logic is implemented in an extension that you provide, and our microkernel is just there to execute your extension in VMX root. The "loader" places our microkernel and your extension in VMX root. It is responsible for starting and stopping the hypervisor, and dumping the contents of its debug ring. The "vmmctl" application is used to control the loader. It provides a simple means for telling the loader what to do.

To start Bareflank, compile the "loader" and run it in your OS's kernel. To do that, run the following (replace make with ninja on Windows):
```
make driver_build
make driver_load
```

This builds the "loader" and runs it in the OS's kernel. If you followed the buld instructions above using CMake, you should have already compiled the microkernel, vmmctl and your extension (which by default is our default example). Once these components are compiled, you can run the hypervisor using the following command (replace make with ninja on Windows):
```
make start
```

to get debug information, use the following (replace make with ninja on Windows):

```
make dump
```

To stop the hypervisor use the following (replace make with ninja on Windows):
```
make stop
```

Finally, to unload the "loader" and clean up its build system you can run the following (replace make with ninja on Windows):
```
make driver_unload
make driver_clean
```

And that is it. For more information on how to build and use Bareflank, you can run the following core a complete list of commands available to you as well as the complete build configuration (replace make with ninja on Windows):
```
make info
```

## Writing Your Own Extensions
The Bareflank Hypervisor comes complete with a series of example extensions you can use to create your own custom hypervisor. To start, we will create a working directory, and clone some repos to speed up the build process:
```bash
mkdir ~/working
mkdir ~/working/build
git clone https://github.com/bareflank/bsl ~/working/bsl
git clone https://github.com/bareflank/hypervisor ~/working/hypervisor
```

Next, we will copy an existing example into our working directory (pick the example that provides the best starting point for your project):
```bash
cp -R ~/working/hypervisor/example/default ~/working/extension
```

Finally, we will configure the project, telling the build system how to find our custom extension.
```bash
cd ~/working/build
cmake \
  ../hypervisor \
  -DHYPERVISOR_EXTENSIONS_DIR=$PWD/../extension \
  -DFETCHCONTENT_SOURCE_DIR_BSL=$PWD/../bsl
```

`HYPERVISOR_EXTENSIONS_DIR` defines the location of your extension. Note that the path must be an absolute path, which is why we used the absolute path of the build folder as a starting point and then worked out the location of the extension folder from there.

`FETCHCONTENT_SOURCE_DIR_BSL` is optional. This tells the build system where to find the BSL. Since we already cloned the BSL into our working directory, we can use it instead of asking the build system to automatically fetch the BSL for us. This is great for offline builds, or builds where you are rerunning cmake a lot and don't want to wait for the BSL to download each time.

The rest of the usage instructions above can be used to start/stop your custom hypervisor. For more information about what ABIs the microkernel provides your extension with, please see the [Microkernel Syscall Specification](https://github.com/Bareflank/hypervisor/blob/master/docs/Microkernel%20Syscall%20Specification.md) in the docs folder. We also provide an example implementation of this ABI as a set of C++ APIs that you can use if you would like. This example set of APIs can be seen in the [syscall/include/mk_interface.hpp](https://github.com/Bareflank/hypervisor/blob/master/syscall/include/mk_interface.hpp) file.

To use the Rust example, you will have to install Rust and switch to the nightly channel. 

## **Resources**
[![Join the chat](https://img.shields.io/badge/chat-on%20Slack-brightgreen.svg)](https://bareflank.herokuapp.com/)

The Bareflank hypervisor provides a ton of useful resources to learn how to use the library including:
-   **Specification**: <https://github.com/Bareflank/hypervisor/blob/master/docs/Microkernel%20Syscall%20Specification.md>
-   **Examples**: <https://github.com/Bareflank/hypervisor/tree/master/example>
-   **Integration Tests**: <https://github.com/Bareflank/hypervisor/tree/master/kernel/integration>

If you have any questions, bugs, or feature requests, please feel free to ask on any of the following:
-   **Slack**: <https://bareflank.herokuapp.com/>
-   **Issue Tracker**: <https://github.com/Bareflank/hypervisor/issues>

If you would like to help:
-   **Pull Requests**: <https://github.com/Bareflank/hypervisor/pulls>
-   **Contributing Guidelines**: <https://github.com/Bareflank/hypervisor/blob/master/contributing.md>

## **Testing**
[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Fbareflank%2Fhypervisor%2Fbadge&style=flat)](https://actions-badge.atrox.dev/bareflank/hypervisor/goto)
[![codecov](https://codecov.io/gh/Bareflank/hypervisor/branch/master/graph/badge.svg)](https://codecov.io/gh/Bareflank/hypervisor)

The Bareflank hypervisor leverages the following tools to ensure the highest possible code quality. Each pull request undergoes the following rigorous testing and review:
-   **Static Analysis:** [Clang Tidy](https://github.com/Bareflank/llvm-project)
-   **Dynamic Analysis:** Google's ASAN and UBSAN
-   **Code Coverage:** Code Coverage with CodeCov
-   **Coding Standards**: [AUTOSAR C++14](https://www.autosar.org/fileadmin/user_upload/standards/adaptive/17-03/AUTOSAR_RS_CPP14Guidelines.pdf) and [C++ Core Guidelines](https://github.com/isocppCoreGuidelines/blob/masterCoreGuidelines.md)
-   **Style**: Clang Format
-   **Documentation**: Doxygen

## Serial Instructions
On Windows, serial output might not work, and on some systems (e.g. Intel NUC),
the default Windows serial device may prevent Bareflank from starting at all.
If this is the case, disable the default serial device using the following:
```
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Serial" /f /v "start" /t REG_DWORD /d "4"
```

See "Important Tips" above for additional details on how to use serial devices.

## License
The Bareflank Hypervisor is licensed under the MIT License.

## Related
If you’re interested in Bareflank, you might also be interested in the
following projects:

**MoRE:** <br>
https://github.com/ainfosec/MoRE

**SimpleVisor:**  <br>
https://github.com/ionescu007/SimpleVisor

**HyperPlatform:**  <br>
https://github.com/tandasat/HyperPlatform
