![Bareflank](https://github.com/Bareflank/hypervisor/raw/master/.github/images/hypervisor_logo.png)

## Description
**Warning:** The master branch is under heavy development as we work to complete Bareflank 3.0. For now, you might want to consider one of our offical releases until Bareflank 3.0 is complete .

The Bareflank Hypervisor is an open source hypervisor Software Development Toolkit (SDK), led by Assured Information Security, Inc. (AIS), that provides the tools needed to rapidly prototype and create your own hypervisor.

Most people think that hypervisors are meant to virtualize servers and provide a means to run Windows on a Mac, but there is a whole field of research where hypervisors are used without guest virtual machines. Since a hypervisor is capable of controlling the host OS running underneath it (so-called "ring -1"), host-only hypervisors support introspection, reverse engineering, anti-virus, containerization, diversity, and even architectural research like [MoRE](https://github.com/ainfosec/MoRE). All of these use cases start the same way, by spending months standing up the hypervisor itself before you can start working on your actual project. Existing open source hypervisors are burdened with legacy support, only support a single operating system or contain unnecessary complexity that make them painful to work with when conducting hypervisor research.

Instead, Bareflank uses a layered, modular approach, that lets you pick just how much complexity you need in your project:
- [BSL](https://github.com/Bareflank/bsl): provides a header-only, AUTOSAR compliant implementation of a subset of the C++ Standard Library, used to implement Bareflank's C++ components ensuring Bareflank and projects built using Bareflank can support critical systems applications like Automotive.
- [LLVM](https://github.com/Bareflank/llvm-project): provides our custom implementation of the LLVM Clang compiler and associated tools including additional static analysis checks in Clang Tidy to ensure compliance with AUTOSAR.
- [PAL](https://github.com/Bareflank/pal): provides auto-generated intrinsics APIs for Intel, AMD and ARM on any combination of OS (e.g., Windows and Linux), ABI (e.g., SysV and MS64) and programming language (e.g., C, C++ and Python).
- [hypervisor](https://github.com/Bareflank/hypervisor): provides the base SDK including the loader, the Bareflank microkernel and support applications. If all you need is host-only hypervisor support, this is the project to start with.
- [MicroV](https://github.com/Bareflank/microv): provides support for guest VMs, allowing the user to create an execute additional virtual machines. If you need guest VM support, this is the project to start with.

To support Bareflank's ecosystem, the hypervisor SDK is licensed under MIT, specifically enabling users of the project to both contribute back to the project, but also create proprietary, closed source products that use the Bareflank SDK as their foundation. Feel free to use Bareflank to create your commercial products. All we ask is that if you find a bug or add a feature to the SDK that you consider contributing your changes back to the project.

## **Quick start**
![GitHub release (latest by date)](https://img.shields.io/github/v/release/bareflank/hypervisor?color=brightgreen)

Get the latest version of the Bareflank Hypervisor SDK from GitHub:

```bash
git clone https://github.com/bareflank/hypervisor
mkdir bsl/build && cd bsl/build
cmake -DCMAKE_CXX_COMPILER="clang++" ..
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
the following videos at [CppCon](https://www.youtube.com/user/CppCon) below:

[![CppCon 2019](https://i.imgur.com/hjZg0pf.png)](https://www.youtube.com/watch?v=bKPN-CGhEC0)
[![CppCon 2017](https://i.imgur.com/nBFD6uA.png)](https://www.youtube.com/watch?v=KdJhQuycD78)
[![CppCon 2016](https://i.imgur.com/fwmlOiJ.png)](https://www.youtube.com/watch?v=uQSQy-7lveQ)

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
git clone https://github.com/bareflank/bsl
mkdir bsl/build && cd bsl/build
cmake -DCMAKE_CXX_COMPILER="clang++" -DBUILD_EXAMPLES=ON -DBUILD_TESTS=ON ..
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
git clone https://github.com/bareflank/bsl
mkdir bsl/build && cd bsl/build
cmake -DCMAKE_CXX_COMPILER="clang++" -DBUILD_EXAMPLES=ON -DBUILD_TESTS=ON ..
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

## **Resources**
[![Join the chat](https://img.shields.io/badge/chat-on%20Slack-brightgreen.svg)](https://bareflank.herokuapp.com/)

The Bareflank Support Library provides a ton of useful resources to learn how to use the library including:
-   **Documentation**: <https://bareflank.github.io/hypervisor/>
-   **Examples**: <https://github.com/Bareflank/hypervisor/tree/master/example>
-   **Unit Tests**: <https://github.com/Bareflank/hypervisor/tree/master/test>

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
-   **Coding Standards**: [AUTOSAR C++14](https://www.autosar.org/fileadmin/user_upload/standards/adaptive/17-03/AUTOSAR_RS_CPP14Guidelines.pdf) and [C++ Core Guidelines](https://github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md)
-   **Style**: Clang Format
-   **Documentation**: Doxygen

## Serial Instructions
On Windows, serial output might not work, and on some systems (e.g. Intel NUC),
the default Windows serial device may prevent Bareflank from starting at all.
If this is the case, disable the default serial device using the following:
```
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Serial" /f /v "start" /t REG_DWORD /d "4"
```

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
