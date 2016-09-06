# Bareflank Manager (BFM)

## Description

The Bareflank manager (BFM) is the userspace application responsible for managing the VMM. BFM communicates with the driver entry point to tell the driver to load, start, stop and unload the VMM. It also is capable of getting the VMM's status, and dumping debug information from the VMM.

## How It is Used

BFM itself is a simple, userspace application, written in C++ designed to be cross platform, and simple to use. It is however not intended to be the only application to talk to the driver entries, but rather the console based application that is officially supported by the Bareflank project. BFM is made up of a couple components:
- The command line parser
- IOCTL interface
- IOCTL driver

The command line parser is responsible for taking in the command line arguments passed to BFM, and decide what the user is looking to do. The IOCTL interface is an abstraction of the IOCTL interface the driver entries provide. Each driver entry has to provide it's own set of IOCTLs (for example, an IOCTL to a Windows driver is vastly different than one to a Linux driver), but the interface that BFM wants to drive can be common. Thus, the IOCTL code converts the BFM IOCTL interface to the different driver entry IOCTLs, and as can be seen by the code, there is one IOCTL interface per supported OS.

The IOCTL driver takes the command line parser, and drives the IOCTL interface based on what the command line parser is stating the desired action is. Note that the IOCTL driver also asks the VMM what it's current status is, and will cleanup it's state accordingly. For example, if the VMM is currently started, and the user asks to start the VMM, BFM will stop the VMM, and then start it again. This is great for developers as it provides a simple means to work quickly.

## Notes

At some point in the distant future, we intend to provide GUI support for Bareflank in addition to the console application. Although the console application is great for development, it's terrible for demonstrations which are sometimes critical when pursuing funding for research. Once the critical components of Bareflank are complete, extensible GUI support will be provided to further reduce the barrier to entry for hypervisor research.

Since BFM talks to the kernel, root privileges are required. This can make things a little frustrating in Linux as you have to elevate privileges and tell Linux where the libraries are located, as well as provide which options you want to run. To simplify this, the root repo provides some "make xxx" commands that can easily be run to execute BFM without having to type these commands in constantly. If these shortcuts are not sufficient, the user is encouraged to create their own scripts above and beyond what Bareflank already provides.
