# Bareflank Hypervisor 2.0 Roadmap

## Summary

Version 2.0 of the Bareflank hypervisor will provide the following:
* Support for Both Type 1 and Type 2
* Support for launching multiple, basic guests (i.e. no guest OS support)

Note that this roadmap assumes that the main goals for version 1.0 have 
been completed, prior to the work under this roadmap being started. 
The stretch goals from version 1.0 are optional. 

## Type 1 and Type 2 Support

Version 1.0 of the Bareflank hypervisor provided basic support for a Type 2
hypervisor. Version 2.0 aims to improve upon that initial design by adding
support for Type 1.

<figure><img src="https://raw.githubusercontent.com/Bareflank/hypervisor/master/doc/roadmap/v2.0/type_2.png" alt="type_2"></figure>

A type 2 hypervisor is a hypervisor that is launched after the host operating
system has already been loaded. Type 2 hypervisors can be much easier to
setup and launch, as the host operating system takes care of a lot of the
initial setup of the system. Type 2 hypervisors, typically, do not use their
own schedulers, but instead rely on the host operating system's scheduler to
tell the hypervisor when it should execute different guests.

The main disadvantage to a type 2 hypervisor is the fact that the hypervisor
has to trust that the host operating system has not been compromised.
Although there are mechanisms to assert this trust, the process is far from
optimal. Type 2 hypervisors are usually also bloated, typically requiring a
much larger host operating system to function (as the user generally has
access to the host operating system, KVM being a good exception to this
generalization). Type 2 hypervisors are also less efficient as they are
designed to act as applications in the host operating system, and thus disable
virtualization on each host context switch.

<figure><img src="https://raw.githubusercontent.com/Bareflank/hypervisor/master/doc/roadmap/v2.0/type_1.png" alt="type_1"></figure>

A type 1 hypervisor loads the hypervisor first, and then launches a _control_
guest virtual machine. This virtual machine (although restricted) has access
to the physical hardware, and is capable of starting / stopping less
privileged virtual machines. The best example of this architecture is the Xen
hypervisor, but others exist (e.g. VMWare ESXi).

Type 1 hypervisors solve a large majority of the issues encountered with type 2
hypervisors. Since the hypervisor loads first, it only needs to validate
itself, reducing the trusted computing base. Since the hypervisor has it's
own scheduler, it is in control of itself, and each guest operating system,
generally resulting in better performance. Since the user does not require
access to the control guest virtual machine, the hypervisor as a whole can
be less bloated, as this virtual machine can be created using embedded
operating systems (e.g. OpenEmbedded).

The main disadvantage to type 1 hypervisors is they are more complex. The best
example of this is KVM vs Xen. The KVM hypervisor is simple. Since KVM runs
the Linux operating in the Virtual Machine Monitor (VMM), KVM does not need
to provide a scheduler, memory manager, device drivers or power management
(at the expense of an insanely huge trusted computing base, and reduced
performance). The VMM code itself simply needs to manage hardware virtualize
extensions (e.g. Intel's VT-x, VT-d). The Xen hypervisor on the other hand
(being type 1), must provide a scheduler, memory manager, basic set of
device drivers, and power management. Amazingly, the Xen hypervisor is able
to provide this functionality in less then 150K lines of source code
including support for Intel and ARM, while also providing support for both
hardware virtualization, para-virtualization and a full tool-stack, thus
providing proof that a type 1 hypervisor is attainable.

Version 2.0 of the Bareflank hypervisor in addition to type 2 support,
will add support for type 1. To accomplish this, the hypervisor will include
support for:

- Basic EFI driver entry
- Basic interrupt injection
- Basic memory manager (non-optimized page pool)
- Basic scheduler
- Basic power management (halt on complete)

To launch the hypervisor, an additional driver entry will be added that
supports EFI. The Bareflank hypervisor will not have support for legacy BIOS
and therefore will not support GRUB. The boot process for EFI will
consist of the following:

<figure><img src="https://raw.githubusercontent.com/Bareflank/hypervisor/master/doc/roadmap/v2.0/efi_boot_process.png" alt="efi_boot_process"></figure>

Normally, EFI locates the operating system's boot image on the filesystem
or additional drive. The Bareflank hypervisor's additional EFI based driver
entry will be loaded by EFI instead, and then Bareflank will use EFI's
LoadImage and StartImage functions to load an operating system of it's choice
(either on the filesystem, or on another form of media). Using this
chain-loading process, Bareflank will be capable of loading first, and
modifying the EFI environment as needed to boot an operating system in a
control virtual machine.

[LoadImage](http://wiki.phoenix.com/wiki/index.php/EFI_BOOT_SERVICES#LoadImage.28.29) <br>
[StartImage](http://wiki.phoenix.com/wiki/index.php/EFI_BOOT_SERVICES#StartImage.28.29)

Once the Bareflank hypervisor is loaded, it will need to carve out memory
for itself. This process is much easier to do from EFI than it is from a
host operating system in a type 2 setting. In a host operating system,
gaining access to large amounts of physical memory is actually quite
difficult. Non-paged pools of memory are hard to find in the kernel (
especially when a guest operating system might want gigs of memory). For
this reason, type 2 hypervisors (including Bareflank) need to run an
application in the host for each guest virtual machine and ask for memory
from as a user space application. The problem is, user space memory is
neither contiguous, nor available (i.e. this memory can be paged out).
Thus the memory manager must provide support for identifying when memory is
swapped out.

With type 1, Bareflank will be capable of simply carving out how much
memory it wishes to provide the control virtual machine using EFI's
AllocatePages function. By allocating pages, Bareflank can reserve as
much memory as it needs, only providing the control virtual machine with
as much memory as it is configured to have. Worst case (assuming this
method is not sufficient), Bareflank can hook the GetMemoryMap function
and return a modified memory map to the control virtual machine to carve
out the memory resources it requires.

[AllocatePages](http://wiki.phoenix.com/wiki/index.php/EFI_BOOT_SERVICES#AllocatePages.28.29) <br>
[GetMemoryMap](http://wiki.phoenix.com/wiki/index.php/EFI_BOOT_SERVICES#GetMemoryMap.28.29)

To create the EFI base driver entry, Bareflank will use the GNU-EFI build
environment.

[GNU-EFI](http://sourceforge.net/projects/gnu-efi/)

The GNU-EFI build environment provides a means to create and compile EFI
applications using the GNU compiler toolchain. It is likely that in order to
support this toolchain, a second, EFI based cross-compiler will need to be
created as most existing GNU environments do not include EFI support by
default. Using this build environment, the overall dependency tree will be
minimized as a full-blown TianoCore EFI build environment is massive, and
overkill.

## Guest Support

Version 1.0 does not have support for guest virtual machines. Version 2.0
aims to remove this limitation by adding basic support. With respect to
hardware virtualization, a guest virtual machine is nothing more than an
additional hardware state (e.g. Intel's Virtual Machine Control Structure).
Thus starting another guest is as simple as loading a second CPU state.

As soon as a second CPU state is added to the picture however, the complexity
of the hypervisor itself increases. If the guest virtual machine needs to
execute continuously (for example, it has a lot of work to do), the hypervisor
must provide a scheduler to divide up the CPU's time between the control
virtual machine and the other guest virtual machines that are running. It is
also likely that the guest virtual machine will need resources such as
memory and access to more than on CPU.

The goal of version 2.0 is to solve these problems. In order to do this,
the hypervisor will require a scheduler that is capable of providing access to
each physical CPU to each of the different virtual machines that is executing.
This is not a simple problem, and a great deal of time must be spent on how to
design a scheduler API that is capable of supporting more than one way to
approach this issue. For example, a fair scheduler might create a virtual
CPU state for each virtual CPU (vCPU) that is given to a guest. Each vCPU
would then be added to a worker queue that each physical CPU works from to
service all of the virtual machines. A real-time scheduler however would
likely create a subset of vCPUs for each virtual machine, and then provide
guaranteed time for each virtual machine to the physical CPUs given a
pre-defined interval. Since Bareflank is meant to be a research platform,
it's less important that the default schedulers are flawless, and more
important that the API is capable of supporting more than one type of
scheduler. Therefore, version 2.0 will provide basic support for a round-robin
scheduler, as well as a basic real-time scheduler. Doing so will ensure the
API is robust to different approaches.

Version 2.0 will also provide a basic memory manager. Virtual memory has a
tendency to become fragmented over time (as memory is used, and then
released), and thus most operating systems create different pools of memory
that keep memory better organized to prevent fragmentation. The memory
manager in this version will not support different memory pools, but the
API will not prevent such improvements in the future. Instead, the
hypervisor will use a basic memory pool designed to simply the implementation
of the hypervisor's memory virtualization (e.g. Intel's EPT). The largest
complication will come from Bareflank's type 2 requirements, which will need
to be capable of monitoring when a page of memory is swapped out by the
host operating system. To ensure this works correctly, the memory manager
will include unit tests that both emulate this type of environment, but also
test in the supported operating system, when memory is swapped to ensure
safety.

Most hypervisors are capable of executing complete operating systems as
guest virtual machines. To accomplish this, the hypervisor must include what
is commonly known as a device model (e.g. QEMU). A device model emulates
various physical devices that an operating both expects, and needs to operate.
Each operating system is different in it's needs. For example, Linux can be
configured with little to no device requirements, while Windows expects
a relatively complete environment including support for a basic motherboard,
disk, network and graphics. This version of Bareflank will not support a device
model (leaving this problem to be solved in future versions). Instead, this
version of Bareflank aims to provide all of the support needed to launch
a guest virtual machine up-to the device model, solving the rest of the
virtual machine's dependencies and providing a more sane approach to eventually
supporting a full-blown operating system.

## Tasks

The following defines the high level tasks that this project would prefer to
see in version 2.0. These tasks are in no particular order (i.e. they may be
completed in any order), and some of these tasks may be pushed to future
released if needed.

### Required Tasks for Version 2.0

* EFI cross-compiler scripts (Rian Quinn)
* EFI test application (Rian Quinn)
* EFI driver entry (Rian Quinn)
* EFI driver entry documentation (Rian Quinn)
* EFI driver entry usage documentation for Linux (Rian Quinn)
* EFI cross-compiler Linux documentation (Rian Quinn)
* EFI memory allocation (Rian Quinn)
* Type 1 launch Linux (Rian Quinn)
* Linux type 1 usage documentation (Rian Quinn)
* Linux type 1 compilation documentation (Rian Quinn)
* Linux type 1 installation documentation (Rian Quinn)
* Type 2 memory management (Brendan Kerrigan)
* Type 2 guest support (Brendan Kerrigan)
* Type 2 launch Linux (Brendan Kerrigan)
* Linux type 2 usage documentation (Brendan Kerrigan)
* Linux type 2 compilation documentation (Brendan Kerrigan)
* Linux type 2 installation documentation (Brendan Kerrigan)
* Memory manager (Rian Quinn)
* Round robin scheduler (Rian Quinn)
* Real-time scheduler (Brendan Kerrigan)
* Round robin scheduler documentation (Rian Quinn)
* Real-time scheduler documentation (Brendan Kerrigan)
* API documentation (Rian Quinn / Brendan Kerrigan)

### Stretch Goals

* EFI driver entry usage documentation for Windows
* EFI cross-compiler Windows documentation
* Windows type 1 usage documentation
* Windows type 1 compilation documentation
* Windows type 1 installation documentation
* Windows type 2 usage documentation
* Windows type 2 compilation documentation
* Windows type 2 installation documentation
* Type 1 Launch Windows
* Type 2 Launch Windows

## Schedule

Note that this schedule assumes roughly 6 months of work for 2 developers.
The project spans one full year, and thus, milestones are calculated in
man months, as the date in which these milestones are reached cannot be
defined (since start dates are not defined)

High Level Milestones
* Development: January 2016 - December 2016
* Feature Freeze: November 2016
* Final Release: January 2017
* Demo Type 1: June 2016
* Demo Type 1 with Guest Support: December 2016
* Demo Type 2 with Guest Support: December 2016

Finer Grained Milestones
* Milestone (1.0 months): EFI environment complete
* Milestone (1.0 months): Type 1 launch control VM complete
* Milestone (0.5 months): Type 1 memory manager complete
* Milestone (0.5 months): Round robin scheduler complete
* Milestone (2.0 months): Type 1 launch guest VMs complete
* Milestone (1.0 months): Type 1 documentation complete
* Milestone (1.0 months): Type 2 launch control VM complete
* Milestone (1.0 months): Type 2 memory manager complete
* Milestone (0.5 months): Real-time scheduler complete
* Milestone (2.5 months): Type 2 launch guest VMs complete
* Milestone (1.0 months): Type 2 documentation complete
