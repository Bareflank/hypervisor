# Bareflank Drivers

## Description

The Bareflank drivers (also referred to as the driver entries), are the drivers that load, start, stop, and unload the VMM. The only reason the driver entries are needed is because hypervisor code requires ring 0 to execute (one reason why Apple has created a userspace API for managing hypervisors in ring 3 in OS X). Thus, the driver entries are designed specifically to be as small as possible, with the only code being the IOCTL interface that BFM uses to communicate with the driver entry, as well as the ELF loader used to load and execute the VMM. 

## How It is Used

A Bareflank driver consists of the host OS specific part, and the common.c part. On Linux, this is:

[Linux entry.c](https://github.com/Bareflank/hypervisor/blob/master/bfdrivers/src/arch/linux/entry.c)
[Common](https://github.com/Bareflank/hypervisor/blob/master/bfdrivers/src/common.c)

The host OS part could be from a host OS like Windows or Linux, but also could be a boot environment like UEFI (or BIOS/GRUB if you so inclined to provide legacy support). The common.c part is the bulk of the driver entry, and this code is shared between all of the driver entries, and comes complete with it's own unit test. 

When BFM IOCTL's to the driver entry, the host OS part receives the IOCTL, and calls the associated common_xxx logic. Anything that must be done that is host OS specific must be done in the host OS part. For example, currently, Bareflank uses the CR3 page tables setup by BFM when it executes. These page tables are destroyed when BFM finishes it's execution, but are still being used by the VMM (a limitation that will be addressed in version 1.1). To prevent the page tables from being destroyed, the Linux entry.c saves the BFM context, which must be done outside of the common source code. 

[save context](https://github.com/Bareflank/hypervisor/blob/master/bfdrivers/src/arch/linux/entry.c#L200)

To support the unit test for the common.c part, a set of dummy VMM modules were created, each of which provide dummy symbols for required VMM functionality, providing a means to test different combinations for issues that can occur. For example, one test combination loads a set of dummy modules, specifically leaving out a module that has a required symbol, causing the common.c code to enter an error state, and prove that it can handle the error. 

## Limitations

At the moment, the single biggest limitation with the driver entries is the lack of being able to extend them with custom functionality. Since the driver entry is really just a BFM to VMM communication mechanism, our goal is to provide a driver entry that has support for custom messages to the VMM (likely via a hypercall interface to start, but will likely provide more than that in the future). 

The driver entries currently do no support multi-core (being addressed in version 1.1), and the driver entries have to save the user space page tables as the VMM does not create it's own (also being addressed in version 1.1). 

## Notes

One issue that you will notice while developing in Bareflank is that a bug in the VMM does not translate well to kernel debuggers. This is because we are manually bootstrapping the VMM's environment inside the kernel, so the kernel has no clue what the VMM code is, or how to handle it when an error occurs. This is why developing with serial, or some other external debugging mechanism (like a PCI debugger) is critical. In some cases, if you do get a valid address as the cause of the error, you can sometimes use that information to figure out where in the code VMM code the crash happened. 
