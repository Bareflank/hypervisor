# Bareflank Drivers

## Description

The Bareflank drivers (also referred to as the driver entries), are the drivers that load, start, stop, and unload the VMM. The only reason the driver entries are needed is because VT-x code requires ring 0 to execute (one reason why Apple has created a userspace API for managing hypervisors in ring 3 in OS X). Thus, the driver entries are designed specifically to be as small as possible, with the only code being the IOCTL interface that BFM uses to communicate with the driver entry, as well as the ELF loader used to load and execute the VMM.

## How It is Used

A Bareflank driver consists of the host OS specific part, and the common.c part. On Linux, this is:

[entry.c](https://github.com/Bareflank/hypervisor/blob/master/bfdrivers/src/arch/linux/entry.c)
<br>
[platform.c](https://github.com/Bareflank/hypervisor/blob/master/bfdrivers/src/arch/linux/platform.c)
<br>
[common.c](https://github.com/Bareflank/hypervisor/blob/master/bfdrivers/src/common.c)

The common.c part is the bulk of the driver entry, and this code is shared between all of the driver entries, and comes complete with it's own unit test. When BFM IOCTL's to the driver entry, the driver entry receives the IOCTL, and calls the associated common_xxx logic. Anything that must be done that is host OS specific must be done in the "arch" portion of the driver.

To support the unit test for the common.c part, a set of dummy VMM modules were created, each of which provide dummy symbols for required VMM functionality, providing a means to test different combinations for issues that can occur. For example, one test combination loads a set of dummy modules, specifically leaving out a module that has a required symbol, causing the common.c code to enter an error state, and prove that it can handle the error.

## Notes

One issue that you will notice while developing in Bareflank is that a bug in the VMM does not translate well to kernel debuggers. This is because we are manually bootstrapping the VMM's environment inside the kernel, so the kernel has no clue what the VMM code is, or how to handle it when an error occurs. This is why developing with serial, or some other external debugging mechanism (like a PCI debugger) is critical. In some cases, if you do get a valid address as the cause of the error, you can sometimes use that information to figure out where in the code VMM code the crash happened. To facilitate this, the driver prints the location and size of each module that is loaded and executed which can be used with objdump to locate the instruction that might have caused an issue. 
