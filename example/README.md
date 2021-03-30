# Description

The goal of each of these examples is to provide a starting point for creating your own extensions. For more information about how to create your own extension, please see [Writing Your Own Extensions](https://github.com/Bareflank/hypervisor#writing-your-own-extensions).

## example_default

This example provide the minimum extension that is needed to start/stop the hypervisor. In other words, this is your typical "Hello World" example. If you plan to implement everything yourself, this is a good starting point. This example is also the "default" example if you don't specify an extension manually in the build system.

## example_rdtsc
TBD - demonstrates how to hook the execution of the RDTSC and RDTSCP instructions.

## example_msr
TBD - demonstrates how to hook the execution of specific MSR instructions using the MSR bitmap.

## example_cr
TBD - demonstrates how to hook the execution of the control registers and properly emulate their execution, including how to hide certain bits from the OS using the control register shadows.

## example_io
TBD - demonstrates how to hook the execution of port IO instructions.

## example_ept
TBD - basic EPT example including how to handle the MTTRs on Intel. Just enough to turn EPT on.

## example_uefi
TBD - Provides enough EPT, Unrestricted Guest Support, CR0/CR4 and INIT/SIPI logic to start the hypervisor from UEFI and then boot Windows/Linux

## example_interrupts
TBD - Provides an example of how to trap on external interrupts and inject them back into the root OS.

## example_ddimon
TBD - Provides an example with functionality similar to DdiMon from HyperPlatform, capable of hooking kernel level functions and monitoring there execution.
