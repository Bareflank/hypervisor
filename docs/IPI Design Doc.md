# IPI Design Doc

The microkernel needs a way to IPI itself. For example, if an extension decides free a previously allocated page, the microkernel needs to flush the TLB on all cores to ensure the unmap process doesn't result in a use after free bug.

The problem is, the microkernel is not actually in charge of how virtualization is implemented. Userspace extensions are responsible for this action. This limits what the microkernel is able to use for performing an IPI.

## Options

The following documents the options available to the microkernel WRT to how it implements its own IPI mechanism.

### External Interrupts

The microkernel could IPI an external interrupt. This is the safest way to IPI another core. The problem is, the hypervisor doesn't own external interrupts in the type 1 case (it does in the type 2 case like KVM for example). In the type 1 case, the root OS (sometimes called the root partition or Dom0) owns all of the external interrupt vectors. If the hypervisor wants to use one of these vectors, it would either need to ask the OS for a vector, or it would need to steal a vector.

Asking for a vector has a lot of issues. It means that we must trust the root OS to never use this vector itself. It also doesn't help much while the root OS is booting because we would need a way to ask UEFI to give us a vector, and then from there hope this vector is not used by the OS until we have an opportunity to ask for the vector. This problem is easy to solve with a Linux root OS as we can simply hardcode (which is done today) a vector that we can use. On Windows, or some other random OS that we might want to support, this is a problem.

Stealing the vector is also problematic because we would need to ensure that no external devices are given the vector we decide to steal. With an IOMMU, we could remap a vector that we steal, but this would require that the microkernel is capable of setting up the IOMMU on its own, which again, the userspace extension should be doing, not the microkernel. This also doesn't help us on systems that either do not have an IOMMU, or devices that are not on the PCI bus that are still capable of firing an external interrupt like the APIC and HPET. In other words, this approach would require an enormous amount of emulation in the microkernel which it is not supposed to be doing.

### NMIs

We could use an NMI. On Intel, we cannot mask NMIs, and as a result, we are forced the handle them safely already. What this means is, if an NMI fires while the microkernel is running, it records this and turns on the NMI window, which extensions are required to implement on Intel. One AMD, NMIs are blocked using the global interrupt flag, meaning if an NMI were to fire, it is delivered to the guest on the next VMRun.

The biggest issue with using the NMI method is trying to determine if the NMI came from the hypervisor. NMIs are owned by the root OS. If more than one NMI fires, the second NMI is ignored. On Linux, this is a problem as NMIs fire all the time, which means that the chances of two NMIs colliding is possible. If this occurs while the hypervisor is in the process of handling an IPI, it would result in the NMI the OS is expecting to be dropped. Since NMIs are used by Linux to handle power management, this event would be a real problem.

### SMIs

Another option is to IPI an SMI. The problem with this approach is that on Intel, there is no way to trap SMIs. In fact, on Intel, if an SMI occurs, SMM is executed below the hypervisor. We can trap on SMIs on AMD, but an SMI using an IPI would be considered an external SMI, and on AMD, even after the trap, the SMI is held pending, so once you return back to the guest VM, the SMI will be delivered to the guest with no way to prevent this.

### INIT

Unlike all of the other interrupts discussed above, INIT is actually owned by the hypervisor. Meaning, unlike the other interrupts, the ability to reset a CPU is up to the hypervisor, and the hypervisor can decide how INIT is implemented. Rarely would a hypervisor actually wish to deliver an INIT to the guest VM and instead it would normally emulate INIT itself.

Both Intel and AMD support the ability to trap INIT. On Intel, INIT is trapped as it's own VMExit. From there, it is up to the hypervisor to emulate INIT. On AMD, you can let the guest handle INIT, or you can trap INIT. If you trap INIT, the INIT flag is held pending even after the exit. What this means is that once you enable the global interrupt flag, the CPU would be reset. To prevent this, you need to enable R_INIT in the VM_CR MSR. This tells the CPU to deliver the INIT to the CPU as an SX exception. If the SX exception is intercepted as well, it will result in a VMExit and the hypervisor can emulate INIT from there the same way it would for Intel.

The problem is when SX is delivered to the hypervisor while it is running, and this is really where the nightmare begins. The global interrupt flag doesn't block SX, so like an NMI on Intel, we have to handle it. There are two ways in which we could implement the SX handler:
- If we use an IST, we would end up with the microkernel state becoming corrupt if more than one INIT lands on the CPU in a short period of time. In other words, unless you want to roll the dice, using the IST is not an option.
- If we don't use an IST, it means that whatever stack the CPU is currently using will be used to handle SX. From the hypervisor point of view, this means the stack given to the microkernel, or the stack given to a userspace extension. Since the microkernel doesn't do much, most of the time will be spent in userspace, which means that we are likely to see a userspace stack more often than not.

If we take option #2, it means that we have to allow SX to write to the userspace stack. How this is done depends on two different scenarios:
- If SMAP is disabled, the userspace stack would be used without an issue. So long as there is enough stack space (including space for more than one SX exception), we are good. The biggest issue with this approach is anything the microkernel puts on the stack will be leaked to userspace. Bareflank implements the hypervisor in userspace to provide a clean way to support extensions, but one great side effect is we can design the system such that we do not need to trust userspace. Although this is not our primary goal, it is something we would like to achieve in time. What this means is we either need to trust userspace, or we need to ensure we don't use the stack when handling SX.
- If SMAP is enabled, an SX would immediately result in a Double Fault. Specifically, when the CPU would attempt to use the userspace stack, it would generate a page fault due to Ring 0 trying to use Ring 3 memory. The double fault handler however uses the IST, which means that any additional SX would not have a kernel stack to use instead of a userspace stack. What this means is that when SMAP is enabled, the CPU will never be allowed to use the userspace stack, and instead would have to execute from the double fault handler. With a carefully crafted double fault handler this may be possible.

## Intel Approach

## AMD Approach

Currently SMAP is disabled in the microkernel to ensure support on devices that do not support SMAP. This is done in two ways:
- On AMD, the loader disables SMAP in CR4.
- On Intel, this is not as simple as Intel requires certain CR4 bits to be enabled while VT-x is in use. It just so happens that on some CPUs, SMAP must be enabled in both the host and the guest state for VMLaunch to succeed (for example, some Atom processors do this). To mitigate this issue, the microkernel also ensures that whenever the microkernel is executing, the AC bit is set. This allows SMAP to technically be enabled, but not enforced.

With SMAP disabled, it means that we can use the userspace stack for the SX handler. There are two issues with this that we need to mitigate:
- We would need to trust userspace because kernel specific secrets would be stored on the userspace stack.
- We would need a pretty large userspace stack. Specifically, the stack would have to be large enough to handle normal userspace stuff, plus several SX handler workloads if they happen to pile on.

To mitigate these two issues, this approach will keep the SX handler as simple as possible. Specifically, it would do the following:

- inc gs:[sx_pending]
- if gs:[sx_lock] not set, jump to RIP in VMRun handler
- iret

The code above doesn't use the userspace stack at all. It is also quick, so the chances of SX happening more than once are small, but even if it did, there is no issue here. The only stack modifications using the code above are for the IRET instruction itself. Specifically, when the SX exception fired, microcode will place RIP, RSP, RFLAGS and CS/SS onto the stack. The amount of memory used is so small, it introduces very little risk of the stack running out of space, so issue #2 is addressed above. All we have left to worry about is issue #1. Since we were running in userspace, everything pushed to the stack is userspace specific information, so nothing is leaked.

Well.... that is not actually true. If two SX exceptions fire before we have an opportunity to execute even a single instruction, the kernel's RIP of the SX handler would be leaked. If we implement KASLR, this would provide userspace with a means to detect the location of the kernel. Do we care... no, and here is why:
- Due to how SWAPGS and NMIs do not play nice, we currently leak GS, so if we are ok with leaking GS for now, we should be ok with leaking RIP of the SX handler as well.
- Need be, we can move the SX handler around independent of where KASLR would have put the microkernel, meaning knowing where the SX handler is wouldn't mean you will know where the rest of the microkernel is.

Ok, so now that we have a way to handle SX, we still need a way to handle the state that SX is setting. Specifically, there are two things in the TLS block that SX is working with
- tls.sx_pending, like the tls.nmi_pending is used to signal that the SX handler has executed. Unlike tls.nmi_pending, tls.sx_pending is a counter so that we can determine if more than one SX handler has executed.
- tls.sx_lock is used to determine if we need to jump or not in the VMRun logic. Specifically, when this bit is set, the SX handler is only allowed to increment tls.sx_pending. When this bit is not set, it will jump to a different return path of the VMRun handler designed to return from VMRun with an INIT intercept exit. We need this bit to ensure that once we have checked to see if an SX handler was fired that if we get an SX exception between the check and when we actually call VMRun that we don't actually call VMRun and instead continue to process exits. Without this, if an SX exception were to fire between when we checked tls.sx_pending and when we execute VMRun, could result in an IPI that would not be serviced until the next VMExit. Since Bareflank is designed to support hypervisors that result in a VMExit infrequently, this could be a real issue, especially if a core is waiting for all of the other cores to sync up as that could produce deadlock. We also have to deal with the case of when VMRun returns with a real exit and when tls.sx_lock has not been set yet. If this occurs, as soon as the SX exception fires, we would end up with an exception because likely the TLS block has not even been loaded yet. 
