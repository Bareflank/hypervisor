## Table of Contents <!-- omit in toc -->

# 1. Introduction

This document defines all of the security features that have been added to the design of the Bareflank Microkernel.

# 2. Features

TBD

# 3. Remaining Todos

The following documents all of the security related features that the microkernel still has to implement.

## 3.1. Meltdown
The microkernel currently doesn't protect against Meltdown. This is a problem because one of the goals of being able to support multiple user-space applications is so that we can create a vTPM app that stores vTPM secrets. This would dramatically improve the overall security of a vTPM as it would ensure that only that user-space application and possibly the microkernel can see the secrets in the vTPM, something other hypervisors will struggle with. If other user-space applications can use Meltdown to access these secrets, we have a problem.

There are basically two different ways to prevent this. We could either unmap all of the memory from the microkernel that we hand out to the user-space application, or we could set up a different CR3 between the kernel and the user-space application.

There are several issues with the first approach. First, the process of unmapping is slow, and causes issues with shootdowns, something the microkernel cannot really do as it has no way to IPI itself. The other issue is the microkernel doesn't have the ability to walk it's own page tables. It can only walk the page tables that are allocated for user-space. As a result, it cannot unmap. To solve this, we need to modify the loader to direct map all microkernel memory, including the memory used to store the microkernel's page tables. Since this is recursive, there are issues with running out of stack space in the kernel. In general, although this approach would be extremely effective, and generally faster during normal runtime operations, it is not a great solution and would add a lot of extra complexity.

The second option would be to provide a different CR3 for the microkernel. We already have this CR3, it is the m_system_rpt. We simply need to remove the microkernel aliases from the other RPTs that the extensions use, and then load the m_system_rpt whenever an extension is done executing, which includes the execute() function, the syscall dispatch logic, and the ESR logic (basically anywhere user-space can enter/exit the microkernel from). The problem with this approach is everything is currently marked as global inside the kernel to reduce the overhead of constantly swapping CR3. The global flag would have to be turned off (done in the loader), and we would need something like PCID to prevent the implementation from being insanely slow.

Adding a PCID requirement would severally limit which CPUs this code supports, especially on AMD which added this feature in Zen 3.

For now, we leave this security hole unpatched, but once we attempt to implement a vTPM, this issue should be resolved, and we will either have to implement option #1, or implement option #2 and deal with the massive performance hit systems will take that do not have PCID support.

## 3.2. Transient Execution Attacks
We need to complete any remaining patches for transient execution attacks. Current we have implemented retpoline, and the user-space direct map implementation should mitigate L1TF style attacks. Attacks like MDS are best handled by disabling HyperThreading or purchasing hardware that is not vulnerable to this style of attack. Besides Meltdown which is described above, we might have some others that still need to be completed.

## 3.3. Extension Physical Memory Mapping
We currently do not prevent user-space from mapping in any physical address. This means that a user-space application can map in memory from the microkernel or some other user-space application.

This is obviously an issue, and the solution is not simple. The microkernel has no idea what physical addresses are that it controls as it is given random physical memory from the loader.

There are basically three options to solve this issue. The first option is to walk the page tables of all extensions and the microkernel to see if the physical page that a user-space application is trying to map is owned by the hypervisor. If it is, it should never be mapped by the user-space application. The second approach is to only enable this security feature for the hypervisor when UEFI is used to load the hypervisor. In this case, the loader could be modified to allocate one giant block of memory for everything and then pull from this block of memory as it needs it. The address and size of this block of memory could then be given to the microkernel, and it could determine if a map is valid or not using a simple comparison. The third option is to store a list that contains all of the physical addresses that the hypervisor was provided by the loader. This is essentially how the older version of Bareflank works. This would require some sort of data structure to store this memory, and obviously would use a fair amount of memory itself just to store the physical address list, but would work for any loader. The downside to this approach is determining if a physical address is in the list would likely require the data structure to be a hash table, which we would have to implement from scratch.

Since the Windows/Linux loaders are only intended for developers, the second approach should work great and solve this problem in a way that is both fast, and simple. The only trick is ensuring that the loader pulls all of it's allocations from a single, contiguous block. For example, it could use the page pool argument in the start_vmm to determine the total number of pages that are allowed to be used by the entire hypervisor, and then all allocations come from that specific page pool. Any memory left is given to the microkernel as it's page pool. This would not only ensure a simple means to implement this feature, but it would also provide a nice way to reason about how much memory the hypervisor is using as the page pool would account for all memory allocated, including by the loader which it currently doesn't.

For now, this security issue is left unpatched.

## 3.4. KALSR
We currently do not implement KASLR like we did in the previous version of the hypervisor. To implement this, all addresses should have some random entropy added to them.

Specifically, all of the hypervisor constants are still needed, but we need to simply add some entropy to these values to ensure they are not fixed. The only constants that do not need entropy are the direct map constants as these are based on the size of 4-level paging and must remain fixed.

The other requirement that will be needed to make this work is ensuring that the microkernel and all of it's extensions are compiled as static PIE binaries. We still want "static" compilation because adding support for dynamic libraries would cause issues not only with the overall complexity, but also with retpoline as the PLT that is needed would have to run through an out-of-line retpoline which is not good for performance.

Like the old code, the ELF loader should always perform all relocations when the ELF is loaded (meaning lazy loading should not be implemented). In general, this security feature should be relatively easy to implement since we have already done it once before. The hardest part will be finding a way to generate random numbers.

## 3.5. Hardware Security Features
There are some additional kernel level security features that both Intel and AMD continue to implement that we have not yet implemented. We really should do a complete analysis of all of these features and make sure they are turned on when they can be.

It should be noted that some of them might be due to how the loader works. If any of the bits in CR0/CR4 are turned on, it is likely that the microkernel will inherit these features (which could also cause issues with support for future CPUs). Others like clearing the L1 cache that use MSRs need a full review and implementation where it makes sense.

One exception to this is SMAP. Right now, even if the loader attempts to enable SMAP (which it likely will), we set the RFLAGS to set SMAP disabled at all times. This is done by making sure that FMASK doesn't clear AC, that AC is set in the dispatch and ESR entry points, and that when calling into an extension using call_ext, that AC is disabled as unaligned memory accesses are performed all the time by the compiler which we don't really have control of. This was done to simplify the microkernel's assembly logic, but at some point this will need to be enabled, and we will have to have some way of determining if and when the SMAP instructions should be used depending on what hardware the system is on. Another option would be to simply set RFLAGs manually without using these new instructions. This would allow SMAP to be used on all hardware (as AC is not used in the microkernel, so changing it has no effect). Option #2 is likely the better solution as even the Linux kernel has struggled with this issue since userspace memory access has to occur in areas where performing a feature check is non-trial.

Finally, non of these features are turned on in the UEFI loader, and they should be. Basically, once we know what all of the security features are, and how to turn them on, we need to add this logic to the UEFI loader so that it can ensure the system is as secure as possible. 

## 3.6 Support For Multiple Extensions
The microkernel already has a bunch of logic for handling more than one extension, but the main feature missing is IPC ABIs and the ability for one extension to signal another (which is the method for getting more than one extension to execute since we don't have a scheduler). Once multiple extensions are supported, downstream projects like MicroV can break their logic into different extensions which provides several security benefits. There is more details about how this would work in the ext_t.hpp file.

One detail that MicroV will need to pay attention to once it has more than one extension is how much memory the PV and emulation extensions are using. Ideally, these extensions (which has a communication path to a VM and are thus the first line of defense), should limit how much memory it maps in to as little as possible. They should also be prevented from executing syscalls as much as possible (see below). Again, if these extensions that communicate directly with the VM are ever compromised, or used as a path for transient execution attacks, keeping their access to data and syscalls to a minimum might result in the attack failing overall.

## 3.7 Syscall Policy
Once multiple extensions are supported, a syscall policy should be implemented to determine which extensions should be allowed to execute specific syscalls. This could then be used to prevent an emulation or PV extension (basically any extension that talks to a VM) from being able to perform certain actions that could further improve security.
