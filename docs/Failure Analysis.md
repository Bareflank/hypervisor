## Table of Contents <!-- omit in toc -->

# 1. Introduction

This document defines how failures are handled by the microkernel and what the expected results are.

# 2. Starting

TBD

# 3. Stopping

TBD

# 4. Syscalls

When a syscall is executed it is possible that the microkernel could generate a hardware exception and fail to execute the syscall. If this occurs, the microkernel is designed to return back to the extension with an error code stating that the call to the microkernel failed.

If a syscall returns BF_STATUS_FAILURE_UNKNOWN, it should be assumed that either an unexpected error has occurred, or a hardware exception has occurred. In either case, the following are the expectations that an extension can make about any given syscall:

# 4.1 Resource Creation

Any syscall that creates a resource like bf_vm_op_create_vm, bf_vm_op_create_vp and bf_vm_op_create_vs will leave the internal state of the microkernel the way it was prior to an error. This includes if a hardware exception occurs while attempting to execute the syscall (excluding exceptions like a Machine Check which are unrecoverable by design). It is up to the extension to determine how to proceed. For example, if the extension is implementing guest support and a creation fails for whatever reason, the extension may choose to stop everything, or it may choose to continue the execution of any existing virtual machines and simply fail to create a new one.

# 4.2 Resource Destruction

Resource destruction is way more complicated than resource creation. When we create a resource we are simply taking a clean, unused resource and assigning it so the hardest part about creation is resource starvation. Destruction on the other hand has the following conditions that we need to handle:
- Attempting to destroy resources that were never created or cannot be created. For example, if you attempt to destroy a resource that you never created in the first place, destroying a resource that is above the max allowed, or is invalid.
- Attempting to destroy a resource that is still in use.

In both cases, we need to ensure the microkernel can continue execution without getting into a corrupt state. Any attempt to destroy a resource that was never created or cannot be created will just output an error and move on as there is no state to reverse. If an extension attempts to destroy a resource that is still in use, the extension would be creating a use-after-free bug. Most kernels would just allow the userspace application to crash, become corrupt, etc, but since this is a hypervisor, we need to try to survive this case. To handle this, the microkernel will mark the resource as a "Zombie".

A zombie resource is any resource that is still in use that an extension tried to destroy. When this happens, the microkernel will not allow the resource to be used. What this means is that any attempt to make a syscall using the ID of a zombied resource will fail. To understand why, think about free() with a memory address that is still in use. Once an extension makes the decision to free a resource, it should never, ever try to use it. The microkernel's job is not to magically allow a freed resource to still be usable, but instead to ensure that it doesn't crash while an extension is in this state.

A zombie resource cannot be recovered. For example, if an extension tries to destroy a resource that is still in use, and then realizes it should ensure all other resources are removed first and no longer in use, it cannot then turn around and destroy the zombie resource to get it back. Once a resource is destroyed, it is destroyed. The zombie status is used by the microkernel to say that the resource has been leaked, don't touch it because we don't know how to proceed safely with it. Again, a the zombie status is not about magically providing a means for the extension to do really bad things. It is about providing a means to prevent the hypervisor from crashing which is what would normally happen if a use-after-free bug occurs.

