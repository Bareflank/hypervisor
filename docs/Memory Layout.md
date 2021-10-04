## Table of Contents <!-- omit in toc -->

# 1. Introduction

The question asked to most on the project by beginners is always, "I need to access memory from my application in the hypervisor, but when I dereference it, bad things happen", or at least something to that effect. This document aims to explain why, and how memory is layed out in Bareflank.

# 2. Address Translation

We will use x86 as our primary CPU architecture here, mainly because it is one of the most complicated, at least when it comes to translation, while ARM probably wins with respect to cache management, although I bet some would argue otherwise.

On x86, you have several different modes, and how an address is translated depends on the mode. Intel has many different names for an address including:
- logical
- effective
- virtual
- linear
- physical

To keep this simple, we are going to stick to 64bit mode, in which case, the following gross generalization will help tame the beast:

```
virtual --> linear --> physical
         |          |
         |          |
   segmentation   paging
```

To be clear, it is more complicated than this, and if you need to understand why something might no be working right, you will need to read and learn the different modes of operation including:
- 16bit real mode
- V8086 mode
- 32bit protected mode
- 32bit protected mode with paging
- 32bit compatibility mode
- 64bit long mode

And how each of these change how address translation works. The best way to learn this is to simply read Intel and AMD's manuals. Read both as they both share different interpretations which helps. Also, keep in mind that 64bit mode does NOT remove segmentation, contrary to what you will read online. GS, FS and the TSS all require segmentation.

So lets look at this simple example:

```
thread_local int my_var{};
auto my_ptr = &my_var;
```

The goal with this section is to answer the following questions:
- what is the value of my_ptr?
- how do I access my_ptr from an extension in Bareflank?

There is a ton more to talk about, but honestly we could write a book on nothing but this topic, so the goal is to keep this practical.

Under the hood, TLS on x86 is implemented using both segmentation and paging. Every userspace process has a consistent linear view of memory from 0 - MAX. This is done using paging, which is why we call these addresses linear. Paging allows an operating to create this linear view of memory using physical pages (i.e., physical addresses) that may not be contiguous. Meaning, address 0 might point to physical address 0x2000, address 0x1000 might point to physical address 0x4000 and address 0x2000 might point to physical address 0x1000. The operating system is free to reorder memory however it wants using paging to ensure that every userspace process sees a linear view of memory from 0 - MAX no matter how it is actually laid out in physical memory.

Thread local storage is a special case. Each thread is given it's own copy of a variable depending on which thread is executing. So reading the value of my_var on thread 1 will return a different result than reading the value of my_var on thread 2. But how does the program know which memory address to read? On x86, this is done using segmentation. When you access a TLS variable, the code under the hood reads and offset from FS. So for example:

```
mov rax, fs:[0x10]
```

When a thread changes, the OS changes the value of FS, which changes which memory location my_var is actually pointing to. From a hardware point of view, the CPU takes the value of FS and adds 0x10 giving it a linear address (again, skipping some details here). It then takes this linear address, and converts it to a physical address by walking the page tables. Or in other words, it performs the virtual -> linear -> physical address translation, which tells the CPU where to get the actual value from memory. And again, the TLS calculations above are another gross generalization because in reality, how TLS is done is based on your ABI (SysV or MS64), and there are entire specs dedicated to how this is done, including dynamic linking, etc...

To answer question 2, we must bring two new concepts into the picture. First, it is important to never forget that the segmentation values and page tables change all the time, and they depend on your current context. This is the #1 mistake that everyone makes. They think that a virtual address in their application can somehow be read from another context like the kernel or a hypervisor, but this is not the case. Kernels and hypervisors have their own segmentation register values and page tables. So when you are in the hypervisor, you need ensure the hypervisor's segmentation and page tables are set up to be capable of reading a virtual address from another context.

The second thing we need to introduce is something called second level paging, or second level address translation (SLAT). Second level paging adds a second level of page tables for guest VMs. What this means is that when the hardware converts a linear address to a physical address, what it has really done is convert a guest linear address (GLA) to a guest physical address (GPA). A second level of paging is required to translate from a GPA to a system physical address (SPA) which is the actual memory. Second level paging allows a hypervisor to rearrange memory a second time. Think of it this way. The OS has to provide userspace with a linear view of memory so that an application can run thinking that it owns addresses 0 - MAX no matter how this memory is actually laid out in physical memory. The OS will do this by using paging to map it's linear view of physical memory, in whatever order is needs to, to provide userspace with it's own linear view of memory. A hypervisor must do the same thing for the OS's view of physical memory. The hypervisor is going to have a linear view of system memory, and this view will be broken up into pages, and the order of these pages will likely be mixed up and somewhat random. The hypervisor must provide the OS with a linear view of physical memory, and second level paging provides this.

Ok, so to answer the second question, here we go. We have a TLS variable in a userspace application, from a guest VM, and we want to access this memory from our extension in Bareflank. Keep in mind that the guest VM could be the root VM. It doesn't matter.
- Start by converting the virtual address of my_var to a linear address. How this is done depends on what mode the CPU is in. For now, we will only talk about 32bit mode and 64bit mode. In 32bit mode, we would read the FS segment, which would tell us which GDT entry to use, and then use the value of the base address as the offset into the application's linear address space. If we are in 64bit, we would simply read the FS base MSR as the base address for FS in the GDT is ignored.
- From there we need to know what the offset of my_var is in the FS segment. The best way to get this is to simply decode the instruction for reading my_var. Either that or we would need to know the layout of the TLS variables, which is up to the compiler and where it wants to put each TLS variable.
- With the base address of FS, and the offset into FS, we can no calculate our linear address. We could have also cheated, and had the userspace application use the lea instruction to perform this translation for us, and depending on the VMExit, the VMCS/VMCB might already contain this translation. Either way, we now have a guest linear address.
- With the guest linear address, we need to use paging to determine what the guest physical address is. To do this we need to figure out where the userspace application's page tables are located. This is NOT as simple as reading CR3 from the guest VMCS/VMCB. For example, did your VMExit originate from the userspace process or the kernel? Thanks to Meltdown, the kernel has more than one set of page tables, and the currently located CR3 might not be pointing to a set of page tables that correctly maps the linear address space of the userspace application. Even if the VMExit originates from the userspace application itself, the kernel may be providing userspace with more than one set of page tables and swapping these page tables on-demand. The point is, you need to understand from what POV are you trying to access this memory, and you need to locate the CR3 value that is used to map this POV. This question is asked a lot, and there is no simple answer. For MicroV, we generally are only interested in the emulation of an instruction, so whatever the state is at the time, is all that we care about. For introspection, this is a lot more complicated. One way to get this CR3 value is to simply trap on all writes to CR3, record each write, and try to make sense of each CR3 value you see, which will likely require parsing kernel structures.
- Once you have the CR3 value that maps the guest linear address space associated with the POV you care about, you can then walk the page tables to translate the guest linear address to a guest physical address.
- Oh..., but here is where it gets interesting. To explain why it all goes to hell here, let's start with the first page table. In 64bit, CR3 points to the PML4. Our task is to find the PDPT. To do that, we figure out which entry in the PML4 we care about by grabbing the index into the table from the linear address (bits 39-48). Once we know which entry, we can read the PML4 entry to get the guest physical address of the PDPT. The problem is, the value of CR3 is a guest physical address. But we are in an extension in Bareflank. An extension runs from the host (i.e., VMX-root) in userspace. So it has it's own linear address space which is defined by the microkernel.

So how do we read the PML4, if all we have is a GPA?
- Step 1 is to convert the GPA to an SPA. To do this, we need to walk our second level page tables. How hard can that be? To do this we need to start by getting the pointer to our top level table for second level paging. On Intel, this is NOT our EPTP. It is the virtual address that points to the EPML4. EPTP is the physical address of our EPML4 with some added configuration bits. Typically, the virtual address to the EPML4 will be saved in some structure that also contains other information about the VM you are working with (might just be the root VM), but either way, this pointer is usually just stored somewhere that you can easily get to (it's your extension after all).
- From here, we need to read the EPDPT. To get the address of the EPDPT, we need to figure out which entry in the EPML4 points to the EPDPT that we care about. Like the PML4 -> PDPT, we use bits 39-48, but instead of using the guest linear address, we use the guest physical address. Simply read this entry, and grab the system physical address of the EPDPT.
- The problem is now we have an SPA of the EPDPT. You cannot read SPAs from a Bareflank extension either. Again, your extension has it's own linear address space which is defined by the microkernel. To read the EPDPT, we need a virtual address in the extension that we can read, which means that the microkernel needs to map this SPA into our extension's linear address space for us.

Ok, from here we really need to talk about the memory layout of Bareflank for any of the rest of this to make any sense. All of the major CPU architectures have more linear address bits than physical address bits. For example, on Intel, most systems support up to 42bits of physical memory and 48bits of linear memory (not including 5-level paging here, and really these number can change wildly). The reason they do this is because you can have several different views of ALL of physical memory. Like every OS, Bareflank takes advantage of this. If physical memory is mapped into one of these views using a contiguous layout we call this a direct map. A direct map allows us to take a physical address, add a constant offset, to get our linear address. Direct maps do not always mean that you can then simply dereference the resulting linear address and read memory, it just means that the linear address is a constant offset from the physical address. In Bareflank, you need to ask the microkernel to map this memory before you can read it. Bareflank has more than one direct map.
- bit 48 == 1, bit 47 == 0: direct map and page/huge pool for microkernel
- bit 48 == 1, bit 47 == 1: direct map for extension
- bit 48 == 0, bit 47 == 1: page/huge pool for extension
- bit 48 == 0, bit 47 == 0: code, stack and TLS for kernel and extension

Oh, but it gets worse, but for a good reason. Lets say we map SPA 0x1000 into the direct map of the extension. This map only applies to the active VM. When the active VM changes, the extension's direct map changes too. The page/huge pool for the extension, and the direct map and page/huge pool for the microkernel do not. The reason the direct map for the extension changes is because of Spectre/Meltdown and L1TF. Specifically, each VM has it's own set of page tables dedicated to the direct map in the microkernel. Any attempt to read physical memory from an extension must come from the direct map, but when the active VM changes, this direct map will change as well. This prevents the memory needed by the hypervisor for one VM from being mapped while any other VM is active, preventing a number of Spectre specific attacks. To get a complete view of how memory is laid out, use `make info` as all of the addresses are there.

The Microkernel has has bf_vm_op_map_direct that allows you to map an SPA, and it returns a linear address that you can use to read the SPA. Again, this map is only valid from the VM that is active. If the active VM changes, this linear address is no longer usable. But, that's not what we are going to do here to access our EPDPT. Since the extension created the second level page tables, the address of the EPDPT is already mapped into the extension. We just need to figure out what it is. When the extension created the second level page tables, each table that it added would have created by allocating a page using bf_mem_op_alloc_page. The pages that are allocated are mapped into the linear address space of the extension into it's page/huge direct map. So if we were to use bf_vm_op_map_direct, we would have ended up with a linear address to the EPDPT in both the direct map, and the page/huge pool of the extension. Instead, the reason that page and huge allocations are mapped into one of the three direct maps is so that you can calculate the linear address of an SPA using a simple offset (meaning virt to phys and phys to virt translations for page/huge allocations is a simply offset calculation). So, to figure out what the linear address is of the EPDPT given an SPA, we simply add HYPERVISOR_EXT_PAGE_POOL_ADDR to the SPA, because that is the address that the microkernel would have returned when the EPDPT was originally allocated.

Ok, so now we can read our EPDPT. Back to our list of steps:
- Now that we have a means to read our EPDPT, we can continue to walk our page tables until we get to the EPT. This will give use the SPA of the PML4.
- So now we have the SPA of the PML4, which we want to read. Again, we cannot read an SPA from the extension. Unlike our second level page tables, the page tables that we are parsing so that we can read memory from userspace of an application in the guest is not controlled by us. It is controlled by the OS of the guest VM. So this means that we do not have the PML4 mapped into any of our direct maps. To be able to read this memory, we will need to use bf_vm_op_map_direct. We only need this memory for a short time, so when we are done with all of this we should use bf_vm_op_unmap_direct so that our direct map is put back to normal before we are done.
- bf_vm_op_map_direct will give us a linear address that we can use to access the PML4. We can now locate the entry in the PML4, and get the guest physical address of the PDPT.
- Repeat this process, by getting the physical address of the PDPT, walking the second level page tables to get an SPA, mapping this SPA and then reading the next table, until you end up with finally, the PTE containing the guest physical address of "my_var".
- The rest of this should be obvious at this point. We then take the guest physical address of my_var, walk the second level page tables again, which will give us an SPA of my_var, and then use bf_vm_op_map_direct to get a linear address in our extension that we can use to actually read my_var.

If you are familiar with Bareflank v2.1, you will notice that this process is different. Bareflank v2.1 was monolithic, so your extension ran in ring 0. So instead of calling the microkernel to map memory, you would simply call an API which would map memory directly into the page tables of the hypervisor, and return a linear address that could be used to read/write SPAs. Unlike Bareflank v3.0 however, Bareflank v2.1 did not have any direct maps, so virt to phys and phys to virt translations were slow, because you would have to walk the hypervisor's page tables as well, so the search above was not O(N^2), but actually O(N^3). The addition of the direct maps in Bareflank v3.0 dramatically improve performance. Sadly, this performance is not as good as it would be with something like Linux or Xen, where all of RAM is mapped into the direct map all the time, and the direct map never changes based on which VM is loaded at the time (in the case of Xen at least). These additional security measures do reduce overall performance, but in general this is a non issue.

Extensions like MicroV do not actually do these types of translations often. They are required. For example, if you want to emulate the LAPIC, you need to decode instructions that operate on the LAPIC, and the process above is what is required. But usually, you will do this a couple of times, cache the results, and never do it again. Extensions that focus on introspection can implement their own on-demand paging using the fail handler. Specifically, just access the direct map as if the SPA you want to read is mapped in. If it is not, which will be the case for the first access, a page fault will occur. The microkernel will see this and execute the fail handler, and provide a page fault fail reason, as well as the linear address that created the page fault. From there, the extension can map the address in using bf_vm_op_map_direct, and then return success. This memory access will then continue, and the extension will continue it's execution. All future reads from this address will no longer produce a page fault. Extensions that use this trick can do this on-demand, or preload the direct map on boot using bf_vm_op_map_direct. Either way, once the direct map has every address you might ever care about, the performance of the extension will be the same as Linux or Xen, but unlike Linux or Xen, the extension has the choice, and is capable of choosing what it cares about more.

For more information about all of this stuff, please read the code and the Intel/AMD manuals.

# 3. Stack

TBD - Details about the stack, IST, etc...
