# SPDX-License-Identifier: SPDX-License-Identifier: GPL-2.0 OR MIT
#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

TARGET_MODULE := bareflank_loader
VENDOR_ID := $(shell lscpu | grep 'Vendor ID')

ifneq ($(KERNELRELEASE),)
	obj-m := $(TARGET_MODULE).o

    $(TARGET_MODULE)-objs += src/entry.o
    $(TARGET_MODULE)-objs += src/platform.o
    $(TARGET_MODULE)-objs += src/x64/demote.o
    $(TARGET_MODULE)-objs += src/x64/esr_default.o
    $(TARGET_MODULE)-objs += src/x64/esr_df.o
    $(TARGET_MODULE)-objs += src/x64/esr_gpf.o
    $(TARGET_MODULE)-objs += src/x64/esr_nmi.o
    $(TARGET_MODULE)-objs += src/x64/esr_pf.o
    $(TARGET_MODULE)-objs += src/x64/flush_cache.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_cpuid.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_inb.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_lcr4.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_outb.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_rdmsr.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_scr0.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_scr4.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_scs.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_sds.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_ses.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_sfs.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_sgdt.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_sgs.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_sidt.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_sldtr.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_sss.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_str.o
    $(TARGET_MODULE)-objs += src/x64/intrinsic_wrmsr.o
    $(TARGET_MODULE)-objs += src/x64/promote.o
    $(TARGET_MODULE)-objs += src/x64/serial_write_c.o
    $(TARGET_MODULE)-objs += src/x64/serial_write_hex.o
    $(TARGET_MODULE)-objs += ../src/alloc_and_copy_ext_elf_files_from_user.o
    $(TARGET_MODULE)-objs += ../src/alloc_and_copy_mk_elf_file_from_user.o
    $(TARGET_MODULE)-objs += ../src/alloc_and_copy_mk_elf_segments.o
    $(TARGET_MODULE)-objs += ../src/alloc_mk_args.o
    $(TARGET_MODULE)-objs += ../src/alloc_mk_debug_ring.o
    $(TARGET_MODULE)-objs += ../src/alloc_mk_huge_pool.o
    $(TARGET_MODULE)-objs += ../src/alloc_mk_page_pool.o
    $(TARGET_MODULE)-objs += ../src/alloc_mk_stack.o
    $(TARGET_MODULE)-objs += ../src/dump_ext_elf_files.o
    $(TARGET_MODULE)-objs += ../src/dump_mk_args.o
    $(TARGET_MODULE)-objs += ../src/dump_mk_debug_ring.o
    $(TARGET_MODULE)-objs += ../src/dump_mk_elf_file.o
    $(TARGET_MODULE)-objs += ../src/dump_mk_elf_segments.o
    $(TARGET_MODULE)-objs += ../src/dump_mk_huge_pool.o
    $(TARGET_MODULE)-objs += ../src/dump_mk_page_pool.o
    $(TARGET_MODULE)-objs += ../src/dump_mk_root_page_table.o
    $(TARGET_MODULE)-objs += ../src/dump_mk_stack.o
    $(TARGET_MODULE)-objs += ../src/dump_vmm.o
    $(TARGET_MODULE)-objs += ../src/free_ext_elf_files.o
    $(TARGET_MODULE)-objs += ../src/free_mk_args.o
    $(TARGET_MODULE)-objs += ../src/free_mk_debug_ring.o
    $(TARGET_MODULE)-objs += ../src/free_mk_elf_file.o
    $(TARGET_MODULE)-objs += ../src/free_mk_elf_segments.o
    $(TARGET_MODULE)-objs += ../src/free_mk_huge_pool.o
    $(TARGET_MODULE)-objs += ../src/free_mk_page_pool.o
    $(TARGET_MODULE)-objs += ../src/free_mk_stack.o
    $(TARGET_MODULE)-objs += ../src/g_cpu_status.o
    $(TARGET_MODULE)-objs += ../src/g_ext_elf_files.o
    $(TARGET_MODULE)-objs += ../src/g_mk_args.o
    $(TARGET_MODULE)-objs += ../src/g_mk_code_aliases.o
    $(TARGET_MODULE)-objs += ../src/g_mk_debug_ring.o
    $(TARGET_MODULE)-objs += ../src/g_mk_elf_file.o
    $(TARGET_MODULE)-objs += ../src/g_mk_elf_segments.o
    $(TARGET_MODULE)-objs += ../src/g_mk_huge_pool.o
    $(TARGET_MODULE)-objs += ../src/g_mk_page_pool.o
    $(TARGET_MODULE)-objs += ../src/g_mk_root_page_table.o
    $(TARGET_MODULE)-objs += ../src/g_mk_stack.o
    $(TARGET_MODULE)-objs += ../src/g_mk_state.o
    $(TARGET_MODULE)-objs += ../src/g_root_vp_state.o
    $(TARGET_MODULE)-objs += ../src/g_vmm_status.o
    $(TARGET_MODULE)-objs += ../src/get_mk_huge_pool_addr.o
    $(TARGET_MODULE)-objs += ../src/get_mk_page_pool_addr.o
    $(TARGET_MODULE)-objs += ../src/loader_fini.o
    $(TARGET_MODULE)-objs += ../src/loader_init.o
    $(TARGET_MODULE)-objs += ../src/map_4k_page_rw.o
    $(TARGET_MODULE)-objs += ../src/map_4k_page_rx.o
    $(TARGET_MODULE)-objs += ../src/map_ext_elf_files.o
    $(TARGET_MODULE)-objs += ../src/map_mk_args.o
    $(TARGET_MODULE)-objs += ../src/map_mk_debug_ring.o
    $(TARGET_MODULE)-objs += ../src/map_mk_elf_file.o
    $(TARGET_MODULE)-objs += ../src/map_mk_elf_segments.o
    $(TARGET_MODULE)-objs += ../src/map_mk_huge_pool.o
    $(TARGET_MODULE)-objs += ../src/map_mk_page_pool.o
    $(TARGET_MODULE)-objs += ../src/map_mk_stack.o
    $(TARGET_MODULE)-objs += ../src/serial_write.o
    $(TARGET_MODULE)-objs += ../src/start_vmm.o
    $(TARGET_MODULE)-objs += ../src/start_vmm_per_cpu.o
    $(TARGET_MODULE)-objs += ../src/stop_and_free_the_vmm.o
    $(TARGET_MODULE)-objs += ../src/stop_vmm.o
    $(TARGET_MODULE)-objs += ../src/stop_vmm_per_cpu.o
    $(TARGET_MODULE)-objs += ../src/x64/alloc_and_copy_mk_code_aliases.o
    $(TARGET_MODULE)-objs += ../src/x64/alloc_and_copy_mk_state.o
    $(TARGET_MODULE)-objs += ../src/x64/alloc_and_copy_root_vp_state.o
    $(TARGET_MODULE)-objs += ../src/x64/alloc_mk_root_page_table.o
    $(TARGET_MODULE)-objs += ../src/x64/alloc_pdpt.o
    $(TARGET_MODULE)-objs += ../src/x64/alloc_pdt.o
    $(TARGET_MODULE)-objs += ../src/x64/alloc_pt.o
    $(TARGET_MODULE)-objs += ../src/x64/dump_mk_code_aliases.o
    $(TARGET_MODULE)-objs += ../src/x64/dump_mk_state.o
    $(TARGET_MODULE)-objs += ../src/x64/dump_root_vp_state.o
    $(TARGET_MODULE)-objs += ../src/x64/free_mk_code_aliases.o
    $(TARGET_MODULE)-objs += ../src/x64/free_mk_root_page_table.o
    $(TARGET_MODULE)-objs += ../src/x64/free_mk_state.o
    $(TARGET_MODULE)-objs += ../src/x64/free_pdpt.o
    $(TARGET_MODULE)-objs += ../src/x64/free_pdt.o
    $(TARGET_MODULE)-objs += ../src/x64/free_pml4t.o
    $(TARGET_MODULE)-objs += ../src/x64/free_root_vp_state.o
    $(TARGET_MODULE)-objs += ../src/x64/get_gdt_descriptor_attrib.o
    $(TARGET_MODULE)-objs += ../src/x64/get_gdt_descriptor_base.o
    $(TARGET_MODULE)-objs += ../src/x64/get_gdt_descriptor_limit.o
    $(TARGET_MODULE)-objs += ../src/x64/map_4k_page.o
    $(TARGET_MODULE)-objs += ../src/x64/map_mk_code_aliases.o
    $(TARGET_MODULE)-objs += ../src/x64/map_mk_state.o
    $(TARGET_MODULE)-objs += ../src/x64/map_root_vp_state.o
    $(TARGET_MODULE)-objs += ../src/x64/send_command_report_off.o
    $(TARGET_MODULE)-objs += ../src/x64/send_command_report_on.o
    $(TARGET_MODULE)-objs += ../src/x64/send_command_stop.o
    $(TARGET_MODULE)-objs += ../src/x64/serial_init.o
    $(TARGET_MODULE)-objs += ../src/x64/set_gdt_descriptor.o
    $(TARGET_MODULE)-objs += ../src/x64/set_idt_descriptor.o

	EXTRA_CFLAGS += -I$(src)/include
	EXTRA_CFLAGS += -I$(src)/include/x64
	EXTRA_CFLAGS += -I$(src)/include/std
	EXTRA_CFLAGS += -I$(src)/include/platform_interface/c
	EXTRA_CFLAGS += -I$(src)/../include
	EXTRA_CFLAGS += -I$(src)/../include/x64/
	EXTRA_CFLAGS += -I$(src)/../include/interface/c
	EXTRA_CFLAGS += -I$(src)/../include/interface/c/x64
	EXTRA_CFLAGS += -I$(CMAKE_BINARY_DIR)/include

    EXTRA_AFLAGS += -I$(CMAKE_BINARY_DIR)/include

  	ifneq (,$(findstring AuthenticAMD,$(VENDOR_ID)))
		$(TARGET_MODULE)-objs += src/x64/amd/disable_interrupts.o
		$(TARGET_MODULE)-objs += src/x64/amd/enable_interrupts.o
		$(TARGET_MODULE)-objs += ../src/x64/amd/check_cpu_configuration.o
		$(TARGET_MODULE)-objs += ../src/x64/amd/disable_hve.o
		$(TARGET_MODULE)-objs += ../src/x64/amd/enable_hve.o

		EXTRA_CFLAGS += -I$(src)/include/x64/amd
		EXTRA_CFLAGS += -I$(src)/../include/x64/amd
		EXTRA_CFLAGS += -I$(src)/../include/interface/c/x64/amd
	endif

	ifneq (,$(findstring GenuineIntel,$(VENDOR_ID)))
		$(TARGET_MODULE)-objs += src/x64/intel/disable_interrupts.o
		$(TARGET_MODULE)-objs += src/x64/intel/enable_interrupts.o
		$(TARGET_MODULE)-objs += src/x64/intel/intrinsic_vmxoff.o
		$(TARGET_MODULE)-objs += src/x64/intel/intrinsic_vmxon.o
		$(TARGET_MODULE)-objs += ../src/x64/intel/check_cpu_configuration.o
		$(TARGET_MODULE)-objs += ../src/x64/intel/disable_hve.o
		$(TARGET_MODULE)-objs += ../src/x64/intel/enable_hve.o

		EXTRA_CFLAGS += -I$(src)/include/x64/intel
		EXTRA_CFLAGS += -I$(src)/../include/x64/intel
		EXTRA_CFLAGS += -I$(src)/../include/interface/c/x64/intel
	endif

else
	BUILDSYSTEM_DIR := /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

all:
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) clean
	rm -f ../src/*.o*
	rm -f ../src/.*.o*
	rm -f ../src/x64/*.o*
	rm -f ../src/x64/.*.o*
	rm -f ../src/x64/amd/*.o*
	rm -f ../src/x64/amd/.*.o*
	rm -f ../src/x64/intel/*.o*
	rm -f ../src/x64/intel/.*.o*

load:
	@insmod ./$(TARGET_MODULE).ko

unload:
	-@rmmod ./$(TARGET_MODULE).ko

endif
