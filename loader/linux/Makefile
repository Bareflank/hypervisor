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

	EXTRA_CFLAGS += -I$(src)/include
	EXTRA_CFLAGS += -I$(src)/../include

	$(TARGET_MODULE)-objs += src/entry.o
	$(TARGET_MODULE)-objs += src/platform.o
	$(TARGET_MODULE)-objs += ../src/dump_vmm.o
	$(TARGET_MODULE)-objs += ../src/global_resources.o
	$(TARGET_MODULE)-objs += ../src/loader_fini.o
	$(TARGET_MODULE)-objs += ../src/loader_init.o
	$(TARGET_MODULE)-objs += ../src/start_vmm_per_cpu.o
	$(TARGET_MODULE)-objs += ../src/start_vmm.o
	$(TARGET_MODULE)-objs += ../src/stop_vmm_per_cpu.o
	$(TARGET_MODULE)-objs += ../src/stop_vmm.o

	ifneq (,$(findstring AuthenticAMD,$(VENDOR_ID)))
		$(TARGET_MODULE)-objs += src/x64/arch_cpuid.o
		$(TARGET_MODULE)-objs += src/x64/arch_lgdt.o
		$(TARGET_MODULE)-objs += src/x64/arch_lidt.o
		$(TARGET_MODULE)-objs += src/x64/arch_rdmsr.o
		$(TARGET_MODULE)-objs += src/x64/arch_readcr0.o
		$(TARGET_MODULE)-objs += src/x64/arch_readcr2.o
		$(TARGET_MODULE)-objs += src/x64/arch_readcr3.o
		$(TARGET_MODULE)-objs += src/x64/arch_readcr4.o
		$(TARGET_MODULE)-objs += src/x64/arch_readcr8.o
		$(TARGET_MODULE)-objs += src/x64/arch_readcs.o
		$(TARGET_MODULE)-objs += src/x64/arch_readdr0.o
		$(TARGET_MODULE)-objs += src/x64/arch_readdr1.o
		$(TARGET_MODULE)-objs += src/x64/arch_readdr2.o
		$(TARGET_MODULE)-objs += src/x64/arch_readdr3.o
		$(TARGET_MODULE)-objs += src/x64/arch_readdr6.o
		$(TARGET_MODULE)-objs += src/x64/arch_readdr7.o
		$(TARGET_MODULE)-objs += src/x64/arch_readds.o
		$(TARGET_MODULE)-objs += src/x64/arch_reades.o
		$(TARGET_MODULE)-objs += src/x64/arch_readfs.o
		$(TARGET_MODULE)-objs += src/x64/arch_readgs.o
		$(TARGET_MODULE)-objs += src/x64/arch_readss.o
		$(TARGET_MODULE)-objs += src/x64/arch_sgdt.o
		$(TARGET_MODULE)-objs += src/x64/arch_sidt.o
		$(TARGET_MODULE)-objs += src/x64/arch_wrmsr.o
		$(TARGET_MODULE)-objs += src/x64/amd/arch_vmload.o
		$(TARGET_MODULE)-objs += src/x64/amd/arch_vmrun.o
		$(TARGET_MODULE)-objs += src/x64/amd/arch_vmsave.o
		$(TARGET_MODULE)-objs += ../src/x64/amd/arch_check_hvm_support.o
		$(TARGET_MODULE)-objs += ../src/x64/amd/arch_loader_fini.o
		$(TARGET_MODULE)-objs += ../src/x64/amd/arch_loader_init.o
		$(TARGET_MODULE)-objs += ../src/x64/amd/arch_start_vmm_per_cpu.o
		$(TARGET_MODULE)-objs += ../src/x64/amd/arch_stop_vmm_per_cpu.o

		EXTRA_CFLAGS += -I$(src)/include/x64
		EXTRA_CFLAGS += -I$(src)/../include/x64/
		EXTRA_CFLAGS += -I$(src)/include/x64/amd
		EXTRA_CFLAGS += -I$(src)/../include/x64/amd
	endif

	ifneq (,$(findstring GenuineIntel,$(VENDOR_ID)))
		$(TARGET_MODULE)-objs += src/x64/arch_cpuid.o
		$(TARGET_MODULE)-objs += src/x64/arch_lgdt.o
		$(TARGET_MODULE)-objs += src/x64/arch_lidt.o
		$(TARGET_MODULE)-objs += src/x64/arch_rdmsr.o
		$(TARGET_MODULE)-objs += src/x64/arch_readcr0.o
		$(TARGET_MODULE)-objs += src/x64/arch_readcr2.o
		$(TARGET_MODULE)-objs += src/x64/arch_readcr3.o
		$(TARGET_MODULE)-objs += src/x64/arch_readcr4.o
		$(TARGET_MODULE)-objs += src/x64/arch_readcr8.o
		$(TARGET_MODULE)-objs += src/x64/arch_readcs.o
		$(TARGET_MODULE)-objs += src/x64/arch_readdr0.o
		$(TARGET_MODULE)-objs += src/x64/arch_readdr1.o
		$(TARGET_MODULE)-objs += src/x64/arch_readdr2.o
		$(TARGET_MODULE)-objs += src/x64/arch_readdr3.o
		$(TARGET_MODULE)-objs += src/x64/arch_readdr6.o
		$(TARGET_MODULE)-objs += src/x64/arch_readdr7.o
		$(TARGET_MODULE)-objs += src/x64/arch_readds.o
		$(TARGET_MODULE)-objs += src/x64/arch_reades.o
		$(TARGET_MODULE)-objs += src/x64/arch_readfs.o
		$(TARGET_MODULE)-objs += src/x64/arch_readgs.o
		$(TARGET_MODULE)-objs += src/x64/arch_readss.o
		$(TARGET_MODULE)-objs += src/x64/arch_sgdt.o
		$(TARGET_MODULE)-objs += src/x64/arch_sidt.o
		$(TARGET_MODULE)-objs += src/x64/arch_wrmsr.o
		$(TARGET_MODULE)-objs += ../src/x64/intel/arch_check_hvm_support.o
		$(TARGET_MODULE)-objs += ../src/x64/intel/arch_loader_fini.o
		$(TARGET_MODULE)-objs += ../src/x64/intel/arch_loader_init.o
		$(TARGET_MODULE)-objs += ../src/x64/intel/arch_start_vmm_per_cpu.o
		$(TARGET_MODULE)-objs += ../src/x64/intel/arch_stop_vmm_per_cpu.o

		EXTRA_CFLAGS += -I$(src)/include/x64/
		EXTRA_CFLAGS += -I$(src)/../include/x64/
		EXTRA_CFLAGS += -I$(src)/include/x64/intel
		EXTRA_CFLAGS += -I$(src)/../include/x64/intel
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
	rm -f ../src/x64/amd/*.o*
	rm -f ../src/x64/amd/.*.o*
	rm -f ../src/x64/intel/*.o*
	rm -f ../src/x64/intel/.*.o*

load:
	@insmod ./$(TARGET_MODULE).ko

unload:
	-@rmmod ./$(TARGET_MODULE).ko

endif
