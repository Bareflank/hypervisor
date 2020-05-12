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
	$(TARGET_MODULE)-objs += ../src/dump_vmm.o
	$(TARGET_MODULE)-objs += ../src/loader_fini.o
	$(TARGET_MODULE)-objs += ../src/loader_init.o
	$(TARGET_MODULE)-objs += ../src/start_vmm.o
	$(TARGET_MODULE)-objs += ../src/stop_vmm.o

	EXTRA_CFLAGS += -I$(src)/include
	EXTRA_CFLAGS += -I$(src)/../include

	ifneq (,$(findstring AuthenticAMD,$(VENDOR_ID)))
		$(TARGET_MODULE)-objs += src/x64/amd/intrinsics.o
		$(TARGET_MODULE)-objs += ../src/x64/amd/arch_check_hvm_support.o
		$(TARGET_MODULE)-objs += ../src/x64/amd/arch_loader_fini.o
		$(TARGET_MODULE)-objs += ../src/x64/amd/arch_loader_init.o
		$(TARGET_MODULE)-objs += ../src/x64/amd/arch_prepare_context.o
		$(TARGET_MODULE)-objs += ../src/x64/amd/arch_start_vmm.o
		$(TARGET_MODULE)-objs += ../src/x64/amd/arch_stop_vmm.o

		EXTRA_CFLAGS += -I$(src)/include/x64/amd
		EXTRA_CFLAGS += -I$(src)/../include/x64/amd
	endif

	ifneq (,$(findstring GenuineIntel,$(VENDOR_ID)))
		$(TARGET_MODULE)-objs += src/x64/intel/intrinsics.o
		$(TARGET_MODULE)-objs += ../src/x64/intel/arch_check_hvm_support.o
		$(TARGET_MODULE)-objs += ../src/x64/intel/arch_loader_fini.o
		$(TARGET_MODULE)-objs += ../src/x64/intel/arch_loader_init.o
		$(TARGET_MODULE)-objs += ../src/x64/intel/arch_prepare_context.o
		$(TARGET_MODULE)-objs += ../src/x64/intel/arch_start_vmm.o
		$(TARGET_MODULE)-objs += ../src/x64/intel/arch_stop_vmm.o

		EXTRA_CFLAGS += -I$(src)/include/x64/amd
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
	insmod ./$(TARGET_MODULE).ko

unload:
	-rmmod ./$(TARGET_MODULE).ko

quick:
	-rmmod ./$(TARGET_MODULE).ko
	insmod ./$(TARGET_MODULE).ko

endif
