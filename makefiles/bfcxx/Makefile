################################################################################
# Auto Generated Section (created by configured script)
################################################################################

HYPER_ABS:=/home/user/hypervisor
BUILD_ABS:=/home/user/hypervisor
HYPER_REL:=/home/user/hypervisor/bfcxx
BUILD_REL:=/home/user/hypervisor/makefiles/bfcxx
COMPILER:=clang
LINKER:=ld
CONFIGURED_CROSS_CCFLAGS:= -fpic -fexceptions -mmmx -msse -msse2 -msse3 -mssse3 -msse4.1 -msse4.2 -msse4 -mavx -mno-red-zone -mstackrealign -fstack-protector-strong -std=c99
CONFIGURED_CROSS_CXXFLAGS:= -fpic -fexceptions -mmmx -msse -msse2 -msse3 -mssse3 -msse4.1 -msse4.2 -msse4 -mavx -mno-red-zone -mstackrealign -fstack-protector-strong -std=c++14
CONFIGURED_NATIVE_CCFLAGS:= -fpic -fexceptions -mmmx -msse -msse2 -msse3 -mssse3 -msse4.1 -msse4.2 -msse4 -mavx -std=c99
CONFIGURED_NATIVE_CXXFLAGS:= -fpic -fexceptions -mmmx -msse -msse2 -msse3 -mssse3 -msse4.1 -msse4.2 -msse4 -mavx -std=c++14
MAKEFILE_ABS:=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ifneq ($(dir $(BUILD_REL)/), $(MAKEFILE_ABS))
    $(error Build system has moved which is not supported!!!)
endif


#
# Bareflank Hypervisor
#
# Copyright (C) 2015 Assured Information Security, Inc.
# Author: Rian Quinn        <quinnr@ainfosec.com>
# Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 
################################################################################
# Custom Targets
################################################################################
 
Makefile: $(HYPER_REL)/Makefile.bf
	@ BUILD_ABS=$(BUILD_ABS) BUILD_REL=$(BUILD_REL) HYPER_REL=$(HYPER_REL) $(HYPER_ABS)/configure -r --this-is-make
 
.PHONY: clean
.PHONY: clean_src
.PHONY: clean_tests
.PHONY: build_src
.PHONY: build_tests
.PHONY: run_tests
 
.DEFAULT_GOAL := all
 
ifneq ($(STATIC_ANALYSIS_ENABLED), true)
 
all: $(BUILD_ABS)/sysroot_vmm/x86_64-vmm-elf/lib/libc++.so
	@echo > /dev/null
 
$(BUILD_ABS)/sysroot_vmm/x86_64-vmm-elf/lib/libc++abi.so:
	SYSROOT_NAME=vmm $(BUILD_ABS)/build_scripts/build_libcxxabi.sh
 
$(BUILD_ABS)/sysroot_vmm/x86_64-vmm-elf/lib/libc++.so: $(BUILD_ABS)/sysroot_vmm/x86_64-vmm-elf/lib/libc++abi.so
	SYSROOT_NAME=vmm $(BUILD_ABS)/build_scripts/build_libcxx.sh
 
build_src: all
build_tests: all
 
endif
 
run_tests:
	@echo > /dev/null
 
clean: clean_src
 
clean_src:
	rm -Rf $(BUILD_ABS)/sysroot_vmm/x86_64-vmm-elf/lib/libc++.so
	rm -Rf $(BUILD_ABS)/sysroot_vmm/x86_64-vmm-elf/lib/libc++.so.1
	rm -Rf $(BUILD_ABS)/sysroot_vmm/x86_64-vmm-elf/lib/libc++.so.1.0
	rm -Rf $(BUILD_ABS)/sysroot_vmm/x86_64-vmm-elf/lib/libc++abi.a
	rm -Rf $(BUILD_ABS)/sysroot_vmm/x86_64-vmm-elf/lib/libc++abi.so
	rm -Rf $(BUILD_ABS)/sysroot_vmm/x86_64-vmm-elf/lib/libc++abi.so.1
	rm -Rf $(BUILD_ABS)/sysroot_vmm/x86_64-vmm-elf/lib/libc++abi.so.1.0
 
clean_tests:
	@echo > /dev/null
