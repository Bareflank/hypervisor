################################################################################
# Auto Generated Section (created by configured script)
################################################################################

HYPER_ABS:=/home/user/hypervisor
BUILD_ABS:=/home/user/hypervisor
HYPER_REL:=/home/user/hypervisor
BUILD_REL:=/home/user/hypervisor/makefiles
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
 
SHELL=/bin/bash
 
################################################################################
# Color
################################################################################
 
CS='\033[1;95m'
CE='\033[0m'
 
################################################################################
# Load Modules
################################################################################
 
ifeq ($(MODULES),)
	MODULE_FILE=/home/user/hypervisor/module_file
else
	ifneq ($(shell if [[ "$(MODULES)" == "/"* ]]; then echo abs; fi; ),abs)
		MODULE_FILE=$(PWD)/$(MODULES)
	endif
endif
 
FILTERED_MODULE_FILE=/tmp/module_file
 
################################################################################
# Sudo
################################################################################
 
ifeq ($(shell uname -s), Linux)
	SUDO:=sudo
else
	SUDO:=
endif
 
################################################################################
# CPUID / VCPUID
################################################################################
 
ifeq ($(CPUID),)
	CPUID=0
endif
 
ifeq ($(VCPUID),)
	VCPUID=0
endif
 
################################################################################
# Subdirs
################################################################################
 
PARENT_SUBDIRS += bfc
PARENT_SUBDIRS += bfcxx
PARENT_SUBDIRS += bfunwind
PARENT_SUBDIRS += bfm
PARENT_SUBDIRS += bfdrivers
PARENT_SUBDIRS += bfelf_loader
PARENT_SUBDIRS += bfvmm
PARENT_SUBDIRS += $(wildcard /home/user/hypervisor/extended_apis/)
PARENT_SUBDIRS += $(wildcard /home/user/hypervisor/hyperkernel/)
PARENT_SUBDIRS += $(wildcard /home/user/hypervisor/src_*/)
PARENT_SUBDIRS += $(wildcard /home/user/hypervisor/hypervisor_*/)
 
ifneq (/home/user/hypervisor, /home/user/hypervisor)
	PARENT_SUBDIRS += $(wildcard /home/user/hypervisor/makefiles/src_*/)
	PARENT_SUBDIRS += $(wildcard /home/user/hypervisor/makefiles/hypervisor_*/)
endif
 
include /home/user/hypervisor/extensions.mk
 
################################################################################
# Common
################################################################################
 
include /home/user/hypervisor/common/common_subdir.mk
 
################################################################################
# Custom Targets
################################################################################
 
.PHONY: linux_build
.PHONY: linux_load
.PHONY: linux_unload
.PHONY: windows_build
.PHONY: windows_load
.PHONY: windows_unload
.PHONY: driver_build
.PHONY: driver_load
.PHONY: driver_unload
.PHONY: load
.PHONY: unload
.PHONY: start
.PHONY: stop
.PHONY: dump
.PHONY: status
.PHONY: quick
.PHONY: loop
.PHONY: unittest
.PHONY: astyle
.PHONY: astyle_clean
.PHONY: doxygen
.PHONY: doxygen_clean
.PHONY: test
.PHONY: tidy
 
windows_build: force
	@/home/user/hypervisor/build_scripts/build_driver.sh
 
windows_load: force
	@/home/user/hypervisor/build_scripts/build_driver.sh
	@/home/user/hypervisor/build_scripts/load_driver.sh
 
windows_unload: force
	@/home/user/hypervisor/build_scripts/clean_driver.sh
 
linux_build: force
	@/home/user/hypervisor/build_scripts/build_driver.sh
 
linux_load: force
	@/home/user/hypervisor/build_scripts/build_driver.sh
	@/home/user/hypervisor/build_scripts/load_driver.sh
 
linux_unload: force
	@/home/user/hypervisor/build_scripts/clean_driver.sh
 
driver_build:
	@/home/user/hypervisor/build_scripts/build_driver.sh
 
driver_load:
	@/home/user/hypervisor/build_scripts/build_driver.sh
	@/home/user/hypervisor/build_scripts/load_driver.sh
 
driver_unload: force
	@/home/user/hypervisor/build_scripts/clean_driver.sh
 
load: force
	@$(SUDO) rm -Rf $(FILTERED_MODULE_FILE)
	@/home/user/hypervisor/build_scripts/filter_module_file.sh $(MODULE_FILE) $(FILTERED_MODULE_FILE)
	@$(SUDO) LD_LIBRARY_PATH=/home/user/hypervisor/makefiles/bfm/bin/native/ /home/user/hypervisor/makefiles/bfm/bin/native/bfm load $(FILTERED_MODULE_FILE)
	@$(SUDO) rm -Rf $(FILTERED_MODULE_FILE)
 
unload: force
	@$(SUDO) LD_LIBRARY_PATH=/home/user/hypervisor/makefiles/bfm/bin/native/ /home/user/hypervisor/makefiles/bfm/bin/native/bfm unload
 
start: force
	@sync
	@$(SUDO) LD_LIBRARY_PATH=/home/user/hypervisor/makefiles/bfm/bin/native/ /home/user/hypervisor/makefiles/bfm/bin/native/bfm start
 
stop: force
	@$(SUDO) LD_LIBRARY_PATH=/home/user/hypervisor/makefiles/bfm/bin/native/ /home/user/hypervisor/makefiles/bfm/bin/native/bfm stop
 
dump: force
	@$(SUDO) LD_LIBRARY_PATH=/home/user/hypervisor/makefiles/bfm/bin/native/ /home/user/hypervisor/makefiles/bfm/bin/native/bfm dump --vcpuid $(VCPUID)
 
status: force
	@$(SUDO) LD_LIBRARY_PATH=/home/user/hypervisor/makefiles/bfm/bin/native/ /home/user/hypervisor/makefiles/bfm/bin/native/bfm status
 
vmcall: force
	@$(SUDO) LD_LIBRARY_PATH=/home/user/hypervisor/makefiles/bfm/bin/native/ /home/user/hypervisor/makefiles/bfm/bin/native/bfm vmcall --cpuid $(CPUID) ${ARGS}
 
help: force
	@$(SUDO) LD_LIBRARY_PATH=/home/user/hypervisor/makefiles/bfm/bin/native/ /home/user/hypervisor/makefiles/bfm/bin/native/bfm --help
 
quick: load start
 
loop: force
	@for n in $(shell seq 1 $(NUM)); do \
		echo -e $(CS)"cycle: $$n"$(CE); \
		$(MAKE) --no-print-directory load; \
		$(MAKE) --no-print-directory start; \
		$(MAKE) --no-print-directory stop; \
		$(MAKE) --no-print-directory unload; \
	done \
 
unittest: run_tests
test: run_tests
 
astyle:
	@cd /home/user/hypervisor; \
	/home/user/hypervisor/tools/astyle/run.sh /home/user/hypervisor
 
astyle_clean:
	@cd /home/user/hypervisor; \
	/home/user/hypervisor/tools/astyle/run.sh clean
 
doxygen:
	@cd /home/user/hypervisor; \
	/home/user/hypervisor/tools/doxygen/linux/run.sh
 
doxygen_clean:
	@cd /home/user/hypervisor; \
	/home/user/hypervisor/tools/doxygen/linux/run.sh clean
 
tidy:
	@cd /home/user/hypervisor; \
	/home/user/hypervisor/build_scripts/verify_source.sh
