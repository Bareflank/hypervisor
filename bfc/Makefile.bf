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

all: $(BUILD_ABS)/sysroot_vmm/x86_64-vmm-elf/lib/libc.so
	@echo > /dev/null

$(BUILD_ABS)/sysroot_vmm/x86_64-vmm-elf/lib/libc.so:
	SYSROOT_NAME=vmm $(BUILD_ABS)/build_scripts/build_newlib.sh

build_src: all
build_tests: all

endif

run_tests:
	@echo > /dev/null

clean: clean_src

clean_src:
	rm $(BUILD_ABS)/sysroot_vmm/x86_64-vmm-elf/lib/libc.so

clean_tests:
	@echo > /dev/null
