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
	MODULE_FILE=%BUILD_ABS%/module_file
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
PARENT_SUBDIRS += $(wildcard %HYPER_ABS%/extended_apis/)
PARENT_SUBDIRS += $(wildcard %HYPER_ABS%/hyperkernel/)
PARENT_SUBDIRS += $(wildcard %HYPER_ABS%/src_*/)
PARENT_SUBDIRS += $(wildcard %HYPER_ABS%/hypervisor_*/)

ifneq (%HYPER_ABS%, %BUILD_ABS%)
	PARENT_SUBDIRS += $(wildcard %BUILD_ABS%/makefiles/src_*/)
	PARENT_SUBDIRS += $(wildcard %BUILD_ABS%/makefiles/hypervisor_*/)
endif

include extensions.mk

################################################################################
# Common
################################################################################

include %HYPER_ABS%/common/common_subdir.mk

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
	@%BUILD_ABS%/build_scripts/build_driver.sh

windows_load: force
	@%BUILD_ABS%/build_scripts/build_driver.sh
	@%BUILD_ABS%/build_scripts/load_driver.sh

windows_unload: force
	@%BUILD_ABS%/build_scripts/clean_driver.sh

linux_build: force
	@%BUILD_ABS%/build_scripts/build_driver.sh

linux_load: force
	@%BUILD_ABS%/build_scripts/build_driver.sh
	@%BUILD_ABS%/build_scripts/load_driver.sh

linux_unload: force
	@%BUILD_ABS%/build_scripts/clean_driver.sh

driver_build:
	@%BUILD_ABS%/build_scripts/build_driver.sh

driver_load:
	@%BUILD_ABS%/build_scripts/build_driver.sh
	@%BUILD_ABS%/build_scripts/load_driver.sh

driver_unload: force
	@%BUILD_ABS%/build_scripts/clean_driver.sh

load: force
	@$(SUDO) rm -Rf $(FILTERED_MODULE_FILE)
	@%BUILD_ABS%/build_scripts/filter_module_file.sh $(MODULE_FILE) $(FILTERED_MODULE_FILE)
	@$(SUDO) LD_LIBRARY_PATH=%BUILD_ABS%/makefiles/bfm/bin/native/ %BUILD_ABS%/makefiles/bfm/bin/native/bfm load $(FILTERED_MODULE_FILE)
	@$(SUDO) rm -Rf $(FILTERED_MODULE_FILE)

unload: force
	@$(SUDO) LD_LIBRARY_PATH=%BUILD_ABS%/makefiles/bfm/bin/native/ %BUILD_ABS%/makefiles/bfm/bin/native/bfm unload

start: force
	@sync
	@$(SUDO) LD_LIBRARY_PATH=%BUILD_ABS%/makefiles/bfm/bin/native/ %BUILD_ABS%/makefiles/bfm/bin/native/bfm start

stop: force
	@$(SUDO) LD_LIBRARY_PATH=%BUILD_ABS%/makefiles/bfm/bin/native/ %BUILD_ABS%/makefiles/bfm/bin/native/bfm stop

dump: force
	@$(SUDO) LD_LIBRARY_PATH=%BUILD_ABS%/makefiles/bfm/bin/native/ %BUILD_ABS%/makefiles/bfm/bin/native/bfm dump --vcpuid $(VCPUID)

status: force
	@$(SUDO) LD_LIBRARY_PATH=%BUILD_ABS%/makefiles/bfm/bin/native/ %BUILD_ABS%/makefiles/bfm/bin/native/bfm status

vmcall: force
	@$(SUDO) LD_LIBRARY_PATH=%BUILD_ABS%/makefiles/bfm/bin/native/ %BUILD_ABS%/makefiles/bfm/bin/native/bfm vmcall --cpuid $(CPUID) ${ARGS}

help: force
	@$(SUDO) LD_LIBRARY_PATH=%BUILD_ABS%/makefiles/bfm/bin/native/ %BUILD_ABS%/makefiles/bfm/bin/native/bfm --help

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
	@cd %HYPER_ABS%; \
	%HYPER_ABS%/tools/astyle/run.sh %BUILD_ABS%

astyle_clean:
	@cd %HYPER_ABS%; \
	%HYPER_ABS%/tools/astyle/run.sh clean

doxygen:
	@cd %HYPER_ABS%; \
	%HYPER_ABS%/tools/doxygen/linux/run.sh

doxygen_clean:
	@cd %HYPER_ABS%; \
	%HYPER_ABS%/tools/doxygen/linux/run.sh clean

tidy:
	@cd %HYPER_ABS%; \
	%BUILD_ABS%/build_scripts/verify_source.sh
