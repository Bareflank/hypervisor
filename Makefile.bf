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
# VCPUID
################################################################################

ifeq ($(VCPUID),)
	VCPUID=0
endif

################################################################################
# Subdirs
################################################################################

PARENT_SUBDIRS += bfcrt
PARENT_SUBDIRS += bfunwind
PARENT_SUBDIRS += bfc
PARENT_SUBDIRS += bfcxx
PARENT_SUBDIRS += bfdrivers
PARENT_SUBDIRS += bfelf_loader
PARENT_SUBDIRS += bfm
PARENT_SUBDIRS += bfvmm
PARENT_SUBDIRS += $(wildcard %HYPER_ABS%/src_*/)
PARENT_SUBDIRS += $(wildcard %HYPER_ABS%/hypervisor_*/)
PARENT_SUBDIRS += $(wildcard %BUILD_ABS%/makefiles/src_*/)
PARENT_SUBDIRS += $(wildcard %BUILD_ABS%/makefiles/hypervisor_*/)

################################################################################
# Common
################################################################################

include %HYPER_ABS%/common/common_subdir.mk

################################################################################
# Custom Targets
################################################################################

.PHONY: linux_load
.PHONY: linux_unload
.PHONY: linux_clean
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

ifeq ($(shell uname -s), Linux)
    SUDO:=sudo
else
    SUDO:=
endif

windows_load: force
	rm -Rf %BUILD_ABS%/outdir
	rm -Rf %BUILD_ABS%/intdir
	SCRIPT_PATH=`cygpath -w %HYPER_ABS%/tools/scripts/build_windows.bat`; \
	HYPER_ABS_PATH=`cygpath -w %HYPER_ABS%`; \
	BUILD_ABS_PATH=`cygpath -w %BUILD_ABS%`; \
	DATE=`date +%m/%d/%Y`; \
	TIME=`date +%H%M%S`; \
	cmd.exe /c $$SCRIPT_PATH $$HYPER_ABS_PATH $$BUILD_ABS_PATH $$DATE $$TIME
	/cygdrive/c/ewdk/Program\ Files/Windows\ Kits/10/bin/x64/certmgr /add `cygpath -w %BUILD_ABS%/outdir/bareflank.cer` /s /r localMachine root
	/cygdrive/c/ewdk/Program\ Files/Windows\ Kits/10/bin/x64/certmgr /add `cygpath -w %BUILD_ABS%/outdir/bareflank.cer` /s /r localMachine trustedpublisher
	/cygdrive/c/ewdk/Program\ Files/Windows\ Kits/10/Tools/x64/devcon remove "ROOT\bareflank"
	/cygdrive/c/ewdk/Program\ Files/Windows\ Kits/10/Tools/x64/devcon install `cygpath -w %BUILD_ABS%/outdir/bareflank/bareflank.inf` "ROOT\bareflank"

windows_unload: force
	rm -Rf %BUILD_ABS%/outdir
	rm -Rf %BUILD_ABS%/intdir
	/cygdrive/c/ewdk/Program\ Files/Windows\ Kits/10/Tools/x64/devcon remove "ROOT\bareflank"

linux_load: force
	@cd %HYPER_ABS%/bfdrivers/src/arch/linux; \
	$(SUDO) make unload; \
	make clean; \
	make; \
	$(SUDO) make load

linux_unload: force
	@cd %HYPER_ABS%/bfdrivers/src/arch/linux; \
	$(SUDO) make unload; \
	make clean

linux_clean: linux_unload

load: force
	@%BUILD_ABS%/build_scripts/filter_module_file.sh $(MODULE_FILE) $(FILTERED_MODULE_FILE)
	@$(SUDO) LD_LIBRARY_PATH=%BUILD_ABS%/makefiles/bfm/bin/native/ %BUILD_ABS%/makefiles/bfm/bin/native/bfm load $(FILTERED_MODULE_FILE)

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

astyle:
	@cd %HYPER_ABS%; \
	%HYPER_ABS%/tools/astyle/linux/run.sh

astyle_clean:
	@cd %HYPER_ABS%; \
	%HYPER_ABS%/tools/astyle/linux/run.sh clean

doxygen:
	@cd %HYPER_ABS%; \
	%HYPER_ABS%/tools/doxygen/linux/run.sh

doxygen_clean:
	@cd %HYPER_ABS%; \
	%HYPER_ABS%/tools/doxygen/linux/run.sh clean
