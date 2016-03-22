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
# Subdirs
################################################################################

PARENT_SUBDIRS += bfelf_loader
PARENT_SUBDIRS += bfm
PARENT_SUBDIRS += bfunwind
PARENT_SUBDIRS += bfvmm
PARENT_SUBDIRS += driver_entry

################################################################################
# Common
################################################################################

include ./common/common_subdir.mk

################################################################################
# Custom Targets
################################################################################

CS_M='\033[1;95m'

.PHONY: debian_load
.PHONY: debian_unload
.PHONY: debian_clean
.PHONY: load
.PHONY: unload
.PHONY: start
.PHONY: stop
.PHONY: dump
.PHONY: status
.PHONY: quick
.PHONY: loop
.PHONY: unittest

debian_load: force
	@cd driver_entry/src/arch/linux; \
	sudo make unload; \
	make clean; \
	make; \
	sudo make load

debian_unload: force
	@cd driver_entry/src/arch/linux; \
	sudo make unload; \
	make clean

debian_clean: debian_unload

load: force
	@cd bfm/bin/native; \
	sudo ./run.sh load vmm.modules;

unload: force
	@cd bfm/bin/native; \
	sudo ./run.sh unload

start: force
	@cd bfm/bin/native; \
	sudo ./run.sh start

stop: force
	@cd bfm/bin/native; \
	sudo ./run.sh stop

dump: force
	@cd bfm/bin/native; \
	sudo ./run.sh dump

status: force
	@cd bfm/bin/native; \
	sudo ./run.sh status

quick: load start

loop: force
	@for n in $(shell seq 1 $(NUM)); do \
		echo $(CS_M)"cycle: $$n"$(CE); \
		$(MAKE) --no-print-directory load; \
		$(MAKE) --no-print-directory start; \
		$(MAKE) --no-print-directory stop; \
		$(MAKE) --no-print-directory unload; \
    done \

unittest: run_tests
