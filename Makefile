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

SUBDIRS += bfelf_loader
SUBDIRS += bfm
SUBDIRS += bfvmm
SUBDIRS += driver_entry

################################################################################
# Common
################################################################################

include ./common/common_subdir.mk

################################################################################
# Custom Targets
################################################################################

CS_M='\033[1;95m'

.PHONY: debian_load
.PHONY: debian_clean
.PHONY: start
.PHONY: stop
.PHONY: cycle
.PHONY: cycle_dump
.PHONY: loop

debian_load:
	cd driver_entry/src/arch/linux; \
	sudo make unload; \
	make clean; \
	make; \
	sudo make load

debian_clean:
	cd driver_entry/src/arch/linux; \
	sudo make unload; \
	make clean

start:
	cd bfm/bin/native; \
	sudo ./run.sh start vmm.modules

stop:
	cd bfm/bin/native; \
	sudo ./run.sh stop

dump:
	cd bfm/bin/native; \
	sudo ./run.sh dump

cycle: start stop

cycle_dump: start dump stop

loop: force
	@for n in $(shell seq 1 $(NUM)); do \
		echo $(CS_M)"cycle: $$n"$(CE); \
		$(MAKE) cycle; \
		echo; \
    done
