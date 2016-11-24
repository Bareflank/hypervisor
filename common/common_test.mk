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

CG='\033[1;32m'
CS='\033[1;35m'
CE='\033[0m'

################################################################################
# Paths
################################################################################

LIBRARY_PATH := $(LIBRARY_PATH):.

################################################################################
# Targets
################################################################################

Makefile: $(HYPER_REL)/Makefile.bf
	@ BUILD_ABS=$(BUILD_ABS) BUILD_REL=$(BUILD_REL) HYPER_REL=$(HYPER_REL) $(HYPER_ABS)/configure -r --this-is-make

.PHONY: run_tests

.DEFAULT_GOAL := run_tests

run_tests: force
	@echo -e $(CS)"--------------------------------------------------------------------------------"$(CE)
	@LD_LIBRARY_PATH=$(LIBRARY_PATH) ./test > output.txt 2>&1 || (cat output.txt; exit 1)
	@cat output.txt | grep --text "totals:"
	@rm output.txt
	@echo -e $(CS)"--------------------------------------------------------------------------------"$(CE)

force: ;
