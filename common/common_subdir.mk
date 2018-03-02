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

CI='\033[1;32m'
CO='\033[1;35m'
CS='\033[1;34m'
CE='\033[0m'

################################################################################
# Variables
################################################################################

CURRENT_DIR=$(shell pwd)

################################################################################
# Build Dirs
################################################################################

BUILD_SRC_DIRS:=$(filter-out bin,$(SUBDIRS))
BUILD_SRC_DIRS:=$(filter-out test,$(BUILD_SRC_DIRS))

BUILD_TST_DIRS:=$(filter test,$(SUBDIRS))

ifeq ($(strip $(BUILD_SRC_DIRS)), )
	BUILD_SRC_DIRS+=$(PARENT_SUBDIRS)
endif

ifeq ($(strip $(BUILD_TST_DIRS)), )
	BUILD_TST_DIRS+=$(PARENT_SUBDIRS)
endif

################################################################################
# Run Dirs
################################################################################

RUN_DIRS+=$(filter bin,$(SUBDIRS))
RUN_DIRS+=$(filter native,$(SUBDIRS))

ifeq ($(strip $(RUN_DIRS)), )
	RUN_DIRS+=$(PARENT_SUBDIRS)
endif

################################################################################
# Clean Dirs
################################################################################

CLEAN_DIRS:=$(filter-out bin,$(SUBDIRS))

ifeq ($(strip $(CLEAN_DIRS)), )
	CLEAN_DIRS+=$(PARENT_SUBDIRS)
endif

################################################################################
# Targets
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

all:
	@$(MAKE) --no-print-directory build_src
ifeq ($(shell uname -s), Linux)
	@$(MAKE) --no-print-directory build_tests
endif

build_src:
	@for dir in $(BUILD_SRC_DIRS); do \
		dir=`basename $$dir`; \
		echo -e $(CI)"-->" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
		if [[ ! -d $(CURRENT_DIR)/$$dir ]]; then \
			mkdir $(CURRENT_DIR)/$$dir; \
		fi; \
		if [[ ! -f $(CURRENT_DIR)/$$dir/Makefile ]]; then \
			pushd $(CURRENT_DIR)/$$dir; \
			BUILD_ABS=$(BUILD_ABS) BUILD_REL=$(BUILD_REL)/$$dir HYPER_REL=$(HYPER_REL)/$$dir $(HYPER_ABS)/configure -r --this-is-make; \
			popd; \
		fi; \
		$(MAKE) --no-print-directory -C $$dir build_src || exit 1; \
		echo -e $(CO)"<--" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
	done

ifeq ($(shell uname -s), Linux)
build_tests:

	@for dir in $(BUILD_TST_DIRS); do \
		dir=`basename $$dir`; \
		echo -e $(CI)"-->" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
		if [[ ! -d $(CURRENT_DIR)/$$dir ]]; then \
			mkdir $(CURRENT_DIR)/$$dir; \
		fi; \
		if [[ ! -f $(CURRENT_DIR)/$$dir/Makefile ]]; then \
			pushd $(CURRENT_DIR)/$$dir; \
			BUILD_ABS=$(BUILD_ABS) BUILD_REL=$(BUILD_REL)/$$dir HYPER_REL=$(HYPER_REL)/$$dir $(HYPER_ABS)/configure -r --this-is-make; \
			popd; \
		fi; \
		$(MAKE) --no-print-directory -C $$dir build_tests || exit 1; \
		echo -e $(CO)"<--" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
	done
endif

ifeq ($(shell uname -s), Linux)
run_tests: force
	@for dir in $(RUN_DIRS); do \
		dir=`basename $$dir`; \
		echo -e $(CI)"-->" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
		if [[ ! -d $(CURRENT_DIR)/$$dir ]]; then \
			mkdir $(CURRENT_DIR)/$$dir; \
		fi; \
		if [[ ! -f $(CURRENT_DIR)/$$dir/Makefile ]]; then \
			pushd $(CURRENT_DIR)/$$dir; \
			BUILD_ABS=$(BUILD_ABS) BUILD_REL=$(BUILD_REL)/$$dir HYPER_REL=$(HYPER_REL)/$$dir $(HYPER_ABS)/configure -r --this-is-make; \
			popd; \
		fi; \
		$(MAKE) --no-print-directory -C $$dir run_tests || exit 1; \
		echo -e $(CO)"<--" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
	done
endif

clean:
	@for dir in $(CLEAN_DIRS); do \
		dir=`basename $$dir`; \
		echo -e $(CI)"-->" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
		if [[ ! -d $(CURRENT_DIR)/$$dir ]]; then \
			mkdir $(CURRENT_DIR)/$$dir; \
		fi; \
		if [[ ! -f $(CURRENT_DIR)/$$dir/Makefile ]]; then \
			pushd $(CURRENT_DIR)/$$dir; \
			BUILD_ABS=$(BUILD_ABS) BUILD_REL=$(BUILD_REL)/$$dir HYPER_REL=$(HYPER_REL)/$$dir $(HYPER_ABS)/configure -r --this-is-make; \
			popd; \
		fi; \
		$(MAKE) --no-print-directory -C $$dir clean; \
		echo -e $(CO)"<--" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
	done

clean_src:
	@for dir in $(BUILD_SRC_DIRS); do \
		dir=`basename $$dir`; \
		echo -e $(CI)"-->" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
		if [[ ! -d $(CURRENT_DIR)/$$dir ]]; then \
			mkdir $(CURRENT_DIR)/$$dir; \
		fi; \
		if [[ ! -f $(CURRENT_DIR)/$$dir/Makefile ]]; then \
			pushd $(CURRENT_DIR)/$$dir; \
			BUILD_ABS=$(BUILD_ABS) BUILD_REL=$(BUILD_REL)/$$dir HYPER_REL=$(HYPER_REL)/$$dir $(HYPER_ABS)/configure -r --this-is-make; \
			popd; \
		fi; \
		$(MAKE) --no-print-directory -C $$dir clean_src; \
		echo -e $(CO)"<--" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
	done

ifeq ($(shell uname -s), Linux)
clean_tests:
	@for dir in $(BUILD_TST_DIRS); do \
		dir=`basename $$dir`; \
		echo -e $(CI)"-->" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
		if [[ ! -d $(CURRENT_DIR)/$$dir ]]; then \
			mkdir $(CURRENT_DIR)/$$dir; \
		fi; \
		if [[ ! -f $(CURRENT_DIR)/$$dir/Makefile ]]; then \
			pushd $(CURRENT_DIR)/$$dir; \
			BUILD_ABS=$(BUILD_ABS) BUILD_REL=$(BUILD_REL)/$$dir HYPER_REL=$(HYPER_REL)/$$dir $(HYPER_ABS)/configure -r --this-is-make; \
			popd; \
		fi; \
		$(MAKE) --no-print-directory -C $$dir clean_tests; \
		echo -e $(CO)"<--" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
	done
endif

force:;
