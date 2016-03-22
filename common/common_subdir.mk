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

.PHONY: clean
.PHONY: clean_src
.PHONY: clean_tests
.PHONY: build_src
.PHONY: build_tests
.PHONY: run_tests

.DEFAULT_GOAL := all

all: build_src build_tests

build_src:
	@for dir in $(BUILD_SRC_DIRS); do \
		echo $(CI)"-->" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
		$(MAKE) --no-print-directory -C $$dir build_src || exit 1; \
		echo $(CO)"<--" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
	done

build_tests:
	@for dir in $(BUILD_TST_DIRS); do \
		echo $(CI)"-->" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
		$(MAKE) --no-print-directory -C $$dir build_tests || exit 1; \
		echo $(CO)"<--" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
	done

run_tests: force
	@for dir in $(RUN_DIRS); do \
		echo $(CI)"-->" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
		$(MAKE) --no-print-directory -C $$dir run_tests || exit 1; \
		echo $(CO)"<--" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
	done

clean:
	@for dir in $(CLEAN_DIRS); do \
		echo $(CI)"-->" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
		$(MAKE) --no-print-directory -C $$dir clean; \
		echo $(CO)"<--" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
	done

clean_src:
	@for dir in $(BUILD_SRC_DIRS); do \
		echo $(CI)"-->" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
		$(MAKE) --no-print-directory -C $$dir clean_src; \
		echo $(CO)"<--" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
	done

clean_tests:
	@for dir in $(BUILD_TST_DIRS); do \
		echo $(CI)"-->" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
		$(MAKE) --no-print-directory -C $$dir clean_tests; \
		echo $(CO)"<--" $(CS)$(CURRENT_DIR)/$$dir$(CE); \
	done

force:;
