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

LIBRARY_PATH := $(LIBRARY_PATH):%BUILD_ABS%/makefiles/bfvmm/src/debug_ring/bin/native
LIBRARY_PATH := $(LIBRARY_PATH):%BUILD_ABS%/makefiles/bfvmm/src/entry/bin/native
LIBRARY_PATH := $(LIBRARY_PATH):%BUILD_ABS%/makefiles/bfvmm/src/exit_handler/bin/native
LIBRARY_PATH := $(LIBRARY_PATH):%BUILD_ABS%/makefiles/bfvmm/src/intrinsics/bin/native
LIBRARY_PATH := $(LIBRARY_PATH):%BUILD_ABS%/makefiles/bfvmm/src/memory_manager/bin/native
LIBRARY_PATH := $(LIBRARY_PATH):%BUILD_ABS%/makefiles/bfvmm/src/misc/bin/native
LIBRARY_PATH := $(LIBRARY_PATH):%BUILD_ABS%/makefiles/bfvmm/src/serial/bin/native
LIBRARY_PATH := $(LIBRARY_PATH):%BUILD_ABS%/makefiles/bfvmm/src/vcpu/bin/native
LIBRARY_PATH := $(LIBRARY_PATH):%BUILD_ABS%/makefiles/bfvmm/src/vcpu_factory/bin/native
LIBRARY_PATH := $(LIBRARY_PATH):%BUILD_ABS%/makefiles/bfvmm/src/vmcs/bin/native
LIBRARY_PATH := $(LIBRARY_PATH):%BUILD_ABS%/makefiles/bfvmm/src/vmxon/bin/native

include %HYPER_ABS%/common/common_test.mk

