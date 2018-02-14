#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
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

TARGET_MODULE:=bareflank

ifneq ($(KERNELRELEASE),)
	obj-m := $(TARGET_MODULE).o

	$(TARGET_MODULE)-objs += entry.o
	$(TARGET_MODULE)-objs += platform.o
	$(TARGET_MODULE)-objs += ../../common.o

	EXTRA_CFLAGS += -DKERNEL
	EXTRA_CFLAGS += -DLINUX_KERNEL
	EXTRA_CFLAGS += -I$(src)/../../../include/
	EXTRA_CFLAGS += -I$(src)/../../../../bfsdk/include/
	EXTRA_CFLAGS += -I$(src)/../../../../bfelf_loader/include/

else
	BUILDSYSTEM_DIR:=/lib/modules/$(shell uname -r)/build
	PWD:=$(shell pwd)

all:
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) clean
	rm -f ../../common.o
	rm -f ../../.common.o.cmd

load:
	insmod ./$(TARGET_MODULE).ko

unload:
	-rmmod ./$(TARGET_MODULE).ko

endif
