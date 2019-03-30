#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

TARGET_MODULE:=bareflank

ifneq ($(KERNELRELEASE),)
	obj-m := $(TARGET_MODULE).o

	$(TARGET_MODULE)-objs += entry.o
	$(TARGET_MODULE)-objs += platform.o
	$(TARGET_MODULE)-objs += intrinsics.o
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
