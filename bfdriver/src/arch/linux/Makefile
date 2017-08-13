TARGET_MODULE:=bareflank

ifneq ($(KERNELRELEASE),)
	obj-m := $(TARGET_MODULE).o

	$(TARGET_MODULE)-objs += entry.o
	$(TARGET_MODULE)-objs += vmcall.o
	$(TARGET_MODULE)-objs += platform.o
	$(TARGET_MODULE)-objs += ../../common.o

	EXTRA_CFLAGS += -DKERNEL
	EXTRA_CFLAGS += -DLINUX_KERNEL
	EXTRA_CFLAGS += -I$(src)/../../../include/
	EXTRA_CFLAGS += -I$(CMAKE_INSTALL_PREFIX)/include/

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

$(KBUILD_EXTMOD)/vmcall.o: vmcall.asm
	@echo "cmd_${KBUILD_EXTMOD}/vmcall.o := nasm -f elf64 -o vmcall.asm" > $(KBUILD_EXTMOD)/.vmcall.o.cmd
	@nasm -f elf64 -o $@ $^
