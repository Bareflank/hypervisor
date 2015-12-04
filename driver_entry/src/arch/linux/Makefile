TARGET_MODULE:=bareflank

ifneq ($(KERNELRELEASE),)
	obj-m := $(TARGET_MODULE).o

	$(TARGET_MODULE)-objs += entry.o
	$(TARGET_MODULE)-objs += platform.o
	$(TARGET_MODULE)-objs += ../../common.o
	$(TARGET_MODULE)-objs += ../../../../src/debug_ring_interface.o
	$(TARGET_MODULE)-objs += ../../../../bfelf_loader/src/bfelf_loader.o

	EXTRA_CFLAGS += -DKERNEL
	EXTRA_CFLAGS += -DLINUX_KERNEL
	EXTRA_CFLAGS += -I$(PWD)/../../../include/
	EXTRA_CFLAGS += -I$(PWD)/../../../../include/
	EXTRA_CFLAGS += -I$(PWD)/../../../../bfelf_loader/include/

else
	BUILDSYSTEM_DIR:=/lib/modules/$(shell uname -r)/build
	PWD:=$(shell pwd)

all :
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) clean
	rm -f ../../../../bfelf_loader/src/bfelf_loader.o
	rm -f ../../../../bfelf_loader/src/.bfelf_loader.o.cmd
	rm -f ../../../../src/debug_ring_interface.o
	rm -f ../../../../src/.debug_ring_interface.o.cmd
	rm -f ../../common.o
	rm -f ../../.common.o.cmd

load:
	insmod ./$(TARGET_MODULE).ko
	chmod a+rw /dev/bareflank

unload:
	rmmod ./$(TARGET_MODULE).ko

endif
