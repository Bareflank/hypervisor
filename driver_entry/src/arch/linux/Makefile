TARGET_MODULE:=bareflank

ifneq ($(KERNELRELEASE),)
	$(TARGET_MODULE)-objs := entry.o platform.o ../../../../bfelf_loader/src/bfelf_loader.o ../../common.o
	obj-m := $(TARGET_MODULE).o

	EXTRA_CFLAGS += -DKERNEL
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
	rm ../../../../bfelf_loader/src/bfelf_loader.o
	rm ../../../../bfelf_loader/src/.bfelf_loader.o.cmd
	rm ../../common.o
	rm ../../.common.o.cmd

load:
	insmod ./$(TARGET_MODULE).ko
	chmod a+rw /dev/bareflank

unload:
	rmmod ./$(TARGET_MODULE).ko

endif
