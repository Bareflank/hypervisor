

TOP			:= 	$(shell pwd)
ARCH		:= 	$(shell uname -m)

# These values are overwritten by values passed in by cmake
SYSROOT		?= ../../../../../buildex/prefixes/x86_64-userspace-elf
MODULE		?= ../../../../../buildex/prefixes/x86_64-vmm-elf/bin/eapis_efi_static
MODNAME		 = $(notdir $(MODULE))

LIBDIR		:= $(SYSROOT)/lib

CRTOBJ		:= $(LIBDIR)/crt0-efi-$(ARCH).o
LDSCRIPT	:= $(LIBDIR)/elf_$(ARCH)_efi.lds

CC       = clang

CFLAGS  += $(ARCH3264) -g -O2 -Wall -Wextra -DGNU_EFI_USE_MS_ABI
CFLAGS  += --std=c11 -fshort-wchar -fno-strict-aliasing -fno-merge-all-constants
CFLAGS  += -ffreestanding -fno-stack-protector -fno-stack-check
CFLAGS  += -U_FORTIFY_SOURCE -fpic

ARFLAGS += -U
ASFLAGS += $(ARCH3264)
LDFLAGS	+= -nostdlib --warn-common --no-undefined --fatal-warnings \
		   -shared -Bsymbolic -L$(LIBDIR) -defsym=EFI_SUBSYSTEM=0xa --no-undefined

CFLAGS		+= -I$(TOP)/include
CFLAGS		+= -I$(TOP)/modules
CFLAGS		+= -I$(TOP)/include/gnuefi
CFLAGS		+= -I$(TOP)/../../../include
CFLAGS		+= -I$(TOP)/../../../../bfsdk/include
CFLAGS		+= -I$(TOP)/../../../../bfelf_loader/include
CFLAGS		+= -I$(SYSROOT)/include/efi
CFLAGS		+= -I$(SYSROOT)/include/efi/x86_64

LOADLIBES	+= $(CRTOBJ) -lefi -lgnuefi -T $(LDSCRIPT)

FORMAT		:= -O binary --target=efi-app-$(ARCH)

FILES		:= bfloader console boot platform common start x86_64 gnuefi/bflib
OBJS		:= $(foreach FILE,$(FILES),src/$(FILE).o) module/$(MODNAME).o

TARGET		:=	bfloader

all: modules $(TARGET).efi

$(TARGET).efi: $(TARGET).so
	objcopy -j .text -j .sdata -j .data -j .dynamic -j .dynsym -j .rel \
			-j .rela -j .rel.* -j .rela.* -j .rel* -j .rela*           \
			-j .reloc $(FORMAT) $^ $@
	rm -f bfloader.so

$(TARGET).so: $(OBJS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LOADLIBES)

$(OBJS): Makefile

module/$(MODNAME).o: $(MODULE)
	mkdir -p module
	cp $(MODULE) module/$(MODNAME)
	cd module && objcopy -I binary -O elf64-x86-64 -B i386                           \
			--redefine-sym _binary_$(MODNAME)_start=target_module_start              \
			--redefine-sym _binary_$(MODNAME)_size=target_module_size $(MODNAME) $(MODNAME).o

%.o: %.S
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -c -o $@

src/common.o: ../../common.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -c -o $@

clean:
	rm -rf $(TARGET).efi $(TARGET).so src/*.o src/gnuefi/*.o

cleanall: clean
	rm -rf module/

.PHONY: clean cleanall modules
