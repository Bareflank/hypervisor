cmd_/home/user/working/hypervisor/loader/linux/../src/x64/serial_write.o := gcc -Wp,-MD,/home/user/working/hypervisor/loader/linux/../src/x64/.serial_write.o.d  -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/9/include  -I./arch/x86/include -I./arch/x86/include/generated  -I./include -I./arch/x86/include/uapi -I./arch/x86/include/generated/uapi -I./include/uapi -I./include/generated/uapi -include ./include/linux/kconfig.h -Iubuntu/include  -include ./include/linux/compiler_types.h -D__KERNEL__ -Wall -Wundef -Werror=strict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE -Werror=implicit-function-declaration -Werror=implicit-int -Wno-format-security -std=gnu89 -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -m64 -falign-jumps=1 -falign-loops=1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3 -mskip-rax-setup -mtune=generic -mno-red-zone -mcmodel=kernel -DCONFIG_X86_X32_ABI -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 -DCONFIG_AS_CFI_SECTIONS=1 -DCONFIG_AS_SSSE3=1 -DCONFIG_AS_AVX=1 -DCONFIG_AS_AVX2=1 -DCONFIG_AS_AVX512=1 -DCONFIG_AS_SHA1_NI=1 -DCONFIG_AS_SHA256_NI=1 -Wno-sign-compare -fno-asynchronous-unwind-tables -mindirect-branch=thunk-extern -mindirect-branch-register -fno-jump-tables -fno-delete-null-pointer-checks -Wno-frame-address -Wno-format-truncation -Wno-format-overflow -Wno-address-of-packed-member -O2 --param=allow-store-data-races=0 -Wframe-larger-than=1024 -fstack-protector-strong -Wno-unused-but-set-variable -Wimplicit-fallthrough -Wno-unused-const-variable -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-var-tracking-assignments -pg -mrecord-mcount -mfentry -DCC_USING_FENTRY -flive-patching=inline-clone -Wdeclaration-after-statement -Wvla -Wno-pointer-sign -Wno-stringop-truncation -fno-strict-overflow -fno-merge-all-constants -fmerge-constants -fno-stack-check -fconserve-stack -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -fmacro-prefix-map=./= -fcf-protection=none -Wno-packed-not-aligned -I/home/user/working/hypervisor/loader/linux/include -I/home/user/working/hypervisor/loader/linux/include/std -I/home/user/working/hypervisor/loader/linux/include/platform_interface/c -I/home/user/working/hypervisor/loader/linux/../include -I/home/user/working/hypervisor/loader/linux/../include/interface/c -I/home/user/working/hypervisor/loader/linux/../include/interface/c/bfelf -I'/home/user/working/build'/include -I/home/user/working/hypervisor/loader/linux/include/x64 -I/home/user/working/hypervisor/loader/linux/include/x64/amd -I/home/user/working/hypervisor/loader/linux/../include/x64/ -I/home/user/working/hypervisor/loader/linux/../include/x64/amd -I/home/user/working/hypervisor/loader/linux/../include/interface/c/x64 -I/home/user/working/hypervisor/loader/linux/../include/interface/c/x64/amd  -DMODULE  -DKBUILD_BASENAME='"serial_write"' -DKBUILD_MODNAME='"bareflank_loader"' -c -o /home/user/working/hypervisor/loader/linux/../src/x64/serial_write.o /home/user/working/hypervisor/loader/linux/../src/x64/serial_write.c

source_/home/user/working/hypervisor/loader/linux/../src/x64/serial_write.o := /home/user/working/hypervisor/loader/linux/../src/x64/serial_write.c

deps_/home/user/working/hypervisor/loader/linux/../src/x64/serial_write.o := \
  include/linux/kconfig.h \
    $(wildcard include/config/cpu/big/endian.h) \
    $(wildcard include/config/booger.h) \
    $(wildcard include/config/foo.h) \
  include/linux/compiler_types.h \
    $(wildcard include/config/have/arch/compiler/h.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/optimize/inlining.h) \
    $(wildcard include/config/cc/has/asm/inline.h) \
  include/linux/compiler_attributes.h \
  include/linux/compiler-gcc.h \
    $(wildcard include/config/retpoline.h) \
    $(wildcard include/config/arch/use/builtin/bswap.h) \
  /home/user/working/build/include/constants.h \
  /home/user/working/hypervisor/loader/linux/include/std/stdint.h \
  include/linux/types.h \
    $(wildcard include/config/have/uid16.h) \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/arch/dma/addr/t/64bit.h) \
    $(wildcard include/config/phys/addr/t/64bit.h) \
    $(wildcard include/config/64bit.h) \
  include/uapi/linux/types.h \
  arch/x86/include/generated/uapi/asm/types.h \
  include/uapi/asm-generic/types.h \
  include/asm-generic/int-ll64.h \
  include/uapi/asm-generic/int-ll64.h \
  arch/x86/include/uapi/asm/bitsperlong.h \
  include/asm-generic/bitsperlong.h \
  include/uapi/asm-generic/bitsperlong.h \
  include/uapi/linux/posix_types.h \
  include/linux/stddef.h \
  include/uapi/linux/stddef.h \
  include/linux/compiler_types.h \
  arch/x86/include/asm/posix_types.h \
    $(wildcard include/config/x86/32.h) \
  arch/x86/include/uapi/asm/posix_types_64.h \
  include/uapi/asm-generic/posix_types.h \
  /home/user/working/hypervisor/loader/linux/include/x64/intrinsic_inb.h \
  /home/user/working/hypervisor/loader/linux/include/types.h \
  /home/user/working/hypervisor/loader/linux/include/std/inttypes.h \
  /home/user/working/hypervisor/loader/linux/include/std/stdint.h \
  /home/user/working/hypervisor/loader/linux/include/x64/intrinsic_outb.h \

/home/user/working/hypervisor/loader/linux/../src/x64/serial_write.o: $(deps_/home/user/working/hypervisor/loader/linux/../src/x64/serial_write.o)

$(deps_/home/user/working/hypervisor/loader/linux/../src/x64/serial_write.o):
