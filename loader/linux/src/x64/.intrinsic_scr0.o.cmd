cmd_/home/user/working/hypervisor/loader/linux/src/x64/intrinsic_scr0.o := gcc -Wp,-MD,/home/user/working/hypervisor/loader/linux/src/x64/.intrinsic_scr0.o.d  -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/9/include  -I./arch/x86/include -I./arch/x86/include/generated  -I./include -I./arch/x86/include/uapi -I./arch/x86/include/generated/uapi -I./include/uapi -I./include/generated/uapi -include ./include/linux/kconfig.h -Iubuntu/include  -D__KERNEL__ -D__ASSEMBLY__ -fno-PIE -m64 -DCONFIG_X86_X32_ABI -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 -DCONFIG_AS_CFI_SECTIONS=1 -DCONFIG_AS_SSSE3=1 -DCONFIG_AS_AVX=1 -DCONFIG_AS_AVX2=1 -DCONFIG_AS_AVX512=1 -DCONFIG_AS_SHA1_NI=1 -DCONFIG_AS_SHA256_NI=1 -DCC_USING_FENTRY  -DMODULE  -c -o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_scr0.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_scr0.S

source_/home/user/working/hypervisor/loader/linux/src/x64/intrinsic_scr0.o := /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_scr0.S

deps_/home/user/working/hypervisor/loader/linux/src/x64/intrinsic_scr0.o := \
  include/linux/kconfig.h \
    $(wildcard include/config/cpu/big/endian.h) \
    $(wildcard include/config/booger.h) \
    $(wildcard include/config/foo.h) \

/home/user/working/hypervisor/loader/linux/src/x64/intrinsic_scr0.o: $(deps_/home/user/working/hypervisor/loader/linux/src/x64/intrinsic_scr0.o)

$(deps_/home/user/working/hypervisor/loader/linux/src/x64/intrinsic_scr0.o):
