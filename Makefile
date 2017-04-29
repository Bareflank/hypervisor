default: all
Makefile: /home/user/hypervisor/Makefile.bf
	@/home/user/hypervisor/configure -r --this-is-make
all astyle astyle_clean build_src build_tests clean clean_src clean_tests doxygen doxygen_clean driver_build driver_load driver_unload dump force help linux_build linux_load linux_unload load loop quick run_tests start status stop test tidy unittest unload vmcall windows_build windows_load windows_unload :
	@/home/user/hypervisor/configure -s --this-is-make
	@$(MAKE) --no-print-directory -C makefiles $(MAKECMDGOALS)
