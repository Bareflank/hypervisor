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

do_test(arch/x64/test_gdt.cpp ${ARGN})
do_test(arch/x64/test_idt.cpp ${ARGN})
do_test(arch/intel_x64/test_check_vmcs_controls_fields.cpp ${ARGN})
do_test(arch/intel_x64/test_check_vmcs_guest_fields.cpp ${ARGN})
do_test(arch/intel_x64/test_check_vmcs_host_fields.cpp ${ARGN})
#do_test(arch/intel_x64/test_nmi.cpp ${ARGN})
do_test(arch/intel_x64/test_exception.cpp ${ARGN})
do_test(arch/intel_x64/test_check.cpp ${ARGN})
do_test(arch/intel_x64/test_exit_handler.cpp ${ARGN})
do_test(arch/intel_x64/test_vmcs.cpp ${ARGN})
do_test(arch/intel_x64/test_vmx.cpp ${ARGN})
