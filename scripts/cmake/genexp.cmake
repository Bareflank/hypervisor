#
# Bareflank Hypervisor
# Copyright (C) 2018 Assured Information Security, Inc.
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

# Booleans
#
# When dereferenced, each generator expression below evaluates to
# either 0 or 1 at build time
#
set(WIN $<BOOL:${WIN32}>)

set(VMM $<AND:$<STREQUAL:${PREFIX},vmm>,$<BOOL:${BUILD_VMM}>>)
set(USR $<AND:$<STREQUAL:${PREFIX},userspace>,$<BOOL:${BUILD_USERSPACE}>>)
set(TST $<AND:$<STREQUAL:${PREFIX},test>,$<BOOL:${BUILD_TEST}>>)
set(EFI $<AND:$<STREQUAL:${PREFIX},efi>,$<BOOL:${BUILD_EFI}>>)

set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(ARM64 $<STREQUAL:${BUILD_TARGET_ARCH},aarch64>)
set(C $<COMPILE_LANGUAGE:C>)
set(CXX $<COMPILE_LANGUAGE:CXX>)
set(C_CXX $<OR:${C},${CXX}>)
set(MSVC $<CXX_COMPILER_ID:MSVC>)
set(CLANG $<CXX_COMPILER_ID:Clang>)
set(C_CXX_X64 $<AND:${C_CXX},${X64}>)

set(VMM_X64 $<AND:${VMM},${X64}>)
set(VMM_ARM64 $<AND:${VMM},${ARM64}>)
set(VMM_C $<AND:${VMM},${C}>)
set(VMM_CXX $<AND:${VMM},${CXX}>)
set(VMM_C_CXX $<AND:${VMM},${C_CXX}>)
set(VMM_C_CXX_CLANG $<AND:${VMM_C_CXX},${CLANG}>)
set(VMM_C_CXX_MSVC $<AND:${VMM_C_CXX},${MSVC}>)

set(USR_X64 $<AND:${USR},${X64}>)
set(USR_ARM64 $<AND:${USR},${ARM64}>)
set(USR_C $<AND:${USR},${C}>)
set(USR_CXX $<AND:${USR},${CXX}>)
set(USR_CXX_CLANG $<AND:${USR},${CXX},${CLANG}>)
set(USR_CXX_MSVC $<AND:${USR},${CXX},${MSVC}>)
set(USR_C_CXX $<AND:${USR},${C_CXX}>)
set(USR_C_CXX_CLANG $<AND:${USR_C_CXX},${CLANG}>)
set(USR_C_CXX_MSVC $<AND:${USR_C_CXX},${MSVC}>)

set(TST_X64 $<AND:${TST},${X64}>)
set(TST_ARM64 $<AND:${TST},${ARM64}>)
set(TST_C $<AND:${TST},${C}>)
set(TST_CXX $<AND:${TST},${CXX}>)
set(TST_CXX_CLANG $<AND:${TST},${CXX},${CLANG}>)
set(TST_CXX_MSVC $<AND:${TST},${CXX},${MSVC}>)
set(TST_C_CXX $<AND:${TST},${C_CXX}>)
set(TST_C_CXX_CLANG $<AND:${TST_C_CXX},${CLANG}>)
set(TST_C_CXX_MSVC $<AND:${TST_C_CXX},${MSVC}>)

set(TST_C_CXX_CLANG_ASAN $<AND:${TST_C_CXX_CLANG},$<BOOL:${ENABLE_ASAN}>>)
set(TST_C_CXX_CLANG_USAN $<AND:${TST_C_CXX_CLANG},$<BOOL:${ENABLE_USAN}>>)
set(TST_C_CXX_CLANG_CODECOV $<AND:${TST_C_CXX_CLANG},$<BOOL:${ENABLE_CODECOV}>>)

set(EFI_X64 $<AND:${EFI},${X64}>)
set(EFI_ARM64 $<AND:${EFI},${ARM64}>)
set(EFI_C $<AND:${EFI},${C}>)
set(EFI_CXX $<AND:${EFI},${CXX}>)
set(EFI_C_CXX $<AND:${EFI},${C_CXX}>)
set(EFI_C_CXX_CLANG $<AND:${EFI_C_CXX},${CLANG}>)
set(EFI_C_CXX_MSVC $<AND:${EFI_C_CXX},${MSVC}>)
