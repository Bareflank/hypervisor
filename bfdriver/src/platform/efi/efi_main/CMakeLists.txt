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

set(EFI_VMM ${VMM_PREFIX_PATH}/bin/${EFI_VMM_NAME})
set(EFI_VMM_OBJ ${EFI_OUTPUT_DIR}/${EFI_VMM_NAME}.o)
set(EFI_TARGET_NAME bfloader)

add_custom_command(
    OUTPUT ${EFI_VMM_OBJ}
    COMMAND ${CMAKE_COMMAND} -E copy ${EFI_VMM} ${EFI_VMM_NAME}
    COMMAND ${CMAKE_OBJCOPY}
    ARGS -I binary -O elf64-x86-64 -B i386
    ARGS --redefine-sym _binary_${EFI_VMM_NAME}_start=target_vmm_start
    ARGS --redefine-sym _binary_${EFI_VMM_NAME}_end=target_vmm_end
    ARGS ${EFI_VMM_NAME} ${EFI_VMM_OBJ}
    DEPENDS ${EFI_VMM}
    WORKING_DIRECTORY ${EFI_OUTPUT_DIR}
    COMMENT "Using ${EFI_VMM_NAME}"
)

list(APPEND SOURCES
    ${VMM_PREFIX_PATH}/lib/crt0-efi-${BUILD_TARGET_ARCH}.o
    efi_main.c
    boot.c
    ${EFI_VMM_OBJ}
)

add_library(${EFI_TARGET_NAME} SHARED ${SOURCES})
set_property(TARGET ${EFI_TARGET_NAME} PROPERTY SKIP_BUILD_RPATH TRUE)

add_library(libgnuefi STATIC IMPORTED)
set_target_properties(libgnuefi PROPERTIES IMPORTED_LOCATION
    ${VMM_PREFIX_PATH}/lib/libgnuefi.a
)
add_dependencies(libgnuefi gnuefi)

add_library(libefi STATIC IMPORTED)
set_target_properties(libefi PROPERTIES IMPORTED_LOCATION
    ${VMM_PREFIX_PATH}/lib/libefi.a
)
add_dependencies(libefi gnuefi)

target_link_libraries(${EFI_TARGET_NAME} libgnuefi libefi)

set(EFI_LINKER_SCRIPT ${VMM_PREFIX_PATH}/lib/elf_${BUILD_TARGET_ARCH}_efi.lds)
target_link_libraries(${EFI_TARGET_NAME} -T ${EFI_LINKER_SCRIPT})

file(READ ${EFI_SOURCES_CMAKE} EXTERNAL_SOURCES)

foreach(src ${EXTERNAL_SOURCES})
    message(STATUS "Adding EFI external source: ${src}")
    target_sources(${EFI_TARGET_NAME} PRIVATE ${src})
endforeach()

add_custom_command(
    TARGET ${EFI_TARGET_NAME}
    POST_BUILD
    COMMAND ${CMAKE_OBJCOPY}
    ARGS -j .text -j .sdata -j .data -j .dynamic -j .dynsym -j .rel -j .rela -j .rel.* -j .rela.* -j .rel*
    ARGS -j .rela* -j .reloc --target=efi-app-${BUILD_TARGET_ARCH} lib${EFI_TARGET_NAME}.so ${EFI_OUTPUT_DIR}/${EFI_TARGET_NAME}.efi
    MAIN_DEPENDENCY lib${EFI_TARGET_NAME}.so
    COMMENT "Linking bfloader.efi"
)

install(FILES ${EFI_OUTPUT_DIR}/${EFI_TARGET_NAME}.efi DESTINATION bin)
