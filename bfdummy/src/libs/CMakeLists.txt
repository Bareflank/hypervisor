#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
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

add_library(dummy_lib1 STATIC dummy_lib1.cpp)
add_library(dummy_lib2 STATIC dummy_lib2.cpp)
#add_library(dummy_lib1_shared SHARED dummy_lib1.cpp)
#add_library(dummy_lib2_shared SHARED dummy_lib2.cpp)

set_target_properties(dummy_lib1 PROPERTIES LINKER_LANGUAGE C)
set_target_properties(dummy_lib2 PROPERTIES LINKER_LANGUAGE C)
#set_target_properties(dummy_lib1_shared PROPERTIES LINKER_LANGUAGE C)
#set_target_properties(dummy_lib2_shared PROPERTIES LINKER_LANGUAGE C)

target_compile_definitions(dummy_lib1 INTERFACE STATIC_DUMMY)
target_compile_definitions(dummy_lib2 INTERFACE STATIC_DUMMY)
#target_compile_definitions(dummy_lib1_shared INTERFACE SHARED_DUMMY)
#target_compile_definitions(dummy_lib2_shared INTERFACE SHARED_DUMMY)

install(TARGETS dummy_lib1 DESTINATION lib)
install(TARGETS dummy_lib2 DESTINATION lib)
#install(TARGETS dummy_lib1_shared DESTINATION lib)
#install(TARGETS dummy_lib2_shared DESTINATION lib)
