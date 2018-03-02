#
# Bareflank Hypervisor
#
# Copyright (C) 2015 Assured Information Security, Inc.
# Author: Rian Quinn        <quinnr@ainfosec.com>
# Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

SHELL=/bin/bash

################################################################################
# Compilers
################################################################################

ifeq ($(TARGET_COMPILER), native)
	TARGET_CROSS_COMPILED:=
	TARGET_NATIVE_COMPILED:=true
endif

ifeq ($(TARGET_COMPILER), cross)
	ifeq ($(STATIC_ANALYSIS_ENABLED), true)
		TARGET_CROSS_COMPILED:=
		TARGET_NATIVE_COMPILED:=
	else
		TARGET_CROSS_COMPILED:=true
		TARGET_NATIVE_COMPILED:=
	endif
endif

ifeq ($(TARGET_COMPILER), both)
	ifeq ($(STATIC_ANALYSIS_ENABLED), true)
		TARGET_CROSS_COMPILED:=
		TARGET_NATIVE_COMPILED:=true
	else
		TARGET_CROSS_COMPILED:=true
		TARGET_NATIVE_COMPILED:=true
	endif
endif

################################################################################
# OS Detection
################################################################################

ifeq ($(OS), Windows_NT)
	OS:=windows
else
	UNAME:=$(shell uname -s)
	ifeq ($(UNAME), Linux)
		OS:=linux
	else
		OS:=osx
	endif
endif

################################################################################
# Output Directories
################################################################################

NATIVE_OBJDIR_PARENT:=$(NATIVE_OBJDIR)
NATIVE_OUTDIR_PARENT:=$(NATIVE_OUTDIR)
NATIVE_OBJDIR:=$(NATIVE_OBJDIR)/native
NATIVE_OUTDIR:=$(NATIVE_OUTDIR)/native

CROSS_OBJDIR_PARENT:=$(CROSS_OBJDIR)
CROSS_OUTDIR_PARENT:=$(CROSS_OUTDIR)
CROSS_OBJDIR:=$(CROSS_OBJDIR)/cross
CROSS_OUTDIR:=$(CROSS_OUTDIR)/cross

################################################################################
# Exectuables
################################################################################

NATIVE_CC:=$(CC)
NATIVE_CXX:=$(CXX)
NATIVE_ASM:=nasm
NATIVE_LD:=$(CXX)
NATIVE_AR:=$(AR)

ifeq ($(SYSROOT_NAME),)
	SYSROOT_NAME:=vmm
endif

CROSS_CC:=$(BUILD_ABS)/build_scripts/x86_64-$(SYSROOT_NAME)-clang
CROSS_CXX:=$(BUILD_ABS)/build_scripts/x86_64-$(SYSROOT_NAME)-clang++
CROSS_ASM:=$(BUILD_ABS)/build_scripts/x86_64-$(SYSROOT_NAME)-nasm
CROSS_LD:=$(BUILD_ABS)/build_scripts/x86_64-$(SYSROOT_NAME)-clang++
CROSS_AR:=$(BUILD_ABS)/build_scripts/x86_64-$(SYSROOT_NAME)-elf-ar

RM:=rm -rf
MD:=mkdir -p
TEST:=test
RMDIR:=rmdir --ignore-fail-on-non-empty -p

################################################################################
# Default CC Flags
################################################################################

# Most of the compiler flags are already provided in the configure script.
# We add warnings here to prevent warnings from being compiled into some of
# our dependecies like Libc++ which would break if all of these warnings
# were turned on. For more compiler flags, please see the configure script.
# Also note that the naming of the flags variables is done in such a way that
# alows uses to add flags to their bash environments prior to compilation
# to customize the builds system, while also suppliying these flags to our
# dependencies.

NATIVE_CCFLAGS+=-Wall
NATIVE_CCFLAGS+=-Wextra
NATIVE_CCFLAGS+=-Wpedantic
NATIVE_CCFLAGS+=-Wshadow
NATIVE_CCFLAGS+=-Wconversion
NATIVE_CCFLAGS+=-Wsign-conversion
NATIVE_CCFLAGS+=$(CONFIGURED_NATIVE_CCFLAGS)

ifeq ($(DYNAMIC_ANALYSIS_ENABLED), true)
	ifneq ($(NO_ADDRESS_SANATIZE), true)
		NATIVE_CCFLAGS+=-fsanitize=address
	endif
	NATIVE_CCFLAGS+=-fsanitize=undefined
	NATIVE_CCFLAGS+=-fno-sanitize=vptr
	NATIVE_CCFLAGS+=-fno-sanitize=alignment
endif

CROSS_CCFLAGS+=-Wall
CROSS_CCFLAGS+=-Wextra
CROSS_CCFLAGS+=-Wpedantic
CROSS_CCFLAGS+=-Wshadow
CROSS_CCFLAGS+=-Wconversion
CROSS_CCFLAGS+=-Wsign-conversion
CROSS_CCFLAGS+=$(CONFIGURED_CROSS_CCFLAGS)

ifeq ($(COVERALLS), true)
	NATIVE_CCFLAGS+=-fprofile-arcs -ftest-coverage
endif

# ifneq ($(IGNORE_WARNINGS),yes)
# 	NATIVE_CCFLAGS+=-Werror
# 	CROSS_CCFLAGS+=-Werror
# endif

ifeq ($(TARGET_NATIVE_COMPILED), true)
	ifeq ($(OS), windows)
		NATIVE_CCFLAGS+=$(WINDOWS_CCFLAGS)
	endif
	ifeq ($(OS), linux)
		NATIVE_CCFLAGS+=$(LINUX_CCFLAGS)
	endif
	ifeq ($(OS), osx)
		NATIVE_CCFLAGS+=$(OSX_CCFLAGS)
	endif
endif

################################################################################
# Default CXX Flags
################################################################################

# Most of the compiler flags are already provided in the configure script.
# We add warnings here to prevent warnings from being compiled into some of
# our dependecies like Libc++ which would break if all of these warnings
# were turned on. For more compiler flags, please see the configure script.
# Also note that the naming of the flags variables is done in such a way that
# alows uses to add flags to their bash environments prior to compilation
# to customize the builds system, while also suppliying these flags to our
# dependencies.

NATIVE_CXXFLAGS+=-Wall
NATIVE_CXXFLAGS+=-Wextra
NATIVE_CXXFLAGS+=-Wpedantic
NATIVE_CXXFLAGS+=-Wctor-dtor-privacy
NATIVE_CXXFLAGS+=-Wshadow
NATIVE_CXXFLAGS+=-Wnon-virtual-dtor
NATIVE_CXXFLAGS+=-Wold-style-cast
NATIVE_CXXFLAGS+=-Woverloaded-virtual
NATIVE_CXXFLAGS+=-Wconversion
NATIVE_CXXFLAGS+=-Wsign-conversion
NATIVE_CXXFLAGS+=-DGSL_THROW_ON_CONTRACT_VIOLATION
NATIVE_CXXFLAGS+=$(CONFIGURED_NATIVE_CXXFLAGS)

ifeq ($(DYNAMIC_ANALYSIS_ENABLED), true)
	ifneq ($(NO_ADDRESS_SANATIZE), true)
		NATIVE_CXXFLAGS+=-fsanitize=address
	endif
	NATIVE_CXXFLAGS+=-fsanitize=undefined
	NATIVE_CXXFLAGS+=-fno-sanitize=vptr
	NATIVE_CXXFLAGS+=-fno-sanitize=alignment
endif

CROSS_CXXFLAGS+=-Wall
CROSS_CXXFLAGS+=-Wextra
CROSS_CXXFLAGS+=-Wpedantic
CROSS_CXXFLAGS+=-Wctor-dtor-privacy
CROSS_CXXFLAGS+=-Wshadow
CROSS_CXXFLAGS+=-Wnon-virtual-dtor
CROSS_CXXFLAGS+=-Wold-style-cast
CROSS_CXXFLAGS+=-Woverloaded-virtual
CROSS_CXXFLAGS+=-Wconversion
CROSS_CXXFLAGS+=-Wsign-conversion
CROSS_CXXFLAGS+=-DGSL_THROW_ON_CONTRACT_VIOLATION
CROSS_CXXFLAGS+=$(CONFIGURED_CROSS_CXXFLAGS)

ifeq ($(COVERALLS), true)
	NATIVE_CXXFLAGS+=-fprofile-arcs -ftest-coverage
endif

# ifneq ($(IGNORE_WARNINGS),yes)
# 	NATIVE_CXXFLAGS+=-Werror
# 	CROSS_CXXFLAGS+=-Werror
# endif

ifeq ($(TARGET_NATIVE_COMPILED), true)
	ifeq ($(OS), windows)
		NATIVE_CXXFLAGS+=$(WINDOWS_CXXFLAGS)
	endif
	ifeq ($(OS), linux)
		NATIVE_CXXFLAGS+=$(LINUX_CXXFLAGS)
	endif
	ifeq ($(OS), osx)
		NATIVE_CXXFLAGS+=$(OSX_CXXFLAGS)
	endif
endif

################################################################################
# Default ASM Flags
################################################################################

NATIVE_ASMFLAGS+=-f elf64
CROSS_ASMFLAGS+=-f elf64

ifeq ($(AVX_SUPPORTED), true)
	NATIVE_ASMFLAGS+=-dAVX_SUPPORTED
	CROSS_ASMFLAGS+=-dAVX_SUPPORTED
endif

################################################################################
# Default AR Flags
################################################################################

NATIVE_ARFLAGS+=rcs

CROSS_ARFLAGS+=rcs

################################################################################
# Default LD Flags
################################################################################

ifeq ($(COVERALLS), true)
	NATIVE_LDFLAGS+=-lgcov --coverage
endif

ifeq ($(DYNAMIC_ANALYSIS_ENABLED), true)
	ifneq ($(NO_ADDRESS_SANATIZE), true)
		NATIVE_LDFLAGS+=-fsanitize=address
	endif
	NATIVE_LDFLAGS+=-fsanitize=undefined
	NATIVE_LDFLAGS+=-fno-sanitize=vptr
	NATIVE_LDFLAGS+=-fno-sanitize=alignment
	NATIVE_LDFLAGS+=-fuse-ld=gold
	NATIVE_LDFLAGS+=-Wl,--no-as-needed
endif

################################################################################
# Target Naming
################################################################################

ifeq ($(TARGET_CROSS_COMPILED), true)
	CROSS_BIN_EXT:=
	CROSS_BIN_PRE:=
	CROSS_SHARED_LIB_EXT:=.so
	CROSS_SHARED_LIB_PRE:=lib
	CROSS_STATIC_LIB_EXT:=_static.a
	CROSS_STATIC_LIB_PRE:=lib
endif

ifeq ($(TARGET_NATIVE_COMPILED), true)
	ifeq ($(OS), windows)
		NATIVE_BIN_EXT:=.exe
		NATIVE_BIN_PRE:=
		NATIVE_SHARED_LIB_EXT:=.dll
		NATIVE_SHARED_LIB_PRE:=
		NATIVE_STATIC_LIB_EXT:=_static.lib
		NATIVE_STATIC_LIB_PRE:=
	endif
	ifeq ($(OS), linux)
		NATIVE_BIN_EXT:=
		NATIVE_BIN_PRE:=
		NATIVE_SHARED_LIB_EXT:=.so
		NATIVE_SHARED_LIB_PRE:=lib
		NATIVE_STATIC_LIB_EXT:=_static.a
		NATIVE_STATIC_LIB_PRE:=lib
	endif
	ifeq ($(OS), osx)
		NATIVE_BIN_EXT:=
		NATIVE_BIN_PRE:=
		NATIVE_SHARED_LIB_EXT:=.dylib
		NATIVE_SHARED_LIB_PRE:=lib
		NATIVE_STATIC_LIB_EXT:=_static.a
		NATIVE_STATIC_LIB_PRE:=lib
	endif
endif

NATIVE_TARGET_BIN:=$(patsubst %, $(NATIVE_OUTDIR)/$(NATIVE_BIN_PRE)%$(NATIVE_BIN_EXT), $(TARGET_NAME))
NATIVE_TARGET_SHARED:=$(patsubst %, $(NATIVE_OUTDIR)/$(NATIVE_SHARED_LIB_PRE)%$(NATIVE_SHARED_LIB_EXT), $(TARGET_NAME))
NATIVE_TARGET_STATIC:=$(patsubst %, $(NATIVE_OUTDIR)/$(NATIVE_STATIC_LIB_PRE)%$(NATIVE_STATIC_LIB_EXT), $(TARGET_NAME))

CROSS_TARGET_BIN:=$(patsubst %, $(CROSS_OUTDIR)/$(CROSS_BIN_PRE)%$(CROSS_BIN_EXT), $(TARGET_NAME))
CROSS_TARGET_SHARED:=$(patsubst %, $(CROSS_OUTDIR)/$(CROSS_SHARED_LIB_PRE)%$(CROSS_SHARED_LIB_EXT), $(TARGET_NAME))
CROSS_TARGET_STATIC:=$(patsubst %, $(CROSS_OUTDIR)/$(CROSS_STATIC_LIB_PRE)%$(CROSS_STATIC_LIB_EXT), $(TARGET_NAME))

################################################################################
# Source Files
################################################################################

ifeq ($(TARGET_CROSS_COMPILED), true)
	CROSS_SOURCES+=$(SOURCES)
	CROSS_SOURCES+=$(VMM_SOURCES)
endif

ifeq ($(TARGET_NATIVE_COMPILED), true)
	ifeq ($(OS), windows)
		NATIVE_SOURCES+=$(SOURCES)
		NATIVE_SOURCES+=$(WINDOWS_SOURCES)
	endif
	ifeq ($(OS), linux)
		NATIVE_SOURCES+=$(SOURCES)
		NATIVE_SOURCES+=$(LINUX_SOURCES)
	endif
	ifeq ($(OS), osx)
		NATIVE_SOURCES+=$(SOURCES)
		NATIVE_SOURCES+=$(OSX_SOURCES)
	endif
endif

CROSS_CC_SOURCES:=$(filter %.c, $(wildcard $(CROSS_SOURCES)))
CROSS_CXX_SOURCES:=$(filter %.cpp, $(wildcard $(CROSS_SOURCES)))
CROSS_ASM_SOURCES:=$(filter %.asm, $(wildcard $(CROSS_SOURCES)))

NATIVE_CC_SOURCES:=$(filter %.c, $(wildcard $(NATIVE_SOURCES)))
NATIVE_CXX_SOURCES:=$(filter %.cpp ,$(wildcard $(NATIVE_SOURCES)))
NATIVE_ASM_SOURCES:=$(filter %.asm, $(wildcard $(NATIVE_SOURCES)))

################################################################################
# Include Paths
################################################################################

ifeq ($(TARGET_CROSS_COMPILED), true)
	CROSS_INCLUDE_PATHS+=$(INCLUDE_PATHS)
	CROSS_INCLUDE_PATHS+=$(VMM_INCLUDE_PATHS)
endif

ifeq ($(TARGET_NATIVE_COMPILED), true)
	ifeq ($(OS), windows)
		NATIVE_INCLUDE_PATHS+=$(INCLUDE_PATHS)
		NATIVE_INCLUDE_PATHS+=$(WINDOWS_INCLUDE_PATHS)
	endif
	ifeq ($(OS), linux)
		NATIVE_INCLUDE_PATHS+=$(INCLUDE_PATHS)
		NATIVE_INCLUDE_PATHS+=$(LINUX_INCLUDE_PATHS)
	endif
	ifeq ($(OS), osx)
		NATIVE_INCLUDE_PATHS+=$(INCLUDE_PATHS)
		NATIVE_INCLUDE_PATHS+=$(OSX_INCLUDE_PATHS)
	endif
endif

CROSS_CCFLAGS+=$(addprefix -I, $(strip $(CROSS_INCLUDE_PATHS)))
CROSS_CXXFLAGS+=$(addprefix -I, $(strip $(CROSS_INCLUDE_PATHS)))

NATIVE_CCFLAGS+=$(addprefix -I, $(strip $(NATIVE_INCLUDE_PATHS)))
NATIVE_CXXFLAGS+=$(addprefix -I, $(strip $(NATIVE_INCLUDE_PATHS)))

################################################################################
# Library Paths
################################################################################

ifeq ($(TARGET_CROSS_COMPILED), true)
	CROSS_LIBRARY_PATHS+=$(LIBRARY_PATHS)
	CROSS_LIBRARY_PATHS+=$(VMM_LIBRARY_PATHS)
endif

ifeq ($(TARGET_NATIVE_COMPILED), true)
	ifeq ($(OS), windows)
		NATIVE_LIBRARY_PATHS+=$(LIBRARY_PATHS)
		NATIVE_LIBRARY_PATHS+=$(WINDOWS_LIBRARY_PATHS)
	endif
	ifeq ($(OS), linux)
		NATIVE_LIBRARY_PATHS+=$(LIBRARY_PATHS)
		NATIVE_LIBRARY_PATHS+=$(LINUX_LIBRARY_PATHS)
	endif
	ifeq ($(OS), osx)
		NATIVE_LIBRARY_PATHS+=$(LIBRARY_PATHS)
		NATIVE_LIBRARY_PATHS+=$(OSX_LIBRARY_PATHS)
		NATIVE_LDFLAGS+=$(OSX_LDFLAGS)
	endif
endif

NATIVE_LDFLAGS+=$(addprefix -L, $(strip $(NATIVE_LIBRARY_PATHS)))

CROSS_LDFLAGS+=$(addprefix -L, $(strip $(CROSS_LIBRARY_PATHS)))

################################################################################
# Libraries
################################################################################

ifeq ($(TARGET_CROSS_COMPILED), true)
	CROSS_LIBS+=$(LIBS)
	CROSS_LIBS+=$(VMM_LIBS)
endif

ifeq ($(TARGET_NATIVE_COMPILED), true)
	ifeq ($(OS), windows)
		NATIVE_LIBS+=$(LIBS)
		NATIVE_LIBS+=$(WINDOWS_LIBS)
	endif
	ifeq ($(OS), linux)
		NATIVE_LIBS+=$(LIBS)
		NATIVE_LIBS+=$(LINUX_LIBS)
	endif
	ifeq ($(OS), osx)
		NATIVE_LIBS+=$(LIBS)
		NATIVE_LIBS+=$(OSX_LIBS)
	endif
endif

NATIVE_LDFLAGS+=$(addprefix -l, $(strip $(NATIVE_LIBS)))

CROSS_LDFLAGS+=$(addprefix -l, $(strip $(CROSS_LIBS)))

################################################################################
# Object Files
################################################################################

CROSS_OBJECTS+=$(patsubst %.c, %.o, $(CROSS_CC_SOURCES))
CROSS_OBJECTS+=$(patsubst %.cpp, %.o, $(CROSS_CXX_SOURCES))
CROSS_OBJECTS+=$(patsubst %.asm, %.o, $(CROSS_ASM_SOURCES))

NATIVE_OBJECTS+=$(patsubst %.c, %.o, $(NATIVE_CC_SOURCES))
NATIVE_OBJECTS+=$(patsubst %.cpp, %.o, $(NATIVE_CXX_SOURCES))
NATIVE_OBJECTS+=$(patsubst %.asm, %.o, $(NATIVE_ASM_SOURCES))

################################################################################
# OS Defines
################################################################################

ifeq ($(TARGET_CROSS_COMPILED), true)
	CROSS_DEFINES+=OS_VMM
endif

ifeq ($(TARGET_NATIVE_COMPILED), true)
	ifeq ($(OS), windows)
		NATIVE_DEFINES+=OS_WINDOWS
	endif
	ifeq ($(OS), linux)
		NATIVE_DEFINES+=OS_LINUX
	endif
	ifeq ($(OS), osx)
		NATIVE_DEFINES+=OS_OSX
	endif
endif

################################################################################
# Compiler Defines
################################################################################

ifeq ($(TARGET_CROSS_COMPILED), true)
	CROSS_DEFINES+=CROSS_COMPILED
endif

ifeq ($(TARGET_NATIVE_COMPILED), true)
	NATIVE_DEFINES+=NATIVE_COMPILED
endif

################################################################################
# Define Flags
################################################################################

ifeq ($(TARGET_NATIVE_COMPILED), true)
	ifeq ($(OS), windows)
		NATIVE_DEFINES+=$(WINDOWS_DEFINES)
	endif
	ifeq ($(OS), linux)
		NATIVE_DEFINES+=$(LINUX_DEFINES)
	endif
	ifeq ($(OS), osx)
		NATIVE_DEFINES+=$(OSX_DEFINES)
	endif
endif

CROSS_CCFLAGS+=$(addprefix -D, $(strip $(CROSS_DEFINES)))
CROSS_CXXFLAGS+=$(addprefix -D, $(strip $(CROSS_DEFINES)))

NATIVE_CCFLAGS+=$(addprefix -D, $(strip $(NATIVE_DEFINES)))
NATIVE_CXXFLAGS+=$(addprefix -D, $(strip $(NATIVE_DEFINES)))

################################################################################
# Undefines Flags
################################################################################

CROSS_CCFLAGS+=$(addprefix -U, $(strip $(CROSS_UNDEFINES)))
CROSS_CXXFLAGS+=$(addprefix -U, $(strip $(CROSS_UNDEFINES)))

NATIVE_CCFLAGS+=$(addprefix -U, $(strip $(NATIVE_UNDEFINES)))
NATIVE_CXXFLAGS+=$(addprefix -U, $(strip $(NATIVE_UNDEFINES)))

################################################################################
# Dependency Auto-Genetaion
################################################################################

# http://make.mad-scientist.net/papers/advanced-auto-dependency-generation/

CROSS_DEPFLAGS=-MT $@ -MMD -MP -MF $(CROSS_OBJDIR)/$*.Td
CROSS_POSTCOMPILE=@mv -f $(CROSS_OBJDIR)/$*.Td $(CROSS_OBJDIR)/$*.d

NATIVE_DEPFLAGS=-MT $@ -MMD -MP -MF $(NATIVE_OBJDIR)/$*.Td
NATIVE_POSTCOMPILE=@mv -f $(NATIVE_OBJDIR)/$*.Td $(NATIVE_OBJDIR)/$*.d

################################################################################
# VPATH Directories
################################################################################

vpath %.c $(dir $(CROSS_CC_SOURCES)) $(dir $(NATIVE_CC_SOURCES))
vpath %.cpp $(dir $(CROSS_CXX_SOURCES)) $(dir $(NATIVE_CXX_SOURCES))
vpath %.asm $(dir $(CROSS_ASM_SOURCES)) $(dir $(NATIVE_ASM_SOURCES))

################################################################################
# Object Files Paths
################################################################################

CROSS_OBJECTS:=$(addprefix $(CROSS_OBJDIR)/, $(notdir $(CROSS_OBJECTS)))
NATIVE_OBJECTS:=$(addprefix $(NATIVE_OBJDIR)/, $(notdir $(NATIVE_OBJECTS)))

################################################################################
# Cross Cleanup
################################################################################

CROSS_OBJDIR:=$(strip $(CROSS_OBJDIR))
CROSS_OUTDIR:=$(strip $(CROSS_OUTDIR))

CROSS_CCFLAGS:=$(strip $(CROSS_CCFLAGS))
CROSS_CXXFLAGS:=$(strip $(CROSS_CXXFLAGS))
CROSS_ASMFLAGS:=$(strip $(CROSS_ASMFLAGS))
CROSS_LDFLAGS:=$(strip $(CROSS_LDFLAGS))
CROSS_ARFLAGS:=$(strip $(CROSS_ARFLAGS))

################################################################################
# Native Cleanup
################################################################################

NATIVE_OBJDIR:=$(strip $(NATIVE_OBJDIR))
NATIVE_OUTDIR:=$(strip $(NATIVE_OUTDIR))

NATIVE_CCFLAGS:=$(strip $(NATIVE_CCFLAGS))
NATIVE_CXXFLAGS:=$(strip $(NATIVE_CXXFLAGS))
NATIVE_ASMFLAGS:=$(strip $(NATIVE_ASMFLAGS))
NATIVE_LDFLAGS:=$(strip $(NATIVE_LDFLAGS))
NATIVE_ARFLAGS:=$(strip $(NATIVE_ARFLAGS))

################################################################################
# Target Settings
################################################################################

Makefile: $(HYPER_REL)/Makefile.bf
	@ BUILD_ABS=$(BUILD_ABS) BUILD_REL=$(BUILD_REL) HYPER_REL=$(HYPER_REL) $(HYPER_ABS)/configure -r --this-is-make

.PHONY: all
.PHONY: cross
.PHONY: native
.PHONY: cross_target
.PHONY: native_target
.PHONY: clean
.PHONY: clean_src
.PHONY: clean_tests
.PHONY: clean-cross
.PHONY: clean-native
.PHONY: build_src
.PHONY: build_tests
.PHONY: pre_target
.PHONY: post_target

.DEFAULT_GOAL := all

build_src: all
build_tests: all

clean_src: clean
clean_tests: clean

all: pre_target cross native post_target
	@echo > /dev/null

clean: clean-cross clean-native

force: ;

pre_target:
	@$(PRE_COMMAND)

post_target:
	@$(POST_COMMAND)

################################################################################
# Cross Targets
################################################################################

ifeq ($(TARGET_CROSS_COMPILED), true)

cross: $(CROSS_OBJDIR) $(CROSS_OUTDIR) cross_target

$(CROSS_OBJDIR):
	@$(MD) $(CROSS_OBJDIR)

$(CROSS_OUTDIR):
	@$(MD) $(CROSS_OUTDIR)

$(CROSS_OBJDIR)/%.o: %.c | $(CROSS_OBJDIR)/%.d
	$(CROSS_CC) $(realpath $<) -o $@ -c $(CROSS_CCFLAGS) $(CROSS_DEPFLAGS)
	$(CROSS_POSTCOMPILE)

$(CROSS_OBJDIR)/%.o: %.cpp | $(CROSS_OBJDIR)/%.d
	$(CROSS_CXX) $(realpath $<) -o $@ -c $(CROSS_CXXFLAGS) $(CROSS_DEPFLAGS)
	$(CROSS_POSTCOMPILE)

$(CROSS_OBJDIR)/%.o: %.asm
	@[[ ! -d $(CROSS_OBJDIR) ]] && $(MD) $(CROSS_OBJDIR) || $(TEST) 1
	$(CROSS_ASM) $(realpath $<) -o $@ $(CROSS_ASMFLAGS)

$(CROSS_TARGET_BIN): $(CROSS_OBJECTS)
	$(CROSS_LD) -o $@ $^ $(CROSS_LDFLAGS)

$(CROSS_TARGET_SHARED): $(CROSS_OBJECTS)
	$(CROSS_LD) -shared -o $@ $^ $(CROSS_LDFLAGS)

$(CROSS_TARGET_STATIC): $(CROSS_OBJECTS)
	$(CROSS_AR) $(CROSS_ARFLAGS) $@ $^

ifeq ($(TARGET_TYPE),lib)
cross_target: $(CROSS_TARGET_STATIC) $(CROSS_TARGET_SHARED)
else
cross_target: $(CROSS_TARGET_BIN)
endif

$(CROSS_OBJDIR)/%.d: ;
-include $(patsubst %, $(CROSS_OBJDIR)/%.d, $(notdir $(basename $(CROSS_SOURCES))))

clean-cross:
ifeq ($(TARGET_TYPE),lib)
	$(RM) $(CROSS_TARGET_SHARED)
	$(RM) $(CROSS_TARGET_STATIC)
else
	$(RM) $(CROSS_TARGET_BIN)
endif
	$(RM) $(CROSS_OBJDIR)/*.o
	$(RM) $(CROSS_OBJDIR)/*.d
	$(RM) $(CROSS_OBJDIR)/*.Td
	([ -d $(CROSS_OBJDIR) ] && $(RMDIR) $(CROSS_OBJDIR)) || $(TEST) 1
	([ -d $(CROSS_OUTDIR) ] && $(RMDIR) $(CROSS_OUTDIR)) || $(TEST) 1
	([ -d $(CROSS_OBJDIR_PARENT) ] && $(RMDIR) $(CROSS_OBJDIR_PARENT)) || $(TEST) 1
	([ -d $(CROSS_OUTDIR_PARENT) ] && $(RMDIR) $(CROSS_OUTDIR_PARENT)) || $(TEST) 1

endif

################################################################################
# Native Targets
################################################################################

ifeq ($(TARGET_NATIVE_COMPILED), true)

native: $(NATIVE_OBJDIR) $(NATIVE_OUTDIR) native_target

$(NATIVE_OBJDIR):
	@$(MD) $(NATIVE_OBJDIR)

$(NATIVE_OUTDIR):
	@$(MD) $(NATIVE_OUTDIR)

$(NATIVE_OBJDIR)/%.o: %.c | $(NATIVE_OBJDIR)/%.d
	$(NATIVE_CC) $(realpath $<) -o $@ -c $(NATIVE_CCFLAGS) $(NATIVE_DEPFLAGS)
	$(NATIVE_POSTCOMPILE)

$(NATIVE_OBJDIR)/%.o: %.cpp | $(NATIVE_OBJDIR)/%.d
	$(NATIVE_CXX) $(realpath $<) -o $@ -c $(NATIVE_CXXFLAGS) $(NATIVE_DEPFLAGS)
	$(NATIVE_POSTCOMPILE)

$(NATIVE_OBJDIR)/%.o: %.asm
	@[[ ! -d $(NATIVE_OBJDIR) ]] && $(MD) $(NATIVE_OBJDIR) || $(TEST) 1
	$(NATIVE_ASM) $(realpath $<) -o $@ $(NATIVE_ASMFLAGS)

$(NATIVE_TARGET_BIN): $(NATIVE_OBJECTS)
	$(NATIVE_LD) $^ -o $@ $(NATIVE_LDFLAGS)

$(NATIVE_TARGET_SHARED): $(NATIVE_OBJECTS)
	$(NATIVE_LD) -shared $^ -o $@ $(NATIVE_LDFLAGS)

$(NATIVE_TARGET_STATIC): $(NATIVE_OBJECTS)
	$(NATIVE_AR) $(NATIVE_ARFLAGS) $@ $^

ifeq ($(TARGET_TYPE),lib)
native_target: $(NATIVE_TARGET_STATIC) $(NATIVE_TARGET_SHARED)
else
native_target: $(NATIVE_TARGET_BIN)
endif

$(NATIVE_OBJDIR)/%.d: ;
-include $(patsubst %, $(NATIVE_OBJDIR)/%.d, $(notdir $(basename $(NATIVE_SOURCES))))

clean-native:
ifeq ($(TARGET_TYPE),lib)
	$(RM) $(NATIVE_TARGET_SHARED)
	$(RM) $(NATIVE_TARGET_STATIC)
else
	$(RM) $(NATIVE_TARGET_BIN)
endif
	$(RM) $(NATIVE_OBJDIR)/*.o
	$(RM) $(NATIVE_OBJDIR)/*.d
	$(RM) $(NATIVE_OBJDIR)/*.Td
	([ -d $(NATIVE_OBJDIR) ] && $(RMDIR) $(NATIVE_OBJDIR)) || $(TEST) 1
	([ -d $(NATIVE_OUTDIR) ] && $(RMDIR) $(NATIVE_OUTDIR)) || $(TEST) 1
	([ -d $(NATIVE_OBJDIR_PARENT) ] && $(RMDIR) $(NATIVE_OBJDIR_PARENT)) || $(TEST) 1
	([ -d $(NATIVE_OUTDIR_PARENT) ] && $(RMDIR) $(NATIVE_OUTDIR_PARENT)) || $(TEST) 1

endif
