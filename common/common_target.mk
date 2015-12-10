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

################################################################################
# OS Detection
################################################################################

ifeq ($(OS),Windows_NT)
	OS=windows
else
	UNAME=$(shell uname -s)
	ifeq ($(UNAME),Linux)
		OS=linux
	endif
	ifeq ($(UNAME),Darwin)
		OS=osx
	endif
endif

################################################################################
# Compilers
################################################################################

ifeq ($(TARGET_COMPILER),native)
	TARGET_CROSS_COMPILED=
	TARGET_NATIVE_COMPILED=true
endif

ifeq ($(TARGET_COMPILER),cross)
	TARGET_CROSS_COMPILED=true
	TARGET_NATIVE_COMPILED=
endif

ifeq ($(TARGET_COMPILER),both)
	TARGET_CROSS_COMPILED=true
	TARGET_NATIVE_COMPILED=true
endif

################################################################################
# Target Naming
################################################################################

ifeq ($(TARGET_CROSS_COMPILED),true)
	CROSS_BIN_EXT=
	CROSS_SHARED_LIB_EXT=.so
	CROSS_SHARED_LIB_PRE=lib
	CROSS_STATIC_LIB_EXT=.a
	CROSS_STATIC_LIB_PRE=lib
	CROSS_SOURCES += $(SOURCES)
	CROSS_SOURCES += $(VMM_SOURCES)
	CROSS_INCLUDE_PATHS+=$(INCLUDE_PATHS)
	CROSS_INCLUDE_PATHS+=$(VMM_INCLUDE_PATHS)
	CROSS_DEFINES+=OS_VMM
endif

ifeq ($(TARGET_NATIVE_COMPILED),true)
	ifeq ($(OS),windows)
		BIN_EXT=.exe
		SHARED_LIB_EXT=.dll
		SHARED_LIB_PRE=
		STATIC_LIB_EXT=.lib
		STATIC_LIB_PRE=
		NATIVE_SOURCES += $(WINDOWS_SOURCES)
		NATIVE_SOURCES += $(SOURCES)
		INCLUDE_PATHS+=$(WINDOWS_INCLUDE_PATHS)
		DEFINES+=OS_WINDOWS
	endif
	ifeq ($(OS),linux)
		BIN_EXT=
		SHARED_LIB_EXT=.so
		SHARED_LIB_PRE=lib
		STATIC_LIB_EXT=.a
		STATIC_LIB_PRE=lib
		NATIVE_SOURCES += $(LINUX_SOURCES)
		NATIVE_SOURCES += $(SOURCES)
		INCLUDE_PATHS+=$(LINUX_INCLUDE_PATHS)
		DEFINES+=OS_LINUX
	endif
	ifeq ($(OS),osx)
		BIN_EXT=
		SHARED_LIB_EXT=.dylib
		SHARED_LIB_PRE=lib
		STATIC_LIB_EXT=.a
		STATIC_LIB_PRE=lib
		NATIVE_SOURCES += $(OSX_SOURCES)
		NATIVE_SOURCES += $(SOURCES)
		INCLUDE_PATHS+=$(OSX_INCLUDE_PATHS)
		DEFINES+=OS_OSX
		ifeq ($(TARGET_TYPE),lib)
			LDFLAGS += -undefined dynamic_lookup
		endif
	endif
endif

ifeq ($(TARGET_TYPE),lib)
	ifeq ($(TARGET_CROSS_COMPILED),true)
		CROSS_CCFLAGS+=-fpic
		CROSS_CXXFLAGS+=-fpic -fno-rtti -fno-sized-deallocation -fno-exceptions -fno-use-cxa-atexit -fno-threadsafe-statics
		CROSS_LDFLAGS+=-shared
		CROSS_LD_OPTION=-o
		CROSS_TARGET=$(patsubst %,$(CROSS_OUTDIR)/$(CROSS_SHARED_LIB_PRE)%$(CROSS_SHARED_LIB_EXT),$(TARGET_NAME))
	endif
	ifeq ($(TARGET_NATIVE_COMPILED),true)
		CCFLAGS+=-fpic
		CXXFLAGS+=-fpic
		LDFLAGS+=-shared
		LD_OPTION=-o
		TARGET=$(patsubst %,$(OUTDIR)/$(SHARED_LIB_PRE)%$(SHARED_LIB_EXT),$(TARGET_NAME))
	endif
endif

ifeq ($(TARGET_TYPE),staticlib)
	ifeq ($(TARGET_CROSS_COMPILED),true)
		CROSS_CCFLAGS+=-fpic
		CROSS_CXXFLAGS+=-fpic -fno-rtti -fno-sized-deallocation -fno-exceptions -fno-use-cxa-atexit -fno-threadsafe-statics
		CROSS_LDFLAGS+=
		CROSS_LD_OPTION=
		CROSS_TARGET=$(patsubst %,$(CROSS_OUTDIR)/$(CROSS_STATIC_LIB_PRE)%$(CROSS_STATIC_LIB_EXT),$(TARGET_NAME))
	endif
	ifeq ($(TARGET_NATIVE_COMPILED),true)
		CCFLAGS+=-fpic
		CXXFLAGS+=-fpic
		LDFLAGS+=
		LD_OPTION=
		TARGET=$(patsubst %,$(OUTDIR)/$(STATIC_LIB_PRE)%$(STATIC_LIB_EXT),$(TARGET_NAME))
	endif
endif

ifeq ($(TARGET_TYPE),bin)
	ifeq ($(TARGET_CROSS_COMPILED),true)
		CROSS_LD_OPTION=-o
		CROSS_TARGET=$(patsubst %,$(CROSS_OUTDIR)/%$(CROSS_BIN_EXT),$(TARGET_NAME))
	endif
	ifeq ($(TARGET_NATIVE_COMPILED),true)
		LDFLAGS+=-Wl,--unresolved-symbols=ignore-all
		LD_OPTION=-o
		TARGET=$(patsubst %,$(OUTDIR)/%$(BIN_EXT),$(TARGET_NAME))
	endif
endif

ifeq ($(TARGET_CROSS_COMPILED),true)
	CROSS_DEFINES+=CROSS_COMPILED
	CROSS_DFLAGS=$(patsubst %,-D%,$(CROSS_DEFINES))
endif

ifeq ($(TARGET_NATIVE_COMPILED),true)
	DEFINES+=NATIVE_COMPILED
	DFLAGS=$(patsubst %,-D%,$(DEFINES))
endif

################################################################################
# Source Files
################################################################################

ifeq ($(TARGET_CROSS_COMPILED),true)
	CROSS_CC_SOURCES=$(filter %.c,$(CROSS_SOURCES))
	CROSS_CXX_SOURCES=$(filter %.cpp,$(CROSS_SOURCES))
	CROSS_ASM_SOURCES=$(filter %.asm,$(CROSS_SOURCES))
endif

ifeq ($(TARGET_NATIVE_COMPILED),true)
	CC_SOURCES=$(filter %.c,$(NATIVE_SOURCES))
	CXX_SOURCES=$(filter %.cpp,$(NATIVE_SOURCES))
	ASM_SOURCES=$(filter %.asm,$(NATIVE_SOURCES))
endif

################################################################################
# Object Files
################################################################################

ifeq ($(TARGET_CROSS_COMPILED),true)
	CROSS_OBJECTS+=$(patsubst %.c,%.o,$(CROSS_CC_SOURCES))
	CROSS_OBJECTS+=$(patsubst %.cpp,%.o,$(CROSS_CXX_SOURCES))
	CROSS_OBJECTS+=$(patsubst %.asm,%.o,$(CROSS_ASM_SOURCES))
	CROSS_CC_FLAGS_INCLUDE_PATHS=$(patsubst %,-I%,$(CROSS_INCLUDE_PATHS))
	CROSS_CXX_FLAGS_INCLUDE_PATHS=$(patsubst %,-I%,$(CROSS_INCLUDE_PATHS))
	CROSS_LD_FLAGS_LIBS=$(patsubst %,-l%,$(LIBS))
	CROSS_LD_FLAGS_LIB_PATHS=$(patsubst %,-L%,$(LIB_PATHS))
endif

ifeq ($(TARGET_NATIVE_COMPILED),true)
	OBJECTS+=$(patsubst %.c,%.o,$(CC_SOURCES))
	OBJECTS+=$(patsubst %.cpp,%.o,$(CXX_SOURCES))
	OBJECTS+=$(patsubst %.asm,%.o,$(ASM_SOURCES))
	CC_FLAGS_INCLUDE_PATHS=$(patsubst %,-I%,$(INCLUDE_PATHS))
	CXX_FLAGS_INCLUDE_PATHS=$(patsubst %,-I%,$(INCLUDE_PATHS))
	LD_FLAGS_LIBS=$(patsubst %,-l%,$(LIBS))
	LD_FLAGS_LIB_PATHS=$(patsubst %,-L%,$(LIB_PATHS))
endif

################################################################################
# Dependency Auto-Genetaion
################################################################################

# http://make.mad-scientist.net/papers/advanced-auto-dependency-generation/

ifeq ($(TARGET_CROSS_COMPILED),true)
	CROSS_DEPFLAGS = -MT $@ -MMD -MP -MF $(CROSS_OBJDIR)/$*.Td
	CROSS_POSTCOMPILE = @mv -f $(CROSS_OBJDIR)/$*.Td $(CROSS_OBJDIR)/$*.d
endif

ifeq ($(TARGET_NATIVE_COMPILED),true)
	DEPFLAGS = -MT $@ -MMD -MP -MF $(OBJDIR)/$*.Td
	POSTCOMPILE = @mv -f $(OBJDIR)/$*.Td $(OBJDIR)/$*.d
endif

################################################################################
# Target Settings
################################################################################

.PHONY: all
.PHONY: cross
.PHONY: native
.PHONY: clean
.PHONY: clean-cross
.PHONY: clean-native
.PHONY: unittest

.DEFAULT_GOAL := all

all: cross native

clean: clean-cross clean-native

force: ;

################################################################################
# Cross Targets
################################################################################

ifeq ($(TARGET_CROSS_COMPILED),true)

cross: $(CROSS_OBJDIR) $(CROSS_OUTDIR) $(CROSS_TARGET)

$(CROSS_OBJDIR):
	@$(MD) $(CROSS_OBJDIR)

$(CROSS_OUTDIR):
	@$(MD) $(CROSS_OUTDIR)

$(CROSS_OBJDIR)/%.o: %.c $(CROSS_OBJDIR)/%.d
	$(CROSS_CC) $< -o $@ -c $(CROSS_CCFLAGS) $(CROSS_DFLAGS) $(CROSS_DEPFLAGS) $(CROSS_CC_FLAGS_INCLUDE_PATHS) $(HEADERS)
	$(CROSS_POSTCOMPILE)

$(CROSS_OBJDIR)/%.o: %.cpp $(CROSS_OBJDIR)/%.d
	$(CROSS_CXX) $< -o $@ -c $(CROSS_CXXFLAGS) $(CROSS_DFLAGS) $(CROSS_DEPFLAGS) $(CROSS_CXX_FLAGS_INCLUDE_PATHS) $(HEADERS)
	$(CROSS_POSTCOMPILE)

$(CROSS_OBJDIR)/%.o: %.asm
	$(CROSS_ASM) $< -o $@ $(CROSS_ASMFLAGS)

$(CROSS_TARGET): $(addprefix $(CROSS_OBJDIR)/, $(CROSS_OBJECTS))
	$(CROSS_LD) $(CROSS_LDFLAGS) $(CROSS_LD_OPTION) $@ $^ $(CROSS_LD_FLAGS_LIB_PATHS) $(CROSS_LD_FLAGS_LIBS)

$(CROSS_OBJDIR)/%.d: ;
-include $(patsubst %,$(CROSS_OBJDIR)/%.d,$(basename $(CROSS_SOURCES)))

clean-cross:
	$(RM) $(CROSS_OBJDIR) $(CROSS_TARGET)

unittest: force

endif

################################################################################
# Native Targets
################################################################################

ifeq ($(TARGET_NATIVE_COMPILED),true)

native: $(OBJDIR) $(OUTDIR) $(TARGET)

$(OBJDIR):
	@$(MD) $(OBJDIR)

$(OUTDIR):
	@$(MD) $(OUTDIR)

$(OBJDIR)/%.o: %.c $(OBJDIR)/%.d
	$(CC) $< -o $@ -c $(CCFLAGS) $(DFLAGS) $(DEPFLAGS) $(CC_FLAGS_INCLUDE_PATHS) $(HEADERS)
	$(POSTCOMPILE)

$(OBJDIR)/%.o: %.cpp $(OBJDIR)/%.d
	$(CXX) $< -o $@ -c $(CXXFLAGS) $(DFLAGS) $(DEPFLAGS) $(CXX_FLAGS_INCLUDE_PATHS) $(HEADERS)
	$(POSTCOMPILE)

$(OBJDIR)/%.o: %.asm
	$(ASM) $< -o $@ $(ASMFLAGS)

$(TARGET): $(addprefix $(OBJDIR)/, $(OBJECTS))
	$(LD) $(LDFLAGS) $(LD_OPTION) $@ $^ $(LD_FLAGS_LIB_PATHS) $(LD_FLAGS_LIBS)

$(OBJDIR)/%.d: ;
-include $(patsubst %,$(OBJDIR)/%.d,$(basename $(SOURCES)))

clean-native:
	$(RM) $(OBJDIR) $(TARGET)

unittest: force

endif
