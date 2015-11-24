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
# Automated Sources
################################################################################

# The following provides us a place to handle OS specific logic.
ifeq ($(TARGET_CROSS_COMPILED),true)
	BIN_EXT=
	LIB_EXT=.so
	LIB_PRE=lib
else
	ifeq ($(OS),Windows_NT)
		BIN_EXT=.exe
		LIB_EXT=.dll
		LIB_PRE=
		SOURCES+=$(WINDOWS_SOURCES)
	else
		UNAME=$(shell uname -s)
		ifeq ($(UNAME),Linux)
			BIN_EXT=
			LIB_EXT=.so
			LIB_PRE=lib
			SOURCES+=$(LINUX_SOURCES)
		endif
		ifeq ($(UNAME),Darwin)
			BIN_EXT=
			LIB_EXT=.dylib
			LIB_PRE=lib
			SOURCES+=$(OSX_SOURCES)
			ifeq ($(TARGET_TYPE),lib)
				LDFLAGS += -undefined dynamic_lookup
			endif
		endif
	endif
endif

# If we have a library, we need to compile the executable using -shared, and
# -pic for the compilation stage. We also need to modify the target name as
# libraries have very spcific names
ifeq ($(TARGET_TYPE),lib)
	CCFLAGS+=-fpic
	CXXFLAGS+=-fpic
	LDFLAGS+=-shared
	TARGET=$(patsubst %,$(OUTDIR)/$(LIB_PRE)%$(LIB_EXT),$(TARGET_NAME))
else
	TARGET=$(patsubst %,$(OUTDIR)/%$(BIN_EXT),$(TARGET_NAME))
endif

# Get a list of C and CPP sources
CC_SOURCES=$(filter %.c,$(SOURCES))
CXX_SOURCES=$(filter %.cpp,$(SOURCES))
ASM_SOURCES=$(filter %.asm,$(SOURCES))

# Create a list of object files to compile for C and CPP
CC_OBJECTS=$(patsubst %.c,%.o,$(CC_SOURCES))
CXX_OBJECTS=$(patsubst %.cpp,%.o,$(CXX_SOURCES))
ASM_OBJECTS=$(patsubst %.asm,%.o,$(ASM_SOURCES))

# Concat the object file list (we need both forms)
OBJECTS+=$(CC_OBJECTS)
OBJECTS+=$(CXX_OBJECTS)
OBJECTS+=$(ASM_OBJECTS)

# Create a list of include files for C and CPP
CC_FLAGS_INCLUDE_PATHS=$(patsubst %,-I%,$(INCLUDE_PATHS))
CXX_FLAGS_INCLUDE_PATHS=$(patsubst %,-I%,$(INCLUDE_PATHS))

# Create a list of lib files for C and CPP
LD_FLAGS_LIBS=$(patsubst %,-l%,$(LIBS))
LD_FLAGS_LIB_PATHS=$(patsubst %,-L%,$(LIB_PATHS))

################################################################################
# Dependency Auto-Genetaion
################################################################################

# http://make.mad-scientist.net/papers/advanced-auto-dependency-generation/

DFLAGS=$(patsubst %,-D%,$(DEFINES))
DEPFLAGS = -MT $@ -MMD -MP -MF $(OBJDIR)/$*.Td
POSTCOMPILE = @mv -f $(OBJDIR)/$*.Td $(OBJDIR)/$*.d

################################################################################
# Targets
################################################################################

.PHONY: all
.PHONY: clean
.PHONY: custom_clean

.DEFAULT_GOAL := all

all: $(OBJDIR) $(OUTDIR) $(TARGET)

$(OBJDIR):
	@$(MD) $(OBJDIR)

$(OUTDIR):
	@$(MD) $(OUTDIR)

$(OBJDIR)/%.o: %.c $(OBJDIR)/%.d
	$(CC) $< -o $@ -c $(CCFLAGS) $(DFLAGS) $(DEPFLAGS) $(CC_FLAGS_INCLUDE_PATHS) $(INCLUDES)
	$(POSTCOMPILE)

$(OBJDIR)/%.o: %.cpp $(OBJDIR)/%.d
	$(CXX) $< -o $@ -c $(CXXFLAGS) $(DFLAGS) $(DEPFLAGS) $(CXX_FLAGS_INCLUDE_PATHS) $(INCLUDES)
	$(POSTCOMPILE)

$(OBJDIR)/%.o: %.asm
	$(ASM) $< -o $@ $(ASMFLAGS)

$(TARGET): $(addprefix $(OBJDIR)/, $(OBJECTS))
	$(LD) -o $@ $^ $(LDFLAGS) $(LD_FLAGS_LIB_PATHS) $(LD_FLAGS_LIBS)

clean: custom_clean
	$(RM) $(OBJDIR) $(TARGET)

$(OBJDIR)/%.d: ;
-include $(patsubst %,$(OBJDIR)/%.d,$(basename $(SOURCES)))
