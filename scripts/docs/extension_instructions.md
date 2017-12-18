# Bareflank Extensions

Bareflank extensions are the primary mechanism to add features to the base
hypervisor, which is a minimal VMM implementation that does almost nothing.
Extensions are encouraged to integrate with and build on top of other
extensions, and the base Bareflank hypervisor makes it easy to accomplish this.
This document assumes that you have a working Bareflank workspace as described
in the [base build instructions](./build_instructions.md), and that you are
working with the same Bareflank workspace directory structure.

## Building and Integrating Extensions
Extensions can be added to the Bareflank build system by using the
*vmm_extension()* macro within a Bareflank build configuration file
(bfconfig.cmake). The vmm_extension macro is compatible with all valid arguments
to CMake's built-in
[ExternalProject_Add()](https://cmake.org/cmake/help/v3.6/module/ExternalProject.html)
function. For example, you could add the Bareflank extended apis extension from
GitHub by adding the following to your build configuration file
(bfconfig.cmake):

```
vmm_extension(
    extended_apis
    GIT_REPOSITORY https://github.com/bareflank/extended_apis.git
    GIT_TAG dev
)
```

## Creating a new extension

To begin writing your own extension, first create a directory to hold the
extension's source code in your Bareflank workspace:

```
mkdir ~/bareflank/my_extension
```

Inside your extension directory, create a file called CMakeLists.txt with the
following text:

```
cmake_minimum_required(VERSION 3.6)
project(my_extension C CXX)
include(${BF_VMM_EXTENSION})
```

This accomplishes the following:
1. Declare the minimum version of CMake required to build your extension
2. Give your extension project a unique name (in this case: my_extension)
3. Integrate the base Bareflank build system into your extension

Those three lines are the only requirements for your extension to implement, the
rest is up to you! Next, lets add the new extension to the Bareflank build
system and declare the Bareflank extended apis as a dependency. Add the
following to your build configuration file (bfconfig.cmake):

```
vmm_extension(
    my_extension
    SOURCE_DIR ../my_extension
    DEPENDS extended_apis
)
```

And finally, build your extension from within your build directory:

```
cmake ../hypervisor
make
```

## Extension Build Configurations

Much like the base Bareflank hypervisor, extensions can have their own
extension-specific build configurations. To declare a new configuration for an
extension, use a build configuration file (by convention named configs.cmake)
to the top level of your extension project. Then, use the *add_config()* macro
to add new configurations. For example:

```
# Add a config with selectable string values
add_config(
    CONFIG_NAME EXAMPLE_BOOL_CONFIG
    CONFIG_TYPE STRING
    DEFAULT_VAL Option1
    OPTIONS Option1 Option2 Option3
    DESCRIPTION "An example selectable-string configuration"
)

# Add a boolean configuration that only shows up in cmake-gui as "advanced"
add_config(
    CONFIG_NAME EXAMPLE_BOOL_CONFIG
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "An example boolean configuration"
    ADVANCED
)

# Add a path configuration
add_config(
    CONFIG_NAME EXAMPLE_PATH_CONFIG
    CONFIG_TYPE PATH
    DEFAULT_VAL "/the/default/value/for/this/path"
    DESCRIPTION "An example path configuration"
)

# Add a file configuration that doesn't get validated by the build system
add_config(
    CONFIG_NAME EXAMPLE_PATH_CONFIG
    CONFIG_TYPE PATH
    DEFAULT_VAL "/the/default/path/to/this/file.txt"
    DESCRIPTION "An example file configuration"
    SKIP_VALIDATION
)
```

Then, the build configuration file (bfconfig.cmake) can specify values for these
configs as follows:

```
vmm_extension(
    my_extension
    SOURCE_DIR ../my_extension
    DEPENDS extended_apis
    CMAKE_ARGS
        -DEXAMPLE_BOOL_CONFIG=OFF
        -DEXAMPLE_PATH_CONFIG=/a/path/different/from/the/deafult
)
```

Additionally, the base Bareflank build system provides some build configurations
to all Bareflank extensions by default. To view and manipulate all
extension-specific build configurations, use ccmake or cmake-gui:

```
ccmake ~/bareflank/build/extensions/<extension_name>/build
```

## Extension Build Rules

Bareflank extensions can also provide extension-specific build validation rules
using the same mechanism as the base hypervisor. If any of these build rules
are violated, the build system will error before it begins building the
extension. To declare extension-specific build rules, add a file named
build_rules.cmake to the top level directory of the extension, and use the
*add_build_rule* macro. For example:

```
# You can use build configs from the base hypervisor:
add_build_rule(
    FAIL_ON ${BUILD_TARGET_ARCH} NOT STREQUAL x86_64
    FAIL_MSG "This extension is only supported on x86_64"
)

# Or you can use extension-specific build configs:
add_build_rule(
    FAIL_ON ${EXAMPLE_OPTION_CONFIG} STREQUAL Option3 AND NOT ${EXAMPLE_BOOL_CONFIG}
    FAIL_MSG "Cannot build with EXAMPLE_OPTION_CONFIG Option3 while EXAMPLE_BOOL_CONFIG is OFF"
)
```

## Conventions and Default Behaviors

The recommended structure for Bareflank extensions is as follows:

```
| bareflank/ (<-- workspace directory)
   | - build/
   | - hypervisor/
   | - my_extension/ (<-- extension directory)
       | - build_rules.cmake
       | - CMakeLists.txt
       | - config.cmake
       | - include/
       | - src/
       | - test/
```

If you follow this suggested structure, the Bareflank build system will
perform the following for you automatically:

1. The ```include``` directory will be added to your extension's header include
path
2. CMake will add ```src``` as a build subdirectory
3. CMake will add both ```src``` and ```test``` as subdirectories for unit-test
builds
4. The build system will add any extension-specific build configurations
declared in config.cmake
5. The build system will validate any extension-specific build rules declared
in build_rules.cmake
