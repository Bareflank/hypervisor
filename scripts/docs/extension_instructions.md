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
`EXTENSION` variable to pass on the root directories of the extensions.

In the top-level `CMakeLists.txt` file, you can setup and include extensions by
using the `vmm_extension()` function.
Here is an example for adding the [extended_apis](https://github.com/Bareflank/extended_apis) extension.

```bash
cd ~/bareflank
git clone -b https://github.com/Bareflank/hypervisor
git clone -b https://github.com/bareflank/extended_apis.git
mkdir build; cd build
cmake ../hypervisor -DDEFAULT_VMM=eapis_vmm -DEXTENSION=../extended_apis
make
```

You can do the same with a build configuration file. For an example, take a look
at the [example_config.cmake](../cmake/config/example_config.cmake).

## Creating a new extension

To begin writing your own extension, first create a directory to hold the
extension's source code in your Bareflank workspace:

```bash
mkdir ~/bareflank/my_extension
```

Inside your extension directory, create a file named `CMakeLists.txt`.
Next, lets add the new extension to the Bareflank build
system and declare the Bareflank extended_apis as a dependency. Add the
following to your created `CMakeLists.txt`:

```
vmm_extension(
    my_extension
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/src
    DEPENDS eapis
)
```

In the `src` subdirectory you have to again create a file named `CMakeLists.txt`.
In this file you can either include more subdirectories or directly add
a target executable/library:

```
cmake_minimum_required(VERSION 3.6)
project(example_vmm C CXX)

include(${SOURCE_CMAKE_DIR}/project.cmake)
init_project(
    INCLUDES ${CMAKE_CURRENT_LIST_DIR}/../include
)

add_vmm_executable(example_vmm
    SOURCES example_vcpu_factory.cpp
)
```

The first 4 instructions are mandatory before adding any targets via
`add_vmm_executable`, `add_static_library` or `add_shared_library`.

And finally, build your extension from within your build directory:

```
cd ~/bareflank/build
cmake ../hypervisor
make
```

For a complete example, look at the
[hypervisor_exmaple_cpuidcount](https://github.com/Bareflank/hypervisor_example_cpuidcount) extension.

## Conventions

The recommended structure for Bareflank extensions is as follows:

```
| bareflank/ (<-- workspace directory)
   | - build/
   | - hypervisor/
   | - my_extension/ (<-- extension directory)
       | - CMakeLists.txt
       | - include/
       | - src/
            | - CMakeLists.txt
```
