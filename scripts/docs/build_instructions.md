# Configuring and Building the Bareflank Hypervisor

## Dependencies

Although Bareflank can be made to run on most systems, the following are the
official supported platforms and their dependencies:

* Arch Linux:
```
sudo pacman -S git linux-headers nasm clang cmake base-devel
```

* Ubuntu 17.04 (or Higher):
```
sudo apt-get install git build-essential linux-headers-$(uname -r) nasm clang cmake
```

Next, create a workspace to hold all Bareflank related source code, build
artifacts and extensions...

```
mkdir ~/bareflank
cd ~/bareflank
```

...then clone the Bareflank hypervisor repository, and create a build directory:

```
git clone https://github.com/bareflank/hypervisor.git
mkdir build
cd build
```

Your Bareflank workspace should look like this:
```
| bareflank
   | - build
   | - hypervisor
```

Bareflank uses CMake (VERSION 3.7+) to build VMM components, dependencies, and
Bareflank extension projects. In general, CMake requires that you create a
separate build directory for each build you would like to perform.
Build directories can be located anywhere, but we suggest keeping them
at the level of your Bareflank workspace to keep build outputs
close (but separate) from source code and extensions. Unless otherwise noted,
the rest of this document assumes you are building on Ubuntu 17.04 from within a
Bareflank workspace and build directory at ```~/bareflank/build```

## Basic Usage

By default, Bareflank will configure itself for the host operating system and
architecture that you are currently building on. To configure and build with
default settings, run the following from your build directory:

```
cmake ../hypervisor
make
```

To speed up the build process, Bareflank also supports parallel
builds:

```
cmake ../hypervisor
make -j<#-of-cores + 1>
```

## Configuring Build Options

You can change the default build options using a few different methods.
For changing only a few configurations, the easiest method is to specify them
as command line arguments to CMake. You can run cmake as many times as
necessary, specifying different options each time. For example:

```
cmake ../hypervisor -DBUILD_VERBOSE=ON
cmake ../hypervisor -DBUILD_TYPE=Release -DBUILD_TARGET_ARCH=x86_64
```

If you would like to specify many build configuration options at once, you
should use a Bareflank build configuration file. By default, Bareflank
creates a file named *config.cmake* in your build directory, and uses any
options specified there (using CMake syntax) to configure your build.
An example config.cmake file might look like the following:

```
# ~/bareflank/build/config.cmake (comments start with '#')

set(BUILD_TYPE Release)
set(BUILD_TARGET_ARCH x86_64)

set(BUILD_VMM_SHARED OFF)
set(BUILD_VMM_STATIC ON)
set(ENABLE_DEVELOPER_MODE ON)
```

You can also specify a relative path to a Bareflank configuration file
explicity:

```
cmake ../hypervisor -DCONFIG=/path/to/config.cmake
```

To view and configure *all* of the provided build configuration options at once,
you can use the CMake configuration tools *ccmake* (from a command line) and
*cmake-gui* (for a graphical user interface). From your build directory:

```
sudo apt-get install cmake-curses-gui
cmake ../hypervisor
ccmake .
```

Each time you reconfigure Bareflank with new build options, the build system
validates your new build configuration. If you attempt to configure Bareflank
with (a combinations of) options that aren't supported, the build system
will fail and warn about options that need to be changed. If your build was
configured properly, a usage message will guide you to the next steps (usually
to run ```make```).

## Developer features
Some build features that may be particularly useful if you would like to modify
Bareflank or develop your own extensions include:
* ENABLE_BUILD_TEST - Enables unit testing support. You can can also turn unit
tests for specific projects on/off using the various UNITTEST_<PROJECT_NAME>
configurations
* ENABLE_TIDY - Enable support for clang-tidy static analysis checks
* ENABLE_ASTYLE - Enable support for astyle code formatting checks
* ENABLE_DEVELOPER_MODE - Enable all of the above options and automatically run
them on each build. These are the same checks performed by Bareflank CI before
pull requests will be accepted

Additionally, developers may want to use Ninja to build Bareflank efficiently.
This is supportted by specifying ninja as a generator to CMake:

```
cmake ../hypervisor -G Ninja
ninja
```
