## Linux Driver Compilation Instructions

Supported Linux distributions are:
- Ubuntu 16.10
- Debian Stretch
- Fedora 25, 24, 23
- OpenSUSE Leap 42.2

NOTE: If you would like to use an unsupported platform, so long as you have
the latest clang and cmake it's likely that a build is
possible. The above platforms are simply what our developers are testing.
If you plan to use an unsupported platform, start by modifying a
setup_\<platform\>.sh to suit your needs. In some cases, all you have to
do is enable the platform your using.

To compile Bareflank, first start by downloading the repo, and running the
setup_\<platform\>.sh script

```
cd ~/
git clone https://github.com/Bareflank/hypervisor.git
cd ~/hypervisor

./tools/scripts/setup_ubuntu.sh
```

Next you need to build the main source code.
This can be done by doing the following:

```
make
make driver_load
```

To cleanup everything, run the following:

```
make driver_unload
make clean
```

## Usage Instructions

To use the Bareflank hypervisor, you will use the Bareflank Manager (bfm).
This can be done manually by executing:

```
pushd bfm/bin/native
sudo ./bfm load <module_file>
sudo ./bfm start
sudo ./bfm status
sudo ./bfm dump
popd
```

To stop the hypervisor, run the following:

```
pushd bfm/bin/native
sudo ./bfm stop
sudo ./bfm unload
popd
```

On Linux, you can also run the following make shortcuts:

```
make load
make start
make status
make dump

make stop
make unload

make quick
make loop NUM=<xxx>
ARGS="" make vmcall
make help
```

Bareflank comes with a stock module file called vmm.modules. This file is
encoded and must be translated to be useful. The "make" shortcuts do this
for you. If you have your own modules file, you can use absolute / relative
addresses and no decoding is needed. If you, however, use the BUILD_ABS and
HYPER_ABS macros, like the vmm.modules file, you can decode the paths by
using the build_scripts/filter_module_file.sh script which takes in the file
to be decoded, and stores the results in a file referenced in the second
argument. To see how this is done, look at the root Makefile.

If you are using the "make" shortcuts, and you want to specify a different
modules file, you can use the following:

```
make [load|quick] MODULES=<path to list>
```

Also note that when you run the setup_\<platform\>.sh script, you can ask it
to not configure for you, which allows you to setup an out-of-tree build
where you can specify your own module file and extensions as follows:

```
cd ~/
git clone https://github.com/Bareflank/hypervisor.git
cd ~/hypervisor

./tools/scripts/setup_ubuntu.sh --no-configure

cd ~/
mkdir build
cd ~/build

~/hypervisor/configure -m <path to module_file> -e <path to extension>

make
make test

make driver_load
make quick
make stop
make driver_unload

```

Note that when you use the "-m" with the configure script yourself, you no
longer need to specify the module file you wish to use as the bulid system
will remember which module file you specified.
