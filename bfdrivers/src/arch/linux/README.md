## Linux Driver Compilation Instructions

Supported Linux distributions are:
- Ubuntu 12.04, 14.04, 15.04, 15.10
- Debian Jessie
- Fedora 22, 23

To compile bareflank, first start by downloading the repo, and running the
setup-\<platform\>.sh script, which creates the cross compiler and sysroot
that will be used later.

```
cd ~/
git clone https://github.com/Bareflank/hypervisor.git
cd ~/hypervisor

./tools/scripts/setup-ubuntu.sh
```

Once you have a cross compiler setup, you need to build the main source code.
This can be done by doing the following:

```
make
make linux_load
```

To cleanup everything, run the following:

```
make linux_unload
make clean
```

## Usage Instructions

To use the bareflank hypervisor, you will use the bareflank manager (bfm).
This can be done manually by executing:

```
pushd bfm/bin/native
sudo LD_LIBRARY_PATH=. ./bfm load vmm.modules
sudo LD_LIBRARY_PATH=. ./bfm start
sudo LD_LIBRARY_PATH=. ./bfm status
sudo LD_LIBRARY_PATH=. ./bfm dump
popd
```

To stop the hypervisor, run the following:

```
pushd bfm/bin/native
sudo LD_LIBRARY_PATH=. ./bfm stop
sudo LD_LIBRARY_PATH=. ./bfm unload
popd
```

On Linux, you can also run the following shortcuts from the repo's root:

```
make load
make start
make stop
make unload
make quick
make status
make dump
make loop NUM=<xxx>
```

When extending the hypervisor, you need to provide the list
of modules you want to load. If you do this by hand, simply
replace vmm.modules with your own. If however you use the
shortcuts, do the following:

```
make [load|quick] MODULES=<path to list>
```

or

```
export MODULES=<path to list>
make [load|quick]
```
