## Compilation Instructions

To compile the bareflank hypevisor on Linux, first ensure that bareflank's
main source code has been compiled. To do this, you must first have a
cross compiler setup. The following instructions assume that you are using
Ubuntu.

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
make debian_load
```

To cleanup everything, run the following:

```
make debian_unload
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

On Linux, you can also:

```
make quick
make load
make start
make status
make dump
make stop
make unload
```
