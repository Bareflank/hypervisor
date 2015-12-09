## Compilation Instructions

To compile Bareflank on Linux, first ensure that Bareflank's main source code
has been compiled. To do this, you must first have a cross compiler setup.
The following instructions assume that you are using Debian.

```
cd ~/
git clone https://github.com/Bareflank/hypervisor.git
cd ~/hypervisor

./tools/scripts/debian-cross-compiler.sh
```

Once you have a cross compiler setup, you need build the main source code. This
can be done by doing the following:

```
make
make unittest
```

The last compilation step involves compiling the Linux driver entry. This
driver entry will be used to start the hypervisor using the Bareflank Manager
(bfm). To compile the Linux driver entry perform the following:

```
cd ~/hypervisor/driver_entry/src/arch/linux/
make
```

To cleanup everything, run the following:

```
cd ~/hypervisor/driver_entry/src/arch/linux/
sudo make unload
make clean

cd ~/hypervisor
make clean
```

## Usage Instructions

To use the Bareflank hypervisor, you first must load the driver entry

```
cd ~/hypervisor/driver_entry/src/arch/linux/
sudo make load
```

Once the driver entry is load, to run the hypervisor, you must run the
following:

```
cd ~/hypervisor/bfm/bin/native
./bfm start vmm.modules
./bfm dump
dmesg
```
