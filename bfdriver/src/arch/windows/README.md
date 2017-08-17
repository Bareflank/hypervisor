## Windows Driver Compilation Instructions

Supported Windows versions are:
- Windows 10 64bit
- Windows 8.1 64bit

To compile Bareflank, first start by downloading
[cygwin](https://cygwin.com/install.html) 64bit. You can install any packages
you wish, but a default install is all that is needed (i.e. keep clicking
next). Once cygwin is installed, you must copy the setup-x86_64.exe to cygwin's
"bin" folder. Usually this is "c:\cygwin64\bin". The scripts will use this
executable to install the different packages that it needs. Finally, you can
setup the build environment with a default cygwin terminal, but to install the
and use Bareflank, you must use a cygwin terminal with admin privileges and if
you happen to ssh into the cygwin shell, you don't need to worry about admin
rights as it has it by default.

Before we compile code, the windows driver will be compiled and signed using
a test signature, and thus, test signing will need to be enabled. From
cmd.exe or a cygwin terminal wtih admin rights run:

```
bcdedit.exe /set testsigning ON
<reboot>
```

Once you have installed cygwin, copied the installer to cygwin's bin directory,
turned test signing on, rebooted, and opened a cygwin terminal with admin
rights, download the repo doing the following:

```
setup-x86_64.exe -q -P git

cd ~/
git clone https://github.com/Bareflank/hypervisor.git
```

Next run the cygwin setup script.

```
cd ~/
mkdir build
cd ~/hypervisor
./tools/scripts/setup_cygwin.sh
```

Once you have a cross compiler setup, you need to build the main source code.
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

To use the Bareflank hypervisor, you will use the Bareflank manager (bfm).
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

On Windows, you can also run the following make shortcuts:

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

./tools/scripts/setup_cygwin.sh --no-configure

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

## SSHD Instructions

To install SSHD, open a cygwin terminal with admin rights and run the following
(this assumes the setup-x86_64.exe installer is in cygwin's "bin" folder):

```
setup-x86_64.exe -q -P getent,cygrunsrv,openssl,openssh

ssh-host-config -y
<password>
<password>

net start sshd

netsh advfirewall firewall add rule name='SSH Port' dir=in action=allow protocol=TCP localport=22
```

After this is complete, you can ssh into the Windows box. Using this
configuration, you have admin rights while ssh'd into the machine so
installing and usign Bareflank works fine. SSHFS also works.

## Debugging

The best way to get debug information from the Bareflank driver is to use
[DbgView](https://download.sysinternals.com/files/DebugView.zip). Serial
works with Bareflank and Windows except when using VMWare. For some reason
serial commands are ignored by VMWare when Windows is installed.
