# Windows Kernel Mode Debugging

## Serial Connection (VMWare)

The following instructions are for VMWare using two VMs (a _host_ VM, and a _target_ VM). Any serial connection will work, so long as you have a connection from the host machine to the target machine (physical, virtual or any combination)

Open up the <xxx>.vmx file for the host virtual machine and add:

```
serial0.present = "TRUE"
serial0.fileType = "pipe"
serial0.fileName = "\\.\pipe\com_1"
serial0.tryNoRxLoss = "FALSE"
serial0.pipe.endPoint = "server" 
```

If there is already a serial device (newer versions have a “thinprint” serial device 0), you might have to increment the serial device here, or remove the existing serial device. 

Finally, open the <xxx>.vmx file for the target virtual machine and add:

```
serial0.present = "TRUE"
serial0.fileType = "pipe"
serial0.fileName = "\\.\pipe\com_1"
serial0.tryNoRxLoss = "FALSE"
serial0.pipe.endPoint = "client"
```

Notice that the only difference is one is a “server” while the other is a “client”. Make sure that you start up the VMs in the right order. For whatever reason, if you missing any of the options above, VMWare will complain that the settings are invalid for the ones that do exist, so make sure nothing is missing. 

For more information, see the following link:

[VMWare VMX Settings](http://sanbarrow.com/vmx/vmx-serial-ports.html)

## Windows Update

The first thing your going to need to do once you have a host and target machine setup is update Windows. If your using Windows 7, this will take some time (on most systems this can take several hours) so make sure you have plenty of time. Sadly, you will need to nurse the update, so keep an eye on it. 

## Administrator Account

To perform kernel mode debugging, the _target_ machine must be run from the administrator account (not to be confused with an account with administrative privileges). To enable this account, perform the following steps:

- Logo->Control Panel->System and Security->Administrative Tools->Computer Management->Local Users and Groups->Users
- Double Click “Administrator”
- Uncheck “Account is disabled”
- Logo->Logo Off
- Login to “Administrator”

## Visual Studio 2015

Next, you need to download and install Visual Studio 2015 on the _host_ machine. When you install VS, make sure you do the following:

- Select “Custom”
- Uncheck all “Features” (you only need one)
- Check Programming Languages->Visual C++->Common Tools for Visual C++ 2015
- Next
- Install

[Visual Studio 2015](https://go.microsoft.com/fwlink/?LinkId=532606&clcid=0x409)

## WDK

Your going to need to download and install the Windows Development Kit version 10 (or WDK 10). Don’t bother with an older version, Microsoft has killed the links for previous versions of the WDK, and the older versions do not work with Visual Studio 2015. Install the WDK 10 on both the _host_ and the _target_. Make sure that for the _host_, you have installed Visual Studio 2015 first. 

[WDK 10](http://go.microsoft.com/fwlink/p/?LinkId=526733)

## SDK

Your also going to need to install the Windows Software Development Kit version 10 (or SDK 10). Same thing here, must be version 10. The SDK 10 only needs to be installed on the _host_ machine, after you have already installed Visual Studio 2015 and the WDK 10.  

[SDK 10](https://go.microsoft.com/fwlink/p/?LinkId=619296)

## Computer Name

Visual Studio 2015 will look for the _target_ machine on the network using it’s computer name. Make sure that you provide the VM with a simple, unique name:

- Logo->Right Click “Computer”->Properties
- Change Settings
- Change
- Computer Name: <name>
- Ok
- Ok
- Close
- Restart Now

## Firewall

The firewall needs to be opened up to make sure that the _host_ can locate the _target_. While performing this task, ensure that the network you are connected to is labeled “private” or “home".

- Logo->Control Panel->Network and Internet->Network and Sharing Center->Network
- A pull down should appear that asks to turn on Network Discovery and File Sharing. Click it
- Turn on network discovery and file sharing

## Test Target Setup

Before you can provision, the _target_ must have an application running that the provisioner communicates with to perform actions on it’s behalf. 

- Logo->Computer
- Local Disk C:->Program Files (x86)->Windows Kits->10->Remote->x64->WDK Test Target Setup x64-x64_en-us.msi

## Provisioning Wizard

If you are using Windows 7, you must use a “serial” setup as Windows 7 does not support network based kernel mode debugging. If your using a newer version, you can skip the serial portion of this document, and just use a network based connection. If you end up using a network based connection, all of the settings are the same, minus you will select “Network” instead of “Serial”. 

If you using a serial based connection, a network connection between the _host_ and _target_ is still needed. This network connection will be used by the “WDK Remote Communication Service” to provision the _target_. 

- Driver->Test->Configure Devices
- Add New Device
- Display Name: <name>
- Network host name: <name>
- Next
- Connection Type: Serial
- Next

The following link might provide more information if you run into problems:

[Provisioning](https://msdn.microsoft.com/en-us/library/windows/hardware/dn745909(v=vs.85).aspx)

## Troubleshooting

Network based kernel mode debugging is only supported by Windows 8 and above, something the documentation does not state. If you plan to use Windows 7, you must use serial. The error you will see if this happens is “file not found” in the log generated by the provisioner. 

If the provisioner hangs on the first step “Installing necessary components”, it’s likely due to the fact that the _host_ cannot connect to the _target_. Ensure that network discovery and file sharing is enabled. If you are doing network based kernel mode debugging, you will need to open a port for the provisioner to connect to (also not described in the documentation). The easy way to figure out if this is the issue is to disable the firewall completely (on the _target_) and see if that solves your problem. If it does, work backwards to find out what the firewall is blocking. 

If the provisioner errors out early, it might be because you are not logged into the administrator account on the _target_. 

If the provisioner errors out saying the the _target_ actively refused the connection, it’s likely because the WDK Remote Communication Service is not running. Make sure you start the WDK Test Target Setup x64-x64_en-us.msi on the _target_.

