# Windows SSHD

## Cygwin Initial Setup

To setup SSHD, you will need Cygwin. To download Cygwin, use the following link:

[Cygwin](https://www.cygwin.com/)

## Cygwin Packages

The following packages are needed for SSHD

- openssh
- cygrunsrv
- syslog-ng

You might also find the following useful

- wget
- make
- gcc-g++
- diffutils
- libgmp-devel
- libmpfr-devel
- libmpc-devel
- libisl-devel
- vim

## SSHD User

The daemon needs it’s own user account to operate. This account needs administrative access as well. To setup this account, do the following:

- Logo->Control Panel
- Click->User Accounts and Family Safety
- Click->Add or remove user accounts
- Click->Create a new account
- Type: sshd
- Select: Administrator
- Click->Create Account
- Click->sshd
- Click->Create a password
- Type: <password>
- Type: <password>
- Click->Create password

From here, the next step is to setup the access rights that the new account will need. This must be done from Cygwin with Administrative access. To do this:

- Logo->All Programs->Cygwin
- Right Click->Cygwin64 Terminal
- Click->Run as administrator
- Type the following

```
editrights -a SeAssignPrimaryTokenPrivilege -u sshd
editrights -a SeCreateTokenPrivilege -u sshd
editrights -a SeTcbPrivilege -u sshd
editrights -a SeServiceLogonRight -u sshd
```

## SSH Host Config

The next step is to run the ssh-host-config script. This will setup SSHD. To do this (inside a Cygwin terminal with administrative access):

- ssh-host-config
- Should StrictModes be used? (yes/no): no
- Should privilege separation be used? (yes/no): yes
- Do you want to install sshd as a service?: yes
- Enter the value of CYGWIN for the daemon: []: <hit enter>
- Do you want to use a different name? (yes/no): yes
- Enter the new user name: sshd
- Reenter: sshd
- Please enter the password for user 'sshd': <password>
- Reenter: <password>

## Cygwin LSA Authentication

This step is needed, not really sure why. To do this (inside a Cygwin terminal with administrative access):

- cyglsa-config
- Are you sure you want to continue? (yes/no): yes
- Logo->Restart (to reboot the machine)

## Firewall

You will also need to open up the SSH port for external access. To do this:

- Logo->Control Panel->Network and Internal
- Click->Network and Sharing Center
- Click->Windows Firewall
- Click->Advanced Settings
- Click->Inbound Rules
- Click->New Rule
- Select->Port
- Click->Next
- Type: 22
- Click->Next
- Click->Next
- Click->Next
- Type: SSH
- Click->Finish

## Links

[Cygwin SSHD Setup](http://techtorials.me/cygwin/sshd-configuration/)



