# FindSyscallRip
[UsingWinSyscall](https://github.com/xmaple555/UsingWinSyscall) demonstrates how to call Windows syscalls without getting the ntapi's address. Sometimes the program may be highly packed, so it is almost impossible to find out what syscall the program uses via static and dynamic analyses. Unlike Linux, Windows doesn't have any tools to trace syscalls, so we need to use Windows kernel drivers and Windbg to access Windows kernel to figure out. Here we will hook SSDT to find out what syscall has been used and where it is called in user-mode program.

