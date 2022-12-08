# short-reverse-shellcode

A pretty short(300 bytes) fully functional TCP reverse shellcode.
C code is a loader, main shellcode is in the asm braces

Note: shellcode assumes WSAStartup is already called by the whatever vulnerable program, because it probably is.

Otherwise, you can either send a payload consisting of solely a WSAStartup call before the main payload if space is really a limitation, or just increase the shellcode size to about 320, still pretty short :)
