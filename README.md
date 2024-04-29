# WinExec-Notepad-Shellcode

My intro to assembly and shellcoding so I wanted to start easy. Most of the x64 assembly documentation/code samples exist in conjunction with C++ which I wanted to shy away from in order to make a standalone application. Basically all other maldev focused assembly samples use WinExec so this was just me getting my foot in the door. PSA if you dont know anything about assembly, x64 architecture, or nasm I highly recommend you learn the assembly basics first, unrelated to maldev, and then begin your shellcoding journey

## Features

- Finds kernel32 base address using PEB
- Loops through kernel32 functions until WinExec is found
- Launches notepad.exe via WinExec
- Uses GetProcAddress to find ExitThread and calls to cleanly exit
- Written for NASM and using NASM x64 syntax so it will not compile with MASM, etc

## Getting Started

If you only need the shellcode just copy it from the Shellcode.c file and paste into your code, but if you want to compile it yourself follow the steps below:

### Prerequisites

1. NASM compiler
2. Windows Developer Command Prompt
3. Access to Linux box (WSL, VM, VPS, etc)
4. Understanding of assembly syntax and structure

### Compiling into PE file (Useful for debugging, not necessary for extracting shellcode)

1. Download WinExecNotepad.asm file
  
2. Compile with NASM, ```nasm -f win64 WinExecNotepad.asm -o WinExecNotepad.obj```

3. Open Windows Developer Command Prompt
   
4. Link object file with no lib, ```link /entry:_start subsystem:windows WinExecNotepad.obj /nodefaultlib```

5. Successfully compiled into WinExecNotepad.exe!

### Compiling into binary and extracting shellcode

1. Download WinExecNotepad.asm file
  
2. Compile with NASM, ```nasm -f bin WinExecNotepad.asm -o WinExecNotepad.bin```

3. Open a linux instance and use xxd to view shellcode, ```xxd -p WinExecNotepad.bin```

4. Successfully extracted shellcode!


---

Done!
