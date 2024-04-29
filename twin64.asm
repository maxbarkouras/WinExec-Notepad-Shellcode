BITS 64

section .text
global _start

_start:

    ;kernel32 base poi(poi(poi(poi($peb+0x18)+0x20)-10))
    ;sub rsp, 0xfffffffffffffdf8

    sub rsp, 0x28                 ; 40 bytes of shadow space
    and rsp, 0FFFFFFFFFFFFFFF0h

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    mov rax, [gs:60h + rbx] ;set rax to PEB
    mov rax, [rax+18h] ;set rbx to LDR
    mov rax, [rax+20h] ;set rcx to module list
    mov rax, [rax+rcx]
    mov rax, [rax+rcx] ;kernel32.dll
    mov rbx, [rax+20h] ;kernel32 base addr to r9
    mov r8, rbx
    mov ebx, [rbx+3ch]
    add rbx, r8 ;PE Addres
    mov rcx, 0x88FFFFFFFFFFFFFF
    shr rcx, 78h
    mov edx, [rbx + rcx]	
    add rdx, r8 ;export table addr
    mov r10d, [rdx + 14h] ;num of functions to r10
    xor r11, r11
    mov r11d, [rdx + 20h] ;function addr to r11
    add r11, r8
    xor rcx, rcx

    ;r8 ntdll base addr
    ;r10 number of functions
    ;r11 addr of function names

    mov rcx, r10
    functionfinder:
        jecxz functionfound
        xor ebx, ebx
        mov ebx, [r11+4+rcx*4]
        add rbx, r8
        dec rcx
        mov rax, 636578456E6957FFh
        shr rax, 8h
        cmp [rbx], rax
        jnz functionfinder
    
    functionfound:
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
        mov r14, rax
        
        xor rax, rax      
        mov rax, 657865FFFFFFFFFFh

        shr rax, 68h
        push rax
        mov rax, 'notepad.'
        push rax
        mov rcx, rsp
        ;add rsp, 8h
        ;add rsp, 8h

        xor rdx,rdx
        inc rdx
        sub rsp, 0x30
        call r14
        add rsp, 0x30 
        add rsp, 0x10 
        ;add rsp, 20h


;  EXIT PROCESS

xor rax, rax
xor rbx, rbx
xor rcx, rcx
mov rax, [gs:60h + rbx] ;set rax to PEB
mov rax, [rax+18h] ;set rbx to LDR
mov rax, [rax+20h] ;set rcx to module list
mov rax, [rax+rcx]
mov rax, [rax+rcx] ;kernel32.dll
mov rbx, [rax+20h] ;kernel32 base addr to r9
mov r8, rbx
mov ebx, [rbx+3ch]
add rbx, r8 ;PE Addres
mov rcx, 0x88FFFFFFFFFFFFFF
shr rcx, 78h
mov edx, [rbx + rcx]	
add rdx, r8 ;export table addr
mov r10d, [rdx + 14h] ;num of functions to r10
xor r11, r11
mov r11d, [rdx + 20h] ;function addr to r11
add r11, r8
xor rcx, rcx

;r8 ntdll base addr
;r10 number of functions
;r11 addr of function names

mov rcx, r10
mov rax, 737365726464FFFFh
shr rax, 10h
push rax
mov rax, 41636F7250746547h
push rax
mov rax, [rsp]
findgetproc:
    jecxz foundgetproc
    xor ebx, ebx
    mov ebx, [r11+4+rcx*4]
    add rbx, r8
    dec rcx
    cmp [rbx], rax
    jnz findgetproc

foundgetproc:
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
    mov r14, rax

xor rcx, rcx
xor rdx, rdx
mov rcx, r10
mov rax, 6461FFFFFFFFFFFFh
shr rax, 70h
push rax
mov rax, 6572685474697845h
push rax
mov rdx, rsp
mov rcx, r8
sub rsp, 30h
call r14
add rsp, 30h
add rsp, 10h
mov r15, rax
xor rcx, rcx
xor rdx, rdx
sub rsp, 30h
call r15