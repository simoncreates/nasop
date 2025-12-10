bits 64

start:
    mov     eax, 1
    cmp     eax, 2
    je      equal_label  
    mov     ebx, 42
    jmp     done 

equal_label:
    mov     ebx, 99

done:
    add     eax, ebx
    int3
