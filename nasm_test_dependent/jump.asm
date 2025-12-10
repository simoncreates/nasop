bits 64

    mov     eax, 10
    mov     ebx, 5
    add     eax, ebx

    jmp     do_more   

after_jump:
    mov     eax, 123
    int3

do_more:
    sub     eax, 3
    jmp     after_jump  
