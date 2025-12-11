bits 64

start:
    mov eax, 0,
    mov ebx, 1
    mov ecx, 10 

loop:
    add eax, ebx
    ;swap values
    mov edx, eax
    mov eax, ebx
    mov ebx, edx

    dec ecx
    cmp ecx, 0
    jne loop
int3
    
