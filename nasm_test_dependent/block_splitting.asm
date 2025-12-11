bits 64

start:
    mov rax, 1
    mov rbx, 2 
    cmp rax, rbx
    jne mid
    imul rax, rbx
unused: 
    mov rax, rbx
mid:
    add rax, rbx
    jmp split_block

split_block:
    int3
