#include <windows.h>

extern "C" void __attribute__((naked)) callback(){
    __asm__ volatile(
        ".intel_syntax noprefix\n"
        "push rax\n"
        "push rcx\n"
        "push rbx\n"
        "push rbp\n"
        "push rdi\n"
        "push rsi\n"
        "push r12\n"
        "push r13\n"
        "push r14\n"
        "push r15\n"
        "sub rsp, 0x1000\n"
        "movabs rax, 0xDEADBEEFDEADBEEF\n"
        "call rax\n"
        "add rsp, 0x1000\n"
        "pop r15\n"
        "pop r14\n"
        "pop r13\n"
        "pop r12\n"
        "pop rsi\n"
        "pop rdi\n"
        "pop rbp\n"
        "pop rbx\n"
        "pop rcx\n"
        "pop rax\n"
        "jmp rcx\n"
        ".att_syntax prefix\n"
    );
}