.code
; code taken from VbsApi.dll and slightly modified
HviIsAnyHypervisorPresent proc
			push	rbx		; cpuid returns information also
							; in RBX so this register must be 
							; preserved between function calls
			xor     ecx, ecx
			mov     r9d, 1
			mov     eax, r9d
			xor     r8b, r8b
			cpuid
			test    ecx, ecx
			jns     short @@exit
			xor     ecx, ecx
			movzx   r8d, r8b
			mov     eax, 40000001h
			cpuid
			cmp     eax, 766E6258h
			cmovnz  r8d, r9d

@@exit:                          
			mov     al, r8b
			pop		rbx
			ret

HviIsAnyHypervisorPresent endp

HviIsHypervisorMicrosoftCompatible proc
			push	rbx
			mov     eax, 40000001h
			xor     ecx, ecx
			cpuid			
			cmp     eax, 31237648h
			setz    al
			pop		rbx
			ret
HviIsHypervisorMicrosoftCompatible endp

CpuidTest proc
			push rbx
			mov eax, 40000006h
			xor ecx, ecx
			cpuid
			pop rbx
			ret
CpuidTest endp


end
