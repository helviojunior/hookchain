.data
	qTableAddr QWORD 0h
    qListEntrySize QWORD 30h
    qStubEntrySize QWORD 14h
    qUnhookAddr QWORD 0h
    qUnhookAddr2 QWORD 0h
    qPayloadAddr QWORD 0h
    qPayloadSize QWORD 0h

    qDebug QWORD 0h

    qIdx0 QWORD 0h
    qIdx1 QWORD 0h
    qIdx2 QWORD 0h
    qIdx3 QWORD 0h
    qIdx4 QWORD 0h
    qIdx5 QWORD 0h
    qIdx6 QWORD 0h
    
EXTERN PrintCall: PROC
;EXTERN PayloadPointer: PROC
;EXTERN payload: BYTE

.code
    Stop PROC
        int 3
        ret
    Stop ENDP
    
    GetZeroAddr PROC
        jmp short st1

        st2:
            pop rax
            ret

        st1:
            call st2
    GetZeroAddr ENDP

    RetZero PROC
        xor rax, rax
        ret
    RetZero ENDP

    SetDebug PROC
		mov qDebug, rcx
        xor rax, rax
		ret
	SetDebug ENDP
    
    SetAddr PROC
		mov qUnhookAddr, rcx
        xor rax, rax
		ret
	SetAddr ENDP
    
    ExecAddr PROC
        mov rax, qUnhookAddr
        test rax, rax
		je e1
        jmp rax
        e1:
        ret
	ExecAddr ENDP
    
    SetAddr2 PROC
		mov qUnhookAddr2, rcx
        xor rax, rax
		ret
	SetAddr2 ENDP
    
    ExecAddr2 PROC
        mov rax, qUnhookAddr2
        test rax, rax
		je e1
        jmp rax
        e1:
        ret
	ExecAddr2 ENDP
    
    SetPayloadData PROC
		mov qPayloadAddr, rcx
        mov qPayloadSize, rdx
        xor rax, rax
		ret
	SetPayloadData ENDP
    
    RtlCompareStringStub PROC
        mov rax, 0h
        ret
    RtlCompareStringStub ENDP
    
    RtlEqualStringStub PROC
        mov rax, 1h
        ret
    RtlEqualStringStub ENDP

    Caller PROC
        mov rax, [rsp]
        ret
    Caller ENDP

    Execute PROC
        push rbp
        mov rbp, rsp
        mov rax, rcx
        sub rsp, 20h
        xor rdx, rdx
        dec rdx
        shl rdx, 4
		and rsp, rdx
        xor rdx, rdx
		mov rcx, rdx
		mov r8, rdx
		mov r9, rdx
		mov [rsp], rdx
		mov [rsp + 08h], rdx
		mov [rsp + 10h], rdx
		mov [rsp + 18h], rdx
		call rax
        mov rsp, rbp
        pop rbp
        ret
    Execute ENDP

	SetIdx PROC
		mov rax, 0h
        lea r12, qIdx0
        mov [r12 + rcx * 8], rdx
		mov rax, 1h
		ret
	SetIdx ENDP
    
    SetTableAddr PROC
        xor rax, rax
		mov qTableAddr, 0h
		mov qTableAddr, rcx
        call GetAddr
        xor r11, r11
        mov r14, rax
        mov rcx, 200h
        L1:
            mov rax, r11
            mov rdx, qStubEntrySize
            mul rdx
            push rcx
            mov rcx, r11
            lea rdx, [r14 + rax]
            call SetIdxProc
            pop rcx
            inc r11
            loop L1
        
		mov rax, 1h
		ret
	SetTableAddr ENDP
	
    SetIdxProc PROC
		mov rax, rcx
        mov r12, rdx
        mov rdx, qListEntrySize
        mul rdx
        mov rdx, r12
        mov r12, qTableAddr
        lea rax, [r12 + rax]
        mov [rax + 18h], rdx
		ret
	SetIdxProc ENDP
    
    SyscallExec PROC
        
        cmp qDebug, 01h   ; Check if is DEBUG enabled
        jne exec

        ; Code responsible to do a callback to function PrintCall
        push rsi
        mov rsi, [rsp + 08h]
        push rbp
        push rax
        push rcx
        push rdx
        push r8
        push r9
        mov rbp, rsp
        mov rcx, rax
        mov rdx, rsi
        mov r8, rsp
        sub rsp, 20h
        call PrintCall
        mov rsp, rbp
        pop r9
        pop r8
        pop rdx
        pop rcx
        pop rax
        pop rbp
        pop rsi
        ; finish print

        exec:
        sub rsp, 08h   ; Address to place syscall addr and use with ret
        push r12
        push r9
        push r8
        push rdx
        push rcx
        push rbp
        mov rbp, rsp

        
        mov r12, rdx
        mov rdx, qListEntrySize
        mul rdx
        mov rdx, r12
        mov r12, qTableAddr
        lea rax, [r12 + rax]
        mov r12, [rax + 10h]
        mov rax, [rax]

        mov [rbp + 30h], r12    ; 0x30 = 6 * 8 = 48
        mov rsp, rbp
        pop rbp
        pop rcx
        pop rdx
        pop r8
        pop r9
        pop r12

        mov r10, rcx
        ret   ; jmp to the address saved at stack
    SyscallExec ENDP

    ; Functions used to the first Bypass
    NtOpenProcessStub PROC
        mov rax, qIdx0
        jmp SyscallExec
        ret
    NtOpenProcessStub ENDP
    
    NtProtectVirtualMemoryStub PROC
        mov rax, qIdx1
        jmp SyscallExec
        ret
    NtProtectVirtualMemoryStub ENDP

    NtReadVirtualMemoryStub PROC
        mov rax, qIdx2
        jmp SyscallExec
        ret
    NtReadVirtualMemoryStub ENDP

    NtWriteVirtualMemoryStub PROC
        mov rax, qIdx3
        jmp SyscallExec
        ret
    NtWriteVirtualMemoryStub ENDP

    NtAllocateVirtualMemoryStub PROC
        mov rax, qIdx4
        jmp SyscallExec
        ret
    NtAllocateVirtualMemoryStub ENDP
    
    NtDelayExecutionStub PROC
        mov rax, qIdx5
        jmp SyscallExec
        ret
    NtDelayExecutionStub ENDP
    
    NtQueryVirtualMemoryStub PROC
        mov rax, qIdx6
        jmp SyscallExec
        ret
    NtQueryVirtualMemoryStub ENDP

    GetData PROC
        mov r10, rcx
        mov r11, rdx
        mov rdx, qListEntrySize
        mul rdx
        mov rdx, r12
        mov r12, qTableAddr
        lea rax, [r12 + rax]
        lea r12, [rax + 10h]
        mov [r10], rax
        mov [r11], r12
        mov rax, 1h
        ret
    GetData ENDP

    GetAddr PROC
        lea rax, OFFSET L1
        inc rax
        ret
        L1:
        db 90h
    GetAddr ENDP
    
    ; Jmp functions
    
    Fnc0000 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0000h
        ret
        nop
    Fnc0000 ENDP

    Fnc0001 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0001h
        ret
        nop
    Fnc0001 ENDP

    Fnc0002 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0002h
        ret
        nop
    Fnc0002 ENDP

    Fnc0003 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0003h
        ret
        nop
    Fnc0003 ENDP

    Fnc0004 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0004h
        ret
        nop
    Fnc0004 ENDP

    Fnc0005 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0005h
        ret
        nop
    Fnc0005 ENDP

    Fnc0006 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0006h
        ret
        nop
    Fnc0006 ENDP

    Fnc0007 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0007h
        ret
        nop
    Fnc0007 ENDP

    Fnc0008 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0008h
        ret
        nop
    Fnc0008 ENDP

    Fnc0009 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0009h
        ret
        nop
    Fnc0009 ENDP

    Fnc000A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 000ah
        ret
        nop
    Fnc000A ENDP

    Fnc000B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 000bh
        ret
        nop
    Fnc000B ENDP

    Fnc000C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 000ch
        ret
        nop
    Fnc000C ENDP

    Fnc000D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 000dh
        ret
        nop
    Fnc000D ENDP

    Fnc000E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 000eh
        ret
        nop
    Fnc000E ENDP

    Fnc000F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 000fh
        ret
        nop
    Fnc000F ENDP

    Fnc0010 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0010h
        ret
        nop
    Fnc0010 ENDP

    Fnc0011 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0011h
        ret
        nop
    Fnc0011 ENDP

    Fnc0012 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0012h
        ret
        nop
    Fnc0012 ENDP

    Fnc0013 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0013h
        ret
        nop
    Fnc0013 ENDP

    Fnc0014 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0014h
        ret
        nop
    Fnc0014 ENDP

    Fnc0015 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0015h
        ret
        nop
    Fnc0015 ENDP

    Fnc0016 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0016h
        ret
        nop
    Fnc0016 ENDP

    Fnc0017 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0017h
        ret
        nop
    Fnc0017 ENDP

    Fnc0018 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0018h
        ret
        nop
    Fnc0018 ENDP

    Fnc0019 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0019h
        ret
        nop
    Fnc0019 ENDP

    Fnc001A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 001ah
        ret
        nop
    Fnc001A ENDP

    Fnc001B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 001bh
        ret
        nop
    Fnc001B ENDP

    Fnc001C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 001ch
        ret
        nop
    Fnc001C ENDP

    Fnc001D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 001dh
        ret
        nop
    Fnc001D ENDP

    Fnc001E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 001eh
        ret
        nop
    Fnc001E ENDP

    Fnc001F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 001fh
        ret
        nop
    Fnc001F ENDP

    Fnc0020 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0020h
        ret
        nop
    Fnc0020 ENDP

    Fnc0021 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0021h
        ret
        nop
    Fnc0021 ENDP

    Fnc0022 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0022h
        ret
        nop
    Fnc0022 ENDP

    Fnc0023 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0023h
        ret
        nop
    Fnc0023 ENDP

    Fnc0024 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0024h
        ret
        nop
    Fnc0024 ENDP

    Fnc0025 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0025h
        ret
        nop
    Fnc0025 ENDP

    Fnc0026 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0026h
        ret
        nop
    Fnc0026 ENDP

    Fnc0027 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0027h
        ret
        nop
    Fnc0027 ENDP

    Fnc0028 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0028h
        ret
        nop
    Fnc0028 ENDP

    Fnc0029 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0029h
        ret
        nop
    Fnc0029 ENDP

    Fnc002A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 002ah
        ret
        nop
    Fnc002A ENDP

    Fnc002B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 002bh
        ret
        nop
    Fnc002B ENDP

    Fnc002C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 002ch
        ret
        nop
    Fnc002C ENDP

    Fnc002D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 002dh
        ret
        nop
    Fnc002D ENDP

    Fnc002E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 002eh
        ret
        nop
    Fnc002E ENDP

    Fnc002F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 002fh
        ret
        nop
    Fnc002F ENDP

    Fnc0030 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0030h
        ret
        nop
    Fnc0030 ENDP

    Fnc0031 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0031h
        ret
        nop
    Fnc0031 ENDP

    Fnc0032 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0032h
        ret
        nop
    Fnc0032 ENDP

    Fnc0033 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0033h
        ret
        nop
    Fnc0033 ENDP

    Fnc0034 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0034h
        ret
        nop
    Fnc0034 ENDP

    Fnc0035 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0035h
        ret
        nop
    Fnc0035 ENDP

    Fnc0036 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0036h
        ret
        nop
    Fnc0036 ENDP

    Fnc0037 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0037h
        ret
        nop
    Fnc0037 ENDP

    Fnc0038 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0038h
        ret
        nop
    Fnc0038 ENDP

    Fnc0039 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0039h
        ret
        nop
    Fnc0039 ENDP

    Fnc003A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 003ah
        ret
        nop
    Fnc003A ENDP

    Fnc003B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 003bh
        ret
        nop
    Fnc003B ENDP

    Fnc003C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 003ch
        ret
        nop
    Fnc003C ENDP

    Fnc003D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 003dh
        ret
        nop
    Fnc003D ENDP

    Fnc003E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 003eh
        ret
        nop
    Fnc003E ENDP

    Fnc003F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 003fh
        ret
        nop
    Fnc003F ENDP

    Fnc0040 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0040h
        ret
        nop
    Fnc0040 ENDP

    Fnc0041 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0041h
        ret
        nop
    Fnc0041 ENDP

    Fnc0042 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0042h
        ret
        nop
    Fnc0042 ENDP

    Fnc0043 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0043h
        ret
        nop
    Fnc0043 ENDP

    Fnc0044 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0044h
        ret
        nop
    Fnc0044 ENDP

    Fnc0045 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0045h
        ret
        nop
    Fnc0045 ENDP

    Fnc0046 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0046h
        ret
        nop
    Fnc0046 ENDP

    Fnc0047 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0047h
        ret
        nop
    Fnc0047 ENDP

    Fnc0048 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0048h
        ret
        nop
    Fnc0048 ENDP

    Fnc0049 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0049h
        ret
        nop
    Fnc0049 ENDP

    Fnc004A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 004ah
        ret
        nop
    Fnc004A ENDP

    Fnc004B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 004bh
        ret
        nop
    Fnc004B ENDP

    Fnc004C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 004ch
        ret
        nop
    Fnc004C ENDP

    Fnc004D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 004dh
        ret
        nop
    Fnc004D ENDP

    Fnc004E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 004eh
        ret
        nop
    Fnc004E ENDP

    Fnc004F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 004fh
        ret
        nop
    Fnc004F ENDP

    Fnc0050 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0050h
        ret
        nop
    Fnc0050 ENDP

    Fnc0051 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0051h
        ret
        nop
    Fnc0051 ENDP

    Fnc0052 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0052h
        ret
        nop
    Fnc0052 ENDP

    Fnc0053 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0053h
        ret
        nop
    Fnc0053 ENDP

    Fnc0054 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0054h
        ret
        nop
    Fnc0054 ENDP

    Fnc0055 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0055h
        ret
        nop
    Fnc0055 ENDP

    Fnc0056 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0056h
        ret
        nop
    Fnc0056 ENDP

    Fnc0057 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0057h
        ret
        nop
    Fnc0057 ENDP

    Fnc0058 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0058h
        ret
        nop
    Fnc0058 ENDP

    Fnc0059 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0059h
        ret
        nop
    Fnc0059 ENDP

    Fnc005A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 005ah
        ret
        nop
    Fnc005A ENDP

    Fnc005B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 005bh
        ret
        nop
    Fnc005B ENDP

    Fnc005C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 005ch
        ret
        nop
    Fnc005C ENDP

    Fnc005D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 005dh
        ret
        nop
    Fnc005D ENDP

    Fnc005E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 005eh
        ret
        nop
    Fnc005E ENDP

    Fnc005F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 005fh
        ret
        nop
    Fnc005F ENDP

    Fnc0060 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0060h
        ret
        nop
    Fnc0060 ENDP

    Fnc0061 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0061h
        ret
        nop
    Fnc0061 ENDP

    Fnc0062 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0062h
        ret
        nop
    Fnc0062 ENDP

    Fnc0063 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0063h
        ret
        nop
    Fnc0063 ENDP

    Fnc0064 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0064h
        ret
        nop
    Fnc0064 ENDP

    Fnc0065 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0065h
        ret
        nop
    Fnc0065 ENDP

    Fnc0066 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0066h
        ret
        nop
    Fnc0066 ENDP

    Fnc0067 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0067h
        ret
        nop
    Fnc0067 ENDP

    Fnc0068 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0068h
        ret
        nop
    Fnc0068 ENDP

    Fnc0069 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0069h
        ret
        nop
    Fnc0069 ENDP

    Fnc006A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 006ah
        ret
        nop
    Fnc006A ENDP

    Fnc006B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 006bh
        ret
        nop
    Fnc006B ENDP

    Fnc006C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 006ch
        ret
        nop
    Fnc006C ENDP

    Fnc006D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 006dh
        ret
        nop
    Fnc006D ENDP

    Fnc006E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 006eh
        ret
        nop
    Fnc006E ENDP

    Fnc006F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 006fh
        ret
        nop
    Fnc006F ENDP

    Fnc0070 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0070h
        ret
        nop
    Fnc0070 ENDP

    Fnc0071 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0071h
        ret
        nop
    Fnc0071 ENDP

    Fnc0072 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0072h
        ret
        nop
    Fnc0072 ENDP

    Fnc0073 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0073h
        ret
        nop
    Fnc0073 ENDP

    Fnc0074 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0074h
        ret
        nop
    Fnc0074 ENDP

    Fnc0075 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0075h
        ret
        nop
    Fnc0075 ENDP

    Fnc0076 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0076h
        ret
        nop
    Fnc0076 ENDP

    Fnc0077 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0077h
        ret
        nop
    Fnc0077 ENDP

    Fnc0078 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0078h
        ret
        nop
    Fnc0078 ENDP

    Fnc0079 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0079h
        ret
        nop
    Fnc0079 ENDP

    Fnc007A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 007ah
        ret
        nop
    Fnc007A ENDP

    Fnc007B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 007bh
        ret
        nop
    Fnc007B ENDP

    Fnc007C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 007ch
        ret
        nop
    Fnc007C ENDP

    Fnc007D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 007dh
        ret
        nop
    Fnc007D ENDP

    Fnc007E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 007eh
        ret
        nop
    Fnc007E ENDP

    Fnc007F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 007fh
        ret
        nop
    Fnc007F ENDP

    Fnc0080 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0080h
        ret
        nop
    Fnc0080 ENDP

    Fnc0081 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0081h
        ret
        nop
    Fnc0081 ENDP

    Fnc0082 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0082h
        ret
        nop
    Fnc0082 ENDP

    Fnc0083 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0083h
        ret
        nop
    Fnc0083 ENDP

    Fnc0084 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0084h
        ret
        nop
    Fnc0084 ENDP

    Fnc0085 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0085h
        ret
        nop
    Fnc0085 ENDP

    Fnc0086 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0086h
        ret
        nop
    Fnc0086 ENDP

    Fnc0087 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0087h
        ret
        nop
    Fnc0087 ENDP

    Fnc0088 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0088h
        ret
        nop
    Fnc0088 ENDP

    Fnc0089 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0089h
        ret
        nop
    Fnc0089 ENDP

    Fnc008A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 008ah
        ret
        nop
    Fnc008A ENDP

    Fnc008B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 008bh
        ret
        nop
    Fnc008B ENDP

    Fnc008C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 008ch
        ret
        nop
    Fnc008C ENDP

    Fnc008D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 008dh
        ret
        nop
    Fnc008D ENDP

    Fnc008E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 008eh
        ret
        nop
    Fnc008E ENDP

    Fnc008F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 008fh
        ret
        nop
    Fnc008F ENDP

    Fnc0090 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0090h
        ret
        nop
    Fnc0090 ENDP

    Fnc0091 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0091h
        ret
        nop
    Fnc0091 ENDP

    Fnc0092 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0092h
        ret
        nop
    Fnc0092 ENDP

    Fnc0093 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0093h
        ret
        nop
    Fnc0093 ENDP

    Fnc0094 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0094h
        ret
        nop
    Fnc0094 ENDP

    Fnc0095 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0095h
        ret
        nop
    Fnc0095 ENDP

    Fnc0096 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0096h
        ret
        nop
    Fnc0096 ENDP

    Fnc0097 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0097h
        ret
        nop
    Fnc0097 ENDP

    Fnc0098 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0098h
        ret
        nop
    Fnc0098 ENDP

    Fnc0099 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0099h
        ret
        nop
    Fnc0099 ENDP

    Fnc009A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 009ah
        ret
        nop
    Fnc009A ENDP

    Fnc009B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 009bh
        ret
        nop
    Fnc009B ENDP

    Fnc009C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 009ch
        ret
        nop
    Fnc009C ENDP

    Fnc009D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 009dh
        ret
        nop
    Fnc009D ENDP

    Fnc009E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 009eh
        ret
        nop
    Fnc009E ENDP

    Fnc009F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 009fh
        ret
        nop
    Fnc009F ENDP

    Fnc00A0 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00a0h
        ret
        nop
    Fnc00A0 ENDP

    Fnc00A1 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00a1h
        ret
        nop
    Fnc00A1 ENDP

    Fnc00A2 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00a2h
        ret
        nop
    Fnc00A2 ENDP

    Fnc00A3 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00a3h
        ret
        nop
    Fnc00A3 ENDP

    Fnc00A4 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00a4h
        ret
        nop
    Fnc00A4 ENDP

    Fnc00A5 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00a5h
        ret
        nop
    Fnc00A5 ENDP

    Fnc00A6 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00a6h
        ret
        nop
    Fnc00A6 ENDP

    Fnc00A7 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00a7h
        ret
        nop
    Fnc00A7 ENDP

    Fnc00A8 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00a8h
        ret
        nop
    Fnc00A8 ENDP

    Fnc00A9 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00a9h
        ret
        nop
    Fnc00A9 ENDP

    Fnc00AA PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00aah
        ret
        nop
    Fnc00AA ENDP

    Fnc00AB PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00abh
        ret
        nop
    Fnc00AB ENDP

    Fnc00AC PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00ach
        ret
        nop
    Fnc00AC ENDP

    Fnc00AD PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00adh
        ret
        nop
    Fnc00AD ENDP

    Fnc00AE PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00aeh
        ret
        nop
    Fnc00AE ENDP

    Fnc00AF PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00afh
        ret
        nop
    Fnc00AF ENDP

    Fnc00B0 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00b0h
        ret
        nop
    Fnc00B0 ENDP

    Fnc00B1 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00b1h
        ret
        nop
    Fnc00B1 ENDP

    Fnc00B2 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00b2h
        ret
        nop
    Fnc00B2 ENDP

    Fnc00B3 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00b3h
        ret
        nop
    Fnc00B3 ENDP

    Fnc00B4 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00b4h
        ret
        nop
    Fnc00B4 ENDP

    Fnc00B5 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00b5h
        ret
        nop
    Fnc00B5 ENDP

    Fnc00B6 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00b6h
        ret
        nop
    Fnc00B6 ENDP

    Fnc00B7 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00b7h
        ret
        nop
    Fnc00B7 ENDP

    Fnc00B8 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00b8h
        ret
        nop
    Fnc00B8 ENDP

    Fnc00B9 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00b9h
        ret
        nop
    Fnc00B9 ENDP

    Fnc00BA PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00bah
        ret
        nop
    Fnc00BA ENDP

    Fnc00BB PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00bbh
        ret
        nop
    Fnc00BB ENDP

    Fnc00BC PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00bch
        ret
        nop
    Fnc00BC ENDP

    Fnc00BD PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00bdh
        ret
        nop
    Fnc00BD ENDP

    Fnc00BE PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00beh
        ret
        nop
    Fnc00BE ENDP

    Fnc00BF PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00bfh
        ret
        nop
    Fnc00BF ENDP

    Fnc00C0 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00c0h
        ret
        nop
    Fnc00C0 ENDP

    Fnc00C1 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00c1h
        ret
        nop
    Fnc00C1 ENDP

    Fnc00C2 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00c2h
        ret
        nop
    Fnc00C2 ENDP

    Fnc00C3 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00c3h
        ret
        nop
    Fnc00C3 ENDP

    Fnc00C4 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00c4h
        ret
        nop
    Fnc00C4 ENDP

    Fnc00C5 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00c5h
        ret
        nop
    Fnc00C5 ENDP

    Fnc00C6 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00c6h
        ret
        nop
    Fnc00C6 ENDP

    Fnc00C7 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00c7h
        ret
        nop
    Fnc00C7 ENDP

    Fnc00C8 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00c8h
        ret
        nop
    Fnc00C8 ENDP

    Fnc00C9 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00c9h
        ret
        nop
    Fnc00C9 ENDP

    Fnc00CA PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00cah
        ret
        nop
    Fnc00CA ENDP

    Fnc00CB PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00cbh
        ret
        nop
    Fnc00CB ENDP

    Fnc00CC PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00cch
        ret
        nop
    Fnc00CC ENDP

    Fnc00CD PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00cdh
        ret
        nop
    Fnc00CD ENDP

    Fnc00CE PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00ceh
        ret
        nop
    Fnc00CE ENDP

    Fnc00CF PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00cfh
        ret
        nop
    Fnc00CF ENDP

    Fnc00D0 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00d0h
        ret
        nop
    Fnc00D0 ENDP

    Fnc00D1 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00d1h
        ret
        nop
    Fnc00D1 ENDP

    Fnc00D2 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00d2h
        ret
        nop
    Fnc00D2 ENDP

    Fnc00D3 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00d3h
        ret
        nop
    Fnc00D3 ENDP

    Fnc00D4 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00d4h
        ret
        nop
    Fnc00D4 ENDP

    Fnc00D5 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00d5h
        ret
        nop
    Fnc00D5 ENDP

    Fnc00D6 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00d6h
        ret
        nop
    Fnc00D6 ENDP

    Fnc00D7 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00d7h
        ret
        nop
    Fnc00D7 ENDP

    Fnc00D8 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00d8h
        ret
        nop
    Fnc00D8 ENDP

    Fnc00D9 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00d9h
        ret
        nop
    Fnc00D9 ENDP

    Fnc00DA PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00dah
        ret
        nop
    Fnc00DA ENDP

    Fnc00DB PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00dbh
        ret
        nop
    Fnc00DB ENDP

    Fnc00DC PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00dch
        ret
        nop
    Fnc00DC ENDP

    Fnc00DD PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00ddh
        ret
        nop
    Fnc00DD ENDP

    Fnc00DE PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00deh
        ret
        nop
    Fnc00DE ENDP

    Fnc00DF PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00dfh
        ret
        nop
    Fnc00DF ENDP

    Fnc00E0 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00e0h
        ret
        nop
    Fnc00E0 ENDP

    Fnc00E1 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00e1h
        ret
        nop
    Fnc00E1 ENDP

    Fnc00E2 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00e2h
        ret
        nop
    Fnc00E2 ENDP

    Fnc00E3 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00e3h
        ret
        nop
    Fnc00E3 ENDP

    Fnc00E4 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00e4h
        ret
        nop
    Fnc00E4 ENDP

    Fnc00E5 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00e5h
        ret
        nop
    Fnc00E5 ENDP

    Fnc00E6 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00e6h
        ret
        nop
    Fnc00E6 ENDP

    Fnc00E7 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00e7h
        ret
        nop
    Fnc00E7 ENDP

    Fnc00E8 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00e8h
        ret
        nop
    Fnc00E8 ENDP

    Fnc00E9 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00e9h
        ret
        nop
    Fnc00E9 ENDP

    Fnc00EA PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00eah
        ret
        nop
    Fnc00EA ENDP

    Fnc00EB PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00ebh
        ret
        nop
    Fnc00EB ENDP

    Fnc00EC PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00ech
        ret
        nop
    Fnc00EC ENDP

    Fnc00ED PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00edh
        ret
        nop
    Fnc00ED ENDP

    Fnc00EE PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00eeh
        ret
        nop
    Fnc00EE ENDP

    Fnc00EF PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00efh
        ret
        nop
    Fnc00EF ENDP

    Fnc00F0 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00f0h
        ret
        nop
    Fnc00F0 ENDP

    Fnc00F1 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00f1h
        ret
        nop
    Fnc00F1 ENDP

    Fnc00F2 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00f2h
        ret
        nop
    Fnc00F2 ENDP

    Fnc00F3 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00f3h
        ret
        nop
    Fnc00F3 ENDP

    Fnc00F4 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00f4h
        ret
        nop
    Fnc00F4 ENDP

    Fnc00F5 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00f5h
        ret
        nop
    Fnc00F5 ENDP

    Fnc00F6 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00f6h
        ret
        nop
    Fnc00F6 ENDP

    Fnc00F7 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00f7h
        ret
        nop
    Fnc00F7 ENDP

    Fnc00F8 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00f8h
        ret
        nop
    Fnc00F8 ENDP

    Fnc00F9 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00f9h
        ret
        nop
    Fnc00F9 ENDP

    Fnc00FA PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00fah
        ret
        nop
    Fnc00FA ENDP

    Fnc00FB PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00fbh
        ret
        nop
    Fnc00FB ENDP

    Fnc00FC PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00fch
        ret
        nop
    Fnc00FC ENDP

    Fnc00FD PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00fdh
        ret
        nop
    Fnc00FD ENDP

    Fnc00FE PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00feh
        ret
        nop
    Fnc00FE ENDP

    Fnc00FF PROC
        mov rax, SyscallExec
        push rax
        mov rax, 00ffh
        ret
        nop
    Fnc00FF ENDP

    Fnc0100 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0100h
        ret
        nop
    Fnc0100 ENDP

    Fnc0101 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0101h
        ret
        nop
    Fnc0101 ENDP

    Fnc0102 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0102h
        ret
        nop
    Fnc0102 ENDP

    Fnc0103 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0103h
        ret
        nop
    Fnc0103 ENDP

    Fnc0104 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0104h
        ret
        nop
    Fnc0104 ENDP

    Fnc0105 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0105h
        ret
        nop
    Fnc0105 ENDP

    Fnc0106 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0106h
        ret
        nop
    Fnc0106 ENDP

    Fnc0107 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0107h
        ret
        nop
    Fnc0107 ENDP

    Fnc0108 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0108h
        ret
        nop
    Fnc0108 ENDP

    Fnc0109 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0109h
        ret
        nop
    Fnc0109 ENDP

    Fnc010A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 010ah
        ret
        nop
    Fnc010A ENDP

    Fnc010B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 010bh
        ret
        nop
    Fnc010B ENDP

    Fnc010C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 010ch
        ret
        nop
    Fnc010C ENDP

    Fnc010D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 010dh
        ret
        nop
    Fnc010D ENDP

    Fnc010E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 010eh
        ret
        nop
    Fnc010E ENDP

    Fnc010F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 010fh
        ret
        nop
    Fnc010F ENDP

    Fnc0110 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0110h
        ret
        nop
    Fnc0110 ENDP

    Fnc0111 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0111h
        ret
        nop
    Fnc0111 ENDP

    Fnc0112 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0112h
        ret
        nop
    Fnc0112 ENDP

    Fnc0113 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0113h
        ret
        nop
    Fnc0113 ENDP

    Fnc0114 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0114h
        ret
        nop
    Fnc0114 ENDP

    Fnc0115 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0115h
        ret
        nop
    Fnc0115 ENDP

    Fnc0116 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0116h
        ret
        nop
    Fnc0116 ENDP

    Fnc0117 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0117h
        ret
        nop
    Fnc0117 ENDP

    Fnc0118 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0118h
        ret
        nop
    Fnc0118 ENDP

    Fnc0119 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0119h
        ret
        nop
    Fnc0119 ENDP

    Fnc011A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 011ah
        ret
        nop
    Fnc011A ENDP

    Fnc011B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 011bh
        ret
        nop
    Fnc011B ENDP

    Fnc011C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 011ch
        ret
        nop
    Fnc011C ENDP

    Fnc011D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 011dh
        ret
        nop
    Fnc011D ENDP

    Fnc011E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 011eh
        ret
        nop
    Fnc011E ENDP

    Fnc011F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 011fh
        ret
        nop
    Fnc011F ENDP

    Fnc0120 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0120h
        ret
        nop
    Fnc0120 ENDP

    Fnc0121 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0121h
        ret
        nop
    Fnc0121 ENDP

    Fnc0122 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0122h
        ret
        nop
    Fnc0122 ENDP

    Fnc0123 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0123h
        ret
        nop
    Fnc0123 ENDP

    Fnc0124 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0124h
        ret
        nop
    Fnc0124 ENDP

    Fnc0125 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0125h
        ret
        nop
    Fnc0125 ENDP

    Fnc0126 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0126h
        ret
        nop
    Fnc0126 ENDP

    Fnc0127 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0127h
        ret
        nop
    Fnc0127 ENDP

    Fnc0128 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0128h
        ret
        nop
    Fnc0128 ENDP

    Fnc0129 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0129h
        ret
        nop
    Fnc0129 ENDP

    Fnc012A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 012ah
        ret
        nop
    Fnc012A ENDP

    Fnc012B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 012bh
        ret
        nop
    Fnc012B ENDP

    Fnc012C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 012ch
        ret
        nop
    Fnc012C ENDP

    Fnc012D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 012dh
        ret
        nop
    Fnc012D ENDP

    Fnc012E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 012eh
        ret
        nop
    Fnc012E ENDP

    Fnc012F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 012fh
        ret
        nop
    Fnc012F ENDP

    Fnc0130 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0130h
        ret
        nop
    Fnc0130 ENDP

    Fnc0131 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0131h
        ret
        nop
    Fnc0131 ENDP

    Fnc0132 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0132h
        ret
        nop
    Fnc0132 ENDP

    Fnc0133 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0133h
        ret
        nop
    Fnc0133 ENDP

    Fnc0134 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0134h
        ret
        nop
    Fnc0134 ENDP

    Fnc0135 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0135h
        ret
        nop
    Fnc0135 ENDP

    Fnc0136 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0136h
        ret
        nop
    Fnc0136 ENDP

    Fnc0137 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0137h
        ret
        nop
    Fnc0137 ENDP

    Fnc0138 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0138h
        ret
        nop
    Fnc0138 ENDP

    Fnc0139 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0139h
        ret
        nop
    Fnc0139 ENDP

    Fnc013A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 013ah
        ret
        nop
    Fnc013A ENDP

    Fnc013B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 013bh
        ret
        nop
    Fnc013B ENDP

    Fnc013C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 013ch
        ret
        nop
    Fnc013C ENDP

    Fnc013D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 013dh
        ret
        nop
    Fnc013D ENDP

    Fnc013E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 013eh
        ret
        nop
    Fnc013E ENDP

    Fnc013F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 013fh
        ret
        nop
    Fnc013F ENDP

    Fnc0140 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0140h
        ret
        nop
    Fnc0140 ENDP

    Fnc0141 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0141h
        ret
        nop
    Fnc0141 ENDP

    Fnc0142 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0142h
        ret
        nop
    Fnc0142 ENDP

    Fnc0143 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0143h
        ret
        nop
    Fnc0143 ENDP

    Fnc0144 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0144h
        ret
        nop
    Fnc0144 ENDP

    Fnc0145 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0145h
        ret
        nop
    Fnc0145 ENDP

    Fnc0146 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0146h
        ret
        nop
    Fnc0146 ENDP

    Fnc0147 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0147h
        ret
        nop
    Fnc0147 ENDP

    Fnc0148 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0148h
        ret
        nop
    Fnc0148 ENDP

    Fnc0149 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0149h
        ret
        nop
    Fnc0149 ENDP

    Fnc014A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 014ah
        ret
        nop
    Fnc014A ENDP

    Fnc014B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 014bh
        ret
        nop
    Fnc014B ENDP

    Fnc014C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 014ch
        ret
        nop
    Fnc014C ENDP

    Fnc014D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 014dh
        ret
        nop
    Fnc014D ENDP

    Fnc014E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 014eh
        ret
        nop
    Fnc014E ENDP

    Fnc014F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 014fh
        ret
        nop
    Fnc014F ENDP

    Fnc0150 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0150h
        ret
        nop
    Fnc0150 ENDP

    Fnc0151 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0151h
        ret
        nop
    Fnc0151 ENDP

    Fnc0152 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0152h
        ret
        nop
    Fnc0152 ENDP

    Fnc0153 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0153h
        ret
        nop
    Fnc0153 ENDP

    Fnc0154 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0154h
        ret
        nop
    Fnc0154 ENDP

    Fnc0155 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0155h
        ret
        nop
    Fnc0155 ENDP

    Fnc0156 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0156h
        ret
        nop
    Fnc0156 ENDP

    Fnc0157 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0157h
        ret
        nop
    Fnc0157 ENDP

    Fnc0158 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0158h
        ret
        nop
    Fnc0158 ENDP

    Fnc0159 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0159h
        ret
        nop
    Fnc0159 ENDP

    Fnc015A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 015ah
        ret
        nop
    Fnc015A ENDP

    Fnc015B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 015bh
        ret
        nop
    Fnc015B ENDP

    Fnc015C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 015ch
        ret
        nop
    Fnc015C ENDP

    Fnc015D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 015dh
        ret
        nop
    Fnc015D ENDP

    Fnc015E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 015eh
        ret
        nop
    Fnc015E ENDP

    Fnc015F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 015fh
        ret
        nop
    Fnc015F ENDP

    Fnc0160 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0160h
        ret
        nop
    Fnc0160 ENDP

    Fnc0161 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0161h
        ret
        nop
    Fnc0161 ENDP

    Fnc0162 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0162h
        ret
        nop
    Fnc0162 ENDP

    Fnc0163 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0163h
        ret
        nop
    Fnc0163 ENDP

    Fnc0164 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0164h
        ret
        nop
    Fnc0164 ENDP

    Fnc0165 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0165h
        ret
        nop
    Fnc0165 ENDP

    Fnc0166 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0166h
        ret
        nop
    Fnc0166 ENDP

    Fnc0167 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0167h
        ret
        nop
    Fnc0167 ENDP

    Fnc0168 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0168h
        ret
        nop
    Fnc0168 ENDP

    Fnc0169 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0169h
        ret
        nop
    Fnc0169 ENDP

    Fnc016A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 016ah
        ret
        nop
    Fnc016A ENDP

    Fnc016B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 016bh
        ret
        nop
    Fnc016B ENDP

    Fnc016C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 016ch
        ret
        nop
    Fnc016C ENDP

    Fnc016D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 016dh
        ret
        nop
    Fnc016D ENDP

    Fnc016E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 016eh
        ret
        nop
    Fnc016E ENDP

    Fnc016F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 016fh
        ret
        nop
    Fnc016F ENDP

    Fnc0170 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0170h
        ret
        nop
    Fnc0170 ENDP

    Fnc0171 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0171h
        ret
        nop
    Fnc0171 ENDP

    Fnc0172 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0172h
        ret
        nop
    Fnc0172 ENDP

    Fnc0173 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0173h
        ret
        nop
    Fnc0173 ENDP

    Fnc0174 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0174h
        ret
        nop
    Fnc0174 ENDP

    Fnc0175 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0175h
        ret
        nop
    Fnc0175 ENDP

    Fnc0176 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0176h
        ret
        nop
    Fnc0176 ENDP

    Fnc0177 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0177h
        ret
        nop
    Fnc0177 ENDP

    Fnc0178 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0178h
        ret
        nop
    Fnc0178 ENDP

    Fnc0179 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0179h
        ret
        nop
    Fnc0179 ENDP

    Fnc017A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 017ah
        ret
        nop
    Fnc017A ENDP

    Fnc017B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 017bh
        ret
        nop
    Fnc017B ENDP

    Fnc017C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 017ch
        ret
        nop
    Fnc017C ENDP

    Fnc017D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 017dh
        ret
        nop
    Fnc017D ENDP

    Fnc017E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 017eh
        ret
        nop
    Fnc017E ENDP

    Fnc017F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 017fh
        ret
        nop
    Fnc017F ENDP

    Fnc0180 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0180h
        ret
        nop
    Fnc0180 ENDP

    Fnc0181 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0181h
        ret
        nop
    Fnc0181 ENDP

    Fnc0182 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0182h
        ret
        nop
    Fnc0182 ENDP

    Fnc0183 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0183h
        ret
        nop
    Fnc0183 ENDP

    Fnc0184 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0184h
        ret
        nop
    Fnc0184 ENDP

    Fnc0185 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0185h
        ret
        nop
    Fnc0185 ENDP

    Fnc0186 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0186h
        ret
        nop
    Fnc0186 ENDP

    Fnc0187 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0187h
        ret
        nop
    Fnc0187 ENDP

    Fnc0188 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0188h
        ret
        nop
    Fnc0188 ENDP

    Fnc0189 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0189h
        ret
        nop
    Fnc0189 ENDP

    Fnc018A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 018ah
        ret
        nop
    Fnc018A ENDP

    Fnc018B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 018bh
        ret
        nop
    Fnc018B ENDP

    Fnc018C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 018ch
        ret
        nop
    Fnc018C ENDP

    Fnc018D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 018dh
        ret
        nop
    Fnc018D ENDP

    Fnc018E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 018eh
        ret
        nop
    Fnc018E ENDP

    Fnc018F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 018fh
        ret
        nop
    Fnc018F ENDP

    Fnc0190 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0190h
        ret
        nop
    Fnc0190 ENDP

    Fnc0191 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0191h
        ret
        nop
    Fnc0191 ENDP

    Fnc0192 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0192h
        ret
        nop
    Fnc0192 ENDP

    Fnc0193 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0193h
        ret
        nop
    Fnc0193 ENDP

    Fnc0194 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0194h
        ret
        nop
    Fnc0194 ENDP

    Fnc0195 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0195h
        ret
        nop
    Fnc0195 ENDP

    Fnc0196 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0196h
        ret
        nop
    Fnc0196 ENDP

    Fnc0197 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0197h
        ret
        nop
    Fnc0197 ENDP

    Fnc0198 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0198h
        ret
        nop
    Fnc0198 ENDP

    Fnc0199 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 0199h
        ret
        nop
    Fnc0199 ENDP

    Fnc019A PROC
        mov rax, SyscallExec
        push rax
        mov rax, 019ah
        ret
        nop
    Fnc019A ENDP

    Fnc019B PROC
        mov rax, SyscallExec
        push rax
        mov rax, 019bh
        ret
        nop
    Fnc019B ENDP

    Fnc019C PROC
        mov rax, SyscallExec
        push rax
        mov rax, 019ch
        ret
        nop
    Fnc019C ENDP

    Fnc019D PROC
        mov rax, SyscallExec
        push rax
        mov rax, 019dh
        ret
        nop
    Fnc019D ENDP

    Fnc019E PROC
        mov rax, SyscallExec
        push rax
        mov rax, 019eh
        ret
        nop
    Fnc019E ENDP

    Fnc019F PROC
        mov rax, SyscallExec
        push rax
        mov rax, 019fh
        ret
        nop
    Fnc019F ENDP

    Fnc01A0 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01a0h
        ret
        nop
    Fnc01A0 ENDP

    Fnc01A1 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01a1h
        ret
        nop
    Fnc01A1 ENDP

    Fnc01A2 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01a2h
        ret
        nop
    Fnc01A2 ENDP

    Fnc01A3 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01a3h
        ret
        nop
    Fnc01A3 ENDP

    Fnc01A4 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01a4h
        ret
        nop
    Fnc01A4 ENDP

    Fnc01A5 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01a5h
        ret
        nop
    Fnc01A5 ENDP

    Fnc01A6 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01a6h
        ret
        nop
    Fnc01A6 ENDP

    Fnc01A7 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01a7h
        ret
        nop
    Fnc01A7 ENDP

    Fnc01A8 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01a8h
        ret
        nop
    Fnc01A8 ENDP

    Fnc01A9 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01a9h
        ret
        nop
    Fnc01A9 ENDP

    Fnc01AA PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01aah
        ret
        nop
    Fnc01AA ENDP

    Fnc01AB PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01abh
        ret
        nop
    Fnc01AB ENDP

    Fnc01AC PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01ach
        ret
        nop
    Fnc01AC ENDP

    Fnc01AD PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01adh
        ret
        nop
    Fnc01AD ENDP

    Fnc01AE PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01aeh
        ret
        nop
    Fnc01AE ENDP

    Fnc01AF PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01afh
        ret
        nop
    Fnc01AF ENDP

    Fnc01B0 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01b0h
        ret
        nop
    Fnc01B0 ENDP

    Fnc01B1 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01b1h
        ret
        nop
    Fnc01B1 ENDP

    Fnc01B2 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01b2h
        ret
        nop
    Fnc01B2 ENDP

    Fnc01B3 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01b3h
        ret
        nop
    Fnc01B3 ENDP

    Fnc01B4 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01b4h
        ret
        nop
    Fnc01B4 ENDP

    Fnc01B5 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01b5h
        ret
        nop
    Fnc01B5 ENDP

    Fnc01B6 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01b6h
        ret
        nop
    Fnc01B6 ENDP

    Fnc01B7 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01b7h
        ret
        nop
    Fnc01B7 ENDP

    Fnc01B8 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01b8h
        ret
        nop
    Fnc01B8 ENDP

    Fnc01B9 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01b9h
        ret
        nop
    Fnc01B9 ENDP

    Fnc01BA PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01bah
        ret
        nop
    Fnc01BA ENDP

    Fnc01BB PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01bbh
        ret
        nop
    Fnc01BB ENDP

    Fnc01BC PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01bch
        ret
        nop
    Fnc01BC ENDP

    Fnc01BD PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01bdh
        ret
        nop
    Fnc01BD ENDP

    Fnc01BE PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01beh
        ret
        nop
    Fnc01BE ENDP

    Fnc01BF PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01bfh
        ret
        nop
    Fnc01BF ENDP

    Fnc01C0 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01c0h
        ret
        nop
    Fnc01C0 ENDP

    Fnc01C1 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01c1h
        ret
        nop
    Fnc01C1 ENDP

    Fnc01C2 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01c2h
        ret
        nop
    Fnc01C2 ENDP

    Fnc01C3 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01c3h
        ret
        nop
    Fnc01C3 ENDP

    Fnc01C4 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01c4h
        ret
        nop
    Fnc01C4 ENDP

    Fnc01C5 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01c5h
        ret
        nop
    Fnc01C5 ENDP

    Fnc01C6 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01c6h
        ret
        nop
    Fnc01C6 ENDP

    Fnc01C7 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01c7h
        ret
        nop
    Fnc01C7 ENDP

    Fnc01C8 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01c8h
        ret
        nop
    Fnc01C8 ENDP

    Fnc01C9 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01c9h
        ret
        nop
    Fnc01C9 ENDP

    Fnc01CA PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01cah
        ret
        nop
    Fnc01CA ENDP

    Fnc01CB PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01cbh
        ret
        nop
    Fnc01CB ENDP

    Fnc01CC PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01cch
        ret
        nop
    Fnc01CC ENDP

    Fnc01CD PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01cdh
        ret
        nop
    Fnc01CD ENDP

    Fnc01CE PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01ceh
        ret
        nop
    Fnc01CE ENDP

    Fnc01CF PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01cfh
        ret
        nop
    Fnc01CF ENDP

    Fnc01D0 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01d0h
        ret
        nop
    Fnc01D0 ENDP

    Fnc01D1 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01d1h
        ret
        nop
    Fnc01D1 ENDP

    Fnc01D2 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01d2h
        ret
        nop
    Fnc01D2 ENDP

    Fnc01D3 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01d3h
        ret
        nop
    Fnc01D3 ENDP

    Fnc01D4 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01d4h
        ret
        nop
    Fnc01D4 ENDP

    Fnc01D5 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01d5h
        ret
        nop
    Fnc01D5 ENDP

    Fnc01D6 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01d6h
        ret
        nop
    Fnc01D6 ENDP

    Fnc01D7 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01d7h
        ret
        nop
    Fnc01D7 ENDP

    Fnc01D8 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01d8h
        ret
        nop
    Fnc01D8 ENDP

    Fnc01D9 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01d9h
        ret
        nop
    Fnc01D9 ENDP

    Fnc01DA PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01dah
        ret
        nop
    Fnc01DA ENDP

    Fnc01DB PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01dbh
        ret
        nop
    Fnc01DB ENDP

    Fnc01DC PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01dch
        ret
        nop
    Fnc01DC ENDP

    Fnc01DD PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01ddh
        ret
        nop
    Fnc01DD ENDP

    Fnc01DE PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01deh
        ret
        nop
    Fnc01DE ENDP

    Fnc01DF PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01dfh
        ret
        nop
    Fnc01DF ENDP

    Fnc01E0 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01e0h
        ret
        nop
    Fnc01E0 ENDP

    Fnc01E1 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01e1h
        ret
        nop
    Fnc01E1 ENDP

    Fnc01E2 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01e2h
        ret
        nop
    Fnc01E2 ENDP

    Fnc01E3 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01e3h
        ret
        nop
    Fnc01E3 ENDP

    Fnc01E4 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01e4h
        ret
        nop
    Fnc01E4 ENDP

    Fnc01E5 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01e5h
        ret
        nop
    Fnc01E5 ENDP

    Fnc01E6 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01e6h
        ret
        nop
    Fnc01E6 ENDP

    Fnc01E7 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01e7h
        ret
        nop
    Fnc01E7 ENDP

    Fnc01E8 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01e8h
        ret
        nop
    Fnc01E8 ENDP

    Fnc01E9 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01e9h
        ret
        nop
    Fnc01E9 ENDP

    Fnc01EA PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01eah
        ret
        nop
    Fnc01EA ENDP

    Fnc01EB PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01ebh
        ret
        nop
    Fnc01EB ENDP

    Fnc01EC PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01ech
        ret
        nop
    Fnc01EC ENDP

    Fnc01ED PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01edh
        ret
        nop
    Fnc01ED ENDP

    Fnc01EE PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01eeh
        ret
        nop
    Fnc01EE ENDP

    Fnc01EF PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01efh
        ret
        nop
    Fnc01EF ENDP

    Fnc01F0 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01f0h
        ret
        nop
    Fnc01F0 ENDP

    Fnc01F1 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01f1h
        ret
        nop
    Fnc01F1 ENDP

    Fnc01F2 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01f2h
        ret
        nop
    Fnc01F2 ENDP

    Fnc01F3 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01f3h
        ret
        nop
    Fnc01F3 ENDP

    Fnc01F4 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01f4h
        ret
        nop
    Fnc01F4 ENDP

    Fnc01F5 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01f5h
        ret
        nop
    Fnc01F5 ENDP

    Fnc01F6 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01f6h
        ret
        nop
    Fnc01F6 ENDP

    Fnc01F7 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01f7h
        ret
        nop
    Fnc01F7 ENDP

    Fnc01F8 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01f8h
        ret
        nop
    Fnc01F8 ENDP

    Fnc01F9 PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01f9h
        ret
        nop
    Fnc01F9 ENDP

    Fnc01FA PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01fah
        ret
        nop
    Fnc01FA ENDP

    Fnc01FB PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01fbh
        ret
        nop
    Fnc01FB ENDP

    Fnc01FC PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01fch
        ret
        nop
    Fnc01FC ENDP

    Fnc01FD PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01fdh
        ret
        nop
    Fnc01FD ENDP

    Fnc01FE PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01feh
        ret
        nop
    Fnc01FE ENDP

    Fnc01FF PROC
        mov rax, SyscallExec
        push rax
        mov rax, 01ffh
        ret
        nop
    Fnc01FF ENDP


end
