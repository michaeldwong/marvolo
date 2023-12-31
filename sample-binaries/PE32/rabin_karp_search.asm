.686p
.XMM
.MODEL FLAT
ASSUME FS:NOTHING

INCLUDELIB KERNEL32.lib
INCLUDELIB msvcrt.lib

EXTERN __imp__DeleteCriticalSection:PROC
EXTERN _DeleteCriticalSection:PROC
EXTERN __imp__EnterCriticalSection:PROC
EXTERN _EnterCriticalSection:PROC
EXTERN __imp__GetCurrentProcess:PROC
EXTERN _GetCurrentProcess:PROC
EXTERN __imp__GetCurrentProcessId:PROC
EXTERN _GetCurrentProcessId:PROC
EXTERN __imp__GetCurrentThreadId:PROC
EXTERN _GetCurrentThreadId:PROC
EXTERN __imp__GetLastError:PROC
EXTERN _GetLastError:PROC
EXTERN __imp__GetStartupInfoA:PROC
EXTERN _GetStartupInfoA:PROC
EXTERN __imp__GetSystemTimeAsFileTime:PROC
EXTERN _GetSystemTimeAsFileTime:PROC
EXTERN __imp__GetTickCount:PROC
EXTERN _GetTickCount:PROC
EXTERN __imp__InitializeCriticalSection:PROC
EXTERN _InitializeCriticalSection:PROC
EXTERN __imp__LeaveCriticalSection:PROC
EXTERN _LeaveCriticalSection:PROC
EXTERN __imp__QueryPerformanceCounter:PROC
EXTERN _QueryPerformanceCounter:PROC
EXTERN __imp__SetUnhandledExceptionFilter:PROC
EXTERN _SetUnhandledExceptionFilter:PROC
EXTERN __imp__Sleep:PROC
EXTERN _Sleep:PROC
EXTERN __imp__TerminateProcess:PROC
EXTERN _TerminateProcess:PROC
EXTERN __imp__TlsGetValue:PROC
EXTERN _TlsGetValue:PROC
EXTERN __imp__UnhandledExceptionFilter:PROC
EXTERN _UnhandledExceptionFilter:PROC
EXTERN __imp__VirtualProtect:PROC
EXTERN _VirtualProtect:PROC
EXTERN __imp__VirtualQuery:PROC
EXTERN _VirtualQuery:PROC
EXTERN __imp____getmainargs:PROC
EXTERN ___getmainargs:PROC
EXTERN __imp____initenv:PROC
EXTERN ___initenv:PROC
EXTERN __imp____lconv_init:PROC
EXTERN ___lconv_init:PROC
EXTERN __imp____p__acmdln:PROC
EXTERN ___p__acmdln:PROC
EXTERN __imp____p__fmode:PROC
EXTERN ___p__fmode:PROC
EXTERN __imp____set_app_type:PROC
EXTERN ___set_app_type:PROC
EXTERN __imp____setusermatherr:PROC
EXTERN ___setusermatherr:PROC
EXTERN __imp___amsg_exit:PROC
EXTERN __amsg_exit:PROC
EXTERN __imp___cexit:PROC
EXTERN __cexit:PROC
EXTERN __imp___initterm:PROC
EXTERN __initterm:PROC
EXTERN __imp___iob:PROC
EXTERN __iob:PROC
EXTERN __imp___onexit:PROC
EXTERN __onexit:PROC
EXTERN __imp__abort:PROC
EXTERN _abort:PROC
EXTERN __imp__calloc:PROC
EXTERN _calloc:PROC
EXTERN __imp__exit:PROC
EXTERN _exit:PROC
EXTERN __imp__fprintf:PROC
EXTERN _fprintf:PROC
EXTERN __imp__free:PROC
EXTERN _free:PROC
EXTERN __imp__fwrite:PROC
EXTERN _fwrite:PROC
EXTERN __imp__malloc:PROC
EXTERN _malloc:PROC
EXTERN __imp__memcpy:PROC
EXTERN _memcpy:PROC
EXTERN __imp__printf:PROC
EXTERN _printf:PROC
EXTERN __imp__signal:PROC
EXTERN _signal:PROC
EXTERN __imp__strlen:PROC
EXTERN _strlen:PROC
EXTERN __imp__strncmp:PROC
EXTERN _strncmp:PROC
EXTERN __imp__vfprintf:PROC
EXTERN _vfprintf:PROC

EXTERN ___ImageBase:BYTE


;===================================
_TEXT    SEGMENT
;===================================

ALIGN 16
FUN_4198400:

            ret 

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
            nop
$L_401010:

            sub ESP,28
            xor EAX,EAX
            cmp WORD PTR [___ImageBase],23117
            mov DWORD PTR [$L_40538c],1
            mov DWORD PTR [$L_405388],1
            mov DWORD PTR [$L_405384],1
            mov DWORD PTR [$L_405028],1
            jne $L_401060

            mov EDX,DWORD PTR [___ImageBase+60]
            cmp DWORD PTR [EDX+___ImageBase],17744
            lea ECX,DWORD PTR [EDX+___ImageBase]
            je $L_4010b0
$L_401060:

            mov DWORD PTR [$L_40500c],EAX
            mov EAX,DWORD PTR [$L_405394]
            test EAX,EAX
            jne $L_4010a0

            mov DWORD PTR [ESP],1
            call FUN_4204716
$L_40107a:

            call FUN_4204724

            mov EDX,DWORD PTR [$L_4053a8]
            mov DWORD PTR [EAX],EDX
            call FUN_4200624

            cmp DWORD PTR [$L_403018],1
            je $L_4010e0

            xor EAX,EAX
            add ESP,28
            ret 

            lea ESI,DWORD PTR [ESI]
            nop
$L_4010a0:

            mov DWORD PTR [ESP],2
            call FUN_4204716

            jmp $L_40107a
          BYTE 066H
          BYTE 090H
$L_4010b0:

            movzx EDX,WORD PTR [ECX+24]
            cmp DX,267
            je $L_4010f8

            cmp DX,523
            jne $L_401060

            cmp DWORD PTR [ECX+132],14
            jbe $L_401060

            mov EDX,DWORD PTR [ECX+248]
            xor EAX,EAX
            test EDX,EDX
            setne AL
            jmp $L_401060

            lea ESI,DWORD PTR [ESI]
$L_4010e0:

            mov DWORD PTR [ESP],OFFSET $L_401b10
            call FUN_4202528

            xor EAX,EAX
            add ESP,28
            ret 

            lea ESI,DWORD PTR [ESI]
$L_4010f8:

            cmp DWORD PTR [ECX+116],14
            jbe $L_401060

            mov ECX,DWORD PTR [ECX+232]
            xor EAX,EAX
            test ECX,ECX
            setne AL
            jmp $L_401060

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
            nop
$L_401120:

            sub ESP,44
            mov EAX,DWORD PTR [$L_405380]
            mov DWORD PTR [ESP+16],OFFSET $L_405004
            mov DWORD PTR [$L_405004],EAX
            mov EAX,DWORD PTR [$L_405024]
            mov DWORD PTR [ESP+8],OFFSET $L_405014
            mov DWORD PTR [ESP+12],EAX
            mov DWORD PTR [ESP+4],OFFSET $L_405018
            mov DWORD PTR [ESP],OFFSET $L_40501c
            call FUN_4204740

            add ESP,44
            ret 
          BYTE 066H
          BYTE 090H
$L_401160:

            lea ECX,DWORD PTR [ESP+4]
            and ESP,4294967280
            xor EAX,EAX
            push DWORD PTR [ECX-4]
            push EBP
            mov EBP,ESP
            push EDI
            push ESI
            lea EDX,DWORD PTR [EBP-92]
            push EBX
            mov EDI,EDX
            push ECX
            mov ECX,17
            sub ESP,120
            mov ESI,DWORD PTR [$L_405394]

            rep stosd DWORD PTR ES:[EDI]

            test ESI,ESI
            jne $L_401430
$L_401190:

            mov EAX,DWORD PTR FS:[24]
            mov ESI,DWORD PTR __imp__Sleep
            mov EDI,DWORD PTR [EAX+4]
            xor EBX,EBX
            jmp $L_4011bc

            lea ESI,DWORD PTR [ESI]
            nop
$L_4011a8:

            cmp EDI,EAX
            je $L_4013c8

            mov DWORD PTR [ESP],1000
            call ESI

            sub ESP,4
$L_4011bc:

            mov EAX,EBX
            lock cmpxchg DWORD PTR [$L_4053e0],EDI
            test EAX,EAX
            jne $L_4011a8

            mov EAX,DWORD PTR [$L_4053e4]
            xor EBX,EBX
            cmp EAX,1
            je $L_4013db
$L_4011da:

            mov EAX,DWORD PTR [$L_4053e4]
            test EAX,EAX
            je $L_401460

            mov DWORD PTR [$L_405008],1
$L_4011f1:

            mov EAX,DWORD PTR [$L_4053e4]
            cmp EAX,1
            je $L_4013f5
$L_4011ff:

            test EBX,EBX
            je $L_40141b
$L_401207:

            mov EAX,DWORD PTR [$L_404084]
            test EAX,EAX
            je $L_40122c

            mov DWORD PTR [ESP+8],0
            mov DWORD PTR [ESP+4],2
            mov DWORD PTR [ESP],0
            call EAX

            sub ESP,12
$L_40122c:

            call FUN_4201792

            mov DWORD PTR [ESP],OFFSET $L_402030
            call DWORD PTR __imp__SetUnhandledExceptionFilter

            sub ESP,4
            mov DWORD PTR [$L_4053ac],EAX
            mov DWORD PTR [ESP],OFFSET FUN_4198400
            call FUN_4204784

            call FUN_4201360

            mov DWORD PTR [$L_4053dc],4194304
            call FUN_4204732

            xor ECX,ECX
            mov EAX,DWORD PTR [EAX]
            test EAX,EAX
            jne $L_401281

            jmp $L_4012bd
$L_401270:

            test DL,DL
            je $L_4012b8

            and ECX,1
            je $L_4012a0

            mov ECX,1
$L_40127e:

            add EAX,1
$L_401281:

            movzx EDX,BYTE PTR [EAX]
            cmp DL,32
            jle $L_401270

            mov EBX,ECX
            xor EBX,1
            cmp DL,34
            cmove ECX,EBX
            jmp $L_40127e

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
$L_4012a0:

            test DL,DL
            je $L_4012b8

            lea ESI,DWORD PTR [ESI]
$L_4012a8:

            movzx EDX,BYTE PTR [EAX+1]
            add EAX,1
            test DL,DL
            je $L_4012b8

            cmp DL,32
            jle $L_4012a8
$L_4012b8:

            mov DWORD PTR [$L_4053d8],EAX
$L_4012bd:

            mov EBX,DWORD PTR [$L_405394]
            test EBX,EBX
            je $L_4012db

            mov EAX,10
            test BYTE PTR [EBP-48],1
            jne $L_4013b8
$L_4012d6:

            mov DWORD PTR [$L_403000],EAX
$L_4012db:

            mov EBX,DWORD PTR [$L_40501c]
            lea ESI,DWORD PTR [EBX*4+4]
            mov DWORD PTR [ESP],ESI
            call FUN_4204620

            mov EDX,DWORD PTR [$L_405018]
            mov DWORD PTR [EBP-112],EAX
            test EBX,EBX
            jle $L_401483

            mov EBX,EAX
            lea EAX,DWORD PTR [ESI-4]
            mov EDI,EDX
            mov DWORD PTR [EBP-116],EAX
            add EAX,EDX
            mov DWORD PTR [EBP-108],EAX
$L_401310:

            mov EAX,DWORD PTR [EDI]
            add EBX,4
            add EDI,4
            mov DWORD PTR [ESP],EAX
            call FUN_4204588

            lea ESI,DWORD PTR [EAX+1]
            mov DWORD PTR [ESP],ESI
            call FUN_4204620

            mov DWORD PTR [EBX-4],EAX
            mov ECX,DWORD PTR [EDI-4]
            mov DWORD PTR [ESP+8],ESI
            mov DWORD PTR [ESP+4],ECX
            mov DWORD PTR [ESP],EAX
            call FUN_4204612

            cmp DWORD PTR [EBP-108],EDI
            jne $L_401310

            mov EAX,DWORD PTR [EBP-116]
            add EAX,DWORD PTR [EBP-112]
$L_40134c:

            mov DWORD PTR [EAX],0
            mov EAX,DWORD PTR [EBP-112]
            mov DWORD PTR [$L_405018],EAX
            call FUN_4200576

            mov EAX,DWORD PTR [$L_405014]
            mov EDX,DWORD PTR __imp____initenv
            mov DWORD PTR [EDX],EAX
            mov DWORD PTR [ESP+8],EAX
            mov EAX,DWORD PTR [$L_405018]
            mov DWORD PTR [ESP+4],EAX
            mov EAX,DWORD PTR [$L_40501c]
            mov DWORD PTR [ESP],EAX
            call FUN_4200106

            mov ECX,DWORD PTR [$L_40500c]
            mov DWORD PTR [$L_405010],EAX
            test ECX,ECX
            je $L_40148b

            mov EDX,DWORD PTR [$L_405008]
            test EDX,EDX
            je $L_401448

            lea ESP,DWORD PTR [EBP-16]
            pop ECX
            pop EBX
            pop ESI
            pop EDI
            pop EBP
            lea ESP,DWORD PTR [ECX-4]
            ret 

            lea ESI,DWORD PTR [ESI]
            nop
$L_4013b8:

            movzx EAX,WORD PTR [EBP-44]
            jmp $L_4012d6

            lea ESI,DWORD PTR [ESI]
$L_4013c8:

            mov EAX,DWORD PTR [$L_4053e4]
            mov EBX,1
            cmp EAX,1
            jne $L_4011da
$L_4013db:

            mov DWORD PTR [ESP],31
            call FUN_4204700

            mov EAX,DWORD PTR [$L_4053e4]
            cmp EAX,1
            jne $L_4011ff
$L_4013f5:

            mov DWORD PTR [ESP+4],OFFSET $L_407008
            mov DWORD PTR [ESP],OFFSET $L_407000
            call FUN_4204684

            mov DWORD PTR [$L_4053e4],2
            test EBX,EBX
            jne $L_401207
$L_40141b:

            xchg DWORD PTR [$L_4053e0],EBX
            jmp $L_401207

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
$L_401430:

            mov DWORD PTR [ESP],EDX
            call DWORD PTR __imp__GetStartupInfoA

            sub ESP,4
            jmp $L_401190

            lea ESI,DWORD PTR [ESI]
$L_401448:

            call FUN_4204692

            mov EAX,DWORD PTR [$L_405010]
            lea ESP,DWORD PTR [EBP-16]
            pop ECX
            pop EBX
            pop ESI
            pop EDI
            pop EBP
            lea ESP,DWORD PTR [ECX-4]
            ret 
          BYTE 066H
          BYTE 090H
$L_401460:

            mov DWORD PTR [ESP+4],OFFSET $L_407018
            mov DWORD PTR [ESP],OFFSET $L_40700c
            mov DWORD PTR [$L_4053e4],1
            call FUN_4204684

            jmp $L_4011f1
$L_401483:

            mov EAX,DWORD PTR [EBP-112]
            jmp $L_40134c
$L_40148b:

            mov DWORD PTR [ESP],EAX
            call FUN_4204652

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
            sub ESP,12
            mov DWORD PTR [$L_405394],1
            call FUN_4200640

            add ESP,12
            jmp $L_401160

            lea ESI,DWORD PTR [ESI]
FUN_4199616:
__EntryPoint PROC EXPORT
__EntryPoint ENDP

            sub ESP,12
            mov DWORD PTR [$L_405394],0
            call FUN_4200640

            add ESP,12
            jmp $L_401160

            lea ESI,DWORD PTR [ESI]
FUN_4199648:

            sub ESP,28
            mov EAX,DWORD PTR [ESP+32]
            mov DWORD PTR [ESP],EAX
            call FUN_4204676

            test EAX,EAX
            sete AL
            add ESP,28
            movzx EAX,AL
            neg EAX
            ret 
          BYTE 090H
          BYTE 090H
          BYTE 090H
$L_401500:

            push EBP
            mov EBP,ESP
            sub ESP,24
            mov DWORD PTR [ESP],OFFSET $L_401520
            call FUN_4199648

            leave 
            ret 

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
            nop
$L_401520:

            ret 
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
FUN_4199728:

            push EBP
            mov EBP,ESP
            sub ESP,56
            mov EAX,DWORD PTR [EBP+8]
            mov DWORD PTR [ESP],EAX
            call FUN_4204588

            mov DWORD PTR [EBP-32],EAX
            mov EAX,DWORD PTR [EBP+12]
            mov DWORD PTR [ESP],EAX
            call FUN_4204588

            mov DWORD PTR [EBP-36],EAX
            mov DWORD PTR [EBP-16],1
            mov DWORD PTR [EBP-20],0
            mov DWORD PTR [EBP-24],0
            mov DWORD PTR [EBP-12],0
            jmp $L_401582
$L_401570:

            mov EAX,DWORD PTR [EBP+16]
            imul EAX,DWORD PTR [EBP-16]
            cdq 
            idiv DWORD PTR [EBP+20]
            mov DWORD PTR [EBP-16],EDX
            add DWORD PTR [EBP-12],1
$L_401582:

            mov EAX,DWORD PTR [EBP-36]
            sub EAX,1
            cmp DWORD PTR [EBP-12],EAX
            jl $L_401570

            mov DWORD PTR [EBP-12],0
            jmp $L_4015da
$L_401596:

            mov EAX,DWORD PTR [EBP+16]
            imul EAX,DWORD PTR [EBP-24]
            mov EDX,EAX
            mov ECX,DWORD PTR [EBP-12]
            mov EAX,DWORD PTR [EBP+12]
            add EAX,ECX
            movzx EAX,BYTE PTR [EAX]
            movsx EAX,AL
            add EAX,EDX
            cdq 
            idiv DWORD PTR [EBP+20]
            mov DWORD PTR [EBP-24],EDX
            mov EAX,DWORD PTR [EBP+16]
            imul EAX,DWORD PTR [EBP-20]
            mov EDX,EAX
            mov ECX,DWORD PTR [EBP-12]
            mov EAX,DWORD PTR [EBP+8]
            add EAX,ECX
            movzx EAX,BYTE PTR [EAX]
            movsx EAX,AL
            add EAX,EDX
            cdq 
            idiv DWORD PTR [EBP+20]
            mov DWORD PTR [EBP-20],EDX
            add DWORD PTR [EBP-12],1
$L_4015da:

            mov EAX,DWORD PTR [EBP-12]
            cmp EAX,DWORD PTR [EBP-36]
            jl $L_401596

            mov DWORD PTR [EBP-12],0
            jmp $L_401697
$L_4015ee:

            mov EAX,DWORD PTR [EBP-24]
            cmp EAX,DWORD PTR [EBP-20]
            jne $L_40164a

            mov DWORD PTR [EBP-28],0
            jmp $L_401624
$L_4015ff:

            mov EDX,DWORD PTR [EBP-28]
            mov EAX,DWORD PTR [EBP+12]
            add EAX,EDX
            movzx EDX,BYTE PTR [EAX]
            mov ECX,DWORD PTR [EBP-12]
            mov EAX,DWORD PTR [EBP-28]
            add EAX,ECX
            mov ECX,EAX
            mov EAX,DWORD PTR [EBP+8]
            add EAX,ECX
            movzx EAX,BYTE PTR [EAX]
            cmp DL,AL
            jne $L_40162e

            add DWORD PTR [EBP-28],1
$L_401624:

            mov EAX,DWORD PTR [EBP-28]
            cmp EAX,DWORD PTR [EBP-36]
            jl $L_4015ff

            jmp $L_40162f
$L_40162e:

            nop
$L_40162f:

            mov EAX,DWORD PTR [EBP-36]
            cmp EAX,DWORD PTR [EBP-28]
            jne $L_40164a

            mov EAX,DWORD PTR [EBP-12]
            mov DWORD PTR [ESP+4],EAX
            mov DWORD PTR [ESP],OFFSET $L_404000
            call FUN_4204604
$L_40164a:

            mov EDX,DWORD PTR [EBP-12]
            mov EAX,DWORD PTR [EBP+8]
            add EAX,EDX
            movzx EAX,BYTE PTR [EAX]
            movsx EAX,AL
            imul EAX,DWORD PTR [EBP-16]
            mov EDX,DWORD PTR [EBP-20]
            sub EDX,EAX
            mov EAX,EDX
            imul EAX,DWORD PTR [EBP+16]
            mov EDX,EAX
            mov ECX,DWORD PTR [EBP-12]
            mov EAX,DWORD PTR [EBP-36]
            add EAX,ECX
            mov ECX,EAX
            mov EAX,DWORD PTR [EBP+8]
            add EAX,ECX
            movzx EAX,BYTE PTR [EAX]
            movsx EAX,AL
            add EAX,EDX
            cdq 
            idiv DWORD PTR [EBP+20]
            mov DWORD PTR [EBP-20],EDX
            cmp DWORD PTR [EBP-20],0
            jns $L_401693

            mov EAX,DWORD PTR [EBP+20]
            add DWORD PTR [EBP-20],EAX
$L_401693:

            add DWORD PTR [EBP-12],1
$L_401697:

            mov EAX,DWORD PTR [EBP-32]
            sub EAX,DWORD PTR [EBP-36]
            cmp DWORD PTR [EBP-12],EAX
            jle $L_4015ee

            nop
            nop
            leave 
            ret 
FUN_4200106:

            push EBP
            mov EBP,ESP
            and ESP,4294967280
            sub ESP,64
            call FUN_4200576

            mov DWORD PTR [ESP+38],1128415553
            mov DWORD PTR [ESP+42],842089025
            mov DWORD PTR [ESP+46],1094796865
            mov DWORD PTR [ESP+50],1111573314
            mov DWORD PTR [ESP+54],1195722310
            mov DWORD PTR [ESP+58],1094926913
            mov WORD PTR [ESP+62],66
            mov DWORD PTR [ESP+32],1094926913
            mov WORD PTR [ESP+36],66
            mov DWORD PTR [ESP+28],4605510
            mov DWORD PTR [ESP+24],4342083
            lea EAX,DWORD PTR [ESP+38]
            mov DWORD PTR [ESP+4],EAX
            mov DWORD PTR [ESP],OFFSET $L_40401b
            call FUN_4204604

            lea EAX,DWORD PTR [ESP+32]
            mov DWORD PTR [ESP+4],EAX
            mov DWORD PTR [ESP],OFFSET $L_40402c
            call FUN_4204604

            mov DWORD PTR [ESP+12],29
            mov DWORD PTR [ESP+8],256
            lea EAX,DWORD PTR [ESP+32]
            mov DWORD PTR [ESP+4],EAX
            lea EAX,DWORD PTR [ESP+38]
            mov DWORD PTR [ESP],EAX
            call FUN_4199728

            lea EAX,DWORD PTR [ESP+28]
            mov DWORD PTR [ESP+4],EAX
            mov DWORD PTR [ESP],OFFSET $L_404046
            call FUN_4204604

            mov DWORD PTR [ESP+12],29
            mov DWORD PTR [ESP+8],256
            lea EAX,DWORD PTR [ESP+28]
            mov DWORD PTR [ESP+4],EAX
            lea EAX,DWORD PTR [ESP+38]
            mov DWORD PTR [ESP],EAX
            call FUN_4199728

            lea EAX,DWORD PTR [ESP+24]
            mov DWORD PTR [ESP+4],EAX
            mov DWORD PTR [ESP],OFFSET $L_404060
            call FUN_4204604

            mov DWORD PTR [ESP+12],29
            mov DWORD PTR [ESP+8],256
            lea EAX,DWORD PTR [ESP+24]
            mov DWORD PTR [ESP+4],EAX
            lea EAX,DWORD PTR [ESP+38]
            mov DWORD PTR [ESP],EAX
            call FUN_4199728

            mov EAX,0
            leave 
            ret 
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 066H
          BYTE 090H
          BYTE 066H
          BYTE 090H
          BYTE 066H
          BYTE 090H
          BYTE 066H
          BYTE 090H
          BYTE 066H
          BYTE 090H
          BYTE 066H
          BYTE 090H
$L_4017e0:

            mov EAX,DWORD PTR [$L_403004]
            mov EAX,DWORD PTR [EAX]
            test EAX,EAX
            je $L_401810

            sub ESP,12
            nop
            nop
$L_4017f0:

            call EAX

            mov EAX,DWORD PTR [$L_403004]
            lea EDX,DWORD PTR [EAX+4]
            mov EAX,DWORD PTR [EAX+4]
            mov DWORD PTR [$L_403004],EDX
            test EAX,EAX
            jne $L_4017f0

            add ESP,12
            ret 

            lea ESI,DWORD PTR [ESI]
            nop
$L_401810:

            ret 

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
            nop
$L_401820:

            push EBX
            sub ESP,24
            mov EBX,DWORD PTR [$L_402910]
            cmp EBX,-1
            je $L_401858
$L_40182f:

            test EBX,EBX
            je $L_401844

            lea ESI,DWORD PTR [ESI]
            nop
$L_401838:

            call DWORD PTR [EBX*4+$L_402910]

            sub EBX,1
            jne $L_401838
$L_401844:

            mov DWORD PTR [ESP],OFFSET $L_4017e0
            call FUN_4199648

            add ESP,24
            pop EBX
            ret 

            lea ESI,DWORD PTR [ESI]
$L_401858:

            xor EAX,EAX
            lea ESI,DWORD PTR [ESI]
$L_401860:

            mov EBX,EAX
            add EAX,1
            mov EDX,DWORD PTR [EAX*4+$L_402910]
            test EDX,EDX
            jne $L_401860

            jmp $L_40182f

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
FUN_4200576:

            mov EAX,DWORD PTR [$L_405020]
            test EAX,EAX
            je $L_401890

            ret 

            lea ESI,DWORD PTR [ESI]
$L_401890:

            mov DWORD PTR [$L_405020],1
            jmp $L_401820
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
$L_4018a0:

            jmp DWORD PTR __imp____lconv_init
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
FUN_4200624:

            xor EAX,EAX
            ret 
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
FUN_4200640:

            push EBP
            push EDI
            push ESI
            push EBX
            sub ESP,44
            mov EAX,DWORD PTR [$L_403028]
            mov DWORD PTR [ESP+16],0
            mov DWORD PTR [ESP+20],0
            cmp EAX,3141592654
            je $L_4018f8

            not EAX
            mov DWORD PTR [$L_40302c],EAX
            add ESP,44
            pop EBX
            pop ESI
            pop EDI
            pop EBP
            ret 

            lea ESI,DWORD PTR [ESI]
$L_4018f8:

            lea EAX,DWORD PTR [ESP+16]
            mov DWORD PTR [ESP],EAX
            call DWORD PTR __imp__GetSystemTimeAsFileTime

            sub ESP,4
            mov EBX,DWORD PTR [ESP+16]
            xor EBX,DWORD PTR [ESP+20]
            call DWORD PTR __imp__GetCurrentProcessId

            mov EBP,EAX
            call DWORD PTR __imp__GetCurrentThreadId

            mov EDI,EAX
            call DWORD PTR __imp__GetTickCount

            mov ESI,EAX
            lea EAX,DWORD PTR [ESP+24]
            mov DWORD PTR [ESP],EAX
            call DWORD PTR __imp__QueryPerformanceCounter

            sub ESP,4
            mov EAX,DWORD PTR [ESP+24]
            xor EAX,EBX
            xor EAX,DWORD PTR [ESP+28]
            xor EAX,EBP
            xor EAX,EDI
            xor EAX,ESI
            cmp EAX,3141592654
            je $L_401970

            mov EDX,EAX
            not EDX
$L_401953:

            mov DWORD PTR [$L_403028],EAX
            mov DWORD PTR [$L_40302c],EDX
            add ESP,44
            pop EBX
            pop ESI
            pop EDI
            pop EBP
            ret 

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
$L_401970:

            mov EDX,1153374640
            mov EAX,3141592655
            jmp $L_401953

            lea ESI,DWORD PTR [ESI]
            push EBP
            mov EBP,ESP
            sub ESP,40
            mov DWORD PTR [$L_405320],3221226505
            mov EAX,DWORD PTR [EBP+4]
            lea EDX,DWORD PTR [EBP+4]
            mov DWORD PTR [$L_405324],1
            mov DWORD PTR [$L_405104],EDX
            mov DWORD PTR [$L_4050f8],EAX
            mov DWORD PTR [$L_40532c],EAX
            mov EAX,DWORD PTR [EBP+8]
            mov DWORD PTR [ESP],0
            mov DWORD PTR [$L_4050ec],EAX
            mov EAX,DWORD PTR [$L_403028]
            mov DWORD PTR [EBP-16],EAX
            mov EAX,DWORD PTR [$L_40302c]
            mov DWORD PTR [EBP-12],EAX
            call DWORD PTR __imp__SetUnhandledExceptionFilter

            sub ESP,4
            mov DWORD PTR [ESP],OFFSET $L_40407c
            call DWORD PTR __imp__UnhandledExceptionFilter

            sub ESP,4
            call DWORD PTR __imp__GetCurrentProcess

            mov DWORD PTR [ESP+4],3221226505
            mov DWORD PTR [ESP],EAX
            call DWORD PTR __imp__TerminateProcess

            sub ESP,8
            call FUN_4204668

            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
$L_401a10:

            sub ESP,28
            mov EAX,DWORD PTR [ESP+36]
            cmp EAX,3
            je $L_401a30

            test EAX,EAX
            je $L_401a30

            mov EAX,1
            add ESP,28
            ret 12

            lea ESI,DWORD PTR [ESI]
            nop
$L_401a30:

            mov DWORD PTR [ESP+4],EAX
            mov EDX,DWORD PTR [ESP+40]
            mov EAX,DWORD PTR [ESP+32]
            mov DWORD PTR [ESP+8],EDX
            mov DWORD PTR [ESP],EAX
            call FUN_4203360

            mov EAX,1
            add ESP,28
            ret 12

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
$L_401a60:

            push ESI
            push EBX
            sub ESP,20
            cmp DWORD PTR [$L_403014],2
            mov EAX,DWORD PTR [ESP+36]
            je $L_401a7c

            mov DWORD PTR [$L_403014],2
$L_401a7c:

            cmp EAX,2
            je $L_401a98

            cmp EAX,1
            je $L_401ad0
$L_401a86:

            add ESP,20
            mov EAX,1
            pop EBX
            pop ESI
            ret 12

            lea ESI,DWORD PTR [ESI]
            nop
$L_401a98:

            mov EBX,OFFSET $L_407030
            mov ESI,OFFSET $L_407030
            cmp ESI,EBX
            je $L_401a86

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
$L_401ab0:

            mov EAX,DWORD PTR [EBX]
            test EAX,EAX
            je $L_401ab8

            call EAX
$L_401ab8:

            add EBX,4
            cmp ESI,EBX
            jne $L_401ab0

            add ESP,20
            mov EAX,1
            pop EBX
            pop ESI
            ret 12

            lea ESI,DWORD PTR [ESI]
$L_401ad0:

            mov EAX,DWORD PTR [ESP+40]
            mov DWORD PTR [ESP+4],1
            mov DWORD PTR [ESP+8],EAX
            mov EAX,DWORD PTR [ESP+32]
            mov DWORD PTR [ESP],EAX
            call FUN_4203360

            add ESP,20
            mov EAX,1
            pop EBX
            pop ESI
            ret 12

            lea ESI,DWORD PTR [ESI]
            xor EAX,EAX
            ret 
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
$L_401b10:

            push ESI
            push EBX
            mov EBX,OFFSET $L_4040a0
            sub ESP,84
            mov EAX,DWORD PTR [ESP+96]
            mov ECX,DWORD PTR [EAX]
            lea EDX,DWORD PTR [ECX-1]
            cmp EDX,5
            ja $L_401b2f

            mov EBX,DWORD PTR [EDX*4+$L_4041bc]
$L_401b2f:

            fld QWORD PTR [EAX+24]
            mov ESI,DWORD PTR [EAX+4]
            fstp QWORD PTR [ESP+72]
            fld QWORD PTR [EAX+16]
            fstp QWORD PTR [ESP+64]
            fld QWORD PTR [EAX+8]
            mov DWORD PTR [ESP],2
            fstp QWORD PTR [ESP+56]
            call FUN_4204752

            fld QWORD PTR [ESP+72]
            mov DWORD PTR [ESP+12],ESI
            mov DWORD PTR [ESP+8],EBX
            mov DWORD PTR [ESP+4],OFFSET $L_4040b0
            fstp QWORD PTR [ESP+32]
            fld QWORD PTR [ESP+64]
            mov DWORD PTR [ESP],EAX
            fstp QWORD PTR [ESP+24]
            fld QWORD PTR [ESP+56]
            fstp QWORD PTR [ESP+16]
            call FUN_4204644

            add ESP,84
            xor EAX,EAX
            pop EBX
            pop ESI
            ret 
          BYTE 090H
          BYTE 090H

            nop
            nop
            nop
FUN_4201360:

            fninit 
            ret 
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
FUN_4201376:

            push EBX
            sub ESP,24
            mov DWORD PTR [ESP],2
            lea EBX,DWORD PTR [ESP+36]
            call FUN_4204752

            mov DWORD PTR [ESP+8],27
            mov DWORD PTR [ESP+12],EAX
            mov DWORD PTR [ESP+4],1
            mov DWORD PTR [ESP],OFFSET $L_4041d4
            call FUN_4204628

            mov DWORD PTR [ESP],2
            call FUN_4204752

            mov EDX,DWORD PTR [ESP+32]
            mov DWORD PTR [ESP+8],EBX
            mov DWORD PTR [ESP],EAX
            mov DWORD PTR [ESP+4],EDX
            call FUN_4204572

            call FUN_4204668

            lea ESI,DWORD PTR [ESI]
FUN_4201472:

            push EDI
            push ESI
            push EBX
            mov EBX,EAX
            sub ESP,48
            mov ESI,DWORD PTR [$L_40539c]
            test ESI,ESI
            jle $L_401d00

            mov EAX,DWORD PTR [$L_4053a0]
            xor ECX,ECX
            add EAX,12
$L_401c20:

            mov EDX,DWORD PTR [EAX]
            cmp EDX,EBX
            ja $L_401c30

            mov EDI,DWORD PTR [EAX+4]
            add EDX,DWORD PTR [EDI+8]
            cmp EBX,EDX
            jb $L_401caf
$L_401c30:

            add ECX,1
            add EAX,20
            cmp ECX,ESI
            jne $L_401c20
$L_401c3a:

            mov DWORD PTR [ESP],EBX
            call FUN_4203888

            mov EDI,EAX
            test EAX,EAX
            je $L_401d27

            mov EAX,DWORD PTR [$L_4053a0]
            lea EBX,DWORD PTR [ESI+ESI*4]
            shl EBX,2
            add EAX,EBX
            mov DWORD PTR [EAX+16],EDI
            mov DWORD PTR [EAX],0
            call FUN_4204160

            mov EDX,DWORD PTR [$L_4053a0]
            add EAX,DWORD PTR [EDI+12]
            mov DWORD PTR [EDX+EBX*1+12],EAX
            lea EDX,DWORD PTR [ESP+20]
            mov DWORD PTR [ESP+8],28
            mov DWORD PTR [ESP+4],EDX
            mov DWORD PTR [ESP],EAX
            call DWORD PTR __imp__VirtualQuery

            sub ESP,12
            test EAX,EAX
            je $L_401d07

            mov EAX,DWORD PTR [ESP+40]
            lea EDX,DWORD PTR [EAX-64]
            and EDX,4294967231
            je $L_401ca8

            sub EAX,4
            and EAX,4294967291
            jne $L_401cb6
$L_401ca8:

            add DWORD PTR [$L_40539c],1
$L_401caf:

            add ESP,48
            pop EBX
            pop ESI
            pop EDI
            ret 
$L_401cb6:

            mov EAX,DWORD PTR [ESP+20]
            mov EDX,DWORD PTR [ESP+32]
            add EBX,DWORD PTR [$L_4053a0]
            mov DWORD PTR [EBX+4],EAX
            mov DWORD PTR [EBX+8],EDX
            mov DWORD PTR [ESP+12],EBX
            mov DWORD PTR [ESP+8],64
            mov DWORD PTR [ESP+4],EDX
            mov DWORD PTR [ESP],EAX
            call DWORD PTR __imp__VirtualProtect

            sub ESP,16
            test EAX,EAX
            jne $L_401ca8

            call DWORD PTR __imp__GetLastError

            mov DWORD PTR [ESP],OFFSET $L_404244
            mov DWORD PTR [ESP+4],EAX
            call FUN_4201376
$L_401d00:

            xor ESI,ESI
            jmp $L_401c3a
$L_401d07:

            mov EAX,DWORD PTR [$L_4053a0]
            mov EAX,DWORD PTR [EAX+EBX*1+12]
            mov DWORD PTR [ESP+8],EAX
            mov EAX,DWORD PTR [EDI+8]
            mov DWORD PTR [ESP],OFFSET $L_404210
            mov DWORD PTR [ESP+4],EAX
            call FUN_4201376
$L_401d27:

            mov DWORD PTR [ESP+4],EBX
            mov DWORD PTR [ESP],OFFSET $L_4041f0
            call FUN_4201376

            lea ESI,DWORD PTR [ESI]
            nop
            nop
FUN_4201792:

            push EBP
            mov EBP,ESP
            push EDI
            push ESI
            push EBX
            sub ESP,60
            mov EAX,DWORD PTR [$L_405398]
            mov DWORD PTR [EBP-52],EAX
            test EAX,EAX
            je $L_401d60
$L_401d55:

            lea ESP,DWORD PTR [EBP-12]
            pop EBX
            pop ESI
            pop EDI
            pop EBP
            ret 

            lea ESI,DWORD PTR [ESI]
$L_401d60:

            mov DWORD PTR [$L_405398],1
            call FUN_4204016

            lea EAX,DWORD PTR [EAX+EAX*4]
            lea EAX,DWORD PTR [EAX*4+27]
            shr EAX,4
            shl EAX,4
            call FUN_4204528

            mov DWORD PTR [$L_40539c],0
            sub ESP,EAX
            lea EAX,DWORD PTR [ESP+31]
            and EAX,4294967280
            mov DWORD PTR [$L_4053a0],EAX
            mov EAX,OFFSET $L_40464c
            sub EAX,OFFSET $L_40464c
            cmp EAX,7
            jle $L_401d55

            mov EDX,DWORD PTR [$L_40464c]
            cmp EAX,11
            jg $L_401e50

            mov EBX,OFFSET $L_40464c
$L_401dbf:

            test EDX,EDX
            jne $L_401f55

            mov EAX,DWORD PTR [EBX+4]
$L_401dca:

            test EAX,EAX
            jne $L_401f55

            mov EAX,DWORD PTR [EBX+8]
            cmp EAX,1
            jne $L_401fa2

            lea EDI,DWORD PTR [EBX+12]
            cmp EDI,OFFSET $L_40464c
            jb $L_401e0f

            jmp $L_401d55
          BYTE 066H
          BYTE 090H
$L_401df0:

            sub EAX,DWORD PTR [EBP-44]
            add EAX,DWORD PTR [EBX]
            mov ESI,EAX
            mov EAX,EBX
            call FUN_4201472

            mov DWORD PTR [EBX],ESI
$L_401e00:

            add EDI,12
            cmp EDI,OFFSET $L_40464c
            jae $L_401ec0
$L_401e0f:

            mov EAX,DWORD PTR [EDI]
            mov ECX,DWORD PTR [EDI+4]
            movzx EDX,BYTE PTR [EDI+8]
            lea ESI,DWORD PTR [EAX+___ImageBase]
            lea EBX,DWORD PTR [ECX+___ImageBase]
            mov EAX,DWORD PTR [EAX+___ImageBase]
            mov DWORD PTR [EBP-44],ESI
            cmp EDX,16
            je $L_401e80

            cmp EDX,32
            je $L_401df0

            cmp EDX,8
            je $L_401f20

            mov DWORD PTR [ESP+4],EDX
            mov DWORD PTR [ESP],OFFSET $L_4042a0
            call FUN_4201376
$L_401e50:

            test EDX,EDX
            jne $L_401f50

            mov EAX,DWORD PTR [4212304]
            mov EDI,EAX
            or EDI,DWORD PTR [4212308]
            jne $L_401f98

            mov EDX,DWORD PTR [4212312]
            mov EBX,4212312
            jmp $L_401dbf

            lea ESI,DWORD PTR [ESI]
            nop
$L_401e80:

            movzx ESI,WORD PTR [ECX+___ImageBase]
            mov DWORD PTR [EBP-48],ECX
            mov ECX,ESI
            or ECX,4294901760
            test SI,SI
            cmovs ESI,ECX
            sub ESI,DWORD PTR [EBP-44]
            add EDI,12
            add ESI,EAX
            mov EAX,EBX
            call FUN_4201472

            mov ECX,DWORD PTR [EBP-48]
            mov WORD PTR [ECX+___ImageBase],SI
            cmp EDI,OFFSET $L_40464c
            jb $L_401e0f

            lea ESI,DWORD PTR [ESI]
$L_401ec0:

            mov EAX,DWORD PTR [$L_40539c]
            test EAX,EAX
            jle $L_401d55

            mov EBX,DWORD PTR __imp__VirtualProtect
            mov EDI,DWORD PTR [EBP-52]
            lea ESI,DWORD PTR [EBP-28]
            lea ESI,DWORD PTR [ESI]
$L_401ee0:

            mov EDX,DWORD PTR [$L_4053a0]
            lea EAX,DWORD PTR [EDI+EDI*4]
            lea EAX,DWORD PTR [EDX+EAX*4]
            mov EDX,DWORD PTR [EAX]
            test EDX,EDX
            je $L_401f0c

            mov DWORD PTR [ESP+12],ESI
            mov DWORD PTR [ESP+8],EDX
            mov EDX,DWORD PTR [EAX+8]
            mov DWORD PTR [ESP+4],EDX
            mov EAX,DWORD PTR [EAX+4]
            mov DWORD PTR [ESP],EAX
            call EBX

            sub ESP,16
$L_401f0c:

            add EDI,1
            cmp EDI,DWORD PTR [$L_40539c]
            jl $L_401ee0

            lea ESP,DWORD PTR [EBP-12]
            pop EBX
            pop ESI
            pop EDI
            pop EBP
            ret 
          BYTE 090H
$L_401f20:

            movzx EDX,BYTE PTR [EBX]
            mov ESI,EDX
            or ESI,4294967040
            test DL,DL
            cmovs EDX,ESI
            sub EDX,DWORD PTR [EBP-44]
            lea ESI,DWORD PTR [EDX+EAX*1]
            mov EAX,EBX
            call FUN_4201472

            mov EAX,ESI
            mov BYTE PTR [EBX],AL
            jmp $L_401e00

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
$L_401f50:

            mov EBX,OFFSET $L_40464c
$L_401f55:

            cmp EBX,OFFSET $L_40464c
            jae $L_401d55

            lea ESI,DWORD PTR [ESI]
$L_401f68:

            mov ESI,DWORD PTR [EBX+4]
            mov EDI,DWORD PTR [EBX]
            add EBX,8
            add EDI,DWORD PTR [ESI+___ImageBase]
            lea EAX,DWORD PTR [ESI+___ImageBase]
            call FUN_4201472

            mov DWORD PTR [ESI+___ImageBase],EDI
            cmp EBX,OFFSET $L_40464c
            jb $L_401f68

            jmp $L_401ec0

            lea ESI,DWORD PTR [ESI]
$L_401f98:

            mov EBX,OFFSET $L_40464c
            jmp $L_401dca
$L_401fa2:

            mov DWORD PTR [ESP+4],EAX
            mov DWORD PTR [ESP],OFFSET $L_40426c
            call FUN_4201376

            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            sub ESP,60
            mov EAX,DWORD PTR [$L_4053a4]
            fld QWORD PTR [ESP+72]
            fld QWORD PTR [ESP+80]
            fld QWORD PTR [ESP+88]
            test EAX,EAX
            je $L_402008

            fxch ST(2)
            mov EDX,DWORD PTR [ESP+64]
            fstp QWORD PTR [ESP+24]
            fstp QWORD PTR [ESP+32]
            mov DWORD PTR [ESP+16],EDX
            mov EDX,DWORD PTR [ESP+68]
            fstp QWORD PTR [ESP+40]
            mov DWORD PTR [ESP+20],EDX
            lea EDX,DWORD PTR [ESP+16]
            mov DWORD PTR [ESP],EDX
            call EAX

            jmp $L_40200e

            lea ESI,DWORD PTR [ESI]
$L_402008:

            fstp ST(0)
            fstp ST(0)
            fstp ST(0)
$L_40200e:

            add ESP,60
            ret 

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
FUN_4202528:

            mov EAX,DWORD PTR [ESP+4]
            mov DWORD PTR [$L_4053a4],EAX
            jmp $L_4028a4
          BYTE 090H
          BYTE 090H
$L_402030:

            push EBX
            sub ESP,24
            mov EBX,DWORD PTR [ESP+32]
            mov EAX,DWORD PTR [EBX]
            mov EAX,DWORD PTR [EAX]
            cmp EAX,3221225619
            je $L_402060

            ja $L_4020a0

            cmp EAX,3221225501
            je $L_40212b

            jbe $L_4020e0

            add EAX,1073741683
            cmp EAX,4
            ja $L_402085
$L_402060:

            mov DWORD PTR [ESP+4],0
            mov DWORD PTR [ESP],8
            call FUN_4204596

            cmp EAX,1
            je $L_402170
$L_40207d:

            test EAX,EAX
            jne $L_402190
$L_402085:

            mov EAX,DWORD PTR [$L_4053ac]
            test EAX,EAX
            je $L_402160

            mov DWORD PTR [ESP+32],EBX
            add ESP,24
            pop EBX
            jmp EAX

            lea ESI,DWORD PTR [ESI]
$L_4020a0:

            cmp EAX,3221225620
            jne $L_402120

            mov DWORD PTR [ESP+4],0
            mov DWORD PTR [ESP],8
            call FUN_4204596

            cmp EAX,1
            jne $L_40207d

            mov DWORD PTR [ESP+4],1
            mov DWORD PTR [ESP],8
            call FUN_4204596

            mov EAX,4294967295
            jmp $L_402162
          BYTE 066H
          BYTE 090H
$L_4020e0:

            cmp EAX,3221225477
            jne $L_402085

            mov DWORD PTR [ESP+4],0
            mov DWORD PTR [ESP],11
            call FUN_4204596

            cmp EAX,1
            je $L_4021a0

            test EAX,EAX
            je $L_402085

            mov DWORD PTR [ESP],11
            call EAX

            mov EAX,4294967295
            jmp $L_402162

            lea ESI,DWORD PTR [ESI]
$L_402120:

            cmp EAX,3221225622
            jne $L_402085
$L_40212b:

            mov DWORD PTR [ESP+4],0
            mov DWORD PTR [ESP],4
            call FUN_4204596

            cmp EAX,1
            je $L_4021b9

            test EAX,EAX
            je $L_402085

            mov DWORD PTR [ESP],4
            call EAX

            mov EAX,4294967295
            jmp $L_402162

            lea ESI,DWORD PTR [ESI]
$L_402160:

            xor EAX,EAX
$L_402162:

            add ESP,24
            pop EBX
            ret 4

            lea ESI,DWORD PTR [ESI]
$L_402170:

            mov DWORD PTR [ESP+4],1
            mov DWORD PTR [ESP],8
            call FUN_4204596

            call FUN_4201360

            mov EAX,4294967295
            jmp $L_402162
$L_402190:

            mov DWORD PTR [ESP],8
            call EAX

            mov EAX,4294967295
            jmp $L_402162
$L_4021a0:

            mov DWORD PTR [ESP+4],1
            mov DWORD PTR [ESP],11
            call FUN_4204596

            or EAX,4294967295
            jmp $L_402162
$L_4021b9:

            mov DWORD PTR [ESP+4],1
            mov DWORD PTR [ESP],4
            call FUN_4204596

            or EAX,4294967295
            jmp $L_402162
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
FUN_4202976:

            push EBP
            push EDI
            push ESI
            push EBX
            sub ESP,28
            mov DWORD PTR [ESP],OFFSET $L_4053b8
            call DWORD PTR __imp__EnterCriticalSection

            mov EBX,DWORD PTR [$L_4053b0]
            sub ESP,4
            test EBX,EBX
            je $L_402235

            mov EBP,DWORD PTR __imp__TlsGetValue
            mov EDI,DWORD PTR __imp__GetLastError
            lea ESI,DWORD PTR [ESI]
$L_402210:

            mov EAX,DWORD PTR [EBX]
            mov DWORD PTR [ESP],EAX
            call EBP

            sub ESP,4
            mov ESI,EAX
            call EDI

            test EAX,EAX
            jne $L_40222e

            test ESI,ESI
            je $L_40222e

            mov EAX,DWORD PTR [EBX+4]
            mov DWORD PTR [ESP],ESI
            call EAX
$L_40222e:

            mov EBX,DWORD PTR [EBX+8]
            test EBX,EBX
            jne $L_402210
$L_402235:

            mov DWORD PTR [ESP],OFFSET $L_4053b8
            call DWORD PTR __imp__LeaveCriticalSection

            sub ESP,4
            add ESP,28
            pop EBX
            pop ESI
            pop EDI
            pop EBP
            ret 

            lea ESI,DWORD PTR [ESI]
            mov EAX,DWORD PTR [$L_4053b4]
            test EAX,EAX
            jne $L_402260

            ret 

            lea ESI,DWORD PTR [ESI]
$L_402260:

            push EBX
            sub ESP,24
            mov DWORD PTR [ESP+4],12
            mov DWORD PTR [ESP],1
            call FUN_4204660

            mov EBX,EAX
            test EAX,EAX
            je $L_4022c0

            mov EAX,DWORD PTR [ESP+32]
            mov DWORD PTR [ESP],OFFSET $L_4053b8
            mov DWORD PTR [EBX],EAX
            mov EAX,DWORD PTR [ESP+36]
            mov DWORD PTR [EBX+4],EAX
            call DWORD PTR __imp__EnterCriticalSection

            mov EAX,DWORD PTR [$L_4053b0]
            mov DWORD PTR [$L_4053b0],EBX
            sub ESP,4
            mov DWORD PTR [EBX+8],EAX
            mov DWORD PTR [ESP],OFFSET $L_4053b8
            call DWORD PTR __imp__LeaveCriticalSection

            xor EAX,EAX
            sub ESP,4
$L_4022bb:

            add ESP,24
            pop EBX
            ret 
$L_4022c0:

            or EAX,4294967295
            jmp $L_4022bb

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
            push EBX
            sub ESP,24
            mov EAX,DWORD PTR [$L_4053b4]
            mov EBX,DWORD PTR [ESP+32]
            test EAX,EAX
            jne $L_4022f0

            add ESP,24
            xor EAX,EAX
            pop EBX
            ret 

            lea ESI,DWORD PTR [ESI]
            nop
$L_4022f0:

            mov DWORD PTR [ESP],OFFSET $L_4053b8
            call DWORD PTR __imp__EnterCriticalSection

            mov EAX,DWORD PTR [$L_4053b0]
            sub ESP,4
            test EAX,EAX
            je $L_402330

            xor ECX,ECX
            jmp $L_402318

            lea ESI,DWORD PTR [ESI]
$L_402310:

            mov ECX,EAX
            test EDX,EDX
            je $L_402330

            mov EAX,EDX
$L_402318:

            mov EDX,DWORD PTR [EAX]
            cmp EDX,EBX
            mov EDX,DWORD PTR [EAX+8]
            jne $L_402310

            test ECX,ECX
            je $L_402350

            mov DWORD PTR [ECX+8],EDX
$L_402328:

            mov DWORD PTR [ESP],EAX
            call FUN_4204636
$L_402330:

            mov DWORD PTR [ESP],OFFSET $L_4053b8
            call DWORD PTR __imp__LeaveCriticalSection

            xor EAX,EAX
            sub ESP,4
            add ESP,24
            pop EBX
            ret 

            lea ESI,DWORD PTR [ESI]
            nop
            nop
$L_402350:

            mov DWORD PTR [$L_4053b0],EDX
            jmp $L_402328

            lea ESI,DWORD PTR [ESI]
            nop
FUN_4203360:

            push EBX
            sub ESP,24
            mov EAX,DWORD PTR [ESP+36]
            cmp EAX,2
            je $L_402430

            ja $L_402398

            test EAX,EAX
            je $L_4023c8

            mov EAX,DWORD PTR [$L_4053b4]
            test EAX,EAX
            je $L_4023b0
$L_402380:

            mov DWORD PTR [$L_4053b4],1
$L_40238a:

            add ESP,24
            mov EAX,1
            pop EBX
            ret 

            lea ESI,DWORD PTR [ESI]
$L_402398:

            cmp EAX,3
            jne $L_40238a

            mov EAX,DWORD PTR [$L_4053b4]
            test EAX,EAX
            je $L_40238a

            call FUN_4202976

            jmp $L_40238a

            lea ESI,DWORD PTR [ESI]
$L_4023b0:

            mov DWORD PTR [ESP],OFFSET $L_4053b8
            call DWORD PTR __imp__InitializeCriticalSection

            sub ESP,4
            jmp $L_402380

            lea ESI,DWORD PTR [ESI]
$L_4023c8:

            mov EAX,DWORD PTR [$L_4053b4]
            test EAX,EAX
            je $L_4023d6

            call FUN_4202976
$L_4023d6:

            mov EAX,DWORD PTR [$L_4053b4]
            cmp EAX,1
            jne $L_40238a

            mov EBX,DWORD PTR [$L_4053b0]
            test EBX,EBX
            je $L_402401

            lea ESI,DWORD PTR [ESI]
$L_4023f0:

            mov EAX,EBX
            mov EBX,DWORD PTR [EBX+8]
            mov DWORD PTR [ESP],EAX
            call FUN_4204636

            test EBX,EBX
            jne $L_4023f0
$L_402401:

            mov DWORD PTR [$L_4053b0],0
            mov DWORD PTR [$L_4053b4],0
            mov DWORD PTR [ESP],OFFSET $L_4053b8
            call DWORD PTR __imp__DeleteCriticalSection

            sub ESP,4
            jmp $L_40238a

            lea ESI,DWORD PTR [ESI]
$L_402430:

            call FUN_4201360

            add ESP,24
            mov EAX,1
            pop EBX
            ret 
          BYTE 090H
FUN_4203584:

            add EAX,DWORD PTR [EAX+60]
            cmp DWORD PTR [EAX],17744
            jne $L_402460

            cmp WORD PTR [EAX+24],267
            sete AL
            movzx EAX,AL
            ret 

            lea ESI,DWORD PTR [ESI]
            nop
$L_402460:

            xor EAX,EAX
            ret 

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
            mov EAX,DWORD PTR [ESP+4]
            cmp WORD PTR [EAX],23117
            jne $L_402480

            jmp FUN_4203584

            lea ESI,DWORD PTR [ESI]
$L_402480:

            xor EAX,EAX
            ret 

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
            push ESI
            push EBX
            mov EDX,DWORD PTR [ESP+12]
            mov EBX,DWORD PTR [ESP+16]
            add EDX,DWORD PTR [EDX+60]
            movzx EAX,WORD PTR [EDX+20]
            movzx ESI,WORD PTR [EDX+6]
            lea EAX,DWORD PTR [EDX+EAX*1+24]
            test ESI,ESI
            je $L_4024c8

            xor ECX,ECX
            nop
$L_4024b0:

            mov EDX,DWORD PTR [EAX+12]
            cmp EDX,EBX
            ja $L_4024be

            add EDX,DWORD PTR [EAX+8]
            cmp EDX,EBX
            ja $L_4024ca
$L_4024be:

            add ECX,1
            add EAX,40
            cmp ECX,ESI
            jne $L_4024b0
$L_4024c8:

            xor EAX,EAX
$L_4024ca:

            pop EBX
            pop ESI
            ret 

            lea ESI,DWORD PTR [ESI]
            push EBP
            push EDI
            push ESI
            push EBX
            xor EBX,EBX
            sub ESP,28
            mov EDI,DWORD PTR [ESP+48]
            mov DWORD PTR [ESP],EDI
            call FUN_4204588

            cmp EAX,8
            ja $L_40254a

            cmp WORD PTR [___ImageBase],23117
            jne $L_40254a

            mov EAX,4194304
            call FUN_4203584

            test EAX,EAX
            je $L_40254a

            mov EAX,DWORD PTR [___ImageBase+60]
            movzx EDX,WORD PTR [EAX+___ImageBase+20]
            movzx EBP,WORD PTR [EAX+___ImageBase+6]
            lea EBX,DWORD PTR [EAX+EDX*1+___ImageBase+24]
            test EBP,EBP
            je $L_402558

            xor ESI,ESI
            jmp $L_402532

            lea ESI,DWORD PTR [ESI]
$L_402528:

            add ESI,1
            add EBX,40
            cmp ESI,EBP
            je $L_402558
$L_402532:

            mov DWORD PTR [ESP+8],8
            mov DWORD PTR [ESP+4],EDI
            mov DWORD PTR [ESP],EBX
            call FUN_4204580

            test EAX,EAX
            jne $L_402528
$L_40254a:

            add ESP,28
            mov EAX,EBX
            pop EBX
            pop ESI
            pop EDI
            pop EBP
            ret 

            lea ESI,DWORD PTR [ESI]
$L_402558:

            add ESP,28
            xor EBX,EBX
            mov EAX,EBX
            pop EBX
            pop ESI
            pop EDI
            pop EBP
            ret 

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
            nop
FUN_4203888:

            xor EDX,EDX
            cmp WORD PTR [___ImageBase],23117
            jne $L_4025e0

            push ESI
            mov EAX,4194304
            push EBX
            call FUN_4203584

            test EAX,EAX
            je $L_4025da

            mov EAX,DWORD PTR [___ImageBase+60]
            mov EBX,DWORD PTR [ESP+12]
            movzx EDX,WORD PTR [EAX+___ImageBase+20]
            movzx ESI,WORD PTR [EAX+___ImageBase+6]
            sub EBX,4194304
            lea EDX,DWORD PTR [EAX+EDX*1+___ImageBase+24]
            test ESI,ESI
            je $L_4025d8

            xor ECX,ECX
            lea ESI,DWORD PTR [ESI]
            nop
            nop
$L_4025c0:

            mov EAX,DWORD PTR [EDX+12]
            cmp EBX,EAX
            jb $L_4025ce

            add EAX,DWORD PTR [EDX+8]
            cmp EBX,EAX
            jb $L_4025da
$L_4025ce:

            add ECX,1
            add EDX,40
            cmp ECX,ESI
            jne $L_4025c0
$L_4025d8:

            xor EDX,EDX
$L_4025da:

            mov EAX,EDX
            pop EBX
            pop ESI
            ret 
          BYTE 090H
$L_4025e0:

            mov EAX,EDX
            ret 

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
FUN_4204016:

            xor EAX,EAX
            cmp WORD PTR [___ImageBase],23117
            jne $L_402617

            mov EAX,OFFSET ___ImageBase
            call FUN_4203584

            test EAX,EAX
            je $L_402617

            mov EAX,DWORD PTR [___ImageBase+60]
            movzx EAX,WORD PTR [EAX+___ImageBase+6]
$L_402617:

            ret 

            lea ESI,DWORD PTR [ESI]
            nop
            xor EDX,EDX
            push EBX
            mov ECX,DWORD PTR [ESP+8]
            cmp WORD PTR [___ImageBase],23117
            jne $L_402679

            mov EAX,4194304
            call FUN_4203584

            test EAX,EAX
            je $L_402679

            mov EAX,DWORD PTR [___ImageBase+60]
            movzx EDX,WORD PTR [EAX+___ImageBase+20]
            movzx EBX,WORD PTR [EAX+___ImageBase+6]
            lea EDX,DWORD PTR [EAX+EDX*1+___ImageBase+24]
            test EBX,EBX
            je $L_402677

            xor EAX,EAX
$L_402660:

            test BYTE PTR [EDX+39],32
            je $L_40266d

            test ECX,ECX
            je $L_402679

            sub ECX,1
$L_40266d:

            add EAX,1
            add EDX,40
            cmp EAX,EBX
            jne $L_402660
$L_402677:

            xor EDX,EDX
$L_402679:

            mov EAX,EDX
            pop EBX
            ret 

            lea ESI,DWORD PTR [ESI]
FUN_4204160:

            xor EDX,EDX
            cmp WORD PTR [___ImageBase],23117
            jne $L_4026a1

            mov EAX,4194304
            call FUN_4203584

            test EAX,EAX
            mov EAX,OFFSET ___ImageBase
            cmovne EDX,EAX
$L_4026a1:

            mov EAX,EDX
            ret 

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
            nop
            xor EAX,EAX
            cmp WORD PTR [___ImageBase],23117
            jne $L_402720

            push ESI
            mov EAX,4194304
            push EBX
            call FUN_4203584

            test EAX,EAX
            je $L_40271a

            mov EDX,DWORD PTR [___ImageBase+60]
            mov EBX,DWORD PTR [ESP+12]
            movzx EAX,WORD PTR [EDX+___ImageBase+20]
            movzx ESI,WORD PTR [EDX+___ImageBase+6]
            sub EBX,4194304
            lea EAX,DWORD PTR [EDX+EAX*1+___ImageBase+24]
            test ESI,ESI
            je $L_402718

            xor ECX,ECX
            lea ESI,DWORD PTR [ESI]
            nop
$L_402700:

            mov EDX,DWORD PTR [EAX+12]
            cmp EBX,EDX
            jb $L_40270e

            add EDX,DWORD PTR [EAX+8]
            cmp EBX,EDX
            jb $L_402728
$L_40270e:

            add ECX,1
            add EAX,40
            cmp ECX,ESI
            jne $L_402700
$L_402718:

            xor EAX,EAX
$L_40271a:

            pop EBX
            pop ESI
            ret 

            lea ESI,DWORD PTR [ESI]
$L_402720:

            ret 

            lea ESI,DWORD PTR [ESI]
$L_402728:

            mov EAX,DWORD PTR [EAX+36]
            pop EBX
            pop ESI
            not EAX
            shr EAX,31
            ret 

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
            xor ECX,ECX
            push EDI
            cmp WORD PTR [___ImageBase],23117
            push ESI
            push EBX
            mov EBX,DWORD PTR [ESP+16]
            jne $L_4027aa

            mov EAX,4194304
            call FUN_4203584

            test EAX,EAX
            je $L_4027aa

            mov EAX,DWORD PTR [___ImageBase+60]
            lea ESI,DWORD PTR [EAX+___ImageBase]
            mov EAX,DWORD PTR [EAX+4194432]
            test EAX,EAX
            je $L_4027aa

            movzx EDX,WORD PTR [ESI+20]
            movzx EDI,WORD PTR [ESI+6]
            lea EDX,DWORD PTR [ESI+EDX*1+24]
            test EDI,EDI
            je $L_4027aa

            xor ESI,ESI
            lea ESI,DWORD PTR [ESI]
$L_402790:

            mov ECX,DWORD PTR [EDX+12]
            cmp EAX,ECX
            jb $L_40279e

            add ECX,DWORD PTR [EDX+8]
            cmp EAX,ECX
            jb $L_4027b0
$L_40279e:

            add ESI,1
            add EDX,40
            cmp ESI,EDI
            jne $L_402790
$L_4027a8:

            xor ECX,ECX
$L_4027aa:

            pop EBX
            mov EAX,ECX
            pop ESI
            pop EDI
            ret 
$L_4027b0:

            add EAX,4194304
            jmp $L_4027c6

            lea ESI,DWORD PTR [ESI]
            nop
            nop
$L_4027c0:

            sub EBX,1
            add EAX,20
$L_4027c6:

            mov ECX,DWORD PTR [EAX+4]
            test ECX,ECX
            jne $L_4027d4

            mov EDX,DWORD PTR [EAX+12]
            test EDX,EDX
            je $L_4027a8
$L_4027d4:

            test EBX,EBX
            jg $L_4027c0

            mov ECX,DWORD PTR [EAX+12]
            pop EBX
            pop ESI
            pop EDI
            add ECX,4194304
            mov EAX,ECX
            ret 
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
FUN_4204528:

            push ECX
            push EAX
            cmp EAX,4096
            lea ECX,DWORD PTR [ESP+12]
            jb $L_402812
$L_4027fd:

            sub ECX,4096
            or DWORD PTR [ECX],0
            sub EAX,4096
            cmp EAX,4096
            ja $L_4027fd
$L_402812:

            sub ECX,EAX
            or DWORD PTR [ECX],0
            pop EAX
            pop ECX
            ret 
          BYTE 090H
          BYTE 090H
FUN_4204572:

            jmp DWORD PTR __imp__vfprintf
          BYTE 090H
          BYTE 090H
FUN_4204580:

            jmp DWORD PTR __imp__strncmp
          BYTE 090H
          BYTE 090H
FUN_4204588:

            jmp DWORD PTR __imp__strlen
          BYTE 090H
          BYTE 090H
FUN_4204596:

            jmp DWORD PTR __imp__signal
          BYTE 090H
          BYTE 090H
FUN_4204604:

            jmp DWORD PTR __imp__printf
          BYTE 090H
          BYTE 090H
FUN_4204612:

            jmp DWORD PTR __imp__memcpy
          BYTE 090H
          BYTE 090H
FUN_4204620:

            jmp DWORD PTR __imp__malloc
          BYTE 090H
          BYTE 090H
FUN_4204628:

            jmp DWORD PTR __imp__fwrite
          BYTE 090H
          BYTE 090H
FUN_4204636:

            jmp DWORD PTR __imp__free
          BYTE 090H
          BYTE 090H
FUN_4204644:

            jmp DWORD PTR __imp__fprintf
          BYTE 090H
          BYTE 090H
FUN_4204652:

            jmp DWORD PTR __imp__exit
          BYTE 090H
          BYTE 090H
FUN_4204660:

            jmp DWORD PTR __imp__calloc
          BYTE 090H
          BYTE 090H
FUN_4204668:

            jmp DWORD PTR __imp__abort
          BYTE 090H
          BYTE 090H
FUN_4204676:

            jmp DWORD PTR __imp___onexit
          BYTE 090H
          BYTE 090H
FUN_4204684:

            jmp DWORD PTR __imp___initterm
          BYTE 090H
          BYTE 090H
FUN_4204692:

            jmp DWORD PTR __imp___cexit
          BYTE 090H
          BYTE 090H
FUN_4204700:

            jmp DWORD PTR __imp___amsg_exit
          BYTE 090H
          BYTE 090H
$L_4028a4:

            jmp DWORD PTR __imp____setusermatherr
          BYTE 090H
          BYTE 090H
FUN_4204716:

            jmp DWORD PTR __imp____set_app_type
          BYTE 090H
          BYTE 090H
FUN_4204724:

            jmp DWORD PTR __imp____p__fmode
          BYTE 090H
          BYTE 090H
FUN_4204732:

            jmp DWORD PTR __imp____p__acmdln
          BYTE 090H
          BYTE 090H
FUN_4204740:

            jmp DWORD PTR __imp____getmainargs
          BYTE 090H
          BYTE 090H
          BYTE 066H
          BYTE 090H
          BYTE 066H
          BYTE 090H
FUN_4204752:

            mov EAX,DWORD PTR [ESP+4]
            shl EAX,5
            add EAX,DWORD PTR __imp___iob
            ret 
          BYTE 090H
          BYTE 090H
$L_4028e0:

            mov EAX,DWORD PTR [$L_4053d4]
            ret 

            lea ESI,DWORD PTR [ESI]
            lea ESI,DWORD PTR [ESI]
FUN_4204784:

            mov EAX,DWORD PTR [ESP+4]
            xchg DWORD PTR [$L_4053d4],EAX
            ret 
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
$L_402900:

            jmp $L_401500
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
          BYTE 090H
$L_402910           BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          DWORD $L_402900
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
$L_402920           DB 4 DUP(0)
;===================================
_TEXT    ENDS
;===================================

;===================================
_DATA    SEGMENT
;===================================

ALIGN 16
$L_403000           BYTE 00aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_403004           DWORD $L_402920
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_403014           BYTE 002H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_403018           BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          DWORD FUN_4204752
          DWORD $L_4028e0
          DWORD FUN_4204784
$L_403028           BYTE 04eH
          BYTE 0e6H
          BYTE 040H
          BYTE 0bbH
$L_40302c           BYTE 0b1H
          BYTE 019H
          BYTE 0bfH
          BYTE 044H
;===================================
_DATA    ENDS
;===================================

;===================================
_RDATA   SEGMENT
;===================================

ALIGN 16
$L_404000                     DB '--Pattern is found at: %d'
          BYTE 00aH
          BYTE 000H

$L_40401b                     DB 'String test: %s'
          BYTE 00aH
          BYTE 000H

$L_40402c                     DB 'Test1: search pattern %s'
          BYTE 00aH
          BYTE 000H

$L_404046                     DB 'Test2: search pattern %s'
          BYTE 00aH
          BYTE 000H

$L_404060                     DB 'Test3: search pattern %s'
          BYTE 00aH
          BYTE 000H

          DB 2 DUP(0)
$L_40407c           DWORD $L_405320
          DWORD $L_405040
$L_404084           DWORD $L_401a60
          DWORD $L_408000
          DWORD $L_408004
          DWORD $L_405390
          DWORD $L_407020
          DB 8 DUP(0)
$L_4040a0                     DB 'Unknown error'
          BYTE 000H

          DB 2 DUP(0)
$L_4040b0                     DB '_matherr(): %s in %s(%g, %g)  (retval=%g)'
          BYTE 00aH
          BYTE 000H

          DB 1 DUP(0)
$L_4040dc                     DB 'Argument domain error (DOMAIN)'
          BYTE 000H

$L_4040fb                     DB 'Argument singularity (SIGN)'
          BYTE 000H

          DB 1 DUP(0)
$L_404118                     DB 'Overflow range error (OVERFLOW)'
          BYTE 000H

$L_404138                     DB 'The result is too small to be represented (UNDERFLOW)'
          BYTE 000H

          DB 2 DUP(0)
$L_404170                     DB 'Total loss of significance (TLOSS)'
          BYTE 000H

          DB 1 DUP(0)
$L_404194                     DB 'Partial loss of significance (PLOSS)'
          BYTE 000H

          DB 3 DUP(0)
$L_4041bc           DWORD $L_4040dc
          DWORD $L_4040fb
          DWORD $L_404118
          DWORD $L_404138
          DWORD $L_404170
          DWORD $L_404194
$L_4041d4                     DB 'Mingw-w64 runtime failure:'
          BYTE 00aH
          BYTE 000H

$L_4041f0                     DB 'Address %p has no image-section'
          BYTE 000H

$L_404210                     DB '  VirtualQuery failed for %d bytes at address %p'
          BYTE 000H

          DB 3 DUP(0)
$L_404244                     DB '  VirtualProtect failed with code 0x%x'
          BYTE 000H

          DB 1 DUP(0)
$L_40426c                     DB '  Unknown pseudo relocation protocol version %d.'
          BYTE 00aH
          BYTE 000H

          DB 2 DUP(0)
$L_4042a0                     DB '  Unknown pseudo relocation bit size %d.'
          BYTE 00aH
          BYTE 000H

          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 033H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 032H
          BYTE 030H
          BYTE 030H
          BYTE 033H
          BYTE 032H
          BYTE 030H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 033H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 032H
          BYTE 030H
          BYTE 030H
          BYTE 033H
          BYTE 032H
          BYTE 030H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 033H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 032H
          BYTE 030H
          BYTE 030H
          BYTE 033H
          BYTE 032H
          BYTE 030H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 032H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 031H
          BYTE 039H
          BYTE 031H
          BYTE 030H
          BYTE 030H
          BYTE 038H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 047H
          BYTE 043H
          BYTE 043H
          BYTE 03aH
          BYTE 020H
          BYTE 028H
          BYTE 047H
          BYTE 04eH
          BYTE 055H
          BYTE 029H
          BYTE 020H
          BYTE 039H
          BYTE 02eH
          BYTE 033H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 033H
          BYTE 032H
          BYTE 020H
          BYTE 032H
          BYTE 030H
          BYTE 032H
          BYTE 030H
          BYTE 030H
          BYTE 033H
          BYTE 032H
          BYTE 030H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_40464c:
;===================================
_RDATA   ENDS
;===================================

;===================================
_BSS     SEGMENT
;===================================

ALIGN 16
          DB 4 DUP(0)
$L_405004           DB 4 DUP(0)
$L_405008           DB 4 DUP(0)
$L_40500c           DB 4 DUP(0)
$L_405010           DB 4 DUP(0)
$L_405014           DB 4 DUP(0)
$L_405018           DB 4 DUP(0)
$L_40501c           DB 4 DUP(0)
$L_405020           DB 4 DUP(0)
$L_405024           DB 4 DUP(0)
$L_405028           DB 24 DUP(0)
$L_405040           DB 172 DUP(0)
$L_4050ec           DB 12 DUP(0)
$L_4050f8           DB 12 DUP(0)
$L_405104           DB 540 DUP(0)
$L_405320           DB 4 DUP(0)
$L_405324           DB 8 DUP(0)
$L_40532c           DB 84 DUP(0)
$L_405380           DB 4 DUP(0)
$L_405384           DB 4 DUP(0)
$L_405388           DB 4 DUP(0)
$L_40538c           DB 4 DUP(0)
$L_405390           DB 4 DUP(0)
$L_405394           DB 4 DUP(0)
$L_405398           DB 4 DUP(0)
$L_40539c           DB 4 DUP(0)
$L_4053a0           DB 4 DUP(0)
$L_4053a4           DB 4 DUP(0)
$L_4053a8           DB 4 DUP(0)
$L_4053ac           DB 4 DUP(0)
$L_4053b0           DB 4 DUP(0)
$L_4053b4           DB 4 DUP(0)
$L_4053b8           DB 28 DUP(0)
$L_4053d4           DB 4 DUP(0)
$L_4053d8           DB 4 DUP(0)
$L_4053dc           DB 4 DUP(0)
$L_4053e0           DB 4 DUP(0)
$L_4053e4           DB 4 DUP(0)
;===================================
_BSS     ENDS
;===================================

;===================================
_IDATA   SEGMENT
;===================================

ALIGN 16
          BYTE 03cH
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0acH
          BYTE 064H
          BYTE 000H
          BYTE 000H
          BYTE 0f4H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 08cH
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 020H
          BYTE 065H
          BYTE 000H
          BYTE 000H
          BYTE 044H
          BYTE 061H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0acH
          BYTE 061H
          BYTE 000H
          BYTE 000H
          BYTE 0c4H
          BYTE 061H
          BYTE 000H
          BYTE 000H
          BYTE 0dcH
          BYTE 061H
          BYTE 000H
          BYTE 000H
          BYTE 0f0H
          BYTE 061H
          BYTE 000H
          BYTE 000H
          BYTE 006H
          BYTE 062H
          BYTE 000H
          BYTE 000H
          BYTE 01cH
          BYTE 062H
          BYTE 000H
          BYTE 000H
          BYTE 02cH
          BYTE 062H
          BYTE 000H
          BYTE 000H
          BYTE 03eH
          BYTE 062H
          BYTE 000H
          BYTE 000H
          BYTE 058H
          BYTE 062H
          BYTE 000H
          BYTE 000H
          BYTE 068H
          BYTE 062H
          BYTE 000H
          BYTE 000H
          BYTE 084H
          BYTE 062H
          BYTE 000H
          BYTE 000H
          BYTE 09cH
          BYTE 062H
          BYTE 000H
          BYTE 000H
          BYTE 0b6H
          BYTE 062H
          BYTE 000H
          BYTE 000H
          BYTE 0d4H
          BYTE 062H
          BYTE 000H
          BYTE 000H
          BYTE 0dcH
          BYTE 062H
          BYTE 000H
          BYTE 000H
          BYTE 0f0H
          BYTE 062H
          BYTE 000H
          BYTE 000H
          BYTE 0feH
          BYTE 062H
          BYTE 000H
          BYTE 000H
          BYTE 01aH
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 02cH
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 03cH
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 04cH
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 058H
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 068H
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 076H
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 084H
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 096H
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 0aaH
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 0b8H
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 0c2H
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 0ceH
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 0d6H
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 0e0H
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 0e8H
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 0f2H
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 0faH
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 004H
          BYTE 064H
          BYTE 000H
          BYTE 000H
          BYTE 00cH
          BYTE 064H
          BYTE 000H
          BYTE 000H
          BYTE 016H
          BYTE 064H
          BYTE 000H
          BYTE 000H
          BYTE 020H
          BYTE 064H
          BYTE 000H
          BYTE 000H
          BYTE 02aH
          BYTE 064H
          BYTE 000H
          BYTE 000H
          BYTE 034H
          BYTE 064H
          BYTE 000H
          BYTE 000H
          BYTE 03eH
          BYTE 064H
          BYTE 000H
          BYTE 000H
          BYTE 048H
          BYTE 064H
          BYTE 000H
          BYTE 000H
          BYTE 052H
          BYTE 064H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_4060f4           BYTE 0acH
          BYTE 061H
          BYTE 000H
          BYTE 000H
$L_4060f8           BYTE 0c4H
          BYTE 061H
          BYTE 000H
          BYTE 000H
$L_4060fc           BYTE 0dcH
          BYTE 061H
          BYTE 000H
          BYTE 000H
$L_406100           BYTE 0f0H
          BYTE 061H
          BYTE 000H
          BYTE 000H
$L_406104           BYTE 006H
          BYTE 062H
          BYTE 000H
          BYTE 000H
$L_406108           BYTE 01cH
          BYTE 062H
          BYTE 000H
          BYTE 000H
$L_40610c                     DB ',b'
          BYTE 000H

          DB 1 DUP(0)
$L_406110                     DB '>b'
          BYTE 000H

          DB 1 DUP(0)
$L_406114                     DB 'Xb'
          BYTE 000H

          DB 1 DUP(0)
$L_406118                     DB 'hb'
          BYTE 000H

          DB 1 DUP(0)
$L_40611c           BYTE 084H
          BYTE 062H
          BYTE 000H
          BYTE 000H
$L_406120           BYTE 09cH
          BYTE 062H
          BYTE 000H
          BYTE 000H
$L_406124           BYTE 0b6H
          BYTE 062H
          BYTE 000H
          BYTE 000H
$L_406128           BYTE 0d4H
          BYTE 062H
          BYTE 000H
          BYTE 000H
$L_40612c           BYTE 0dcH
          BYTE 062H
          BYTE 000H
          BYTE 000H
$L_406130           BYTE 0f0H
          BYTE 062H
          BYTE 000H
          BYTE 000H
$L_406134           BYTE 0feH
          BYTE 062H
          BYTE 000H
          BYTE 000H
$L_406138           BYTE 01aH
          BYTE 063H
          BYTE 000H
          BYTE 000H
$L_40613c                     DB ',c'
          BYTE 000H

          DB 5 DUP(0)
$L_406144                     DB '<c'
          BYTE 000H

          DB 1 DUP(0)
$L_406148           BYTE 04cH
          BYTE 063H
          BYTE 000H
          BYTE 000H
$L_40614c                     DB 'Xc'
          BYTE 000H

          DB 1 DUP(0)
$L_406150                     DB 'hc'
          BYTE 000H

          DB 1 DUP(0)
$L_406154                     DB 'vc'
          BYTE 000H

          DB 1 DUP(0)
$L_406158           BYTE 084H
          BYTE 063H
          BYTE 000H
          BYTE 000H
$L_40615c           BYTE 096H
          BYTE 063H
          BYTE 000H
          BYTE 000H
$L_406160           BYTE 0aaH
          BYTE 063H
          BYTE 000H
          BYTE 000H
$L_406164           BYTE 0b8H
          BYTE 063H
          BYTE 000H
          BYTE 000H
$L_406168           BYTE 0c2H
          BYTE 063H
          BYTE 000H
          BYTE 000H
$L_40616c           BYTE 0ceH
          BYTE 063H
          BYTE 000H
          BYTE 000H
$L_406170           BYTE 0d6H
          BYTE 063H
          BYTE 000H
          BYTE 000H
$L_406174           BYTE 0e0H
          BYTE 063H
          BYTE 000H
          BYTE 000H
$L_406178           BYTE 0e8H
          BYTE 063H
          BYTE 000H
          BYTE 000H
$L_40617c           BYTE 0f2H
          BYTE 063H
          BYTE 000H
          BYTE 000H
$L_406180           BYTE 0faH
          BYTE 063H
          BYTE 000H
          BYTE 000H
$L_406184           BYTE 004H
          BYTE 064H
          BYTE 000H
          BYTE 000H
$L_406188                     BYTE 00cH
          DB 'd'
          BYTE 000H

          DB 1 DUP(0)
$L_40618c           BYTE 016H
          BYTE 064H
          BYTE 000H
          BYTE 000H
$L_406190                     DB ' d'
          BYTE 000H

          DB 1 DUP(0)
$L_406194                     DB '*d'
          BYTE 000H

          DB 1 DUP(0)
$L_406198                     DB '4d'
          BYTE 000H

          DB 1 DUP(0)
$L_40619c                     DB '>d'
          BYTE 000H

          DB 1 DUP(0)
$L_4061a0                     DB 'Hd'
          BYTE 000H

          DB 1 DUP(0)
$L_4061a4                     DB 'Rd'
          BYTE 000H

          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 015H
          BYTE 001H
          BYTE 044H
          BYTE 065H
          BYTE 06cH
          BYTE 065H
          BYTE 074H
          BYTE 065H
          BYTE 043H
          BYTE 072H
          BYTE 069H
          BYTE 074H
          BYTE 069H
          BYTE 063H
          BYTE 061H
          BYTE 06cH
          BYTE 053H
          BYTE 065H
          BYTE 063H
          BYTE 074H
          BYTE 069H
          BYTE 06fH
          BYTE 06eH
          BYTE 000H
          BYTE 036H
          BYTE 001H
          BYTE 045H
          BYTE 06eH
          BYTE 074H
          BYTE 065H
          BYTE 072H
          BYTE 043H
          BYTE 072H
          BYTE 069H
          BYTE 074H
          BYTE 069H
          BYTE 063H
          BYTE 061H
          BYTE 06cH
          BYTE 053H
          BYTE 065H
          BYTE 063H
          BYTE 074H
          BYTE 069H
          BYTE 06fH
          BYTE 06eH
          BYTE 000H
          BYTE 000H
          BYTE 01fH
          BYTE 002H
          BYTE 047H
          BYTE 065H
          BYTE 074H
          BYTE 043H
          BYTE 075H
          BYTE 072H
          BYTE 072H
          BYTE 065H
          BYTE 06eH
          BYTE 074H
          BYTE 050H
          BYTE 072H
          BYTE 06fH
          BYTE 063H
          BYTE 065H
          BYTE 073H
          BYTE 073H
          BYTE 000H
          BYTE 020H
          BYTE 002H
          BYTE 047H
          BYTE 065H
          BYTE 074H
          BYTE 043H
          BYTE 075H
          BYTE 072H
          BYTE 072H
          BYTE 065H
          BYTE 06eH
          BYTE 074H
          BYTE 050H
          BYTE 072H
          BYTE 06fH
          BYTE 063H
          BYTE 065H
          BYTE 073H
          BYTE 073H
          BYTE 049H
          BYTE 064H
          BYTE 000H
          BYTE 024H
          BYTE 002H
          BYTE 047H
          BYTE 065H
          BYTE 074H
          BYTE 043H
          BYTE 075H
          BYTE 072H
          BYTE 072H
          BYTE 065H
          BYTE 06eH
          BYTE 074H
          BYTE 054H
          BYTE 068H
          BYTE 072H
          BYTE 065H
          BYTE 061H
          BYTE 064H
          BYTE 049H
          BYTE 064H
          BYTE 000H
          BYTE 000H
          BYTE 069H
          BYTE 002H
          BYTE 047H
          BYTE 065H
          BYTE 074H
          BYTE 04cH
          BYTE 061H
          BYTE 073H
          BYTE 074H
          BYTE 045H
          BYTE 072H
          BYTE 072H
          BYTE 06fH
          BYTE 072H
          BYTE 000H
          BYTE 000H
          BYTE 0d9H
          BYTE 002H
          BYTE 047H
          BYTE 065H
          BYTE 074H
          BYTE 053H
          BYTE 074H
          BYTE 061H
          BYTE 072H
          BYTE 074H
          BYTE 075H
          BYTE 070H
          BYTE 049H
          BYTE 06eH
          BYTE 066H
          BYTE 06fH
          BYTE 041H
          BYTE 000H
          BYTE 0f3H
          BYTE 002H
          BYTE 047H
          BYTE 065H
          BYTE 074H
          BYTE 053H
          BYTE 079H
          BYTE 073H
          BYTE 074H
          BYTE 065H
          BYTE 06dH
          BYTE 054H
          BYTE 069H
          BYTE 06dH
          BYTE 065H
          BYTE 041H
          BYTE 073H
          BYTE 046H
          BYTE 069H
          BYTE 06cH
          BYTE 065H
          BYTE 054H
          BYTE 069H
          BYTE 06dH
          BYTE 065H
          BYTE 000H
          BYTE 012H
          BYTE 003H
          BYTE 047H
          BYTE 065H
          BYTE 074H
          BYTE 054H
          BYTE 069H
          BYTE 063H
          BYTE 06bH
          BYTE 043H
          BYTE 06fH
          BYTE 075H
          BYTE 06eH
          BYTE 074H
          BYTE 000H
          BYTE 000H
          BYTE 06dH
          BYTE 003H
          BYTE 049H
          BYTE 06eH
          BYTE 069H
          BYTE 074H
          BYTE 069H
          BYTE 061H
          BYTE 06cH
          BYTE 069H
          BYTE 07aH
          BYTE 065H
          BYTE 043H
          BYTE 072H
          BYTE 069H
          BYTE 074H
          BYTE 069H
          BYTE 063H
          BYTE 061H
          BYTE 06cH
          BYTE 053H
          BYTE 065H
          BYTE 063H
          BYTE 074H
          BYTE 069H
          BYTE 06fH
          BYTE 06eH
          BYTE 000H
          BYTE 0cdH
          BYTE 003H
          BYTE 04cH
          BYTE 065H
          BYTE 061H
          BYTE 076H
          BYTE 065H
          BYTE 043H
          BYTE 072H
          BYTE 069H
          BYTE 074H
          BYTE 069H
          BYTE 063H
          BYTE 061H
          BYTE 06cH
          BYTE 053H
          BYTE 065H
          BYTE 063H
          BYTE 074H
          BYTE 069H
          BYTE 06fH
          BYTE 06eH
          BYTE 000H
          BYTE 000H
          BYTE 05eH
          BYTE 004H
          BYTE 051H
          BYTE 075H
          BYTE 065H
          BYTE 072H
          BYTE 079H
          BYTE 050H
          BYTE 065H
          BYTE 072H
          BYTE 066H
          BYTE 06fH
          BYTE 072H
          BYTE 06dH
          BYTE 061H
          BYTE 06eH
          BYTE 063H
          BYTE 065H
          BYTE 043H
          BYTE 06fH
          BYTE 075H
          BYTE 06eH
          BYTE 074H
          BYTE 065H
          BYTE 072H
          BYTE 000H
          BYTE 05aH
          BYTE 005H
          BYTE 053H
          BYTE 065H
          BYTE 074H
          BYTE 055H
          BYTE 06eH
          BYTE 068H
          BYTE 061H
          BYTE 06eH
          BYTE 064H
          BYTE 06cH
          BYTE 065H
          BYTE 064H
          BYTE 045H
          BYTE 078H
          BYTE 063H
          BYTE 065H
          BYTE 070H
          BYTE 074H
          BYTE 069H
          BYTE 06fH
          BYTE 06eH
          BYTE 046H
          BYTE 069H
          BYTE 06cH
          BYTE 074H
          BYTE 065H
          BYTE 072H
          BYTE 000H
          BYTE 06aH
          BYTE 005H
          BYTE 053H
          BYTE 06cH
          BYTE 065H
          BYTE 065H
          BYTE 070H
          BYTE 000H
          BYTE 079H
          BYTE 005H
          BYTE 054H
          BYTE 065H
          BYTE 072H
          BYTE 06dH
          BYTE 069H
          BYTE 06eH
          BYTE 061H
          BYTE 074H
          BYTE 065H
          BYTE 050H
          BYTE 072H
          BYTE 06fH
          BYTE 063H
          BYTE 065H
          BYTE 073H
          BYTE 073H
          BYTE 000H
          BYTE 000H
          BYTE 08dH
          BYTE 005H
          BYTE 054H
          BYTE 06cH
          BYTE 073H
          BYTE 047H
          BYTE 065H
          BYTE 074H
          BYTE 056H
          BYTE 061H
          BYTE 06cH
          BYTE 075H
          BYTE 065H
          BYTE 000H
          BYTE 09bH
          BYTE 005H
          BYTE 055H
          BYTE 06eH
          BYTE 068H
          BYTE 061H
          BYTE 06eH
          BYTE 064H
          BYTE 06cH
          BYTE 065H
          BYTE 064H
          BYTE 045H
          BYTE 078H
          BYTE 063H
          BYTE 065H
          BYTE 070H
          BYTE 074H
          BYTE 069H
          BYTE 06fH
          BYTE 06eH
          BYTE 046H
          BYTE 069H
          BYTE 06cH
          BYTE 074H
          BYTE 065H
          BYTE 072H
          BYTE 000H
          BYTE 000H
          BYTE 0bdH
          BYTE 005H
          BYTE 056H
          BYTE 069H
          BYTE 072H
          BYTE 074H
          BYTE 075H
          BYTE 061H
          BYTE 06cH
          BYTE 050H
          BYTE 072H
          BYTE 06fH
          BYTE 074H
          BYTE 065H
          BYTE 063H
          BYTE 074H
          BYTE 000H
          BYTE 000H
          BYTE 0c0H
          BYTE 005H
          BYTE 056H
          BYTE 069H
          BYTE 072H
          BYTE 074H
          BYTE 075H
          BYTE 061H
          BYTE 06cH
          BYTE 051H
          BYTE 075H
          BYTE 065H
          BYTE 072H
          BYTE 079H
          BYTE 000H
          BYTE 000H
          BYTE 03aH
          BYTE 000H
          BYTE 05fH
          BYTE 05fH
          BYTE 067H
          BYTE 065H
          BYTE 074H
          BYTE 06dH
          BYTE 061H
          BYTE 069H
          BYTE 06eH
          BYTE 061H
          BYTE 072H
          BYTE 067H
          BYTE 073H
          BYTE 000H
          BYTE 03bH
          BYTE 000H
          BYTE 05fH
          BYTE 05fH
          BYTE 069H
          BYTE 06eH
          BYTE 069H
          BYTE 074H
          BYTE 065H
          BYTE 06eH
          BYTE 076H
          BYTE 000H
          BYTE 044H
          BYTE 000H
          BYTE 05fH
          BYTE 05fH
          BYTE 06cH
          BYTE 063H
          BYTE 06fH
          BYTE 06eH
          BYTE 076H
          BYTE 05fH
          BYTE 069H
          BYTE 06eH
          BYTE 069H
          BYTE 074H
          BYTE 000H
          BYTE 000H
          BYTE 04cH
          BYTE 000H
          BYTE 05fH
          BYTE 05fH
          BYTE 070H
          BYTE 05fH
          BYTE 05fH
          BYTE 061H
          BYTE 063H
          BYTE 06dH
          BYTE 064H
          BYTE 06cH
          BYTE 06eH
          BYTE 000H
          BYTE 053H
          BYTE 000H
          BYTE 05fH
          BYTE 05fH
          BYTE 070H
          BYTE 05fH
          BYTE 05fH
          BYTE 066H
          BYTE 06dH
          BYTE 06fH
          BYTE 064H
          BYTE 065H
          BYTE 000H
          BYTE 000H
          BYTE 068H
          BYTE 000H
          BYTE 05fH
          BYTE 05fH
          BYTE 073H
          BYTE 065H
          BYTE 074H
          BYTE 05fH
          BYTE 061H
          BYTE 070H
          BYTE 070H
          BYTE 05fH
          BYTE 074H
          BYTE 079H
          BYTE 070H
          BYTE 065H
          BYTE 000H
          BYTE 000H
          BYTE 06bH
          BYTE 000H
          BYTE 05fH
          BYTE 05fH
          BYTE 073H
          BYTE 065H
          BYTE 074H
          BYTE 075H
          BYTE 073H
          BYTE 065H
          BYTE 072H
          BYTE 06dH
          BYTE 061H
          BYTE 074H
          BYTE 068H
          BYTE 065H
          BYTE 072H
          BYTE 072H
          BYTE 000H
          BYTE 000H
          BYTE 08eH
          BYTE 000H
          BYTE 05fH
          BYTE 061H
          BYTE 06dH
          BYTE 073H
          BYTE 067H
          BYTE 05fH
          BYTE 065H
          BYTE 078H
          BYTE 069H
          BYTE 074H
          BYTE 000H
          BYTE 000H
          BYTE 09fH
          BYTE 000H
          BYTE 05fH
          BYTE 063H
          BYTE 065H
          BYTE 078H
          BYTE 069H
          BYTE 074H
          BYTE 000H
          BYTE 000H
          BYTE 02fH
          BYTE 001H
          BYTE 05fH
          BYTE 069H
          BYTE 06eH
          BYTE 069H
          BYTE 074H
          BYTE 074H
          BYTE 065H
          BYTE 072H
          BYTE 06dH
          BYTE 000H
          BYTE 033H
          BYTE 001H
          BYTE 05fH
          BYTE 069H
          BYTE 06fH
          BYTE 062H
          BYTE 000H
          BYTE 000H
          BYTE 039H
          BYTE 002H
          BYTE 05fH
          BYTE 06fH
          BYTE 06eH
          BYTE 065H
          BYTE 078H
          BYTE 069H
          BYTE 074H
          BYTE 000H
          BYTE 09aH
          BYTE 003H
          BYTE 061H
          BYTE 062H
          BYTE 06fH
          BYTE 072H
          BYTE 074H
          BYTE 000H
          BYTE 0a7H
          BYTE 003H
          BYTE 063H
          BYTE 061H
          BYTE 06cH
          BYTE 06cH
          BYTE 06fH
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 0b1H
          BYTE 003H
          BYTE 065H
          BYTE 078H
          BYTE 069H
          BYTE 074H
          BYTE 000H
          BYTE 000H
          BYTE 0c1H
          BYTE 003H
          BYTE 066H
          BYTE 070H
          BYTE 072H
          BYTE 069H
          BYTE 06eH
          BYTE 074H
          BYTE 066H
          BYTE 000H
          BYTE 0c8H
          BYTE 003H
          BYTE 066H
          BYTE 072H
          BYTE 065H
          BYTE 065H
          BYTE 000H
          BYTE 000H
          BYTE 0d4H
          BYTE 003H
          BYTE 066H
          BYTE 077H
          BYTE 072H
          BYTE 069H
          BYTE 074H
          BYTE 065H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 004H
          BYTE 06dH
          BYTE 061H
          BYTE 06cH
          BYTE 06cH
          BYTE 06fH
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 004H
          BYTE 06dH
          BYTE 065H
          BYTE 06dH
          BYTE 063H
          BYTE 070H
          BYTE 079H
          BYTE 000H
          BYTE 000H
          BYTE 00fH
          BYTE 004H
          BYTE 070H
          BYTE 072H
          BYTE 069H
          BYTE 06eH
          BYTE 074H
          BYTE 066H
          BYTE 000H
          BYTE 000H
          BYTE 023H
          BYTE 004H
          BYTE 073H
          BYTE 069H
          BYTE 067H
          BYTE 06eH
          BYTE 061H
          BYTE 06cH
          BYTE 000H
          BYTE 000H
          BYTE 035H
          BYTE 004H
          BYTE 073H
          BYTE 074H
          BYTE 072H
          BYTE 06cH
          BYTE 065H
          BYTE 06eH
          BYTE 000H
          BYTE 000H
          BYTE 038H
          BYTE 004H
          BYTE 073H
          BYTE 074H
          BYTE 072H
          BYTE 06eH
          BYTE 063H
          BYTE 06dH
          BYTE 070H
          BYTE 000H
          BYTE 057H
          BYTE 004H
          BYTE 076H
          BYTE 066H
          BYTE 070H
          BYTE 072H
          BYTE 069H
          BYTE 06eH
          BYTE 074H
          BYTE 066H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 04bH
          BYTE 045H
          BYTE 052H
          BYTE 04eH
          BYTE 045H
          BYTE 04cH
          BYTE 033H
          BYTE 032H
          BYTE 02eH
          BYTE 064H
          BYTE 06cH
          BYTE 06cH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 06dH
          BYTE 073H
          BYTE 076H
          BYTE 063H
          BYTE 072H
          BYTE 074H
          BYTE 02eH
          BYTE 064H
          BYTE 06cH
          BYTE 06cH
          BYTE 000H
          BYTE 000H
;===================================
_IDATA   ENDS
;===================================

;===================================
_CRT     SEGMENT
;===================================

ALIGN 16
$L_407000           DB 4 DUP(0)
          DWORD $L_401120
$L_407008           DB 4 DUP(0)
$L_40700c           DB 4 DUP(0)
          DWORD $L_401010
          DWORD $L_4018a0
$L_407018           DB 8 DUP(0)
$L_407020           DWORD $L_401a60
          DWORD $L_401a10
          DB 8 DUP(0)
$L_407030           DB 4 DUP(0)
;===================================
_CRT     ENDS
;===================================

;===================================
_TLS     SEGMENT
;===================================

ALIGN 16
$L_408000           DB 4 DUP(0)
$L_408004           DB 4 DUP(0)
;===================================
_TLS     ENDS
;===================================

END