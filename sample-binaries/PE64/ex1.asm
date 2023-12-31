INCLUDELIB KERNEL32.lib
INCLUDELIB VCRUNTIME140.lib
INCLUDELIB api-ms-win-crt-stdio-l1-1-0.lib
INCLUDELIB api-ms-win-crt-runtime-l1-1-0.lib
INCLUDELIB api-ms-win-crt-math-l1-1-0.lib
INCLUDELIB api-ms-win-crt-locale-l1-1-0.lib
INCLUDELIB api-ms-win-crt-heap-l1-1-0.lib

EXTERN __imp_GetCurrentProcessId:PROC
EXTERN GetCurrentProcessId:PROC
EXTERN __imp_GetCurrentThreadId:PROC
EXTERN GetCurrentThreadId:PROC
EXTERN __imp_GetModuleHandleW:PROC
EXTERN GetModuleHandleW:PROC
EXTERN __imp_GetSystemTimeAsFileTime:PROC
EXTERN GetSystemTimeAsFileTime:PROC
EXTERN __imp_InitializeSListHead:PROC
EXTERN InitializeSListHead:PROC
EXTERN __imp_IsDebuggerPresent:PROC
EXTERN IsDebuggerPresent:PROC
EXTERN __imp_IsProcessorFeaturePresent:PROC
EXTERN IsProcessorFeaturePresent:PROC
EXTERN __imp_QueryPerformanceCounter:PROC
EXTERN QueryPerformanceCounter:PROC
EXTERN __imp_RtlCaptureContext:PROC
EXTERN RtlCaptureContext:PROC
EXTERN __imp_RtlLookupFunctionEntry:PROC
EXTERN RtlLookupFunctionEntry:PROC
EXTERN __imp_RtlVirtualUnwind:PROC
EXTERN RtlVirtualUnwind:PROC
EXTERN __imp_SetUnhandledExceptionFilter:PROC
EXTERN SetUnhandledExceptionFilter:PROC
EXTERN __imp_UnhandledExceptionFilter:PROC
EXTERN UnhandledExceptionFilter:PROC
EXTERN __imp___C_specific_handler:PROC
EXTERN __C_specific_handler:PROC
EXTERN __imp___current_exception:PROC
EXTERN __current_exception:PROC
EXTERN __imp___current_exception_context:PROC
EXTERN __current_exception_context:PROC
EXTERN __imp___p___argc:PROC
EXTERN __p___argc:PROC
EXTERN __imp___p___argv:PROC
EXTERN __p___argv:PROC
EXTERN __imp___p__commode:PROC
EXTERN __p__commode:PROC
EXTERN __imp___setusermatherr:PROC
EXTERN __setusermatherr:PROC
EXTERN __imp__c_exit:PROC
EXTERN _c_exit:PROC
EXTERN __imp__cexit:PROC
EXTERN _cexit:PROC
EXTERN __imp__configthreadlocale:PROC
EXTERN _configthreadlocale:PROC
EXTERN __imp__configure_narrow_argv:PROC
EXTERN _configure_narrow_argv:PROC
EXTERN __imp__crt_atexit:PROC
EXTERN _crt_atexit:PROC
EXTERN __imp__exit:PROC
EXTERN _exit:PROC
EXTERN __imp__get_initial_narrow_environment:PROC
EXTERN _get_initial_narrow_environment:PROC
EXTERN __imp__initialize_narrow_environment:PROC
EXTERN _initialize_narrow_environment:PROC
EXTERN __imp__initialize_onexit_table:PROC
EXTERN _initialize_onexit_table:PROC
EXTERN __imp__initterm:PROC
EXTERN _initterm:PROC
EXTERN __imp__initterm_e:PROC
EXTERN _initterm_e:PROC
EXTERN __imp__register_onexit_function:PROC
EXTERN _register_onexit_function:PROC
EXTERN __imp__register_thread_local_exe_atexit_callback:PROC
EXTERN _register_thread_local_exe_atexit_callback:PROC
EXTERN __imp__seh_filter_exe:PROC
EXTERN _seh_filter_exe:PROC
EXTERN __imp__set_app_type:PROC
EXTERN _set_app_type:PROC
EXTERN __imp__set_fmode:PROC
EXTERN _set_fmode:PROC
EXTERN __imp__set_new_mode:PROC
EXTERN _set_new_mode:PROC
EXTERN __imp_exit:PROC
EXTERN exit:PROC
EXTERN __imp_memset:PROC
EXTERN memset:PROC
EXTERN __imp_puts:PROC
EXTERN puts:PROC
EXTERN __imp_terminate:PROC
EXTERN terminate:PROC

EXTERN __ImageBase:BYTE


;===================================
_TEXT    SEGMENT
;===================================

ALIGN 16
FUN_5368713216:

            mov DWORD PTR [RSP+16],EDX
            mov DWORD PTR [RSP+8],ECX
            sub RSP,24
            mov DWORD PTR [RSP],0
$L_140001013:

            mov EAX,DWORD PTR [RSP+40]
            cmp DWORD PTR [RSP+32],EAX
            jge $L_140001031

            mov EAX,DWORD PTR [RSP]
            inc EAX
            mov DWORD PTR [RSP],EAX
            mov EAX,DWORD PTR [RSP+32]
            inc EAX
            mov DWORD PTR [RSP+32],EAX
            jmp $L_140001013
$L_140001031:

            add RSP,24
            ret 

          
          
          
          
          
          
          
          
          
          FUN_5368713280:
main:

            sub RSP,40
            mov EDX,20
            mov ECX,10
            call FUN_5368713216

            lea RCX,QWORD PTR [$L_140003000]
            call QWORD PTR __imp_puts

            xor EAX,EAX
            add RSP,40
            ret 

          $L_140001068:

            push RBX
            sub RSP,32
            mov ECX,1
            call _set_app_type

            call FUN_5368714724

            mov ECX,EAX
            call _set_fmode

            call FUN_5368714712

            mov EBX,EAX
            call __p__commode

            mov ECX,1
            mov DWORD PTR [RAX],EBX
            call FUN_5368714084

            test AL,AL
            je $L_140001113

            call FUN_5368715368

            lea RCX,QWORD PTR [$L_1400018a4]
            call FUN_5368714516

            call FUN_5368714716

            mov ECX,EAX
            call _configure_narrow_argv

            test EAX,EAX
            jne $L_140001113

            call FUN_5368714732

            call FUN_5368714800

            test EAX,EAX
            je $L_1400010db

            lea RCX,QWORD PTR [FUN_5368714712]
            call __setusermatherr
$L_1400010db:

            call FUN_5368714752

            call FUN_5368714752

            call FUN_5368714712

            mov ECX,EAX
            call _configthreadlocale

            call FUN_5368714748

            test AL,AL
            je $L_1400010ff

            call _initialize_narrow_environment
$L_1400010ff:

            call FUN_5368714712

            call FUN_5368715168

            test EAX,EAX
            jne $L_140001113

            add RSP,32
            pop RBX
            ret 
$L_140001113:

            mov ECX,7
            call FUN_5368714836

          
          
          $L_140001120:

            sub RSP,40
            call FUN_5368714772

            xor EAX,EAX
            add RSP,40
            ret 
$L_140001130:

            sub RSP,40
            call FUN_5368715260

            call FUN_5368714712

            mov ECX,EAX
            add RSP,40
            jmp _set_new_mode

          
          
          $L_14000114c:

            mov QWORD PTR [RSP+8],RBX
            mov QWORD PTR [RSP+16],RSI
            push RDI
            sub RSP,48
            mov ECX,1
            call FUN_5368714008

            test AL,AL
            je $L_1400012a3

            xor SIL,SIL
            mov BYTE PTR [RSP+32],SIL
            call FUN_5368713948

            mov BL,AL
            mov ECX,DWORD PTR [$L_140003060]
            cmp ECX,1
            je $L_1400012ae

            test ECX,ECX
            jne $L_1400011d9

            mov DWORD PTR [$L_140003060],1
            lea RDX,QWORD PTR [$L_1400021d8]
            lea RCX,QWORD PTR [$L_1400021c0]
            call _initterm_e

            test EAX,EAX
            je $L_1400011ba

            mov EAX,255
            jmp $L_140001293
$L_1400011ba:

            lea RDX,QWORD PTR [$L_1400021b8]
            lea RCX,QWORD PTR [$L_1400021a8]
            call _initterm

            mov DWORD PTR [$L_140003060],2
            jmp $L_1400011e1
$L_1400011d9:

            mov SIL,1
            mov BYTE PTR [RSP+32],SIL
$L_1400011e1:

            mov CL,BL
            call FUN_5368714376

            call FUN_5368714812

            mov RBX,RAX
            cmp QWORD PTR [RAX],0
            je $L_140001214

            mov RCX,RAX
            call FUN_5368714224

            test AL,AL
            je $L_140001214

            xor R8D,R8D
            lea EDX,DWORD PTR [R8+2]
            xor ECX,ECX
            mov RAX,QWORD PTR [RBX]
            call QWORD PTR [$L_140002190]
$L_140001214:

            call FUN_5368714820

            mov RBX,RAX
            cmp QWORD PTR [RAX],0
            je $L_140001236

            mov RCX,RAX
            call FUN_5368714224

            test AL,AL
            je $L_140001236

            mov RCX,QWORD PTR [RBX]
            call _register_thread_local_exe_atexit_callback
$L_140001236:

            call _get_initial_narrow_environment

            mov RDI,RAX
            call __p___argv

            mov RBX,QWORD PTR [RAX]
            call __p___argc

            mov R8,RDI
            mov RDX,RBX
            mov ECX,DWORD PTR [RAX]
            call main

            mov EBX,EAX
            call FUN_5368715176

            test AL,AL
            je $L_1400012b8

            test SIL,SIL
            jne $L_14000126d

            call _cexit
$L_14000126d:

            xor EDX,EDX
            mov CL,1
            call FUN_5368714412

            mov EAX,EBX
            jmp $L_140001293

            mov EBX,EAX
            call FUN_5368715176

            test AL,AL
            je $L_1400012c0

            cmp BYTE PTR [RSP+32],0
            jne $L_140001291

            call _c_exit
$L_140001291:

            mov EAX,EBX
$L_140001293:

            mov RBX,QWORD PTR [RSP+64]
            mov RSI,QWORD PTR [RSP+72]
            add RSP,48
            pop RDI
            ret 
$L_1400012a3:

            mov ECX,7
            call FUN_5368714836

            nop
$L_1400012ae:

            mov ECX,7
            call FUN_5368714836
$L_1400012b8:

            mov ECX,EBX
            call exit

            nop
$L_1400012c0:

            mov ECX,EBX
            call _exit

            nop
FUN_5368713928:
__EntryPoint PROC EXPORT
__EntryPoint ENDP

            sub RSP,40
            call FUN_5368714540

            add RSP,40
            jmp $L_14000114c

          
          FUN_5368713948:

            sub RSP,40
            call FUN_5368715908

            test EAX,EAX
            je $L_14000130a

            mov RAX,QWORD PTR GS:[48]
            mov RCX,QWORD PTR [RAX+8]
            jmp $L_1400012fd
$L_1400012f8:

            cmp RCX,RAX
            je $L_140001311
$L_1400012fd:

            xor EAX,EAX
            lock cmpxchg QWORD PTR [$L_140003068],RCX
            jne $L_1400012f8
$L_14000130a:

            xor AL,AL
$L_14000130c:

            add RSP,40
            ret 
$L_140001311:

            mov AL,1
            jmp $L_14000130c

          
          
          FUN_5368714008:

            push RBX
            sub RSP,32
            movzx EAX,BYTE PTR [$L_140003070]
            test ECX,ECX
            mov EBX,1
            cmove EAX,EBX
            mov BYTE PTR [$L_140003070],AL
            call FUN_5368715488

            call FUN_5368714748

            test AL,AL
            jne $L_140001347
$L_140001343:

            xor AL,AL
            jmp $L_14000135b
$L_140001347:

            call FUN_5368714748

            test AL,AL
            jne $L_140001359

            xor ECX,ECX
            call FUN_5368714748

            jmp $L_140001343
$L_140001359:

            mov AL,BL
$L_14000135b:

            add RSP,32
            pop RBX
            ret 

          
          
          FUN_5368714084:

            push RBX
            sub RSP,32
            cmp BYTE PTR [$L_140003071],0
            mov EBX,ECX
            jne $L_1400013dc

            cmp ECX,1
            ja $L_1400013e4

            call FUN_5368715908

            test EAX,EAX
            je $L_1400013ab

            test EBX,EBX
            jne $L_1400013ab

            lea RCX,QWORD PTR [$L_140003078]
            call _initialize_onexit_table

            test EAX,EAX
            jne $L_1400013a7

            lea RCX,QWORD PTR [$L_140003090]
            call _initialize_onexit_table

            test EAX,EAX
            je $L_1400013d5
$L_1400013a7:

            xor AL,AL
            jmp $L_1400013de
$L_1400013ab:

            movdqa XMM0,XMMWORD PTR [$L_140002200]
            or RAX,-1
            movdqu XMMWORD PTR [$L_140003078],XMM0
            mov QWORD PTR [$L_140003088],RAX
            movdqu XMMWORD PTR [$L_140003090],XMM0
            mov QWORD PTR [$L_1400030a0],RAX
$L_1400013d5:

            mov BYTE PTR [$L_140003071],1
$L_1400013dc:

            mov AL,1
$L_1400013de:

            add RSP,32
            pop RBX
            ret 
$L_1400013e4:

            mov ECX,5
            call FUN_5368714836

          
          FUN_5368714224:

            sub RSP,24
            mov R8,RCX
            mov EAX,23117
            cmp WORD PTR [__ImageBase],AX
            jne $L_14000147d

            movsxd RCX,DWORD PTR [__ImageBase+60]
            lea RDX,QWORD PTR [__ImageBase]
            add RCX,RDX
            cmp DWORD PTR [RCX],17744
            jne $L_14000147d

            mov EAX,523
            cmp WORD PTR [RCX+24],AX
            jne $L_14000147d

            sub R8,RDX
            movzx EAX,WORD PTR [RCX+20]
            lea RDX,QWORD PTR [RCX+24]
            add RDX,RAX
            movzx EAX,WORD PTR [RCX+6]
            lea RCX,QWORD PTR [RAX+RAX*4]
            lea R9,QWORD PTR [RDX+RCX*8]
$L_140001443:

            mov QWORD PTR [RSP],RDX
            cmp RDX,R9
            je $L_140001464

            mov ECX,DWORD PTR [RDX+12]
            cmp R8,RCX
            jb $L_14000145e

            mov EAX,DWORD PTR [RDX+8]
            add EAX,ECX
            cmp R8,RAX
            jb $L_140001466
$L_14000145e:

            add RDX,40
            jmp $L_140001443
$L_140001464:

            xor EDX,EDX
$L_140001466:

            test RDX,RDX
            jne $L_14000146f

            xor AL,AL
            jmp $L_140001483
$L_14000146f:

            cmp DWORD PTR [RDX+36],0
            jge $L_140001479

            xor AL,AL
            jmp $L_140001483
$L_140001479:

            mov AL,1
            jmp $L_140001483
$L_14000147d:

            xor AL,AL
            jmp $L_140001483

            xor AL,AL
$L_140001483:

            add RSP,24
            ret 
FUN_5368714376:

            push RBX
            sub RSP,32
            mov BL,CL
            call FUN_5368715908

            xor EDX,EDX
            test EAX,EAX
            je $L_1400014a6

            test BL,BL
            jne $L_1400014a6

            xchg QWORD PTR [$L_140003068],RDX
$L_1400014a6:

            add RSP,32
            pop RBX
            ret 
FUN_5368714412:

            push RBX
            sub RSP,32
            cmp BYTE PTR [$L_140003070],0
            mov BL,CL
            je $L_1400014c1

            test DL,DL
            jne $L_1400014cd
$L_1400014c1:

            call FUN_5368714748

            mov CL,BL
            call FUN_5368714748
$L_1400014cd:

            mov AL,1
            add RSP,32
            pop RBX
            ret 

          
          
          FUN_5368714456:

            push RBX
            sub RSP,32
            cmp QWORD PTR [$L_140003078],-1
            mov RBX,RCX
            jne $L_1400014f2

            call _crt_atexit

            jmp $L_140001501
$L_1400014f2:

            mov RDX,RBX
            lea RCX,QWORD PTR [$L_140003078]
            call _register_onexit_function
$L_140001501:

            xor EDX,EDX
            test EAX,EAX
            cmove RDX,RBX
            mov RAX,RDX
            add RSP,32
            pop RBX
            ret 

          
          FUN_5368714516:

            sub RSP,40
            call FUN_5368714456

            neg RAX
            sbb EAX,EAX
            neg EAX
            dec EAX
            add RSP,40
            ret 

          FUN_5368714540:

            mov QWORD PTR [RSP+32],RBX
            push RBP
            mov RBP,RSP
            sub RSP,32
            mov RAX,QWORD PTR [$L_140003040]
            mov RBX,47936899621426
            cmp RAX,RBX
            jne $L_1400015c3

            and QWORD PTR [RBP+24],0
            lea RCX,QWORD PTR [RBP+24]
            call QWORD PTR __imp_GetSystemTimeAsFileTime

            mov RAX,QWORD PTR [RBP+24]
            mov QWORD PTR [RBP+16],RAX
            call QWORD PTR __imp_GetCurrentThreadId

            mov EAX,EAX
            xor QWORD PTR [RBP+16],RAX
            call QWORD PTR __imp_GetCurrentProcessId

            mov EAX,EAX
            lea RCX,QWORD PTR [RBP+32]
            xor QWORD PTR [RBP+16],RAX
            call QWORD PTR __imp_QueryPerformanceCounter

            mov EAX,DWORD PTR [RBP+32]
            lea RCX,QWORD PTR [RBP+16]
            shl RAX,32
            xor RAX,QWORD PTR [RBP+32]
            xor RAX,QWORD PTR [RBP+16]
            xor RAX,RCX
            mov RCX,281474976710655
            and RAX,RCX
            mov RCX,47936899621427
            cmp RAX,RBX
            cmove RAX,RCX
            mov QWORD PTR [$L_140003040],RAX
$L_1400015c3:

            mov RBX,QWORD PTR [RSP+72]
            not RAX
            mov QWORD PTR [$L_140003038],RAX
            add RSP,32
            pop RBP
            ret 
FUN_5368714712:

            xor EAX,EAX
            ret 

          FUN_5368714716:

            mov EAX,1
            ret 

          
          FUN_5368714724:

            mov EAX,16384
            ret 

          
          FUN_5368714732:

            lea RCX,QWORD PTR [$L_1400030b0]
            jmp QWORD PTR __imp_InitializeSListHead

          
          FUN_5368714748:

            mov AL,1
            ret 

          FUN_5368714752:

            ret 0

          FUN_5368714756:

            lea RAX,QWORD PTR [$L_1400030c0]
            ret 
FUN_5368714764:

            lea RAX,QWORD PTR [$L_1400030c8]
            ret 
FUN_5368714772:

            sub RSP,40
            call FUN_5368714756

            or QWORD PTR [RAX],36
            call FUN_5368714764

            or QWORD PTR [RAX],2
            add RSP,40
            ret 

          FUN_5368714800:

            xor EAX,EAX
            cmp DWORD PTR [$L_140003018],EAX
            sete AL
            ret 
FUN_5368714812:

            lea RAX,QWORD PTR [$L_1400030f0]
            ret 
FUN_5368714820:

            lea RAX,QWORD PTR [$L_1400030e8]
            ret 
FUN_5368714828:

            and DWORD PTR [$L_1400030d0],0
            ret 
FUN_5368714836:

            mov QWORD PTR [RSP+8],RBX
            push RBP
            lea RBP,QWORD PTR [RSP-1216]
            sub RSP,1472
            mov EBX,ECX
            mov ECX,23
            call QWORD PTR __imp_IsProcessorFeaturePresent

            test EAX,EAX
            je $L_14000167e

            mov ECX,EBX
            int 41
$L_14000167e:

            mov ECX,3
            call FUN_5368714828

            xor EDX,EDX
            lea RCX,QWORD PTR [RBP-16]
            mov R8D,1232
            call memset

            lea RCX,QWORD PTR [RBP-16]
            call QWORD PTR __imp_RtlCaptureContext

            mov RBX,QWORD PTR [RBP+232]
            lea RDX,QWORD PTR [RBP+1240]
            mov RCX,RBX
            xor R8D,R8D
            call QWORD PTR __imp_RtlLookupFunctionEntry

            test RAX,RAX
            je $L_1400016fe

            and QWORD PTR [RSP+56],0
            lea RCX,QWORD PTR [RBP+1248]
            mov RDX,QWORD PTR [RBP+1240]
            mov R9,RAX
            mov QWORD PTR [RSP+48],RCX
            mov R8,RBX
            lea RCX,QWORD PTR [RBP+1256]
            mov QWORD PTR [RSP+40],RCX
            lea RCX,QWORD PTR [RBP-16]
            mov QWORD PTR [RSP+32],RCX
            xor ECX,ECX
            call QWORD PTR __imp_RtlVirtualUnwind
$L_1400016fe:

            mov RAX,QWORD PTR [RBP+1224]
            lea RCX,QWORD PTR [RSP+80]
            mov QWORD PTR [RBP+232],RAX
            xor EDX,EDX
            lea RAX,QWORD PTR [RBP+1224]
            mov R8D,152
            add RAX,8
            mov QWORD PTR [RBP+136],RAX
            call memset

            mov RAX,QWORD PTR [RBP+1224]
            mov QWORD PTR [RSP+96],RAX
            mov DWORD PTR [RSP+80],1073741845
            mov DWORD PTR [RSP+84],1
            call QWORD PTR __imp_IsDebuggerPresent

            cmp EAX,1
            lea RAX,QWORD PTR [RSP+80]
            mov QWORD PTR [RSP+64],RAX
            lea RAX,QWORD PTR [RBP-16]
            sete BL
            mov QWORD PTR [RSP+72],RAX
            xor ECX,ECX
            call QWORD PTR __imp_SetUnhandledExceptionFilter

            lea RCX,QWORD PTR [RSP+64]
            call QWORD PTR __imp_UnhandledExceptionFilter

            test EAX,EAX
            jne $L_14000178e

            test BL,BL
            jne $L_14000178e

            lea ECX,DWORD PTR [RAX+3]
            call FUN_5368714828
$L_14000178e:

            mov RBX,QWORD PTR [RSP+1488]
            add RSP,1472
            pop RBP
            ret 

          FUN_5368715168:

            jmp FUN_5368714712

          
          
          FUN_5368715176:

            sub RSP,40
            xor ECX,ECX
            call QWORD PTR __imp_GetModuleHandleW

            test RAX,RAX
            je $L_1400017f3

            mov ECX,23117
            cmp WORD PTR [RAX],CX
            jne $L_1400017f3

            movsxd RCX,DWORD PTR [RAX+60]
            add RCX,RAX
            cmp DWORD PTR [RCX],17744
            jne $L_1400017f3

            mov EAX,523
            cmp WORD PTR [RCX+24],AX
            jne $L_1400017f3

            cmp DWORD PTR [RCX+132],14
            jbe $L_1400017f3

            cmp DWORD PTR [RCX+248],0
            je $L_1400017f3

            mov AL,1
            jmp $L_1400017f5
$L_1400017f3:

            xor AL,AL
$L_1400017f5:

            add RSP,40
            ret 

          
          FUN_5368715260:

            lea RCX,QWORD PTR [$L_14000180c]
            jmp QWORD PTR __imp_SetUnhandledExceptionFilter

          
          $L_14000180c:

            mov QWORD PTR [RSP+8],RBX
            push RDI
            sub RSP,32
            mov RBX,QWORD PTR [RCX]
            mov RDI,RCX
            cmp DWORD PTR [RBX],3765269347
            jne $L_140001840

            cmp DWORD PTR [RBX+24],4
            jne $L_140001840

            mov EDX,DWORD PTR [RBX+32]
            lea EAX,DWORD PTR [RDX-429065504]
            cmp EAX,2
            jbe $L_14000184d

            cmp EDX,26820608
            je $L_14000184d
$L_140001840:

            mov RBX,QWORD PTR [RSP+48]
            xor EAX,EAX
            add RSP,32
            pop RDI
            ret 
$L_14000184d:

            call __current_exception

            mov QWORD PTR [RAX],RBX
            mov RBX,QWORD PTR [RDI+8]
            call __current_exception_context

            mov QWORD PTR [RAX],RBX
            call terminate

          
          FUN_5368715368:

            mov QWORD PTR [RSP+8],RBX
            push RDI
            sub RSP,32
            lea RBX,QWORD PTR [$L_1400025d0]
            lea RDI,QWORD PTR [$L_1400025d0]
            jmp $L_140001894
$L_140001882:

            mov RAX,QWORD PTR [RBX]
            test RAX,RAX
            je $L_140001890

            call QWORD PTR [$L_140002190]
$L_140001890:

            add RBX,8
$L_140001894:

            cmp RBX,RDI
            jb $L_140001882

            mov RBX,QWORD PTR [RSP+48]
            add RSP,32
            pop RDI
            ret 
$L_1400018a4:

            mov QWORD PTR [RSP+8],RBX
            push RDI
            sub RSP,32
            lea RBX,QWORD PTR [$L_1400025e0]
            lea RDI,QWORD PTR [$L_1400025e0]
            jmp $L_1400018d0
$L_1400018be:

            mov RAX,QWORD PTR [RBX]
            test RAX,RAX
            je $L_1400018cc

            call QWORD PTR [$L_140002190]
$L_1400018cc:

            add RBX,8
$L_1400018d0:

            cmp RBX,RDI
            jb $L_1400018be

            mov RBX,QWORD PTR [RSP+48]
            add RSP,32
            pop RDI
            ret 
FUN_5368715488:

            mov QWORD PTR [RSP+16],RBX
            mov QWORD PTR [RSP+24],RSI
            push RDI
            sub RSP,16
            xor EAX,EAX
            xor ECX,ECX
            cpuid 
            mov R8D,ECX
            xor R11D,R11D
            mov R9D,EBX
            xor R8D,1818588270
            xor R9D,1970169159
            mov R10D,EDX
            mov ESI,EAX
            xor ECX,ECX
            lea EAX,DWORD PTR [R11+1]
            or R9D,R8D
            cpuid 
            xor R10D,1231384169
            mov DWORD PTR [RSP],EAX
            or R9D,R10D
            mov DWORD PTR [RSP+4],EBX
            mov EDI,ECX
            mov DWORD PTR [RSP+8],ECX
            mov DWORD PTR [RSP+12],EDX
            jne $L_140001989

            or QWORD PTR [$L_140003028],-1
            and EAX,268386288
            cmp EAX,67264
            je $L_140001975

            cmp EAX,132704
            je $L_140001975

            cmp EAX,132720
            je $L_140001975

            add EAX,4294769072
            cmp EAX,32
            ja $L_140001989

            mov RCX,4295032833
            bt RCX,RAX
            jae $L_140001989
$L_140001975:

            mov R8D,DWORD PTR [$L_1400030e0]
            or R8D,1
            mov DWORD PTR [$L_1400030e0],R8D
            jmp $L_140001990
$L_140001989:

            mov R8D,DWORD PTR [$L_1400030e0]
$L_140001990:

            mov EAX,7
            lea R9D,DWORD PTR [RAX-5]
            cmp ESI,EAX
            jl $L_1400019c3

            xor ECX,ECX
            cpuid 
            mov DWORD PTR [RSP],EAX
            mov R11D,EBX
            mov DWORD PTR [RSP+4],EBX
            mov DWORD PTR [RSP+8],ECX
            mov DWORD PTR [RSP+12],EDX
            bt EBX,9
            jae $L_1400019c3

            or R8D,R9D
            mov DWORD PTR [$L_1400030e0],R8D
$L_1400019c3:

            mov DWORD PTR [$L_140003020],1
            mov DWORD PTR [$L_140003024],R9D
            bt EDI,20
            jae $L_140001a6f

            mov DWORD PTR [$L_140003020],R9D
            mov EBX,6
            mov DWORD PTR [$L_140003024],EBX
            bt EDI,27
            jae $L_140001a6f

            bt EDI,28
            jae $L_140001a6f

            xor ECX,ECX
            xgetbv 
            shl RDX,32
            or RDX,RAX
            mov QWORD PTR [RSP+32],RDX
            mov RAX,QWORD PTR [RSP+32]
            and AL,BL
            cmp AL,BL
            jne $L_140001a6f

            mov EAX,DWORD PTR [$L_140003024]
            or EAX,8
            mov DWORD PTR [$L_140003020],3
            mov DWORD PTR [$L_140003024],EAX
            test R11B,32
            je $L_140001a6f

            or EAX,32
            mov DWORD PTR [$L_140003020],5
            mov DWORD PTR [$L_140003024],EAX
            mov EAX,3489857536
            and R11D,EAX
            cmp R11D,EAX
            jne $L_140001a6f

            mov RAX,QWORD PTR [RSP+32]
            and AL,224
            cmp AL,224
            jne $L_140001a6f

            or DWORD PTR [$L_140003024],64
            mov DWORD PTR [$L_140003020],EBX
$L_140001a6f:

            mov RBX,QWORD PTR [RSP+40]
            xor EAX,EAX
            mov RSI,QWORD PTR [RSP+48]
            add RSP,16
            pop RDI
            ret 

          
          
          FUN_5368715908:

            xor EAX,EAX
            cmp DWORD PTR [$L_140003050],EAX
            setne AL
            ret 

            jmp QWORD PTR __imp___C_specific_handler
FUN_5368715926:

            jmp QWORD PTR __imp___current_exception
FUN_5368715932:

            jmp QWORD PTR __imp___current_exception_context
FUN_5368715938:

            jmp QWORD PTR __imp_memset
FUN_5368715944:

            jmp QWORD PTR __imp__seh_filter_exe
FUN_5368715950:

            jmp QWORD PTR __imp__set_app_type
FUN_5368715956:

            jmp QWORD PTR __imp___setusermatherr
FUN_5368715962:

            jmp QWORD PTR __imp__configure_narrow_argv
FUN_5368715968:

            jmp QWORD PTR __imp__initialize_narrow_environment
FUN_5368715974:

            jmp QWORD PTR __imp__get_initial_narrow_environment
FUN_5368715980:

            jmp QWORD PTR __imp__initterm
FUN_5368715986:

            jmp QWORD PTR __imp__initterm_e
FUN_5368715992:

            jmp QWORD PTR __imp_exit
FUN_5368715998:

            jmp QWORD PTR __imp__exit
FUN_5368716004:

            jmp QWORD PTR __imp__set_fmode
FUN_5368716010:

            jmp QWORD PTR __imp___p___argc
FUN_5368716016:

            jmp QWORD PTR __imp___p___argv
FUN_5368716022:

            jmp QWORD PTR __imp__cexit
FUN_5368716028:

            jmp QWORD PTR __imp__c_exit
FUN_5368716034:

            jmp QWORD PTR __imp__register_thread_local_exe_atexit_callback
FUN_5368716040:

            jmp QWORD PTR __imp__configthreadlocale
$L_140001b0e:

            jmp QWORD PTR __imp__set_new_mode
FUN_5368716052:

            jmp QWORD PTR __imp___p__commode
FUN_5368716058:

            jmp QWORD PTR __imp__initialize_onexit_table
FUN_5368716064:

            jmp QWORD PTR __imp__register_onexit_function
FUN_5368716070:

            jmp QWORD PTR __imp__crt_atexit
FUN_5368716076:

            jmp QWORD PTR __imp_terminate

          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
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
$L_140001b50:

            jmp RAX

          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
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
$L_140001b70:

            jmp QWORD PTR [$L_140002190]
$L_140001b76:

            push RBP
            sub RSP,32
            mov RBP,RDX
            mov RAX,QWORD PTR [RCX]
            mov RDX,RCX
            mov ECX,DWORD PTR [RAX]
            call _seh_filter_exe

            nop
            add RSP,32
            pop RBP
            ret 

          $L_140001b94:

            push RBP
            mov RBP,RDX
            mov RAX,QWORD PTR [RCX]
            xor ECX,ECX
            cmp DWORD PTR [RAX],3221225477
            sete CL
            mov EAX,ECX
            pop RBP
            ret 

          ;===================================
_TEXT    ENDS
;===================================

;===================================
_RDATA   SEGMENT
;===================================

ALIGN 16
$L_140002000           BYTE 0d8H
          BYTE 028H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002008           BYTE 0f2H
          BYTE 028H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002010           BYTE 008H
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002018           BYTE 01eH
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002020           BYTE 038H
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002028           BYTE 04eH
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002030           BYTE 062H
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002038           BYTE 07cH
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002040           BYTE 090H
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002048           BYTE 0a4H
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002050           BYTE 0c0H
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002058           BYTE 0deH
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002060           BYTE 0faH
          BYTE 029H
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
$L_140002070           BYTE 034H
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002078           BYTE 04aH
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002080           BYTE 068H
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002088           BYTE 01cH
          BYTE 02aH
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
$L_140002098           BYTE 0ccH
          BYTE 02bH
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
$L_1400020a8           BYTE 0b6H
          BYTE 02bH
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
$L_1400020b8           BYTE 0aeH
          BYTE 02aH
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
$L_1400020c8           BYTE 0feH
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_1400020d0           BYTE 020H
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_1400020d8           BYTE 02cH
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_1400020e0           BYTE 03aH
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_1400020e8           BYTE 08cH
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_1400020f0           BYTE 0c2H
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_1400020f8           BYTE 058H
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002100           BYTE 066H
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002108           BYTE 074H
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002110           BYTE 07eH
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002118           BYTE 088H
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002120           BYTE 09eH
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002128           BYTE 042H
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002130           BYTE 032H
          BYTE 02cH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002138           BYTE 0ecH
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002140           BYTE 008H
          BYTE 02cH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002148           BYTE 024H
          BYTE 02cH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002150           BYTE 0dcH
          BYTE 02aH
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
$L_140002160           BYTE 084H
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002168           BYTE 04aH
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140002170           BYTE 0dcH
          BYTE 02bH
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
$L_140002180           QWORD FUN_5368714752
$L_140002188           QWORD FUN_5368714752
$L_140002190           QWORD $L_140001b50
$L_140002198           QWORD $L_140001b70
$L_1400021a0           QWORD $L_140001b70
$L_1400021a8           DB 8 DUP(0)
          QWORD $L_140001130
$L_1400021b8           DB 8 DUP(0)
$L_1400021c0           DB 8 DUP(0)
          QWORD $L_140001068
          QWORD $L_140001120
$L_1400021d8           DB 40 DUP(0)
$L_140002200           BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
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
          BYTE 000H
          BYTE 0f5H
          BYTE 050H
          BYTE 052H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 00dH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 044H
          BYTE 002H
          BYTE 000H
          BYTE 000H
          BYTE 080H
          BYTE 023H
          BYTE 000H
          BYTE 000H
          BYTE 080H
          BYTE 013H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 038H
          BYTE 001H
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
          QWORD $L_140003040
          DB 16 DUP(0)
          QWORD $L_140002180
          QWORD $L_140002190
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
          BYTE 001H
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
          BYTE 000H
          BYTE 000H
          QWORD $L_140002188
          QWORD $L_140002198
          QWORD $L_1400021a0
          QWORD $L_1400030d8
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
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 010H
          BYTE 000H
          BYTE 000H
          BYTE 040H
          BYTE 00bH
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 074H
          BYTE 065H
          BYTE 078H
          BYTE 074H
          BYTE 024H
          BYTE 06dH
          BYTE 06eH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 040H
          BYTE 01bH
          BYTE 000H
          BYTE 000H
          BYTE 036H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 074H
          BYTE 065H
          BYTE 078H
          BYTE 074H
          BYTE 024H
          BYTE 06dH
          BYTE 06eH
          BYTE 024H
          BYTE 030H
          BYTE 030H
          BYTE 000H
          BYTE 076H
          BYTE 01bH
          BYTE 000H
          BYTE 000H
          BYTE 036H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 074H
          BYTE 065H
          BYTE 078H
          BYTE 074H
          BYTE 024H
          BYTE 078H
          BYTE 000H
          BYTE 000H
          BYTE 020H
          BYTE 000H
          BYTE 000H
          BYTE 080H
          BYTE 001H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 069H
          BYTE 064H
          BYTE 061H
          BYTE 074H
          BYTE 061H
          BYTE 024H
          BYTE 035H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 080H
          BYTE 021H
          BYTE 000H
          BYTE 000H
          BYTE 028H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 030H
          BYTE 030H
          BYTE 063H
          BYTE 066H
          BYTE 067H
          BYTE 000H
          BYTE 000H
          BYTE 0a8H
          BYTE 021H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 043H
          BYTE 052H
          BYTE 054H
          BYTE 024H
          BYTE 058H
          BYTE 043H
          BYTE 041H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0b0H
          BYTE 021H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 043H
          BYTE 052H
          BYTE 054H
          BYTE 024H
          BYTE 058H
          BYTE 043H
          BYTE 041H
          BYTE 041H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0b8H
          BYTE 021H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 043H
          BYTE 052H
          BYTE 054H
          BYTE 024H
          BYTE 058H
          BYTE 043H
          BYTE 05aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0c0H
          BYTE 021H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 043H
          BYTE 052H
          BYTE 054H
          BYTE 024H
          BYTE 058H
          BYTE 049H
          BYTE 041H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0c8H
          BYTE 021H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 043H
          BYTE 052H
          BYTE 054H
          BYTE 024H
          BYTE 058H
          BYTE 049H
          BYTE 041H
          BYTE 041H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0d0H
          BYTE 021H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 043H
          BYTE 052H
          BYTE 054H
          BYTE 024H
          BYTE 058H
          BYTE 049H
          BYTE 041H
          BYTE 043H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0d8H
          BYTE 021H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 043H
          BYTE 052H
          BYTE 054H
          BYTE 024H
          BYTE 058H
          BYTE 049H
          BYTE 05aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0e0H
          BYTE 021H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 043H
          BYTE 052H
          BYTE 054H
          BYTE 024H
          BYTE 058H
          BYTE 050H
          BYTE 041H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0e8H
          BYTE 021H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 043H
          BYTE 052H
          BYTE 054H
          BYTE 024H
          BYTE 058H
          BYTE 050H
          BYTE 05aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0f0H
          BYTE 021H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 043H
          BYTE 052H
          BYTE 054H
          BYTE 024H
          BYTE 058H
          BYTE 054H
          BYTE 041H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0f8H
          BYTE 021H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 043H
          BYTE 052H
          BYTE 054H
          BYTE 024H
          BYTE 058H
          BYTE 054H
          BYTE 05aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 022H
          BYTE 000H
          BYTE 000H
          BYTE 080H
          BYTE 001H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 072H
          BYTE 064H
          BYTE 061H
          BYTE 074H
          BYTE 061H
          BYTE 000H
          BYTE 000H
          BYTE 080H
          BYTE 023H
          BYTE 000H
          BYTE 000H
          BYTE 048H
          BYTE 002H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 072H
          BYTE 064H
          BYTE 061H
          BYTE 074H
          BYTE 061H
          BYTE 024H
          BYTE 07aH
          BYTE 07aH
          BYTE 07aH
          BYTE 064H
          BYTE 062H
          BYTE 067H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0c8H
          BYTE 025H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 072H
          BYTE 074H
          BYTE 063H
          BYTE 024H
          BYTE 049H
          BYTE 041H
          BYTE 041H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0d0H
          BYTE 025H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 072H
          BYTE 074H
          BYTE 063H
          BYTE 024H
          BYTE 049H
          BYTE 05aH
          BYTE 05aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0d8H
          BYTE 025H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 072H
          BYTE 074H
          BYTE 063H
          BYTE 024H
          BYTE 054H
          BYTE 041H
          BYTE 041H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0e0H
          BYTE 025H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 072H
          BYTE 074H
          BYTE 063H
          BYTE 024H
          BYTE 054H
          BYTE 05aH
          BYTE 05aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0e8H
          BYTE 025H
          BYTE 000H
          BYTE 000H
          BYTE 0ccH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 078H
          BYTE 064H
          BYTE 061H
          BYTE 074H
          BYTE 061H
          BYTE 000H
          BYTE 000H
          BYTE 0b4H
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 08cH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 069H
          BYTE 064H
          BYTE 061H
          BYTE 074H
          BYTE 061H
          BYTE 024H
          BYTE 032H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 040H
          BYTE 027H
          BYTE 000H
          BYTE 000H
          BYTE 018H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 069H
          BYTE 064H
          BYTE 061H
          BYTE 074H
          BYTE 061H
          BYTE 024H
          BYTE 033H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 058H
          BYTE 027H
          BYTE 000H
          BYTE 000H
          BYTE 080H
          BYTE 001H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 069H
          BYTE 064H
          BYTE 061H
          BYTE 074H
          BYTE 061H
          BYTE 024H
          BYTE 034H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0d8H
          BYTE 028H
          BYTE 000H
          BYTE 000H
          BYTE 00aH
          BYTE 004H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 069H
          BYTE 064H
          BYTE 061H
          BYTE 074H
          BYTE 061H
          BYTE 024H
          BYTE 036H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 030H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 064H
          BYTE 061H
          BYTE 074H
          BYTE 061H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 030H
          BYTE 000H
          BYTE 000H
          BYTE 098H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 062H
          BYTE 073H
          BYTE 073H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 040H
          BYTE 000H
          BYTE 000H
          BYTE 044H
          BYTE 001H
          BYTE 000H
          BYTE 000H
          BYTE 02eH
          BYTE 070H
          BYTE 064H
          BYTE 061H
          BYTE 074H
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
$L_1400025d0           DB 16 DUP(0)
$L_1400025e0           BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 001H
          BYTE 00cH
          BYTE 001H
          BYTE 000H
          BYTE 00cH
          BYTE 022H
          BYTE 000H
          BYTE 000H
          BYTE 001H
          BYTE 004H
          BYTE 001H
          BYTE 000H
          BYTE 004H
          BYTE 042H
          BYTE 000H
          BYTE 000H
          BYTE 001H
          BYTE 006H
          BYTE 002H
          BYTE 000H
          BYTE 006H
          BYTE 032H
          BYTE 002H
          BYTE 030H
          BYTE 001H
          BYTE 004H
          BYTE 001H
          BYTE 000H
          BYTE 004H
          BYTE 042H
          BYTE 000H
          BYTE 000H
          BYTE 009H
          BYTE 00fH
          BYTE 006H
          BYTE 000H
          BYTE 00fH
          BYTE 064H
          BYTE 009H
          BYTE 000H
          BYTE 00fH
          BYTE 034H
          BYTE 008H
          BYTE 000H
          BYTE 00fH
          BYTE 052H
          BYTE 00bH
          BYTE 070H
          BYTE 090H
          BYTE 01aH
          BYTE 000H
          BYTE 000H
          BYTE 002H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 075H
          BYTE 011H
          BYTE 000H
          BYTE 000H
          BYTE 07aH
          BYTE 012H
          BYTE 000H
          BYTE 000H
          BYTE 076H
          BYTE 01bH
          BYTE 000H
          BYTE 000H
          BYTE 07aH
          BYTE 012H
          BYTE 000H
          BYTE 000H
          BYTE 0aeH
          BYTE 012H
          BYTE 000H
          BYTE 000H
          BYTE 0c0H
          BYTE 012H
          BYTE 000H
          BYTE 000H
          BYTE 076H
          BYTE 01bH
          BYTE 000H
          BYTE 000H
          BYTE 07aH
          BYTE 012H
          BYTE 000H
          BYTE 000H
          BYTE 001H
          BYTE 006H
          BYTE 002H
          BYTE 000H
          BYTE 006H
          BYTE 032H
          BYTE 002H
          BYTE 050H
          BYTE 009H
          BYTE 004H
          BYTE 001H
          BYTE 000H
          BYTE 004H
          BYTE 022H
          BYTE 000H
          BYTE 000H
          BYTE 090H
          BYTE 01aH
          BYTE 000H
          BYTE 000H
          BYTE 001H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0f7H
          BYTE 013H
          BYTE 000H
          BYTE 000H
          BYTE 081H
          BYTE 014H
          BYTE 000H
          BYTE 000H
          BYTE 094H
          BYTE 01bH
          BYTE 000H
          BYTE 000H
          BYTE 081H
          BYTE 014H
          BYTE 000H
          BYTE 000H
          BYTE 001H
          BYTE 002H
          BYTE 001H
          BYTE 000H
          BYTE 002H
          BYTE 050H
          BYTE 000H
          BYTE 000H
          BYTE 001H
          BYTE 00dH
          BYTE 004H
          BYTE 000H
          BYTE 00dH
          BYTE 034H
          BYTE 009H
          BYTE 000H
          BYTE 00dH
          BYTE 032H
          BYTE 006H
          BYTE 050H
          BYTE 001H
          BYTE 015H
          BYTE 005H
          BYTE 000H
          BYTE 015H
          BYTE 034H
          BYTE 0baH
          BYTE 000H
          BYTE 015H
          BYTE 001H
          BYTE 0b8H
          BYTE 000H
          BYTE 006H
          BYTE 050H
          BYTE 000H
          BYTE 000H
          BYTE 001H
          BYTE 00aH
          BYTE 004H
          BYTE 000H
          BYTE 00aH
          BYTE 034H
          BYTE 006H
          BYTE 000H
          BYTE 00aH
          BYTE 032H
          BYTE 006H
          BYTE 070H
          BYTE 001H
          BYTE 00fH
          BYTE 006H
          BYTE 000H
          BYTE 00fH
          BYTE 064H
          BYTE 006H
          BYTE 000H
          BYTE 00fH
          BYTE 034H
          BYTE 005H
          BYTE 000H
          BYTE 00fH
          BYTE 012H
          BYTE 00bH
          BYTE 070H
          BYTE 001H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 001H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 058H
          BYTE 027H
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
          BYTE 00eH
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 020H
          BYTE 000H
          BYTE 000H
          BYTE 0c8H
          BYTE 027H
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
          BYTE 072H
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 070H
          BYTE 020H
          BYTE 000H
          BYTE 000H
          BYTE 0b8H
          BYTE 028H
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
          BYTE 03eH
          BYTE 02cH
          BYTE 000H
          BYTE 000H
          BYTE 060H
          BYTE 021H
          BYTE 000H
          BYTE 000H
          BYTE 020H
          BYTE 028H
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
          BYTE 05eH
          BYTE 02cH
          BYTE 000H
          BYTE 000H
          BYTE 0c8H
          BYTE 020H
          BYTE 000H
          BYTE 000H
          BYTE 010H
          BYTE 028H
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
          BYTE 080H
          BYTE 02cH
          BYTE 000H
          BYTE 000H
          BYTE 0b8H
          BYTE 020H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 028H
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
          BYTE 0a0H
          BYTE 02cH
          BYTE 000H
          BYTE 000H
          BYTE 0a8H
          BYTE 020H
          BYTE 000H
          BYTE 000H
          BYTE 0f0H
          BYTE 027H
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
          BYTE 0c2H
          BYTE 02cH
          BYTE 000H
          BYTE 000H
          BYTE 098H
          BYTE 020H
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
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0d8H
          BYTE 028H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0f2H
          BYTE 028H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 01eH
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 038H
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 04eH
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 062H
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 07cH
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 090H
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0a4H
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0c0H
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0deH
          BYTE 029H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0faH
          BYTE 029H
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
          BYTE 034H
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 04aH
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 068H
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 01cH
          BYTE 02aH
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
          BYTE 0ccH
          BYTE 02bH
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
          BYTE 0b6H
          BYTE 02bH
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
          BYTE 0aeH
          BYTE 02aH
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
          BYTE 0feH
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 020H
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 02cH
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 03aH
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 08cH
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0c2H
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 058H
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 066H
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 074H
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 07eH
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 088H
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 09eH
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 042H
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 032H
          BYTE 02cH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0ecH
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 02cH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 024H
          BYTE 02cH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0dcH
          BYTE 02aH
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
          BYTE 084H
          BYTE 02aH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 04aH
          BYTE 02bH
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0dcH
          BYTE 02bH
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
          BYTE 050H
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
          BYTE 01eH
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
                    DB 'ocessId'
          BYTE 000H

          BYTE 022H
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
          BYTE 0f0H
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
                    DB 'ileTime'
          BYTE 000H

          BYTE 06cH
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
          BYTE 053H
          BYTE 04cH
          BYTE 069H
          BYTE 073H
                    DB 'tHead'
          BYTE 000H

          BYTE 0d3H
          BYTE 004H
          BYTE 052H
          BYTE 074H
          BYTE 06cH
          BYTE 043H
          BYTE 061H
          BYTE 070H
          BYTE 074H
          BYTE 075H
          BYTE 072H
          BYTE 065H
          BYTE 043H
          BYTE 06fH
          BYTE 06eH
          BYTE 074H
          BYTE 065H
          BYTE 078H
          BYTE 074H
          BYTE 000H
          BYTE 0daH
          BYTE 004H
          BYTE 052H
          BYTE 074H
          BYTE 06cH
          BYTE 04cH
          BYTE 06fH
          BYTE 06fH
          BYTE 06bH
          BYTE 075H
          BYTE 070H
          BYTE 046H
          BYTE 075H
          BYTE 06eH
          BYTE 063H
          BYTE 074H
          BYTE 069H
          BYTE 06fH
          BYTE 06eH
          BYTE 045H
          BYTE 06eH
          BYTE 074H
          BYTE 072H
          BYTE 079H
          BYTE 000H
          BYTE 000H
          BYTE 0e1H
          BYTE 004H
          BYTE 052H
          BYTE 074H
          BYTE 06cH
          BYTE 056H
          BYTE 069H
          BYTE 072H
          BYTE 074H
          BYTE 075H
          BYTE 061H
          BYTE 06cH
                    DB 'Unwind'
          BYTE 000H

          BYTE 000H
          BYTE 082H
          BYTE 003H
          BYTE 049H
          BYTE 073H
          BYTE 044H
          BYTE 065H
          BYTE 062H
          BYTE 075H
          BYTE 067H
          BYTE 067H
          BYTE 065H
          BYTE 072H
          BYTE 050H
          BYTE 072H
          BYTE 065H
          BYTE 073H
          BYTE 065H
          BYTE 06eH
          BYTE 074H
          BYTE 000H
          BYTE 0bcH
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
                    DB 'Filter'
          BYTE 000H

          BYTE 000H
          BYTE 07bH
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
                    DB 'ilter'
          BYTE 000H

          BYTE 089H
          BYTE 003H
          BYTE 049H
          BYTE 073H
          BYTE 050H
          BYTE 072H
          BYTE 06fH
          BYTE 063H
          BYTE 065H
          BYTE 073H
          BYTE 073H
          BYTE 06fH
          BYTE 072H
          BYTE 046H
          BYTE 065H
          BYTE 061H
          BYTE 074H
          BYTE 075H
          BYTE 072H
          BYTE 065H
          BYTE 050H
          BYTE 072H
          BYTE 065H
          BYTE 073H
          BYTE 065H
          BYTE 06eH
          BYTE 074H
          BYTE 000H
          BYTE 07eH
          BYTE 002H
          BYTE 047H
          BYTE 065H
          BYTE 074H
          BYTE 04dH
          BYTE 06fH
          BYTE 064H
          BYTE 075H
          BYTE 06cH
          BYTE 065H
          BYTE 048H
          BYTE 061H
          BYTE 06eH
          BYTE 064H
          BYTE 06cH
          BYTE 065H
          BYTE 057H
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
          BYTE 008H
          BYTE 000H
          BYTE 05fH
          BYTE 05fH
          BYTE 043H
          BYTE 05fH
          BYTE 073H
          BYTE 070H
          BYTE 065H
          BYTE 063H
          BYTE 069H
          BYTE 066H
          BYTE 069H
          BYTE 063H
          BYTE 05fH
          BYTE 068H
          BYTE 061H
          BYTE 06eH
          BYTE 064H
          BYTE 06cH
          BYTE 065H
          BYTE 072H
          BYTE 000H
          BYTE 000H
          BYTE 01bH
          BYTE 000H
          BYTE 05fH
          BYTE 05fH
          BYTE 063H
          BYTE 075H
          BYTE 072H
          BYTE 072H
          BYTE 065H
          BYTE 06eH
          BYTE 074H
          BYTE 05fH
          BYTE 065H
          BYTE 078H
          BYTE 063H
          BYTE 065H
          BYTE 070H
          BYTE 074H
          BYTE 069H
          BYTE 06fH
          BYTE 06eH
          BYTE 000H
          BYTE 01cH
          BYTE 000H
          BYTE 05fH
          BYTE 05fH
          BYTE 063H
          BYTE 075H
          BYTE 072H
          BYTE 072H
          BYTE 065H
          BYTE 06eH
          BYTE 074H
          BYTE 05fH
          BYTE 065H
          BYTE 078H
          BYTE 063H
          BYTE 065H
          BYTE 070H
          BYTE 074H
          BYTE 069H
          BYTE 06fH
          BYTE 06eH
          BYTE 05fH
                    DB 'context'
          BYTE 000H

          BYTE 03eH
          BYTE 000H
          BYTE 06dH
          BYTE 065H
          BYTE 06dH
          BYTE 073H
          BYTE 065H
          BYTE 074H
          BYTE 000H
          BYTE 000H
          BYTE 056H
          BYTE 043H
          BYTE 052H
          BYTE 055H
          BYTE 04eH
          BYTE 054H
          BYTE 049H
          BYTE 04dH
          BYTE 045H
          BYTE 031H
          BYTE 034H
          BYTE 030H
          BYTE 02eH
          BYTE 064H
          BYTE 06cH
          BYTE 06cH
          BYTE 000H
          BYTE 000H
          BYTE 093H
          BYTE 000H
          BYTE 070H
          BYTE 075H
          BYTE 074H
          BYTE 073H
          BYTE 000H
          BYTE 000H
          BYTE 040H
          BYTE 000H
          BYTE 05fH
          BYTE 073H
          BYTE 065H
          BYTE 068H
          BYTE 05fH
          BYTE 066H
          BYTE 069H
          BYTE 06cH
          BYTE 074H
          BYTE 065H
                    DB 'r_exe'
          BYTE 000H

          BYTE 042H
          BYTE 000H
          BYTE 05fH
          BYTE 073H
          BYTE 065H
          BYTE 074H
          BYTE 05fH
          BYTE 061H
          BYTE 070H
          BYTE 070H
                    DB '_type'
          BYTE 000H

          BYTE 009H
          BYTE 000H
          BYTE 05fH
          BYTE 05fH
          BYTE 073H
          BYTE 065H
          BYTE 074H
          BYTE 075H
          BYTE 073H
          BYTE 065H
                    DB 'rmatherr'
          BYTE 000H

          BYTE 000H
          BYTE 018H
          BYTE 000H
          BYTE 05fH
          BYTE 063H
          BYTE 06fH
          BYTE 06eH
          BYTE 066H
          BYTE 069H
          BYTE 067H
          BYTE 075H
          BYTE 072H
          BYTE 065H
          BYTE 05fH
          BYTE 06eH
          BYTE 061H
          BYTE 072H
          BYTE 072H
          BYTE 06fH
          BYTE 077H
          BYTE 05fH
          BYTE 061H
          BYTE 072H
          BYTE 067H
          BYTE 076H
          BYTE 000H
          BYTE 000H
          BYTE 033H
          BYTE 000H
          BYTE 05fH
          BYTE 069H
          BYTE 06eH
          BYTE 069H
          BYTE 074H
          BYTE 069H
          BYTE 061H
          BYTE 06cH
          BYTE 069H
          BYTE 07aH
          BYTE 065H
          BYTE 05fH
          BYTE 06eH
          BYTE 061H
          BYTE 072H
          BYTE 072H
          BYTE 06fH
          BYTE 077H
          BYTE 05fH
          BYTE 065H
          BYTE 06eH
          BYTE 076H
          BYTE 069H
          BYTE 072H
          BYTE 06fH
          BYTE 06eH
          BYTE 06dH
          BYTE 065H
          BYTE 06eH
          BYTE 074H
          BYTE 000H
          BYTE 000H
          BYTE 028H
          BYTE 000H
          BYTE 05fH
          BYTE 067H
          BYTE 065H
          BYTE 074H
          BYTE 05fH
          BYTE 069H
          BYTE 06eH
          BYTE 069H
          BYTE 074H
          BYTE 069H
          BYTE 061H
          BYTE 06cH
          BYTE 05fH
          BYTE 06eH
          BYTE 061H
          BYTE 072H
          BYTE 072H
          BYTE 06fH
          BYTE 077H
          BYTE 05fH
          BYTE 065H
          BYTE 06eH
          BYTE 076H
          BYTE 069H
                    DB 'ronment'
          BYTE 000H

          BYTE 036H
          BYTE 000H
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
          BYTE 037H
          BYTE 000H
          BYTE 05fH
          BYTE 069H
          BYTE 06eH
          BYTE 069H
          BYTE 074H
          BYTE 074H
          BYTE 065H
          BYTE 072H
          BYTE 06dH
          BYTE 05fH
          BYTE 065H
          BYTE 000H
          BYTE 055H
          BYTE 000H
          BYTE 065H
          BYTE 078H
          BYTE 069H
          BYTE 074H
          BYTE 000H
          BYTE 000H
          BYTE 023H
          BYTE 000H
          BYTE 05fH
          BYTE 065H
          BYTE 078H
          BYTE 069H
          BYTE 074H
          BYTE 000H
          BYTE 054H
          BYTE 000H
          BYTE 05fH
          BYTE 073H
          BYTE 065H
          BYTE 074H
                    DB '_fmode'
          BYTE 000H

          BYTE 000H
          BYTE 004H
          BYTE 000H
          BYTE 05fH
          BYTE 05fH
          BYTE 070H
          BYTE 05fH
          BYTE 05fH
          BYTE 05fH
          BYTE 061H
          BYTE 072H
          BYTE 067H
          BYTE 063H
          BYTE 000H
          BYTE 000H
          BYTE 005H
          BYTE 000H
          BYTE 05fH
          BYTE 05fH
          BYTE 070H
          BYTE 05fH
          BYTE 05fH
          BYTE 05fH
          BYTE 061H
          BYTE 072H
          BYTE 067H
          BYTE 076H
          BYTE 000H
          BYTE 000H
          BYTE 016H
          BYTE 000H
          BYTE 05fH
          BYTE 063H
          BYTE 065H
          BYTE 078H
          BYTE 069H
          BYTE 074H
          BYTE 000H
          BYTE 000H
          BYTE 015H
          BYTE 000H
                    DB '_c_exit'
          BYTE 000H

          BYTE 03dH
          BYTE 000H
          BYTE 05fH
          BYTE 072H
          BYTE 065H
          BYTE 067H
          BYTE 069H
          BYTE 073H
          BYTE 074H
          BYTE 065H
          BYTE 072H
          BYTE 05fH
          BYTE 074H
          BYTE 068H
          BYTE 072H
          BYTE 065H
          BYTE 061H
          BYTE 064H
          BYTE 05fH
          BYTE 06cH
          BYTE 06fH
          BYTE 063H
          BYTE 061H
          BYTE 06cH
          BYTE 05fH
          BYTE 065H
          BYTE 078H
          BYTE 065H
          BYTE 05fH
          BYTE 061H
          BYTE 074H
          BYTE 065H
          BYTE 078H
          BYTE 069H
          BYTE 074H
          BYTE 05fH
          BYTE 063H
          BYTE 061H
          BYTE 06cH
          BYTE 06cH
          BYTE 062H
          BYTE 061H
          BYTE 063H
          BYTE 06bH
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 000H
          BYTE 05fH
          BYTE 063H
          BYTE 06fH
          BYTE 06eH
          BYTE 066H
          BYTE 069H
          BYTE 067H
          BYTE 074H
          BYTE 068H
          BYTE 072H
          BYTE 065H
          BYTE 061H
          BYTE 064H
          BYTE 06cH
          BYTE 06fH
          BYTE 063H
          BYTE 061H
          BYTE 06cH
          BYTE 065H
          BYTE 000H
          BYTE 016H
          BYTE 000H
          BYTE 05fH
          BYTE 073H
          BYTE 065H
          BYTE 074H
          BYTE 05fH
          BYTE 06eH
          BYTE 065H
          BYTE 077H
          BYTE 05fH
          BYTE 06dH
          BYTE 06fH
          BYTE 064H
          BYTE 065H
          BYTE 000H
          BYTE 001H
          BYTE 000H
          BYTE 05fH
          BYTE 05fH
          BYTE 070H
          BYTE 05fH
          BYTE 05fH
          BYTE 063H
          BYTE 06fH
          BYTE 06dH
          BYTE 06dH
          BYTE 06fH
          BYTE 064H
          BYTE 065H
          BYTE 000H
          BYTE 000H
          BYTE 034H
          BYTE 000H
          BYTE 05fH
          BYTE 069H
          BYTE 06eH
          BYTE 069H
          BYTE 074H
          BYTE 069H
          BYTE 061H
          BYTE 06cH
          BYTE 069H
          BYTE 07aH
          BYTE 065H
          BYTE 05fH
          BYTE 06fH
          BYTE 06eH
          BYTE 065H
          BYTE 078H
          BYTE 069H
          BYTE 074H
                    DB '_table'
          BYTE 000H

          BYTE 000H
          BYTE 03cH
          BYTE 000H
          BYTE 05fH
          BYTE 072H
          BYTE 065H
          BYTE 067H
          BYTE 069H
          BYTE 073H
          BYTE 074H
          BYTE 065H
          BYTE 072H
          BYTE 05fH
          BYTE 06fH
          BYTE 06eH
          BYTE 065H
          BYTE 078H
          BYTE 069H
          BYTE 074H
          BYTE 05fH
          BYTE 066H
          BYTE 075H
          BYTE 06eH
          BYTE 063H
          BYTE 074H
          BYTE 069H
          BYTE 06fH
          BYTE 06eH
          BYTE 000H
          BYTE 01eH
          BYTE 000H
          BYTE 05fH
          BYTE 063H
          BYTE 072H
          BYTE 074H
          BYTE 05fH
          BYTE 061H
          BYTE 074H
          BYTE 065H
          BYTE 078H
          BYTE 069H
          BYTE 074H
          BYTE 000H
          BYTE 067H
          BYTE 000H
          BYTE 074H
          BYTE 065H
          BYTE 072H
          BYTE 06dH
                    DB 'inate'
          BYTE 000H

          BYTE 061H
          BYTE 070H
          BYTE 069H
          BYTE 02dH
          BYTE 06dH
          BYTE 073H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 02dH
          BYTE 063H
          BYTE 072H
          BYTE 074H
          BYTE 02dH
          BYTE 073H
          BYTE 074H
          BYTE 064H
          BYTE 069H
          BYTE 06fH
          BYTE 02dH
          BYTE 06cH
          BYTE 031H
          BYTE 02dH
          BYTE 031H
          BYTE 02dH
                    DB '0.dll'
          BYTE 000H

          BYTE 061H
          BYTE 070H
          BYTE 069H
          BYTE 02dH
          BYTE 06dH
          BYTE 073H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 02dH
          BYTE 063H
          BYTE 072H
          BYTE 074H
          BYTE 02dH
          BYTE 072H
          BYTE 075H
          BYTE 06eH
          BYTE 074H
          BYTE 069H
          BYTE 06dH
          BYTE 065H
          BYTE 02dH
          BYTE 06cH
          BYTE 031H
          BYTE 02dH
                    DB '1-0.dll'
          BYTE 000H

          BYTE 061H
          BYTE 070H
          BYTE 069H
          BYTE 02dH
          BYTE 06dH
          BYTE 073H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 02dH
          BYTE 063H
          BYTE 072H
          BYTE 074H
          BYTE 02dH
          BYTE 06dH
          BYTE 061H
          BYTE 074H
          BYTE 068H
          BYTE 02dH
          BYTE 06cH
          BYTE 031H
          BYTE 02dH
          BYTE 031H
                    DB '-0.dll'
          BYTE 000H

          BYTE 000H
          BYTE 061H
          BYTE 070H
          BYTE 069H
          BYTE 02dH
          BYTE 06dH
          BYTE 073H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 02dH
          BYTE 063H
          BYTE 072H
          BYTE 074H
          BYTE 02dH
          BYTE 06cH
          BYTE 06fH
          BYTE 063H
          BYTE 061H
          BYTE 06cH
          BYTE 065H
          BYTE 02dH
          BYTE 06cH
          BYTE 031H
                    DB '-1-0.dll'
          BYTE 000H

          BYTE 000H
          BYTE 061H
          BYTE 070H
          BYTE 069H
          BYTE 02dH
          BYTE 06dH
          BYTE 073H
          BYTE 02dH
          BYTE 077H
          BYTE 069H
          BYTE 06eH
          BYTE 02dH
          BYTE 063H
          BYTE 072H
          BYTE 074H
          BYTE 02dH
          BYTE 068H
          BYTE 065H
          BYTE 061H
          BYTE 070H
          BYTE 02dH
          BYTE 06cH
          BYTE 031H
                    DB '-1-0.dll'
          BYTE 000H

          DB 1 DUP(0)
;===================================
_RDATA   ENDS
;===================================

;===================================
_DATA    SEGMENT
;===================================

ALIGN 16
$L_140003000                     DB '!!!Hello World!!!'
          BYTE 000H

          BYTE 000H
          BYTE 000H
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
          BYTE 0ffH
$L_140003018           BYTE 001H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140003020           BYTE 001H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140003024           BYTE 002H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140003028           BYTE 02fH
          BYTE 020H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 0f8H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 000H
$L_140003038           BYTE 0cdH
          BYTE 05dH
          BYTE 020H
          BYTE 0d2H
          BYTE 066H
          BYTE 0d4H
          BYTE 0ffH
          BYTE 0ffH
$L_140003040           BYTE 032H
          BYTE 0a2H
          BYTE 0dfH
          BYTE 02dH
          BYTE 099H
          BYTE 02bH
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
$L_140003050           BYTE 001H
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
$L_140003060           DB 8 DUP(0)
$L_140003068           DB 8 DUP(0)
$L_140003070           DB 1 DUP(0)
$L_140003071           DB 7 DUP(0)
$L_140003078           DB 16 DUP(0)
$L_140003088           DB 8 DUP(0)
$L_140003090           DB 16 DUP(0)
$L_1400030a0           DB 16 DUP(0)
$L_1400030b0           DB 16 DUP(0)
$L_1400030c0           DB 8 DUP(0)
$L_1400030c8           DB 8 DUP(0)
$L_1400030d0           DB 8 DUP(0)
$L_1400030d8           DB 8 DUP(0)
$L_1400030e0           DB 8 DUP(0)
$L_1400030e8           DB 8 DUP(0)
$L_1400030f0           DB 8 DUP(0)
;===================================
_DATA    ENDS
;===================================

;===================================
_PDATA   SEGMENT
;===================================

ALIGN 16
          BYTE 000H
          BYTE 010H
          BYTE 000H
          BYTE 000H
          BYTE 036H
          BYTE 010H
          BYTE 000H
          BYTE 000H
          BYTE 0e8H
          BYTE 025H
          BYTE 000H
          BYTE 000H
          BYTE 040H
          BYTE 010H
          BYTE 000H
          BYTE 000H
          BYTE 067H
          BYTE 010H
          BYTE 000H
          BYTE 000H
          BYTE 0f0H
          BYTE 025H
          BYTE 000H
          BYTE 000H
          BYTE 068H
          BYTE 010H
          BYTE 000H
          BYTE 000H
          BYTE 01eH
          BYTE 011H
          BYTE 000H
          BYTE 000H
          BYTE 0f8H
          BYTE 025H
          BYTE 000H
          BYTE 000H
          BYTE 020H
          BYTE 011H
          BYTE 000H
          BYTE 000H
          BYTE 030H
          BYTE 011H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 030H
          BYTE 011H
          BYTE 000H
          BYTE 000H
          BYTE 049H
          BYTE 011H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 04cH
          BYTE 011H
          BYTE 000H
          BYTE 000H
          BYTE 0c8H
          BYTE 012H
          BYTE 000H
          BYTE 000H
          BYTE 008H
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 0c8H
          BYTE 012H
          BYTE 000H
          BYTE 000H
          BYTE 0daH
          BYTE 012H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 0dcH
          BYTE 012H
          BYTE 000H
          BYTE 000H
          BYTE 015H
          BYTE 013H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 018H
          BYTE 013H
          BYTE 000H
          BYTE 000H
          BYTE 061H
          BYTE 013H
          BYTE 000H
          BYTE 000H
          BYTE 0f8H
          BYTE 025H
          BYTE 000H
          BYTE 000H
          BYTE 064H
          BYTE 013H
          BYTE 000H
          BYTE 000H
          BYTE 0efH
          BYTE 013H
          BYTE 000H
          BYTE 000H
          BYTE 0f8H
          BYTE 025H
          BYTE 000H
          BYTE 000H
          BYTE 0f0H
          BYTE 013H
          BYTE 000H
          BYTE 000H
          BYTE 088H
          BYTE 014H
          BYTE 000H
          BYTE 000H
          BYTE 048H
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 088H
          BYTE 014H
          BYTE 000H
          BYTE 000H
          BYTE 0acH
          BYTE 014H
          BYTE 000H
          BYTE 000H
          BYTE 0f8H
          BYTE 025H
          BYTE 000H
          BYTE 000H
          BYTE 0acH
          BYTE 014H
          BYTE 000H
          BYTE 000H
          BYTE 0d5H
          BYTE 014H
          BYTE 000H
          BYTE 000H
          BYTE 0f8H
          BYTE 025H
          BYTE 000H
          BYTE 000H
          BYTE 0d8H
          BYTE 014H
          BYTE 000H
          BYTE 000H
          BYTE 012H
          BYTE 015H
          BYTE 000H
          BYTE 000H
          BYTE 0f8H
          BYTE 025H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 015H
          BYTE 000H
          BYTE 000H
          BYTE 02bH
          BYTE 015H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 02cH
          BYTE 015H
          BYTE 000H
          BYTE 000H
          BYTE 0d8H
          BYTE 015H
          BYTE 000H
          BYTE 000H
          BYTE 070H
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 014H
          BYTE 016H
          BYTE 000H
          BYTE 000H
          BYTE 02fH
          BYTE 016H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 054H
          BYTE 016H
          BYTE 000H
          BYTE 000H
          BYTE 09fH
          BYTE 017H
          BYTE 000H
          BYTE 000H
          BYTE 07cH
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 0a8H
          BYTE 017H
          BYTE 000H
          BYTE 000H
          BYTE 0faH
          BYTE 017H
          BYTE 000H
          BYTE 000H
          BYTE 000H
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 00cH
          BYTE 018H
          BYTE 000H
          BYTE 000H
          BYTE 067H
          BYTE 018H
          BYTE 000H
          BYTE 000H
          BYTE 08cH
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 068H
          BYTE 018H
          BYTE 000H
          BYTE 000H
          BYTE 0a4H
          BYTE 018H
          BYTE 000H
          BYTE 000H
          BYTE 08cH
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 0a4H
          BYTE 018H
          BYTE 000H
          BYTE 000H
          BYTE 0e0H
          BYTE 018H
          BYTE 000H
          BYTE 000H
          BYTE 08cH
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 0e0H
          BYTE 018H
          BYTE 000H
          BYTE 000H
          BYTE 081H
          BYTE 01aH
          BYTE 000H
          BYTE 000H
          BYTE 098H
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 050H
          BYTE 01bH
          BYTE 000H
          BYTE 000H
          BYTE 052H
          BYTE 01bH
          BYTE 000H
          BYTE 000H
          BYTE 0a8H
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 070H
          BYTE 01bH
          BYTE 000H
          BYTE 000H
          BYTE 076H
          BYTE 01bH
          BYTE 000H
          BYTE 000H
          BYTE 0b0H
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 076H
          BYTE 01bH
          BYTE 000H
          BYTE 000H
          BYTE 094H
          BYTE 01bH
          BYTE 000H
          BYTE 000H
          BYTE 040H
          BYTE 026H
          BYTE 000H
          BYTE 000H
          BYTE 094H
          BYTE 01bH
          BYTE 000H
          BYTE 000H
          BYTE 0acH
          BYTE 01bH
          BYTE 000H
          BYTE 000H
          BYTE 068H
          BYTE 026H
          BYTE 000H
          BYTE 000H
;===================================
_PDATA   ENDS
;===================================

END