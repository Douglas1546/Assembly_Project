; Aluno: Douglas da Silva Pereira Veras
.686
.model flat, stdcall
option casemap:none 

include \masm32\include\windows.inc 
include \masm32\include\kernel32.inc 
include \masm32\include\masm32.inc

includelib \masm32\lib\kernel32.lib 
includelib \masm32\lib\masm32.lib

.data
    menu db 0ah, "1 - Criptografar", 0ah, "2 - Descriptografar", 0ah, "3 - Sair", 0ah, "Digite a opcao desejada: ", 0h

    msg_erro1 db 0ah, "Erro ao abrir o arquivo", 0h
    msg_erro2 db 0ah, "Erro ao criar o arquivo", 0h

    exibir_msg_1 db 0ah, "Digite o nome do arquivo que deseja criptografar: ", 0h
    exibir_msg_2 db 0ah, "Digite como deseja chamar o arquivo criptografado: ", 0h
    exibir_msg_chave db 0ah, "Digite o numero da chave de criptografia: ", 0h

    exibir_msg_3 db 0ah, "Digite o nome do arquivo que deseja descriptografar: ", 0h
    exibir_msg_4  db 0ah, "Digite como deseja chamar o arquivo que sera descriptografado: ", 0h

    
    inputString db 4 dup(0) ; Para armazenar a opcao escolhida pelo usuario
    inputHandle dd 0        ; Para armazenar o handle de entrada
    consoleRead dd 0              
    
    mensagens_Handle dd 0   ; Handle de controle para exibir mensagens no console
    
    handle_file dd ?        
    handle_file_2 dd ?           

    filePath    db 32 dup(0)   ; Para o arquivo 1 (o que está sendo aberto)
    filePath_2   db 32 dup(0)  ; Para o arquivo 2 (O que está sendo criado)

    buffer      db 512 dup(0)
    buffer2      db 512 dup(0)
    bytesRead   dd 0


    chaveEntrada db 4 dup(?) 
    chave dd ? ; Variavel para armazenar a chave de criptografia
           
.code

; funcao para criptografar o arquivo
func_cripto:
    push ebp
    mov ebp, esp

    mov eax, [ebp+8] 
    mov ebx, [ebp+12]
    mov ecx, [ebp+16] 
    
    xor edx, edx

    mov edi, eax 

    criptografar:
        mov al, [edi + edx]
        add al, bl ; soma a chave de criptografia
        mov [edi + edx], al
        inc edx 
        cmp edx, ecx 
        jl criptografar ; repete até criptografar todos os bytes do bloco

    pop ebp    
    ret 12

; funcao para descriptografar o arquivo
func_descripto:
    push ebp
    mov ebp, esp

    mov eax, [ebp+8] 
    mov ebx, [ebp+12]
    mov ecx, [ebp+16] 
    
    xor edx, edx

    mov edi, eax

    descriptografar:
        mov al, [edi + edx] 
        sub al, bl ; subtrai a chave de criptografia
        mov [edi + edx], al 
        inc edx 
        cmp edx, ecx 
        jl descriptografar ; repete até descriptografar todos os bytes do bloco

    pop ebp    
    ret 12

start:

menu_opcoes:
    ;Exibe o menu de opcoes
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov mensagens_Handle, eax
    invoke WriteConsole, mensagens_Handle, offset menu, sizeof menu, NULL, NULL

    ;Pede ao usuario para digitar a opcao desejada
    invoke GetStdHandle, STD_INPUT_HANDLE
    mov inputHandle, eax 
    invoke ReadConsole, inputHandle, addr inputString, sizeof inputString, addr consoleRead, NULL

    cmp [inputString], '1' ; compara o valor armazenado na primeira posicao de memoria do inputString com o caractere '1'.
    je opcao1

    cmp [inputString], '2' ; compara o valor armazenado na primeira posicao de memoria do inputString com o caractere '2'.
    je opcao2

    cmp [inputString], '3' ; compara o valor armazenado na primeira posicao de memoria do inputString com o caractere '3'.
    je encerrar


opcao1:
 
; Pede a chave de criptografia ao usuario
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov mensagens_Handle, eax
    invoke WriteConsole, mensagens_Handle, offset exibir_msg_chave, sizeof exibir_msg_chave, NULL, NULL

    invoke ReadConsole, inputHandle, addr chaveEntrada, sizeof chaveEntrada, addr consoleRead, NULL

    ; Remove o CR do final da string
    mov esi, offset chaveEntrada 
    proximoxx:
    mov al, [esi] 
    inc esi 
    cmp al, 13 
    jne proximoxx
    dec esi 
    xor al, al 
    mov [esi], al 

    ; Converte a string para um numero inteiro
    invoke atodw, addr chaveEntrada
    mov chave, eax
    
; Pede ao usuario para digitar o nome do arquivo que ele deseja criptografar
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov mensagens_Handle, eax
    invoke WriteConsole, mensagens_Handle, offset exibir_msg_1, sizeof exibir_msg_1, NULL, NULL

    invoke ReadConsole, inputHandle, addr filePath, sizeof filePath, addr consoleRead, NULL
    
    ; Remove o CR do final da string
    mov esi, offset filePath 
    proximo:
    mov al, [esi] 
    inc esi 
    cmp al, 13 
    jne proximo
    dec esi 
    xor al, al 
    mov [esi], al 
    
    ;Leitura do arquivo digitado
    invoke CreateFile, addr filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov ebx, eax ; salva o arquivo aberto em ebx

    cmp ebx, INVALID_HANDLE_VALUE ; Verificar se o arquivo foi aberto com sucesso
    je erro1
       
; Pede ao usuario para digitar o nome do novo arquivo em que será salvo a criptografia
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov mensagens_Handle, eax
    invoke WriteConsole, mensagens_Handle, offset exibir_msg_2, sizeof exibir_msg_2, NULL, NULL

    invoke ReadConsole, inputHandle, addr filePath_2, sizeof filePath_2, addr consoleRead, NULL

    ; Remove o CR do final da string
    mov esi, offset filePath_2 
    next:
    mov al, [esi] 
    inc esi 
    cmp al, 13 
    jne next
    dec esi 
    xor al, al 
    mov [esi], al 

    ; Cria o novo arquivo com o nome digitado pelo usuario para salvar a codificação
    invoke CreateFile, addr filePath_2, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    cmp eax, INVALID_HANDLE_VALUE ; Verificar se o arquivo foi criado com sucesso
    je erro2 

    mov handle_file, ebx ; coloca o arquivo aberto em handle_file
    mov handle_file_2, eax ; coloca o arquivo criado em handle_file_2

; Loop de leitura e criptografia
    leitura_loop:
        invoke ReadFile, handle_file, addr buffer, sizeof buffer, addr bytesRead, NULL ; Le o arquivo original

        cmp bytesRead, 0 ; Verificar se a leitura do arquivo chegou ao fim
        je fim_leitura

        push ecx ; salva o tamanho do bloco na pilha

        push bytesRead 
        push chave 
        push offset buffer 
        

        call func_cripto ; chama a função de criptografar      

        pop ecx ; restaura o tamanho do bloco da pilha  

        invoke WriteFile, handle_file_2, addr buffer, bytesRead, addr buffer2, NULL ; Escreve no novo arquivo
        jmp leitura_loop
        
fim_leitura:
    ; Fecha os arquivos
    invoke CloseHandle, handle_file ; Fecha o arquivo original
    invoke CloseHandle, handle_file_2 ; Fecha o arquivo criptografado
    jmp menu_opcoes

;==========================================================================================================================================================;

opcao2:

; Pede a chave de descriptografia ao usuario
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov mensagens_Handle, eax
    invoke WriteConsole, mensagens_Handle, offset exibir_msg_chave, sizeof exibir_msg_chave, NULL, NULL

    invoke ReadConsole, inputHandle, addr chaveEntrada, sizeof chaveEntrada, addr consoleRead, NULL

    ; Remove o CR do final da string
    mov esi, offset chaveEntrada 
    proximoxxx:
    mov al, [esi] 
    inc esi 
    cmp al, 13 
    jne proximoxxx
    dec esi 
    xor al, al 
    mov [esi], al 

    ; Converte a string para um numero inteiro
    invoke atodw, addr chaveEntrada
    mov chave, eax

; Pede ao usuario para digitar o nome do arquivo que ele deseja descriptografar
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov mensagens_Handle, eax
    invoke WriteConsole, mensagens_Handle, offset exibir_msg_3, sizeof exibir_msg_3, NULL, NULL

    invoke ReadConsole, inputHandle, addr filePath, sizeof filePath, addr consoleRead, NULL
    
    ; Remove o CR do final da string
    mov esi, offset filePath
    prox:
    mov al, [esi] 
    inc esi 
    cmp al, 13 
    jne prox
    dec esi 
    xor al, al 
    mov [esi], al 
    
    ;Leitura do arquivo digitado
    invoke CreateFile, addr filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov ebx, eax ; Armazena o handle do arquivo em ebx

    cmp ebx, INVALID_HANDLE_VALUE ; Verificar se o arquivo foi aberto com sucesso
    je erro1 


; Pede ao usuario para digitar o nome do novo arquivo em que será salvo a descriptografia
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov mensagens_Handle, eax
    invoke WriteConsole, mensagens_Handle, offset exibir_msg_4, sizeof exibir_msg_4, NULL, NULL

    invoke ReadConsole, inputHandle, addr filePath_2, sizeof filePath_2, addr consoleRead, NULL

    ; Remove o CR do final da string
    mov esi, offset filePath_2 
    nxt:
    mov al, [esi] 
    inc esi 
    cmp al, 13 
    jne nxt
    dec esi 
    xor al, al 
    mov [esi], al 

    ; Cria o novo arquivo com o nome digitado pelo usuario para salvar a descriptografia
    invoke CreateFile, addr filePath_2, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    cmp eax, INVALID_HANDLE_VALUE ; Verificar se o arquivo foi criado com sucesso
    je erro2 

; Loop de leitura e descriptografia 
    mov handle_file, ebx ; coloca o arquivo aberto em handle_file
    mov handle_file_2, eax ; coloca o arquivo criado em handle_file_2

    leitu_loop:
        invoke ReadFile, handle_file, addr buffer, sizeof buffer, addr bytesRead, NULL ; Ler um bloco do arquivo

        cmp bytesRead, 0 ; Verificar se a leitura do arquivo chegou ao fim
        je fim_leitura     

        push ecx ; salva o tamanho do bloco na pilha

        push bytesRead
        push chave
        push offset buffer
        
        call func_descripto ; chama a função de descriptografar

        pop ecx ; restaura o tamanho do bloco da pilha  

        invoke WriteFile, handle_file_2, addr buffer, bytesRead, addr buffer2, NULL ; Escreve no novo arquivo
        jmp leitu_loop

fim_leitura_1:
    ; Fecha os arquivos
    invoke CloseHandle, handle_file ; Fecha o arquivo original (criptografado)
    invoke CloseHandle, handle_file_2 ; Fecha o arquivo descriptografado
    jmp menu_opcoes

;==============================================================================================;
;===================================== Mensagens de erro ======================================;
;==============================================================================================;
erro1:
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov mensagens_Handle, eax
    invoke WriteConsole, mensagens_Handle, offset msg_erro1, sizeof msg_erro1, NULL, NULL

    jmp menu_opcoes

erro2:
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov mensagens_Handle, eax
    invoke WriteConsole, mensagens_Handle, offset msg_erro2, sizeof msg_erro2, NULL, NULL

    jmp menu_opcoes

encerrar:
    invoke ExitProcess, 0 ; encerra o programa
    
end start