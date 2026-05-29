---
title: "Reverse de Nanomites"
date: 2026-05-29 12:00:00 +0200
categories: [Reverse, Nanomites]
tags: [reverse, Rust, Anti-Debug]
---
Le binaire utilisé dans cet article a été conçu par moi-même en Rust, il peut donc y'avoir des maladresses dans le code.

Le binaire utilise un principe de "laisser passer". Celui-ci se base sur un principe de jeton (chaîne de caractères ici), c'est-à-dire qu'il existe 2 632 770 148 possibilités afin de valider le binaire, le but est donc de comprendre son fonctionnement afin de programmer un code permettant de générer un jeton valide.

#### 1. Informations sur le binaire

Nous avons donc un binaire compilé en `Rust`, utilisant l'architecture `ELF x86_64`, celui-ci est lié dynamiquement à la `libc` et est non strippé : 

`nanomites: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=b8f01354abc8c786130947f04f385b87050d4256, not stripped`

Le binaire a été compilé avec les différentes protections (peuvent être vues via la commande : `checksec --file=nanomites`) : 

* `RELRO: FULL RELRO` (Full relro indique que les tables GOT et PLT sont en lectures seules).
* `Stack: No canary found` (Le binaire ne possède pas de canary permettant de détecter les SSP).
* `NX: NX enabled` (La stack (Pile) n'est donc pas exécutable).
* `PIE: PIE Enabled` (L'adresse de début du binaire change donc à chaque exécution).
* `Stripped: No` (Les symboles du binaire ne sont pas strippés, donc accessibles en lecture claire).
* `ASLR: ASLR Enabled` (Toutes les adresses des segments du noyau changent à chaque exécution).

#### 2. Comportement du binaire 

Nous lançons donc le binaire une première fois afin d'analyser son comportement : 

`./nanomites
Password: sdsdqs
Bad password...`

Le binaire attend donc un password en entrée, si le password fourni est faux, alors celui-ci renvoie la chaîne de caractères : `Bad password...`

Nous allons effectuer un strace sur le binaire, afin de connaître la chronologie du binaire et les appels intéressants : 

`strace ./nanomites`

Le plus important et intéressant ici sont les différents appels `ptrace`, nous pouvons retrouver : 

* `ptrace(PTRACE_CONT, 1406, NULL, 0)` : Permettant d'ordonner à l'enfant de continuer son exécution une fois que le parent a pris la main.
* `ptrace(PTRACE_GETREGS, 1406, {(valeurs des registres)...}` : Permet au parent de récupérer le contexte des registres de l'enfant.
* `ptrace(PTRACE_SETREGS, 1406, {(valeurs modifiées des registres)...}` : Permet au parent de modifier le contexte des registres de l'enfant.
* `ptrace(PTRACE_KILL, 1406)` : Tue le processus enfant une fois que le programme se termine et se ferme.

Nous retrouvons aussi notre fameuse chaîne de caractères : `Bad password...` : 

`write(1, "Bad password...\n", 16)`

Il est donc facile de comprendre que dans le binaire : 

* Le processus parent créé un processus enfant et s'attache à lui avec la fonction `ptrace(PTRACE_TRACEME)`.
* L'enfant exécute le programme et au moment de certaines interruptions (instruction `INT3` utilisée par les nanomites), le parent prends la main et récupère le contexte des registres de l'enfant puis le modifie afin d'y effectuer certaines choses avec.
* Une fois la modification finie, une comparaison est faite puis selon le password rentré, la chaîne de caractères `Bad password...` apparaît ou non et le programme se termine.

Grâce au SigHandler SIGCHLD étant un signal permettant de réveiller un processus parent dont l'enfant vient de mourir, nous pouvons obtenir certaines informations triviales mais qui confirment notre théorie : 

`SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=1406, si_uid=0, si_status=0, si_utime=0, si_stime=0}`

le paramètre `si_pid=1406` nous confirme donc que le pid vu dans les appels ptrace est bien celui de l'enfant.

#### 3. Analyse du binaire

Lorsqu'un binaire est protégé par des nanomites, l'analyse statique devient extrêmement complexe, mais reste tout de même possible.

Nous allons ici ouvrir le binaire via GDB afin de récupérer l'entiereté du code du binaire, nous pourrions aussi le faire via Ghidra mais le pseudo-code étant inutile dû aux interruptions INT3, GDB est donc plus rapide a utiliser dans notre cas.

Ce qu'il faut savoir avec le compilateur Rust, est que celui-ci afin d'éviter les collisions et de s'y retrouver, génère des noms unique pour chaque fonction, ainsi notre vrai fonction `main` ne s'appelle pas directement `main`, en tappant la commande disas main, nous pouvons donc retrouver le vrai nom de celle-ci : 

```
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000017740 <+0>:     push   rax
   0x0000000000017741 <+1>:     mov    rcx,rsi
   0x0000000000017744 <+4>:     movsxd rdx,edi
   0x0000000000017747 <+7>:     lea    rax,[rip+0xfffffffffffffad2]        # 0x17220 <_ZN9nanomites4main17h9bc09d21e49a71c7E>
   0x000000000001774e <+14>:    mov    QWORD PTR [rsp],rax
   0x0000000000017752 <+18>:    lea    rsi,[rip+0x3f59f]        # 0x56cf8
   0x0000000000017759 <+25>:    mov    rdi,rsp
   0x000000000001775c <+28>:    xor    r8d,r8d
   0x000000000001775f <+31>:    call   QWORD PTR [rip+0x41fe3]        # 0x59748
   0x0000000000017765 <+37>:    pop    rcx
   0x0000000000017766 <+38>:    ret
```

Celle-ci se nomme donc : `_ZN9nanomites4main17h9bc09d21e49a71c7E`

En effectuant un désassemblage de celle-ci, nous pouvons retrouver deux autres fonctions appelées par main : 

```
gef➤  disas _ZN9nanomites4main17h9bc09d21e49a71c7E
Dump of assembler code for function _ZN9nanomites4main17h9bc09d21e49a71c7E:
   0x0000000000017220 <+0>:     push   rax
   0x0000000000017221 <+1>:     call   QWORD PTR [rip+0x424e1]        # 0x59708
   0x0000000000017227 <+7>:     test   eax,eax
   0x0000000000017229 <+9>:     je     0x17238 <_ZN9nanomites4main17h9bc09d21e49a71c7E+24>
   0x000000000001722b <+11>:    cmp    eax,0xffffffff
   0x000000000001722e <+14>:    je     0x1723e <_ZN9nanomites4main17h9bc09d21e49a71c7E+30>
   0x0000000000017230 <+16>:    mov    edi,eax
   0x0000000000017232 <+18>:    pop    rax
   0x0000000000017233 <+19>:    jmp    0x16bd0 <_ZN9nanomites10run_master17h1a8e7e74c8010023E>
   0x0000000000017238 <+24>:    pop    rax
   0x0000000000017239 <+25>:    jmp    0x17270 <_ZN9nanomites9run_slave17h3a22d056c97741c9E>
   0x000000000001723e <+30>:    call   QWORD PTR [rip+0x424bc]        # 0x59700
   0x0000000000017244 <+36>:    mov    DWORD PTR [rsp+0x4],eax
   0x0000000000017248 <+40>:    lea    rdi,[rip+0xffffffffffff3481]        # 0xa6d0
   0x000000000001724f <+47>:    lea    rcx,[rip+0x3fad2]        # 0x56d28
   0x0000000000017256 <+54>:    lea    r8,[rip+0x3fc43]        # 0x56ea0
   0x000000000001725d <+61>:    lea    rdx,[rsp+0x4]
   0x0000000000017262 <+66>:    mov    esi,0xa
   0x0000000000017267 <+71>:    call   QWORD PTR [rip+0x4248b]        # 0x596f8
```

Nous savons maintenant qu'il y'a aussi deux autres fonctions : 

* `_ZN9nanomites10run_master17h1a8e7e74c8010023E` : Servant surement à gérer la comparaison et les registres, ainsi que le Flux d'exécution de l'enfant.
* `_ZN9nanomites9run_slave17h3a22d056c97741c9E` : Servant à exécuter le code et suivant les modifications du parent sur celui-ci.

Nous allons commencer par regarder les deux fonctions retrouvées afin de comprendre un peu plus le programme ainsi qu'essayer de retrouver la logique de validation (le code entier ne sera pas mis car il fait plus de 1600 lignes assembleurs) :

Récupération du contexte des registres de l'enfant d'une taille de `0xd8` octets :

```
0x000055555556ad03 <+307>:   mov    edx,0xd8
0x000055555556ad08 <+312>:   lea    rsi,[rsp+0x28]
0x000055555556ad0d <+317>:   call   QWORD PTR [rip+0x429c5]  # ptrace(PTRACE_GETREGS, ...)
```

Comparaison avec une valeur fixe : 

```
0x000055555556ad13 <+323>:   mov    r15,QWORD PTR [rsp+0x150]
0x000055555556ad1b <+331>:   cmp    r15,0x601
0x000055555556ad22 <+338>:   jne    0x55555556ad30
```

Si la valeur de comparaison est correcte, alors celle-ci est conservée : 

```
0x000055555556ad58 <+392>:   mov    QWORD PTR [rsp+0x18],r15
```

Deuxième vérification entre la valeur comparée avec `0x601`, afin de vérifier que les registres n'aient pas été modifiés entre temps : 

```
0x000055555556ae2a <+602>:   cmp    QWORD PTR [rsp+0x18],0x601
0x000055555556ae33 <+611>:   jne    0x55555556af15
```

la valeur située précédemment dans le registre `r15` ayant été comparée avec `0x601` est placée à `rsp+0x18` puis `rsp+0x18` est à nouveau comparé avec `0x601`.

Une deuxième comparaison est faite un peu plus loin entre `rsp+0x78` et la valeur `0x99` :

```
0x000055555556aefe <+814>:   cmp    QWORD PTR [rsp+0x78],0x99
0x000055555556af07 <+823>:   mov    rdi,r14
0x000055555556af0a <+826>:   je     0x55555556afa2
```

Pour l'instant nous ne pouvons pas comprendre la logique de vérification, nous n'avons vu que certaines comparaisons pouvant être intéressantes. Nous allons maintenant passer à la fonction `run_slave` : 

Le programme commence a s'exécuter et s'arrête directement via INT3, c'est à ce moment-là que le parent va récupérer le contenu des registres de l'enfant : 

```
   0x000055555556b270 <+0>:     push   rbx
   0x000055555556b271 <+1>:     sub    rsp,0x30
   0x000055555556b275 <+5>:     call   QWORD PTR [rip+0x42495]        # 0x5555555ad710
   0x000055555556b27b <+11>:    cmp    eax,0x86
   0x000055555556b280 <+16>:    jne    0x55555556b662 <_ZN9nanomites9run_slave17h3a22d056c97741c9E+1010>
   0x000055555556b286 <+22>:    int3
```

Bien plus bas dans la fonction, nous trouvons une bonne partie de la logique de validation du password : 

```
0x000055555556b5c0 <+848>:   movzx  edi,BYTE PTR [rax]
0x000055555556b5c3 <+851>:   add    rdi,rsi                  ; Somme du 1er caractère
0x000055555556b5c6 <+854>:   movzx  esi,BYTE PTR [rax+0x1]
0x000055555556b5ca <+858>:   movzx  r8d,BYTE PTR [rax+0x2]
0x000055555556b5cf <+863>:   add    r8,rsi                   ; + 2ème
0x000055555556b5d2 <+866>:   add    r8,rdi                   ; + 3ème
0x000055555556b5d5 <+869>:   movzx  esi,BYTE PTR [rax+0x3]
0x000055555556b5d9 <+873>:   movzx  edi,BYTE PTR [rax+0x4]
0x000055555556b5dd <+877>:   add    rdi,rsi                   ; + 4ème...
...
0x000055555556b5fa <+906>:   add    rsi,r9                   ; Cumul global dans RSI
```

Le programme récupère donc chaque caractère de la chaîne de caractères que nous rentrons en entrée et les additionne, afin de savoir ce que le programme additionne avec chaque caractères nous pouvons nous intéresser un peu plus à l'instruction : 

`0x000055555556b5c0 <+848>:   movzx  edi, BYTE PTR [rax]`

* `BYTE PTR [rax]` : Le programme va donc chercher un seul octet de l'adresse rax où se trouve le password que nous avons entré
* `movzx` : Cette instruction prend l'octet récupéré et le copie dans un registre plus grand (ici `edi` qui fait 32 bits), en remplissant la suite de zéros.

Cela signifie donc que le programme extrait directement la valeur brute de l'octet de notre caractère, exemple : 

* Si nous avons rentré le caractère `A`, l'octet en mémoire vaut donc `01000001` en binaire ce qui vaut donc `0x41` en hexadécimal et `65` en décimal.

Ainsi le programme prend la valeur brute de chaque caractère du password que nous avons rentré et les additionne. 

L'entrée stdin possède un petit piège dans lequel il est important de ne pas tomber non plus : la fin de ligne `\n`. Lorsque nous pressons `Entrée` dans le terminal, la fonction de lecture capture généralement notre saisie plus le caractère de fin de ligne.

Avant de pouvoir retrouver le password, nous devons comprendre aussi à  quoi correspondent les valeurs `0x601` et `0x99`. Nous pouvons retrouver `0x99` dans cette partie de la fonction run_slave : 

```
0x000055555556b63a <+970>:   mov    rax,0x99
0x000055555556b641 <+977>:   int3
```

L'enfant place donc la valeur `0x99` dans le registre rax puis effectue une interruption `INT3`, une fois que le parent a pris la main, celui-ci voit `0x99` dans rax et fait donc : 

```
0x000055555556aefe <+814>:   cmp    QWORD PTR [rsp+0x78],0x99
0x000055555556af07 <+823>:   mov    rdi,r14
0x000055555556af0a <+826>:   je     0x55555556afa2
```

Le parent saute donc à une adresse de sa fonction, ici `0x55555556afa2` : 

```
0x000055555556afa2 <+978>:   mov    esi,0x21
   0x000055555556afa7 <+983>:   call   QWORD PTR [rip+0x4273b]        # 0x5555555ad6e8
   0x000055555556afad <+989>:   mov    edi,ebx
   0x000055555556afaf <+991>:   call   QWORD PTR [rip+0x4273b]        # 0x5555555ad6f0
   0x000055555556afb5 <+997>:   jmp    0x55555556acd1 <_ZN9nanomites10run_master17h1a8e7e74c8010023E+257>
```

Ce que le parent fait à ce moment : 

* Prépare l'argument `0x21` qui correspond a la constante `PTRACE_POKEDATA` pour `ptrace()`.
* Ecrit de forcer une valeur directement dans l'espace mémoire ou dans les registres de l'enfant.
* Appelle ensuite `ptrace(PTRACE_CONT)` afin d'ordonner à l'enfant de reprendre son exécution.

Le parent effectue ensuite encore un saut vers le début de sa propre boucle à l'adresse 0x55555556acdi : 

```
 0x000055555556acd1 <+257>:   add    rsp,0x1d8
   0x000055555556acd8 <+264>:   pop    rbx
   0x000055555556acd9 <+265>:   pop    r12
   0x000055555556acdb <+267>:   pop    r13
   0x000055555556acdd <+269>:   pop    r14
   0x000055555556acdf <+271>:   pop    r15
   0x000055555556ace1 <+273>:   pop    rbp
   0x000055555556ace2 <+274>:   ret
   0x000055555556ace3 <+275>:   lea    rdi,[rsp+0x20]
   0x000055555556ace8 <+280>:   mov    esi,ebx
   0x000055555556acea <+282>:   call   QWORD PTR [rip+0x429e0]        # 0x5555555ad6d0
   0x000055555556acf0 <+288>:   cmp    DWORD PTR [rsp+0x20],0x1
   0x000055555556acf5 <+293>:   je     0x55555556afe7 <_ZN9nanomites10run_master17h1a8e7e74c8010023E+1047>
```

Le parent nettoie l'espace alloué puis restaure le contexte des registres avec toutes les instructions pop successives, une instruction ret est ensuite utilisée afin de terminer la fonction `run_master` proprement.

Si après le ret, le programme continue à lire, celui-ci vérifie l'état de l'enfant puis saute vers encore une autre branche de la fonction : 

```
0x000055555556afe1 <+1041>:  call   QWORD PTR [rip+0x42711]        # 0x5555555ad6f8
   0x000055555556afe7 <+1047>:  mov    eax,DWORD PTR [rsp+0x24]
   0x000055555556afeb <+1051>:  mov    DWORD PTR [rsp+0xc],eax
   0x000055555556afef <+1055>:  lea    rdi,[rip+0xffffffffffff1aaa]        # 0x55555555caa0
   0x000055555556aff6 <+1062>:  lea    rcx,[rip+0x3fd2b]        # 0x5555555aad28
...
```

La suite du programme déclenche ainsi notre rust panic qui fait planter le programme.

Ainsi il est donc possible de comprendre que la comparaison avec `0x99` est une sécurité permettant de confirmer la validation du password et quitter proprement le programme.

Il ne nous reste donc plus que la valeur `0x601`, par déduction celle-ci devrait être notre valeur de comparaison avec notre chaîne de caractères additionnée. Nous allons donc créer un programme qui nous génère une chaîne de caractères aléatoires faisant 0x601 moins 0xa (0xa correspondant à \n) : 

```
import random
import string

def get_valid_chain(target=1527):
    charset = string.ascii_letters + string.digits
    chain = []
    current_sum = 0

    while target - current_sum > 122:
        char = random.choice(charset)
        chain.append(char)
        current_sum += ord(char)

    remainder = target - current_sum
    if chr(remainder) in charset:
        chain.append(chr(remainder))
    else:
        return get_valid_chain(target)

    return "".join(chain)

chaine_valide = get_valid_chain()
print(f"Password généré : {chaine_valide}")
print(f"Somme des caractères du password : {sum(ord(c) for c in chaine_valide)}")
```

A chaque lancement, ce programme nous donne une chaîne de caractères dont la somme vaut 1527, nous pouvons ainsi valider le programme avec différents passwords générés : 

```
(base) ┌──(root㉿pc-alexis)-[~/Rust/Reverse/nanomites]
└─# ./nanomites
Password: SuRGXLFVgvkJVOSVv
Good Password !

(base) ┌──(root㉿pc-alexis)-[~/Rust/Reverse/nanomites]
└─# ./nanomites
Password: CeB6wI90MUaG6cBrPmZ
Good Password !

(base) ┌──(root㉿pc-alexis)-[~/Rust/Reverse/nanomites]
└─# ./nanomites
Password: 4KgE2zHBP1kUZpRGcDK
Good Password !
```

#### 4. Code source du binaire 

```
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::arch::asm;
use std::io::{self, Write};

fn main() {
    match unsafe { fork() }.expect("Fork echec") {
        ForkResult::Parent { child } => {
            run_master(child);
        }

        ForkResult::Child => {
            run_slave();
        }
    }
}

#[inline(never)]
fn run_slave() {
    ptrace::traceme().unwrap();

    unsafe { asm!("int 3") };

    print!("Password: ");
    io::stdout().flush().unwrap();
    let mut raw_input = String::new();
    io::stdin().read_line(&mut raw_input).unwrap();

    let _password = raw_input.trim();

    let mut hash: u64 = 0;
    for &byte in raw_input.as_bytes() {
        hash = hash.wrapping_add(byte as u64);
    }

    unsafe {
        asm!(
            "lea rcx, [rip + 4f]",
            "mov rax, {0}",
            "mov rbx, 0",
            "int 3",
            "nop",

            "cmp rbx, 0",
            "int 3",
            "nop",

            "jmp 5f",

            "4:",
            "mov rax, 0x99",
            "int 3",

            "5:",
            in(reg) hash,
            out("rcx") _,
        );
    }
}

#[inline(never)]
fn run_master(child_pid: Pid) {
    waitpid(child_pid, None).unwrap();

    ptrace::cont(child_pid, None).unwrap();

    let target_hash: u64 = 1537;
    let mut nanomite_count = 0;
    let mut is_authenticated = false;
    let mut win_address: u64 = 0;

    loop {
        match waitpid(child_pid, None).unwrap() {
            WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP) => {
                let mut regs = ptrace::getregs(child_pid).unwrap();
                let trap_addr = regs.rip - 1;

                nanomite_count += 1;

                if nanomite_count == 1 {
                    win_address = regs.rcx;
                    if regs.rax == target_hash {
                        is_authenticated = true;
                        regs.rbx = 1;
                    }
                    regs.rip = trap_addr + 1;
                    ptrace::setregs(child_pid, regs).unwrap();
                    ptrace::cont(child_pid, None).unwrap();
                }
                else if nanomite_count == 2 {
                    if is_authenticated {
                        regs.rip = win_address;
                        ptrace::setregs(child_pid, regs).unwrap();
                        ptrace::cont(child_pid, None).unwrap();

                        match waitpid(child_pid, None).unwrap() {
                            WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP) => {
                                let final_regs = ptrace::getregs(child_pid).unwrap();
                                if final_regs.rax == 0x99 {
                                    println!("Good Password !");
                                }
                            }
                            _ => {
                                println!("Good Password !");
                            }
                        }
                    }
                    else {
                        regs.rip = trap_addr + 1;
                        ptrace::setregs(child_pid, regs).unwrap();
                        ptrace::cont(child_pid, None).unwrap();

                        waitpid(child_pid, None).unwrap();
                        println!("Bad password...");
                    }
                    let _ = ptrace::kill(child_pid);
                    break;
                }
            }
            WaitStatus::Exited(_, _) => {
                break;
            }
            _ => {
                if ptrace::cont(child_pid, None).is_err() {
                    break;
                }
            }
        }
    }
}
```
