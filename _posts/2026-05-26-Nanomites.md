---
title: "Méthode d'Anti-Debug : Nanomites"
date: 2026-05-26 12:00:00 +0200
categories: [Documentation, Anti-Debug Method]
tags: [reverse, Rust, Anti-Debug]
---
#### 1. Introduction

Les nanomites sont une technique d'obfuscation de code logicielle conçue pour casser l'analyse statique et le reverse simple de programmes. Elle repose sur la séparation d'un programme en deux entités : 

* `Un processus Enfant (Child)`
* `Un processus Parent`

Dans un programme classique, les instructions, les opérations ainsi que les conditions sont visibles clairement, un reverseur peut facilement modifier ces instructions afin de forcer le changement de comportement d'un programme (patching).

En utilisant des nanomites, certaines instructions importantes sont donc remplacées par des interruptions matérielles volontaires (`INT 3 : 0xCC`). L'enfant devient un exécuteur passif, c'est le parent qui prend toutes les décisions à sa place et le guide vers les instructions à exécuter via l'API de débogage du système d'exploitation (`ptrace` sous Linux).

#### 2. Architecture Système

Pour comprendre le fonctionnement des nanomites, il faut analyser le comportement des processus sous forme de phases. Au démarrage du binaire, le flux d'exécution standard est rompu et est séparé via l'initialisation d'un `fork()` (le système d'exploitation crée une réplique exacte du processus en mémoire), ainsi le processus parent devient le maître et le processus enfant l'esclave.

Avant tout exécution de code, l'esclave appelle `ptrace(PTRACE_TRACEME)`. Cet appel indique au noyau qu'il autorise au parent d'intercepter ses signaux, de suspendre son processus et de modifier ses registres.

Lorsque l'enfant tombe sur une interruption matérielle `INT 3`, celui-ci se fige puis envoie un signal `SIGTRAP` au parent. Le parent, qui attendait via `waitpid()`, prend ainsi le contrôle et configure le comportement de l'environnement puis ordonne à l'enfant de continuer son exécution via `ptrace(PTRACE_CONT)`.

#### 3. Flux d'exécution

Dès que l'enfant rencontre une nanomite, le flux temporel suit un cycle spécifique : 

##### L'exécution linéaire de l'enfant : 

L'enfant exécute ses instructions de manière classique. Les valeurs nécessaires à la suite du programme sont chargées dans les registres du processeur.

##### Le Trap

L'enfant tombe sur une interruption matérielle `INT 3`. L'enfant est stoppé et le pointeur d'instruction (`RIP en x64`) est figé.

##### L'alerte

Le noyau intercepte l'exception de l'enfant et la traduit en un signal `SIGTRAP`. Le parent prend la main puis reçoit le statut de l'enfant indiquant qu'il est stoppé sur un point d'arrêt.

##### Le choix du parent

Le parent passe en mode supervision puis réalise différentes actions importantes : 

* Il extrait l'intégralité du contexte des registres de l'enfant afin d'en analyser l'état interne via `ptrace(PTRACE_GETREGS)`.
* En fonction de sa table de correspondance ainsi que de l'adresse d'interruption et des valeurs dans les registres, il décide du chemin que prendra ensuite l'enfant.
* Le parent modifie les registres de l'enfant comme il le souhaite. Il peut injecter un résultat ou modifier directement le pointeur d'instruction afin de forcer l'enfant à se déplacer vers un tout autre endroit de la mémoire.

##### Le détachement

Une fois la supervision terminée, le parent ordonne la reprise de l'exécution de l'enfant via `ptrace(PTRACE_CONT)` et se rendort fige immédiatement dans un nouveau `waitpid()`. L'esclave est ensuite réveillé par le noyau, reprend son cours initial et continue avec ses registres altérés et son nouveau flux d'exécution.

#### 4. Complexité de l'analyse statique

Les décompilateurs modernes reconstruisent le code C en générant un `Control Flow Graph (CFG)`. Ils lient les fonctions entre elles en cherchant des instructions de saut.

En ajoutant des nanomites, le `CFG` devient totalement illogique. Les blocs de code qui devraient être liés par des conditions logiques apparaissent comme isolés, sans aucun lien entre eux.

Le décompilateur s'arrête donc souvent au premier `INT 3`, considérant tout ce qui suit comme du code mort ou inaccessible. Le pseudo-code généré devient donc incomplet, voire totalement vide.

Exemple de pseudo-code s'arrêtant au premier `INT 3` sans afficher la suite : 

```

/* nanomites::run_slave */

void __rustcall nanomites::run_slave(void)

{
  code *pcVar1;
  int iVar2;
  undefined8 local_30 [5];
  
  iVar2 = nix::sys::ptrace::linux::traceme();
  if (iVar2 == 0x86) {
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  local_30[0] = CONCAT44(local_30[0]._4_4_,iVar2);
  local_30[0] = core::result::unwrap_failed
                          ("called `Result::unwrap()` on an `Err` valueUnknownErrnoEPERMENOENTESRCHE INTREIOENXIOE2BIGENOEXECEBADFECHILDEAGAINENOMEMEACCESEFAULTENOTBLKEBUSYEEX ISTEXDEVENODEVENOTDIREISDIREINVALENFILEEMFILEENOTTYETXTBSYEFBIGENOSPCESPIP EEROFSEMLINKEPIPE"
                           ,0x2b,local_30,&DAT_00156d28,&PTR_s_src/main.rs_00156eb8);
                    /* try { // try from 00117690 to 001176b4 has its CatchHandler @ 0011771d */
  core::result::unwrap_failed
            ("called `Result::unwrap()` on an `Err` valueUnknownErrnoEPERMENOENTESRCHEINTREIOENXIOE2 BIGENOEXECEBADFECHILDEAGAINENOMEMEACCESEFAULTENOTBLKEBUSYEEXISTEXDEVENODEVENOTDIREISDIRE INVALENFILEEMFILEENOTTYETXTBSYEFBIGENOSPCESPIPEEROFSEMLINKEPIPE"
             ,0x2b,local_30,&PTR_drop_in_place<std::io::error::Error>_00156d48,
             &PTR_s_src/main.rs_00156ed0);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}


```

Le décompilateur tombe sur un `INT 3` et renvoie `invalidInstructionException()`, il considère ensuite que le reste du programme est du code mort ou inaccessible et ne l'affiche pas.

#### 5. La résistance au Patching

Sur un binaire classique, un patch peut être appliqué en inversant un saut, une instruction ou une valeur afin de forcer le succès d'une condition. Sur un programme protégé par les nanomites, si l'interruption matérielle `INT 3` est supprimée ou modifiée, le parent n'est jamais alerté, les registres et le flux d'exécution de l'enfant ne sont jamais modifiés, ainsi le programme crash ou s'arrête sans avoir exécution son but initial.

#### 6. Analyse dynamique

Afin d'analyser un binaire utilisant des nanomites, l'approche statique devenant extrêmement complexe, le moyen le plus simple est de basculer sur une approche dynamique ou hybride.

Le reverseur configure son débogueur afin de suivre l'enfant dès le fork (ex : `set follow-fork-mode child` sous GDB), il le configure ensuite afin de ne pas masquer les signaux et de pouvoir intercepter manuellement chaque `SIGTRAP`.

A chaque arrêt, une analyse de la mémoire doit être faite afin de retrouver les instructions associées à chaque nanomite et dumper les registres de l'enfant avant et après l'intervention du parent afin d'en déduire la logique globale du programme.
