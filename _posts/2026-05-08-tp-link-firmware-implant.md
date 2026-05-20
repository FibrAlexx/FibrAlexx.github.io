---
layout: post
title: TP-Link TL-WR841N - Implant firmware MIPS
date: 2026-05-08
categories: Hardware Hacking
tags:
  - mips
  - firmware
  - flashrom
  - reverse-shell
  - uart
  - squashfs
---

Dans ce post, je vais détailler comment j'ai obtenu un shell root sur un TP-Link TL-WR841N v14 en passant par ses pins UART, comment j'ai extrait, modifié et re-flashé son firmware pour y implanter un reverse shell persistant — et pourquoi le fait que la partition soit en lecture seule (SquashFS RO) n'est pas un obstacle quand on a accès au stockage physique.

Ce projet mêle hardware hacking, cross-compilation et analyse de firmware embarqué.

## La cible

Le TP-Link TL-WR841N est un routeur Wi-Fi bas de gamme extrêmement répandu — il en existe des millions dans les foyers, les hôtels, les petites entreprises. C'est précisément ce qui en fait une cible intéressante : matériel bon marché, firmware minimal, et souvent aucune protection physique sérieuse.

![](/assets/images/tp-link/pasted-20260508161140.png)

## Présentation du PCB

Voici une vue d'ensemble du PCB :

![](/assets/images/tp-link/img-2456.jpg)

Les 3 composants principaux sont :

**La puce SOC (System On Chip)** — elle est appelée ainsi car cette petite puce intègre presque un ordinateur entier (processeur MIPS, contrôleur Wi-Fi, switch Ethernet, etc.) sur un seul bout de silicium. La référence relevée au microscope numérique est une **MediaTek MT7628NN**.

![](/assets/images/tp-link/img-2450-1.jpg)

En consultant le datasheet fourni par le constructeur, on relève quelques informations intéressantes :

![](/assets/images/tp-link/pasted-20260508162018.png)

La puce tourne sur une architecture MIPS et expose plusieurs interfaces intéressantes : JTAG et UART. On apprend également que le firmware tourne sous Linux 2.6.

**La mémoire Flash** :

![](/assets/images/tp-link/img-2451.jpg)

La référence marquée sur la puce est **eFeon QH32B 104HIP**. En cherchant sur internet, aucun datasheet ne correspond exactement à ce nom — tous les résultats pointent vers une puce **EN25Q32B d'EON**. La eFeon QH32B est une copie parmi tant d'autres de cette puce. Le datasheet nous apprend qu'elle fait **32 Mbits soit 4Mo** — c'est elle qui contient le système d'exploitation (Linux 2.6).

![](/assets/images/tp-link/pasted-20260508162612.png)

**La puce DRAM** :

![](/assets/images/tp-link/pasted-20260508163426.png)

Elle fait **256 Mbits soit 32Mo**. Ce n'est pas énorme, mais suffisant pour faire tourner un firmware embarqué minimal.

**Les pins UART** :

![](/assets/images/tp-link/pasted-20260508164309.png)

4 pins sont présentes sur le PCB (TX, RX, GND, VCC). Leur disposition ressemble fortement à un port UART. Un test au multimètre entre GND et VCC confirme une tension de **3.3V** — cohérent avec un UART actif. Ce port est utilisé par les constructeurs pour déboguer leurs produits, et il est donc fréquemment désactivé en production. J'ai quand même tenté de m'y connecter.

## Accès UART

![](/assets/images/tp-link/pasted-20260508165032.png)

N'ayant pas d'adaptateur UART-USB sous la main, j'ai utilisé un **Raspberry Pi Pico** comme bridge. J'ai flashé le firmware disponible sur ce repo : [https://github.com/Noltari/pico-uart-bridge](https://github.com/Noltari/pico-uart-bridge), puis effectué une soudure directement sur le PCB du routeur vers les pins du Pico spécifiées par le créateur du firmware.

![](/assets/images/tp-link/pasted-20260508165558.png)

Shell sur le SOC obtenu avec succès.

![](/assets/images/tp-link/capture-2026-05-07-194228.png)

## Analyse du système en live

![](/assets/images/tp-link/capture-2026-05-08-100053.png)

Il ne reste que 6Mo de RAM libre, mais c'est largement suffisant pour faire tourner une backdoor légère.

En regardant la sortie de `mount`, on comprend vite les contraintes du système :

- `/` est monté sur `/dev/root` en `squashfs (ro,relatime)` — le rootfs entier est en lecture seule. Impossible d'y écrire quoi que ce soit : pas de nouveaux fichiers, pas de modification de binaires existants.
- `/var` est en `ramfs (rw)` — c'est la seule zone accessible en écriture, mais c'est de la RAM pure. Au reboot, tout disparaît.
- `/proc` et `/sys` sont des pseudo-filesystems kernel — ils permettent d'interagir avec le kernel mais ne stockent rien de persistant.

En clair : si on veut implanter quelque chose qui survive au reboot, on ne peut pas passer par le système en live. La seule solution est d'écrire directement sur la puce flash SPI — physiquement, depuis l'extérieur, avec un programmateur. C'est exactement ce qu'on va faire.

![](/assets/images/tp-link/capture-2026-05-08-100200.png)
![](/assets/images/tp-link/capture-2026-05-08-101810.png)

Le `df` confirme ce qu'on suspectait : `/dev/root` affiche **100% utilisé** — le SquashFS est plein, pas un octet de libre.

`cat /proc/mtd` nous donne la carte mémoire complète de la puce flash SPI :

```
mtd0: 00010000 "boot"    →  64KB  - Bootloader U-Boot
mtd1: 000f0000 "kernel"  → 960KB  - Kernel Linux
mtd2: 002e0000 "rootfs"  → 2.87MB - SquashFS (notre cible)
mtd3: 00010000 "config"  →  64KB  - Configuration
mtd4: 00010000 "radio"   →  64KB  - Calibration WiFi
```

Notre cible est **mtd2**, situé à l'offset `0x100000` dans la flash. C'est exactement l'offset qu'on passera à `dd` plus tard pour injecter notre SquashFS modifié.

## Extraction du firmware

Pour extraire le firmware, j'utilise un programmateur **CH341A** équipé d'une pince SOIC8 qui se clippe directement sur les pattes de la puce flash sans dessoudage.

![](/assets/images/tp-link/pasted-20260508171509.png)

J'utilise `flashrom` pour piloter le CH341A. Première étape : un scan pour identifier la puce.

![](/assets/images/tp-link/capture-2026-05-08-102843.png)

Je spécifie le modèle exact avec `-c`, puis je lance la lecture :

```sh
sudo flashrom -p ch341a_spi -c "EN25QH32B" -r dump1.bin
```

![](/assets/images/tp-link/capture-2026-05-08-103414.png)

Pour s'assurer de l'intégrité des données, je répète l'opération 3 fois et compare les MD5 :

![](/assets/images/tp-link/capture-2026-05-08-103541.png)

Les 3 hashs sont identiques — le dump est fiable.

## Analyse du firmware

J'analyse le dump avec `binwalk` pour identifier les composants du firmware :

```sh
binwalk --run-as=root -e dump1.bin
```

![](/assets/images/tp-link/capture-2026-05-08-103925.png)

Deux éléments sont détectés :

- **`0x10200`** — données compressées LZMA : c'est le kernel Linux
- **`0x100000`** — filesystem SquashFS 4.0, compression xz, 3004864 bytes, 625 inodes, créé le 2020-09-03 : c'est notre rootfs, et surtout **notre cible**

Les warnings sur les symlinks (`/etc/TZ`, `/etc/passwd`, `/etc/resolv.conf`) sont normaux — binwalk les redirige vers `/dev/null` par sécurité.

L'offset `0x100000` est confirmé — c'est là qu'on injectera notre SquashFS modifié avec `dd`.

Une fois le SquashFS extrait, j'explore son contenu. Le fichier clé est `etc/init.d/rcS` — c'est le script de démarrage qui s'exécute au boot, notre point d'entrée pour la persistance.

![](/assets/images/tp-link/capture-2026-05-08-104221.png)

## Libération d'espace

Le filesystem fait **13MB décompressé** pour une partition de 2.87MB — c'est la puissance de la compression xz. Mais recompressé, on doit rester sous cette limite. Problème : le SquashFS est déjà plein à 100%, on doit libérer de la place avant d'injecter notre binaire.

![](/assets/images/tp-link/capture-2026-05-08-105844.png)

Deux cibles évidentes :

- **`/web/help`** — 516K de fichiers HTM d'aide en ligne, inutiles pour notre implant
- **`/usr/bin/dropbearmulti`** — 276K, le serveur SSH du routeur

![](/assets/images/tp-link/capture-2026-05-08-110021.png)
![](/assets/images/tp-link/capture-2026-05-08-110729.png)

On supprime les deux, ce qui libère environ **800K** — suffisant pour loger notre backdoor.

## Fabrication du payload

Le reverse shell est minimaliste : connexion TCP vers ma machine, redirection des file descriptors stdin/stdout/stderr sur le socket, puis `execve` pour spawner `/bin/sh`.

![](/assets/images/tp-link/capture-2026-05-08-112729.png)

Le routeur tourne sur architecture **MIPS 32-bit little-endian**. On ne peut pas compiler un binaire x86 et l'envoyer dessus — il faut cross-compiler depuis ma machine Debian avec la toolchain `mipsel-linux-gnu` :

```sh
mipsel-linux-gnu-gcc rev.c -o backdoor -static -Os -s
```

- `-static` : pas de dépendances aux libc dynamiques du routeur
- `-Os` : optimisation taille
- `-s` : strip les symboles

![](/assets/images/tp-link/capture-2026-05-08-113140.png)

## Injection & persistance

Je déplace le binaire dans `/bin/` du squashfs extrait et je patche `rcS` pour le lancer au boot avec un délai de 30 secondes — le temps que le réseau soit monté :

![](/assets/images/tp-link/capture-2026-05-08-113125.png)

## Recompression & flashage

```sh
mksquashfs _dump1.bin.extracted/squashfs-root mtd2_hacked.sqfs -comp xz -b 256K -noappend
```

Le SquashFS final fait **2.84MB** — sous la limite de 2.875MB de la partition mtd2. On injecte ce bloc dans une copie du dump original à l'offset `0x100000` :

```sh
cp dump1.bin dump_custom.bin
dd if=mtd2_hacked.sqfs of=dump_custom.bin bs=1 seek=$((0x100000)) conv=notrunc
```

![](/assets/images/tp-link/capture-2026-05-08-113955.png)
![](/assets/images/tp-link/capture-2026-05-08-114214.png)

Après avoir injecté la partition modifiée dans la copie du dump, je procède au re-flash de la puce avec `flashrom` :

![](/assets/images/tp-link/capture-2026-05-08-115116.png)

`Verifying flash... VERIFIED.`

## Premier boot — Segmentation fault

Avant de redémarrer le routeur, je lance mon listener :

```sh
sudo nc -lvnp 443
```

Au premier boot, le `nc` reçoit bien une connexion — le réseau fonctionne, le binaire s'exécute. Mais je perds le shell immédiatement. Je relance le binaire depuis ma connexion UART et je comprends directement le problème :

```
Segmentation fault
```

Le problème vient de `execve("/bin/sh", NULL, NULL)`. Sur le kernel 2.6.36 MIPS, passer `NULL` comme liste d'arguments provoque un crash. Il faut des tableaux propres :

```c
char *const sh_argv[] = {"/bin/sh", NULL};
char *const sh_envp[] = {NULL};
execve("/bin/sh", sh_argv, sh_envp);
```

![](/assets/images/tp-link/capture-2026-05-08-122813.png)

## Fix & shell root

Je recompile, ré-injecte et re-flashe avec le binaire corrigé :

![](/assets/images/tp-link/capture-2026-05-08-123934.png)

Shell root obtenu.

![](/assets/images/tp-link/capture-2026-05-08-124304.png)
