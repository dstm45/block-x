# projet de fin d'année
## titre: block-x

### Description
---

Le but de block-x est un system de monitoring pour les serveur linux
tournant sur le kernel à l'aide de la technologie ebpf.

### Stack:
---
DB: Postgres
kernel-space: c
user-space: go
conteneurisation: docker ou podman

### Fonctionnement:
---
* block-x surveille les syscalls(avec le module de sécurité de linux lsm) et les log tout en les enregistrant
  dans une bd pour pouvoir reconstituer les évenements d'une heure
  x à une heure y.
* **surveillance des comportements suspects**: le second but de block-x
  est de d'observer l'exécution des processus sur le serveur pour enre
  gistrer des comportements suspects. 
  > * exemple
  > ---
  > un processus qui supprime son executable après un certain temps.
  
  si possible il serait interressant de pouvoir copier l'exécutable
  pour pouvoir observer son comportements dans un environnement con
  trôlé.
* block-x applique une police de sécurité en yaml sur le serveur pour
  établir un environnement zero trust en effet au lieu de fonctionner
  sur base d'une black list(ex: refuser d'éxécuter x logiciel). la 
  police de sécurité introduit la notion de white liste ce qui fait que
  seul les logiciels autorisés pourront avoir la possibiilité d'ouvrir
  certains fichiers ou tout simplement de s'exécuter

  > * exemple pour la police de sécurité
  > ---
  > ```
  > version: "1.0"
  > metadata:
  >   target: "ebpf-lsm-logger"
  > 
  > global_defaults:
  >   on_unmatched: "allow" # Don't crash the OS
  >   audit: true
  > 
  > policies:
  >   - name: "Protect Secrets"
  >     paths: 
  >       - "/home/monga/code/ebpf/syscall_logger/secret.txt"
  >     
  >     # Logic: Grouping syscalls into "Access Modes"
  >     rules:
  >       - mode: "read_only"
  >         apps: ["cat", "grep"]
  >         uids: [1000]
  >         action: "allow"
  > 
  >       - mode: "any"
  >         apps: ["nvim", "vi"]
  >         uids: [1000]
  >         action: "deny"
  > 
  >     # Separate logic for meta-operations
  >     management:
  >       allow_delete: false
  >       allow_rename: false
  >       allow_chmod: false
  > ```

  cette police n'est pas définitive. Je ne vais pas recréer un système
  de police de zéro. Si possible je vais en copier un sur internet.


* block-x propose un système d'alerte qui score les différentes repérées
  avec une note de sévérité allant de 1 à 10 en fonction du danger et de 
  l'urgence de la situation. Dans un premier temps je peux utiliser des
  algorithmes qui vont se servir de règles fixes pour scorer les différentes
  alertes.


### Addition si le delais le permet:
---
#### 1. dashboard
---
Juste la partie exécutables est suffisante pour le projet mais 
un plus si je le termine à temps je pense que je peux rajouter
une interface web pour pouvoir gérer plusieurs machines et voir
quelles polices de sécurité est mise en place et les modifier.
en gros une *dashboard*.

#### 2. honney pot
---
Avoir une vm ou un conteneur docker peut-être, qui va
se charger de continuer d'exécuter un virus si un virus est attrapé
ou en cas d'intrusion qui va permettre de surveiller quels avec une
architecture ressemblant au vrai serveur pour surveiller le comportement
des attaquants et loggers leurs actions.

#### 3. rajout d'un modèle d'intélligence artificielle
utilisation de modèle d'ia basique pour repérer les comportements
suspects en questions(super dur c'est la partie la plus compliquée
du projet).

#### 4. Tester les fichiers
DAns le cas où l'utilisateur peu tuploader des fichiers il faut checker ces
fichiers pour voir si ce ne sont pas des exploits qui peuvent être exécutés
en calculant leur entropie par exemple et en utilisant du regex sur les 
nouveaux fichiers.

#### 5. Renforcer l'aspect zero trust
Je viens de me rendre compte que l'admin système peut quand même attaquer le
système et c'est un casse-tête. Il faut faire en sorte de limiter son action
même si c'est lui qui définit les polices de sécurité.


### Limites du projet
---

Je suis convaincu que ce projet ne dois en aucun cas toucher à ce qui
est réseaux pour gagner du temps donc je ferais le strict minimum de ce
côté là. Le but principal est d'empêcher les attaquants de faire ce qu'ils
veulent après intrusion ou exécution du virus et d'enregistrer leurs
comportements et pouvoir reconstituer l'attaque dans le cas d'un échecs.

### Déploiement
---
Je pense qu'il est évident que block-x va tourner en tant que services trop 
compliqué de setup ce genre de truc en tant que conteneur vu qu'il va tourner
en root. Et grâce à CO-RE mon code ebpf devrait s'exécuter nativement sans aucun
problème sur toutes les distributions linux

Je crois également que l'exécutable qui va run sur le serveur doit manager
d'autre exécutable et lancer des services si nécéssaire au lieu d'avoir un
monolithe qui gère tout(Je ne vois pas comment ça va être propre du coté code.)
Donc j'aurais manager qui lance le programme kernel et le serveur web en background
C'est le manager de block-x qui sera en service et non l'exécutable ebpf directement.

### Timeline:
----------

#### 1. Lundi 2/3/2026 -> Dimanche 8/3/2026: Obtention du mvp
----------

cela veut dire que notre projet à ce stade là sera capable de logger 
et d'enregistrer les information dans la base de données postgres. j'ai déjà
un projet qui fait ça donc je vais le modifier pour qu'il puisse intéragir avec
une base de données et utiliser les bons syscalls c'est-à-dire utiliser le moins
de kprobes possibles pour laisser la place au syscalls lsm

#### 2. Lundi 9/3/2026 -> Dimanche 15/3/2026: Rajout du système de police de sécurité
----------

On va rajouter un système de police de sécurité que je vais trouver sur internet
un truc du genre tetrargon, etc.

#### 3. Lundi 16/3/2026 -> Dimanche 22/3/2026: Rajout des algorithmes des scoring
----------

Il faudra pouvoir scorer les différents alertes qui seront émises
histoire de voir s'il faut une intervention directe ou non.

#### 4. Lundi 23/3/2026 -> Dimanche 29/3/2026: Rajout d'un dashboard
----------

#### 5. Lundi 30/3/2026 -> Dimanche 5/4/2026: Mise en place de l'achitecture du manager
----------

On va coder le manager qui va gérer le serveur web ainsi que le programme ebpf
