# ebpf-tool/internals/ebpf/logs.h

### problème constaté: 
- il y a un define qui n'a pas vraiment de sens POPULATE_LOG_METADATA
  d'après ce que je vois c'est une fonction pour remplir les champs
  d'une structure log. sauf que j'ai aussi une fonction fill_logs.
- choisir des meilleurs noms de fonctions 

# ebpf-tool/internals/ebpf/policy.h

### problèmes constatés
- j'ai utilisé max_elements pour eviter d'avoir des structures trop
  lourdes en mémoire. le problème c'est que ça rend les polices beaucoup
  moins intéressantes à mettre en place à cause des limites. comme dans
  le cas où on a cinq fichiers à protéger il faut soit désigner tout le
  repertoire ou utiliser deux polices.
- MAX_STR_LEN est trop court pour les chemins linux. Peut entrainer des 
  soucis dans certains setup

# ebpf-tool/internals/ebpf/main.ebpf.c
### problèmes rencontrés
- dummy_log_map une map inutile difficile d'identifier à quoi cette map
  sert (note: souvent utilisée pour forcer bpf2go à générer les types Go associés à Log)

# ebpf-tool/internals/ebpf-utils/ebpf_loop.go
### problèmes constatés
- La logique pour émettre des logs se retrouve en à l'exterieur d'une fonction
  dans ebpf_loop le problème c'est que le logger doit etre transmis en paramètre
  à la fonction Run pour avoir un code beaucoup plus compréhensible.
- l'enregistrement des logs dans la base de données est bloquant. Il faut faire
  sorte d'utiliser une goroutine pour faire en sorte que les enregistrement se
  déroule en arrière-plan pour permettre de sortir du case rapidement et reduire
  la latence.
- La fonction Run est trop grand mais c'est une conséquance des deux précédents
  problèmes.

# ebpf-tool/internals/ebpf-utils/parse_policy.go
### problèmes rencontrés
- Retirer les fonctions utilaire telles que StringToInt... et les placer dans le 
  ebpf-tool/internals/ebpf-utils/utils.go
- la fonction translate_policy est trop grande. Il faut créer des fonctions pour
  chaque sections de la police de sécurité pour qu'il y ait une mini fonction
  pour chacune d'entre elles.
- Le code manque de flexibilité. Je sais que c'est inhérent au fait que j'utilise
  une police de sécurité yaml. Mais je suis sur qu'avec une convention de lecture
  je peux faire en sorte de standardiser la lecture des champs.

# ebpf-tool/internals/handler/policy.go & ebpf-tool/config.yaml
### problèmes rencontrés
- le problème n'a rien de syntaxique. c'est juste que les polices de sécurité 
  avec une certains arborescence sont difficile à traduire en c. si on va au-delà
  d'un niveau. Il faut réfléchir à une manière de faire en sorte que la police
  soit aplatie ou gérée dynamiquement via des maps eBPF plus adaptées.

# ebpf-tool/logs/app.log
### problèmes rencontrés
- ce fichier doit etre placé dans un serveur de fichier et ne pas etre stocker dans
  l'arborescence du projet ça rend le projet difficilement portatif.

# orchestrator/cmd/main.go
### problèmes rencontrés
- ici doit etre initialiser une connexion au serveur de fichier pour enregistrer les
  logs.
- Le formattage de logs doit se faire dans un autre fichier.
- les logs d'erreur ne doivent pas etre envoyées dans le stdout
- dans la structuer switch dans la fonction main, il faut eviter les requetes http
  directes.
- Ce sous projet doit etre une cli app au lieu de traiter les arguments de manière
  plus ou moins manuelle. Manque de clarté et de structure
- la gestion des variables d'environment est mauvaise avec loadConfig. Les variables
  sont disponibles en clair dans la mémoire c'est à corriger.
- la base de données ne devrait pas etre accessible par main directement.
- la fonction resolveScoringURL doit récuperer l'url via les variables d'environment
- pareil pour resolveSaveURL.
- la fonction runBatchStep ne peut pas directement avoir accès à la db et est trop
  grande.
- loadEnv ne doit pas etre dans main.go

# ebpf-tool/cmd/main.go
### problèmes rencontrés
- ici doit etre initialiser une connexion au serveur de fichier pour enregistrer les
  logs.

# scoring/
### problèmes rencontrés
- Tout est à refaire ici : modèle en Python externe créant de la latence (HTTP, JSON, GC Python).
- Doit être entièrement réécrit en Go natif (`pkg/scoring`) pour être exécuté in-process dans la boucle eBPF.

# Refonte d'Architecture Globale (Monorepo, Binaire Unique & SQLite)
### Tâches à réaliser :
- **Unification Monorepo** :
  - Créer un `go.mod` unique à la racine (`github.com/dstm45/block-x`).
  - Supprimer les `go.mod` dispersés (`ebpf-tool/go.mod`, `orchestrator/go.mod`, etc.).
  - Réorganiser le projet en suivant le standard Go : `cmd/block-x/main.go`, `pkg/` (code partagé), `internal/` (code privé eBPF).
- **Suppression de l'Orchestrateur & Binaire Central Unique** :
  - Créer un `main.go` central dans `cmd/block-x/` qui charge les programmes eBPF, écoute le ringbuffer et évalue le scoring directement en mémoire sans latence IPC.
  - Utiliser un `chan SyscallEvent` Go bufferisé entre le lecteur ringbuffer et le pipeline d'analyse.
  - Déprécier et supprimer le sous-projet `orchestrator/`.
- **Remplacement de PostgreSQL par SQLite** :
  - Remplacer PostgreSQL par SQLite local en mode WAL (`PRAGMA journal_mode = WAL;`) pour supprimer toute dépendance d'infrastructure externe.
  - Déplacer et adapter le schéma et les requêtes SQL dans `pkg/database/`.
- **Portage du Scoring Python en Go** :
  - Implémenter l'algorithme N-Gramme avec lissage Add-$k$ directement en Go dans `pkg/scoring`.
  - Intégrer l'évaluation d'anomalies en temps réel (< 5 µs par séquence).

