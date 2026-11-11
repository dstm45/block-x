# Rapport d'Analyse des Anomalies et Vulnérabilités de Block-X

Ce document recense l'ensemble des anomalies, bogues critiques, incohérences d'architecture et vulnérabilités de sécurité identifiés dans la base de code **Block-X**.

---

## 1. Module eBPF / Espace Noyau (`ebpf-tool/internals/ebpf/`)

### 1.1 Incohérence PID vs TGID (Échec de recherche dans `datatable`)
- **Fichier** : `ebpf-tool/internals/ebpf/main.ebpf.c` (lignes 93, 296, 369)
- **Problème** :
  - Dans `detect_file_opening` (`sys_enter_openat`), la clé est enregistrée avec `data.pid = BPF_CORE_READ(current_task, pid);`. Dans la structure `task_struct` du noyau Linux, `task->pid` représente l'identifiant du thread (**TID**), alors que `task->tgid` représente l'identifiant du processus (**PID/TGID** en espace utilisateur).
  - En revanche, dans `check_if_file_exists` (`sys_exit_openat`) et `get_path` (`lsm/file_open`), la clé recherchée est calculée via `bpf_get_current_pid_tgid() >> 32`, ce qui extrait le **TGID**.
- **Impact** : Pour tout processus multithreadé (ou thread non principal), `TID != TGID`. La recherche dans `datatable` (`bpf_map_lookup_elem`) échoue systématiquement.

### 1.2 Fuite de mémoire noyau dans la BPF Map `datatable`
- **Fichier** : `ebpf-tool/internals/ebpf/main.ebpf.c` (lignes 297-302)
- **Problème** :
  ```c
  if (ctx->ret >= 0) {
      return 0; // Aucun nettoyage !
  } else {
      bpf_map_delete_elem(&datatable, &pid);
  }
  ```
  Sur `sys_exit_openat`, si l'appel système réussit (`ret >= 0`), l'entrée insérée par `sys_enter_openat` n'est **jamais** supprimée par le code noyau.
- **Impact** : Bien que l'espace utilisateur parcoure la table toutes les secondes, sous forte charge ou lors de nombreuses ouvertures de fichiers, la table (`MAX_ENTRIES = 10240`) sature rapidement. Dès saturation, les nouveaux fichiers ne peuvent plus être enregistrés ni vérifiés par le hook LSM.

### 1.3 Faille critique de contournement de politique dans `is_allowed` (Logique OR au lieu de AND)
- **Fichier** : `ebpf-tool/internals/ebpf/main.ebpf.c` (lignes 343-365)
- **Problème** :
  ```c
  static __always_inline int is_allowed(const AccessControl *ac, u32 uid, const char *comm) {
    if (ac->has_allow == 0) return 0;

    for (int i = 0; i < MAX_ELEMENTS; i++) {
      if (i >= ac->allow.user_uid_count) break;
      if (ac->allow.user_uid[i] == uid) return 1; // Autorise immédiatement si UID correspond
    }

    for (int i = 0; i < MAX_ELEMENTS; i++) {
      if (i >= ac->allow.binary_paths_count) break;
      if (comm_equal(ac->allow.binary_paths[i], comm)) return 1; // Autorise immédiatement si binaire correspond
    }
    return 0;
  }
  ```
- **Impact** :
  1. Si une règle définit `user_uid: [0]` et `binary_paths: ["/bin/cat"]`, **tout processus lancé par root (UID 0)** (bash, python, malware, etc.) est immédiatement autorisé car `uid == 0` renvoie `1`. La restriction de binaire est totalement ignorée.
  2. Inversement, **n'importe quel utilisateur standard** exécutant `/bin/cat` (ou un exécutable nommé `cat`) obtiendra l'autorisation car `comm_equal` renverra `1`.
  3. L'intention de restreindre l'accès à un binaire précis exécuté par un utilisateur précis est contournée.

### 1.4 Sécurité insuffisante sur la comparaison de binaire (`comm_equal`)
- **Fichier** : `ebpf-tool/internals/ebpf/main.ebpf.c` (lignes 334-341) et `parse_policy.go` (ligne 56)
- **Problème** : `comm` est obtenu via `bpf_get_current_comm` (limité à 16 caractères et facilement falsifiable via `prctl(PR_SET_NAME)`). Dans `parse_policy.go`, le chemin absolu configuré (ex: `/bin/cat`) est réduit à son nom de base (`filepath.Base(bpath)` -> `"cat"`).
- **Impact** : N'importe quel binaire malveillant situé dans `/tmp/cat` portera le `comm` `"cat"` et sera validé par la politique.

### 1.5 Absence totale de journalisation des blocages LSM
- **Fichier** : `ebpf-tool/internals/ebpf/main.ebpf.c` (lignes 423, 426, 438, 441)
- **Problème** : Lorsque la politique LSM refuse l'accès (`return -EACCES`), aucun événement n'est émis dans `logs_ringbuf`.
- **Impact** : Les tentatives d'intrusion et les accès bloqués ne sont pas enregistrés dans la base de données. Le système de détection est aveugle aux violations de sécurité actives.

### 1.6 Troncature silencieuse et limites rigides (`policy.h`)
- **Fichier** : `ebpf-tool/internals/ebpf/policy.h` (lignes 9-10)
- **Problème** : `MAX_STR_LEN` est fixé à 64 octets et `MAX_ELEMENTS` à 4.
- **Impact** : Les chemins Linux dépassant 63 caractères sont tronqués silencieusement lors de la conversion en Go (`StringToInt8Array64`). De plus, une configuration contenant plus de 4 fichiers ou répertoires restreints voit ses règles supplémentaires ignorées sans avertissement.

---

## 2. Incohérences de Schéma et Base de Données (`migrations/` vs `scoring/`)

### 2.1 Absence de la colonne `ppid` dans le script SQL officiel
- **Fichier** : `scoring/database_migration.sql` vs `ebpf-tool/internals/database/queries/logs.sql`
- **Problème** :
  - Le `README.md` indique d'exécuter la migration avec :
    ```bash
    psql -U <utilisateur> -d <base_de_données> -f scoring/database_migration.sql
    ```
  - Or, `scoring/database_migration.sql` **ne contient pas** la colonne `ppid`.
  - La requête d'insertion d'ingestion de `ebpf-tool` (`SaveLogs`) exige impérativement `ppid` :
    ```sql
    INSERT INTO logs(timestamp, uid, gid, pid, ppid, comm, executable, tid, syscall, target, return_value, duration) VALUES(...);
    ```
- **Impact** : En suivant les étapes d'installation du README, `ebpf-tool` plante immédiatement à la première insertion avec l'erreur PostgreSQL : `column "ppid" of relation "logs" does not exist`.

### 2.2 Fragmentation des migrations et tables orphelines
- Il existe trois dossiers/scripts de migrations non synchronisés :
  1. `ebpf-tool/internals/database/migrations/` (Goose: `00001_schema.sql` avec `ppid`, `process_events`, et `00002_scoring_metrics.sql`).
  2. `scoring/database_migration.sql` (Script manuel sans `ppid`).
  3. `orchestrator/pkg/database/migrations/00001_schema.sql` (Crée uniquement la table `metrics`, inutilisée par l'orchestrateur).
- La table `process_events` n'est alimentée par aucun composant.

---

## 3. Démon d'Ingestion (`ebpf-tool`)

### 3.1 Résolution erronée du fichier `.env` et échec de connexion DB
- **Fichier** : `ebpf-tool/internals/config/config.go` (lignes 32-34)
- **Problème** :
  ```go
  envPath := filepath.Join(basepath, "..", "..", ".env")
  ```
  `basepath` correspond à `ebpf-tool/internals/config`. Remonter de deux crans pointe vers `ebpf-tool/.env`, qui n'existe pas (le fichier `.env` est à la racine du projet `block-x/`, soit 3 crans au-dessus).
- **Impact** : `godotenv.Load()` échoue. Sans variable d'environnement système préalable, `DatabaseURI` reste vide (`""`). L'appel `pgxpool.New(ctx, "")` dans `cmd/main.go` échoue avec un `log.Fatalln` dès le lancement.

### 3.2 Inversion de données : `Executable` stocke le fichier cible
- **Fichier** : `ebpf-tool/internals/ebpf-utils/ebpf_loop.go` (lignes 105, 108)
- **Problème** :
  ```go
  Comm:       Int8ToString(value.ProcessName[:]),
  Executable: Int8ToString(value.Filepath[:]),
  Syscall:    257,
  Target: pgtype.Text{
      String: Int8ToString(value.Filepath[:]),
      Valid:  true,
  },
  ```
  Le champ `Executable` de la table SQL reçoit `value.Filepath`, qui est le fichier ouvert par l'appel `openat`, et non le binaire du processus.

### 3.3 Défaut de vidage du tampon de logs (Batching défaillant)
- **Fichier** : `ebpf-tool/internals/ebpf-utils/ebpf_loop.go` (lignes 118-121)
- **Problème** :
  ```go
  if len(logs) == configuration.LogBatchNumber {
      query.SaveLogs(ctx, logs)
      logs = make([]database.SaveLogsParams, 0)
  }
  ```
  - La condition est une stricte égalité `==`.
  - Si le nombre d'événements collectés dans l'intervalle est inférieur à `LogBatchNumber`, ils ne sont jamais flushés à la fin du tick.
  - Lors de la réception de `SIGINT` (`stop`), les logs en attente dans le slice ne sont pas persistés.
  - La valeur d'erreur de `query.SaveLogs(ctx, logs)` n'est pas vérifiée.

### 3.4 Incohérence de package
- **Fichier** : `ebpf-tool/internals/utils/utils.go` (ligne 1)
- **Problème** : Le fichier se trouve dans le sous-dossier `utils`, mais déclare `package handler`.

---

## 4. Service d'Orchestration (`orchestrator`)

### 4.1 Variable `LogFilePath` non initialisée provoquant un crash au démarrage
- **Fichier** : `orchestrator/pkg/config/config.go` (lignes 30-35) et `orchestrator/cmd/main.go` (lignes 52-56)
- **Problème** :
  Dans `config.go`, le champ `LogFilePath` n'est pas initialisé et vaut `""`. Dans `main.go`, le code fait :
  ```go
  logPath := configuration.LogFilePath
  logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
  ```
- **Impact** : `os.OpenFile("", ...)` renvoie systématiquement une erreur `open : no such file or directory`.

### 4.2 Mises à jour SQL séquentielles dans une transaction (Goulot d'étranglement)
- **Fichier** : `orchestrator/cmd/main.go` (lignes 263-277)
- **Problème** : L'orchestrateur effectue une boucle de 100 requêtes `UPDATE` individuelles au sein d'une transaction au lieu d'une mise à jour groupée (`UPDATE ... FROM (VALUES ...)`).

### 4.3 Déconnexion entre `pkg/database` et le code applicatif
- Le dossier `orchestrator/pkg/database/` fournit du code généré par sqlc pour insérer des métriques physiques (`SaveMetrics`), alors que l'orchestrateur n'a besoin que de lire et mettre à jour la table `logs`.

---

## 5. Moteur Analytique et Scoring (`scoring/`)

### 5.1 Bogue mathématique du lissage Add-k à l'état initial
- **Fichier** : `scoring/model/ngram.py` (lignes 79-88)
- **Problème** :
  ```python
  vocab_size = max(1, len(self.vocab))
  prob = (t_count + self.k) / (c_count + self.k * vocab_size)
  return 1.0 - prob
  ```
  Au démarrage, sans modèle préchargé, `len(self.vocab) == 0`, d'où `vocab_size = 1`.
  Pour toute première séquence inconnue (`c_count = 0`, `t_count = 0`) :
  $$\text{prob} = \frac{0 + 0.01}{0 + 0.01 \times 1} = 1.0$$
  $$\text{anomaly\_score} = 1.0 - 1.0 = 0.0$$
- **Impact** : Une séquence complètement inédite au démarrage reçoit un score d'anomalie de `0.0` (considérée comme parfaitement normale). Dans `scoring/test_integration.py` (lignes 32-35), le commentaire attendait un score élevé mais l'assertion a été abaissée à `>= 0.0` pour masquer l'anomalie.

### 5.2 Empoisonnement du modèle en mode détection (Data Poisoning)
- **Fichier** : `scoring/worker.py` (lignes 91-98)
- **Problème** :
  ```python
  score = self.model.score(seq)
  event["processed"] = True
  event["anomaly_score"] = score
  event["anomaly"] = (score >= self.anomaly_threshold) if not self.training_mode else False

  # Entraînement inconditionnel !
  self.model.train(seq)
  ```
- **Impact** : Même lorsqu'une séquence est détectée comme malveillante (`anomaly = True`), elle est immédiatement transmise à `self.model.train(seq)`. Le modèle s'auto-empoisonne en apprenant les séquences d'attaque, qui deviennent rapidement considérées comme normales lors des itérations suivantes.

### 5.3 Blocage I/O disque synchrone dans la boucle d'événements asynchrone
- **Fichier** : `scoring/main.py` (lignes 88-92, 183-188)
- **Problème** : À chaque lot envoyé par l'orchestrateur (toutes les 500 ms), `model.save(MODEL_PATH)` est exécuté de manière synchrone (`pickle.dump` sur disque) dans le thread asyncio principal de FastAPI.
- **Impact** : Surcharge disque constante et blocage de la boucle événementielle de l'API sous flux continu.

### 5.4 Corruption des séquences multi-threads par PID
- **Fichier** : `scoring/worker.py` (lignes 34, 49, 70-84)
- **Problème** : Le worker stocke l'historique des fenêtres glissantes uniquement par `pid` (`self.pid_windows[pid]`).
- **Impact** : Sous Linux, tous les threads d'un même processus partagent le même TGID (PID). Les appels système concurrents de plusieurs threads s'entremêlent dans la même fenêtre glissante, créant des n-grammes artificiels et causant de faux positifs.

---

## 6. Services Périphériques (`web`, `sonde`) et Documentation

### 6.1 Conflit de port HTTP entre `web` et `scoring`
- **Fichier** : `.env` (ligne 2) et `web/pkg/config/config.go` (ligne 39)
- **Problème** : Le fichier `.env` définit `SERVER_PORT=8000`.
  - `scoring` écoute sur le port 8000 (FastAPI / Uvicorn).
  - `web` charge `.env` et écoute également sur `SERVER_PORT` (8000).
- **Impact** : Impossible de faire tourner l'API `web` et le service `scoring` simultanément sans collision de port `bind: address already in use`.

### 6.2 Déréférencement de pointeur nul provoquant un crash dans `web`
- **Fichier** : `web/pkg/controllers/data.go` (lignes 25-33)
- **Problème** :
  ```go
  data, err := c.service.Gather(ctx)
  if err != nil {
      log.Println("Erreur lors du rassemblement des données")
  }
  err = json.NewEncoder(w).Encode(&data)
  err = c.service.Save(ctx, *data) // Panique si data == nil !
  ```
- **Impact** : Si `Gather()` renvoie une erreur (`data == nil`), le serveur panique et s'arrête brutalement sur `*data`.

### 6.3 Écart fonctionnel majeur dans le service `web`
- Le `README.md` présente `web` comme une API REST pour interroger les logs et anomalies de sécurité du HIDS.
- En réalité, `web` ne lit jamais la table `logs`. Il se contente de collecter des métriques CPU/RAM locales (dupliquant `sonde`) et de les écrire dans la table `metrics`.

### 6.4 Fichier manquant documenté
- Le `README.md` (lignes 45 et 131) fait référence à `monographie_block_x.tex`, mais ce fichier est absent du dépôt.

---

## Matrice Récapitulative des Anomalies

| Composant | Fichier | Gravité | Type d'Anomalie |
|---|---|---|---|
| **eBPF Kernel** | `main.ebpf.c:93,369` | **Critique** | TID vs TGID: échec de corrélation `datatable` |
| **eBPF Kernel** | `main.ebpf.c:343` | **Critique** | Faille de sécurité: condition OR au lieu de AND dans `is_allowed` |
| **eBPF Kernel** | `main.ebpf.c:297` | **Élevée** | Fuite de mémoire: pas de suppression dans `datatable` si succès |
| **eBPF Kernel** | `main.ebpf.c:423` | **Moyenne** | Absence de télémétrie sur les refus LSM |
| **Base de Données**| `database_migration.sql` | **Critique** | Colonne `ppid` manquante; bloque l'ingestion `ebpf-tool` |
| **ebpf-tool** | `config.go:32` | **Critique** | Chemin `.env` incorrect; échec de démarrage (DSN vide) |
| **ebpf-tool** | `ebpf_loop.go:105` | **Moyenne** | Inversion de champs: chemin cible écrit dans `executable` |
| **Orchestrator** | `config.go:30` / `main.go:56` | **Moyenne** | `LogFilePath` vide; échec d'ouverture du fichier de log |
| **Scoring** | `worker.py:98` | **Critique** | Empoisonnement du modèle: apprentissage des séquences malveillantes |
| **Scoring** | `ngram.py:82` | **Élevée** | Bogue mathématique: probabilité 1.0 (score 0.0) sur séquence inconnue à vide |
| **Web** | `.env:2` / `config.go:39` | **Élevée** | Conflit de port (8000) avec `scoring` |
| **Web** | `controllers/data.go:33` | **Élevée** | Déréférencement de pointeur nul si erreur de collecte |
| **Web** | `services/data.go` | **Moyenne** | Incohérence architecturale: n'expose aucun log de sécurité |
