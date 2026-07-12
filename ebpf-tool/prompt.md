je veux que tu me réalise une monographie de 15 pages avec la méthodologies IMRaD:
1. Résumé
2. Mots-clés
3. Introduction
- contexte
- problématique
- objectifs
- intérêt du projet
4. Méthodologie
- présentation de Linux
- rappel sur eBPF
- architecture
- choix de Go
- choix de PostgreSQL
- fonctionnement des hooks LSM
- communication kernel/userspace
- structure des maps
- déroulement de l'implémentation
5. Résultats
- captures d'écran
- performances
- exemples de logs
- exemples de détection
6. Discussion
- avantages
- limites
- comparaison avec Auditd
- comparaison avec Falco
- comparaison avec Wazuh
- pistes d'amélioration
7. Conclusion
8. Références bibliographiques

Sujet : Conception et implémentation d'un HIDS (Host Intrusion Detection System) basé sur eBPF sous Linux.

Le projet consiste à développer un HIDS utilisant les Linux Security Modules (LSM) et eBPF afin de surveiller
les accès aux fichiers et détecter des comportements suspects. Les programmes eBPF sont écrits en C, l'espace
utilisateur est développé en Go avec la bibliothèque Cilium/ebpf. Les événements sont enregistrés dans PostgreSQL
et la configuration est définie dans un fichier YAML


les livres et sites que j'ai utilisés sont 
- Learning Ebpf de Liz Rice
- The linux Programming Linux Interfaces
- Learning Go, de Joe bodner
- Programming rust parce qu'à un moment j'ai envisagé de constuire le projet en rust avec aya, le soucis était la
documentation pauvre d'aya ainsi que l'équivalent de vmlinux.h pour rust était trop lourd à charger en mémoire
- Linux kernel programming
- nist special publication 800-94 qui décrit ce qu'est un HIDS
- Unix and Linux systemadministration
- https://ebpf-go.dev/ pour apprendre cilium avec go 
- https://eunomia.dev/ pour voir quelques snippets de code en c

