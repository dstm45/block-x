# Définition des caractéristiques pour ma police de configuration
---

Pour le projet block-x je compte utiliser des polices de sécurités 
écrites en yaml pour pouvoir indiquer des règles que je veux enforcer
au programme ebpf

## descrition
---

je veux principalement permettre de pouvoir conditionner l'ouverture et la
lecture d'un fichier. par exemple si quelqu'un sur le serveur essaie d'utiliser
nano ou cat sur /var/www/wordpress/config.php ou /etc/shadow. Il y clairement un soucis
donc par défaut il ne faudrait permettre aucun programme à part ceux étant
considéré comme les propiétaire du fichier d'y accéder comme apache.

deuxièmement je souhaite ajouter une police vive on va dire. C'est à dire que les
règles de la police doivent etre capable de changer pour certains utilisateurs
de sorte à ce que meme si ils sont équivalents à root il puisse etre complètement
restreint en cas de suspiscion.Un peu plus compliqué à mettre en place par ce qu'il
faut intégrer l'analyse comportementale pour aller plus loin que des spéculations.
Peut etre que juste stopper la session de l'utilisateur suspect sera suffisant.

L'idée ici c'est de ne pas etre spécifique dans le cas des polices on va utiliser
des whites listes pour ne pas avoir de longues polices. et peut etre aussi utiliser des
templates pour pouvoir faciliter la modifications des polices par le biais logiciel.

Le soucis c'est que je n'ai aucune idée sur les polices de sécurités.
