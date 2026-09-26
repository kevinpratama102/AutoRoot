# Dirty...Quoi?
Il s'agit de la preuve de concept de Max Kellermann pour le Dirty Pipe, mais modifiée pour écraser le champ du mot de passe de root dans `/etc/passwd` et le restaurer après avoir obtenu un shell root.

**Remarque :** Je ne revendique aucun mérite pour avoir trouvé cette vulnérabilité ou écrit la preuve de concept. Cet exploit est simplement une petite modification de la preuve de concept de Kellermann pour permettre une exploitation rapide et facile. Veuillez lire l'article original sur cette vulnérabilité extrêmement intéressante à l'adresse suivante : https://dirtypipe.cm4all.com/ lorsque vous en aurez l'occasion. Cela mérite vraiment votre attention pour bien la comprendre.

# Utilisation

1. Compilez avec `./compile.sh` (en supposant que `gcc` soit installé)
2. Exécutez `./exploit` et cela ouvrira un shell root

# Escalade de privileges

Si vous obtenez ce message d'erreur :
1. Connectez-vous en tant que `root` avec le mot de passe `polesupdls`.
2. Ensuite, restaurez `/etc/passwd` en exécutant `mv /tmp/passwd.bak /etc/passwd`

