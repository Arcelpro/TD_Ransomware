# TD_Ransomware
Chiffrement
Question 1: Quelle est le nom de l'algorithme de chiffrement ? Est-il robuste et pourquoi ?

 L'algorithme de chiffrement utilisé dans cette fonction est le chiffrement XOR (ou "OU exclusif"). 
Le chiffrement XOR est considéré comme relativement faible en termes de robustesse car il est basé sur une opération mathématique simple, qui est facilement inversible.

- Faible complexité : cet algorithme ne mélange pas les données de manière complexe, ce qui rend le chiffrement XOR vulnérable à certaines attaques, telles que l'attaque par analyse de fréquence.
- Le chiffrement XOR ne fournit pas d'authentification des données, ce qui signifie que les données chiffrées peuvent être modifiées sans être détectées.
- La Répétition des clés : Si une clé est réutilisée pour chiffrer plusieurs messages, cela peut faciliter la tâche des attaquants pour casser l'algorithme..

Question 2 :Pourquoi ne pas hacher le sel et la clef directement ? Et avec un hmac ?

 Hasher directement la clé et le sel ne fournit pas une sécurité suffisante pour la clé dérivée, car il est possible de mener une attaque par force brute en testant toutes les combinaisons possibles de clé. De plus, un simple hash ne prend pas en compte la longueur de la clé et peut être facilement cassé.

L'utilisation d'un HMAC nécessite la gestion d'une clé secrète supplémentaire, ce qui peut rendre la mise en œuvre plus complexe.

Question 3 : Pourquoi il est préférable de vérifier qu'un fichier token.bin n'est pas déjà présent ?
 Il est recommandé de vérifier la présence éventuelle d'un fichier token.bin afin d'éviter tout risque d'écrasement involontaire d'un token existant, ce qui pourrait engendrer des problèmes de sécurité et d'authentification. Il est donc primordial de s'assurer de l'absence du fichier avant de procéder à sa création.

Question 4 :  Q4 : Comment vérifier que la clef la bonne ?
 Pour vérifier si une clé candidate est valide, on peut dériver une clé à partir du sel et de la clé candidate, puis comparer cette clé dérivée avec le token stocké dans la classe SecretManager. On utilise la fonction de hachage SHA256 pour hasher la clé fournie en base64 et comparer le résultat avec le hash de la clé utilisée pour chiffrer les fichiers. Si les deux hashes correspondent, la clé fournie est valide et peut être stockée. Sinon, une exception est levée pour signaler que la clé est invalide.
