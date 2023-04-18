# TP_ransomware

## Introduction

Le but de ce TP est de réaliser un programme qui chiffre des données présentes sur une partition dans des conteneurs Docker.


## Chiffrement

Q1. L'algorithme de chiffrement est un algorithme XOR. Cet algorithme est considéré comme robuste dans certaines conditions. En effet, dans le cas où la clé de chiffrement est parfaitement aléatoire (et donc imprédictible), il n'est pas possible de déterminer le message d'origine.

Q2. 

Q3. 

Q4. On peut vérifier que la clé rentrée est la bonne en refaisant le processus qui a permis de la créer à partir du salt et du token fournis. En effet, la clé a été créée à partir du sel et du token, à l'aide de la fonction ```do_derivation```. On peut donc faire passer le sel et le token existants dans la fonction ```do_derivation``` et comparer le résultat avec la clé fournie.

