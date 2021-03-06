[Livrables](#livrables)

[Échéance](#échéance)

[Quelques pistes importantes](#quelques-pistes-utiles-avant-de-commencer-)

[Travail à réaliser](#travail-à-réaliser)

1. [Deauthentication attack](#1-deauthentication-attack)
2. [Fake channel evil tween attack](#2-fake-channel-evil-tween-attack)
3. [SSID Flood attack](#3-ssid-flood-attack)

# Sécurité des réseaux sans fil

## Laboratoire 802.11 MAC 1

__A faire en équipes de deux personnes__

**Etudiants :** Stefan Dejanovic, Nathanaël Mizutani

### Pour cette partie pratique, vous devez être capable de :

*	Détecter si un certain client WiFi se trouve à proximité
*	Obtenir une liste des SSIDs annoncés par les clients WiFi présents

Vous allez devoir faire des recherches sur internet pour apprendre à utiliser Scapy et la suite aircrack pour vos manipulations. __Il est fortement conseillé d'employer une distribution Kali__ (on ne pourra pas assurer le support avec d'autres distriairodump-ng wlp2s0monbutions). __Si vous utilisez une VM, il vous faudra une interface WiFi usb, disponible sur demande__.

__ATTENTION :__ Pour vos manipulations, il pourrait être important de bien fixer le canal lors de vos captures et/ou vos injections (à vous de déterminer si ceci est nécessaire pour les manipulations suivantes ou pas). Si vous en avez besoin, la méthode la plus sure est d'utiliser l'option :

```--channel``` de ```airodump-ng```

et de garder la fenêtre d'airodump ouverte en permanence pendant que vos scripts tournent ou vos manipulations sont effectuées.


## Quelques pistes utiles avant de commencer :

- Si vous devez capturer et injecter du trafic, il faudra configurer votre interface 802.11 en mode monitor.
- Python a un mode interactif très utile pour le développement. Il suffit de l'invoquer avec la commande ```python```. Ensuite, vous pouvez importer Scapy ou tout autre module nécessaire. En fait, vous pouvez même exécuter tout le script fourni en mode interactif !
- Scapy fonctionne aussi en mode interactif en invoquant la commande ```scapy```.  
- Dans le mode interactif, « nom de variable + <enter> » vous retourne le contenu de la variable.
- Pour visualiser en détail une trame avec Scapy en mode interactif, on utilise la fonction ```show()```. Par exemple, si vous chargez votre trame dans une variable nommée ```beacon```, vous pouvez visualiser tous ces champs et ses valeurs avec la commande ```beacon.show()```. Utilisez cette commande pour connaître les champs disponibles et les formats de chaque champ.

## Travail à réaliser

### 1. Deauthentication attack

Une STA ou un AP peuvent envoyer une trame de déauthentification pour mettre fin à une connexion.

Les trames de déauthentification sont des trames de management, donc de type 0, avec un sous-type 12 (0x0c). Voici le format de la trame de déauthentification :

![Trame de déauthentification](images/deauth.png)

Le corps de la trame (Frame body) contient, entre autres, un champ de deux octets appelé "Reason Code". Le but de ce champ est d'informer la raison de la déauthentification. Voici toutes les valeurs possibles pour le Reason Code :

| Code | Explication 802.11                                                                                                                                     |
|------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0    | Reserved                                                                                                                                              |
| 1    | Unspecified reason                                                                                                                                    |
| 2    | Previous authentication no longer valid                                                                                                               |
| 3    | station is leaving (or has left) IBSS or ESS                                                                                                          |
| 4    | Disassociated due to inactivity                                                                                                                       |
| 5    | Disassociated because AP is unable to handle all currently associated stations                                                                        |
| 6    | Class 2 frame received from nonauthenticated station                                                                                                  |
| 7    | Class 3 frame received from nonassociated station                                                                                                     |
| 8    | Disassociated because sending station is leaving (or has left) BSS                                                                                    |
| 9    | Station requesting (re)association is not authenticated with responding station                                                                       |
| 10   | Disassociated because the information in the Power Capability element is unacceptable                                                                 |
| 11   | Disassociated because the information in the Supported Channels element is unacceptable                                                               |
| 12   | Reserved                                                                                                                                              |
| 13   | Invalid information element, i.e., an information element defined in this standard for which the content does not meet the specifications in Clause 7 |
| 14   | Message integrity code (MIC) failure                                                                                                                                              |
| 15   | 4-Way Handshake timeout                                                                                                                                              |
| 16   | Group Key Handshake timeout                                                                                                                                              |
| 17   | Information element in 4-Way Handshake different from (Re)Association Request/Probe Response/Beacon frame                                                                                                                                              |
| 18   | Invalid group cipher                                                                                                                                              |
| 19   | Invalid pairwise cipher                                                                                                                                              |
| 20   | Invalid AKMP                                                                                                                                              |
| 21   | Unsupported RSN information element version                                                                                                                                              |
| 22   | Invalid RSN information element capabilities                                                                                                                                              |
| 23   | IEEE 802.1X authentication failed                                                                                                                                              |
| 24   | Cipher suite rejected because of the security policy                                                                                                                                              |
| 25-31 | Reserved                                                                                                                                              |
| 32 | Disassociated for unspecified, QoS-related reason                                                                                                                                              |
| 33 | Disassociated because QAP lacks sufficient bandwidth for this QSTA                                                                                                                                              |
| 34 | Disassociated because excessive number of frames need to be acknowledged, but are not acknowledged due to AP transmissions and/or poor channel conditions                                                                                                                                              |
| 35 | Disassociated because QSTA is transmitting outside the limits of its TXOPs                                                                                                                                              |
| 36 | Requested from peer QSTA as the QSTA is leaving the QBSS (or resetting)                                                                                                                                              |
| 37 | Requested from peer QSTA as it does not want to use the mechanism                                                                                                                                              |
| 38 | Requested from peer QSTA as the QSTA received frames using the mechanism for which a setup is required                                                                                                                                              |
| 39 | Requested from peer QSTA due to timeout                                                                                                                                              |
| 40 | Peer QSTA does not support the requested cipher suite                                                                                                                                              |
| 46-65535 | Reserved                                                                                                                                              |

a) Utiliser la fonction de déauthentification de la suite aircrack, capturer les échanges et identifier le Reason code et son interprétation.

__Question__ : quel code est utilisé par aircrack pour déauthentifier un client 802.11. Quelle est son interprétation ?

![](images/Aireplay-Deauth.png)

```markdown
Le code utilisé par aircrack est le 7 : Class 3 frame received from nonassociated station.
```

__Question__ : A l'aide d'un filtre d'affichage, essayer de trouver d'autres trames de déauthentification dans votre capture. Avez-vous en trouvé d'autres ? Si oui, quel code contient-elle et quelle est son interprétation ?

![](images/multiple_deauth.jpg)

```markdown
Oui, nous avons pu trouver d'autres trames de déauthentification.
En comparant les autres trames de déauthentification, nous avons pu remarquer que les codes sont les mêmes.
```

b) Développer un script en Python/Scapy capable de générer et envoyer des trames de déauthentification. Le script donne le choix entre des Reason codes différents (liste ci-après) et doit pouvoir déduire si le message doit être envoyé à la STA ou à l'AP :
* 1 - Unspecified
* 4 - Disassociated due to inactivity
* 5 - Disassociated because AP is unable to handle all currently associated stations
* 8 - Deauthenticated because sending STA is leaving BSS

__Question__ : quels codes/raisons justifient l'envoie de la trame à la STA cible et pourquoi ?

```
Les codes 1, 4 et 5 justifient l'envoi de la trame à la STA cible.
- Le code 1 ne donne pas de raison particulière donc il peut être envoyé aussi bien à la STA que l'AP.
- Le code 4 indique que la STA a été déconnecté car elle est restée trop longtemps inactive. Une telle raison ne ferait pas sens pour un AP.
- Le code 5 indique que l'AP ne peut plus servir une STA de plus. Ce message est clairement à destination de la STA qui a été déauthentifiée.
```

__Question__ : quels codes/raisons justifient l'envoie de la trame à l'AP et pourquoi ?

```
Les codes 1 et 8 Justifient l'envoi de la trame à l'AP.
- Le code 1 ne donne pas de raison particulière donc il peut être envoyé aussi bien à la STA que l'AP.
- Le code 8 indique explicitement qu'il s'agit d'un message d'une STA qui quitte le réseau géré par l'AP.
```

__Question__ : Comment essayer de déauthentifier toutes les STA ?

```
Il faudrait juste faire un broadcast des stations en definissant la valeur des STA à "FF:FF:FF:FF:FF:FF".
```

__Question__ : Quelle est la différence entre le code 3 et le code 8 de la liste ?

```
Le code 3 déauthentifie les clients de l'AP. Alors que la 8, le client quitte le réseau géré par l'AP. 
```

__Question__ : Expliquer l'effet de cette attaque sur la cible

```
Cela va déconnecter la cible de l'access point.
```

**Remarque :** Voici une capture d'écran du fonctionnement du script. À droite nous avons le script qui est exécuté. A gauche, on peut voir une capture wireshark qui confirme qu'une déauthentification est effectuée avec la raison numéro 4. Pour lancer le script il faut passer 3 arguments. Le 1er est l'adresse mac de la station, le 2e est l'adresse mac de l'AP et le dernier est l'interface.

![](images/deauthScript.png)

### 2. Fake channel evil tween attack
a)	Développer un script en Python/Scapy avec les fonctionnalités suivantes :

* Dresser une liste des SSID disponibles à proximité
* Présenter à l'utilisateur la liste, avec les numéros de canaux et les puissances
* Permettre à l'utilisateur de choisir le réseau à attaquer
* Générer un beacon concurrent annonçant un réseau sur un canal différent se trouvant à 6 canaux de séparation du réseau original

__Question__ : Expliquer l'effet de cette attaque sur la cible
```
Si la cible est déjà connectée à l'AP qu'on imite, il ne se passera rien. Par contre si la cible a été préalablement déauthentifier de l'AP, et si notre signal est plus puissant que celui de l'AP, la cible tentera de se connecter sur notre faux réseau.
```
#### Utilisation du script
```
Le script commence par scanner les ssid présents à proximité :
```
![Scan des ssid](images/EvilTwin-Scanning-ssid.png)

```
L'utilisateur peut ensuite choisir le ssid du réseau qu'il souhaite attaquer. Une fois le choix effectué une dernière confirmation est demandée pour lancer l'attaque.
```
![Evil Twin attack](images/EvilTwin-attack.png)

```
On voit ci-dessous une des trames envoyées par le script :
```
![faux beacon](images/EvilTwin-wireshark-beacon.png)

### 3. SSID flood attack

Développer un script en Python/Scapy capable d'inonder la salle avec des SSID dont le nom correspond à une liste contenue dans un fichier texte fournit par un utilisateur. Si l'utilisateur ne possède pas une liste, il peut spécifier le nombre d'AP à générer. Dans ce cas, les SSID seront générés de manière aléatoire.


**Remarque :** Ici nous avons une capture d'écran de l'exécution du script pour faire un SSID flood attack. À droite, on peut voir que la liste fournie par le fichier txt correspond au AP créé. Pour exécuter le script, il faut mettre en argument tout d'abord le nom du fichier à ouvrir ou le nombre d'AP qu'on veut puis l'interface.


![](images/SSIDFloodAttack.png)

## Livrables

Un fork du repo original . Puis, un Pull Request contenant :

- Script de Deauthentication de clients 802.11 __abondamment commenté/documenté__

- Script fake chanel __abondamment commenté/documenté__

- Script SSID flood __abondamment commenté/documenté__

- Captures d'écran du fonctionnement de chaque script

-	Réponses aux éventuelles questions posées dans la donnée. Vous répondez aux questions dans votre ```README.md``` ou dans un pdf séparé

-	Envoyer le hash du commit et votre username GitHub par email au professeur et à l'assistant


## Échéance

Le 9 mars 2020 à 23h59
