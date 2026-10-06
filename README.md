# Module Employé — Caserne Connectée

Projet Qt autonome (Qt 6 Widgets, C++17) qui contient **uniquement** le module Employé :

1. **Interface d'identification** : identifiant + mot de passe, lien « Mot de passe oublié ? ».
2. **Interface Mot de passe oublié** : code à 6 chiffres envoyé par e-mail.
3. **Interface Employés** : gestion des employés, de leurs comptes et de leurs droits d'accès.

Ouvrir `CaserneConnectee.pro` dans Qt Creator puis exécuter (le module Qt **network** est
utilisé pour le hachage PBKDF2 ; il est fourni avec toute installation de Qt).

## Fichiers

| Fichier | Rôle |
|---|---|
| `caserneconnectee.h` | **Le seul fichier d'en-tête** : toutes les classes du module — `Authentification` (comptes, mots de passe hachés, blocage, codes, droits), `Employe` (le module), `CaserneConnectee` (la fenêtre) et les effets animés |
| `caserneconnectee.cpp` | **Le seul fichier source** : connexion, mot de passe oublié, ajout / modification / suppression, droits, tri, recherche, statistiques, planning, PDF, fenêtre, traduction arabe, et `main()` |
| `caserneconnectee.ui` | Les 3 interfaces (Qt Designer) |
| `ressources.qrc`, `images/` | Logo, icônes et motifs |
| `captures/` | Images du module |

## Structure conforme au Guide d'intégration GUI

Une seule interface (`caserneconnectee.ui`) et le code du module dans les fichiers de la fenêtre
principale (`caserneconnectee.h` / `caserneconnectee.cpp`).

**QStackedWidget principal `SWCaserne`** — une page par module :

| Index | Page | Module |
|---|---|---|
| 0 | `PEmploye` | Employé (contient `SWEmploye`) |
| 1 | `PMission` | Missions |
| 2 | `PUnite` | Unités |
| 3 | `PVehicule` | Véhicules |
| 4 | `PMateriel` | Matériel |
| 5 | `PFormation` | Formation |

**QStackedWidget interne `SWEmploye`** :

| Index | Page | Rôle |
|---|---|---|
| 0 | `PLogin` | Identification |
| 1 | `PMenu` | Menu de l'application (carreaux des modules) |
| 2 | `PMotDePasseOublie` | Mot de passe oublié |
| 3 | `PGestionEmploye` | CRUD et fonctionnalités du module Employé |
| 4 | `PTableauDeBord` | Tableau de bord |

**Navigation** : slots créés avec Qt Designer (clic droit → *Aller au slot… → clicked()*) dans
`CaserneConnectee` :
`on_btnMEmploye_clicked()` (SWEmploye 3), `on_btnMMission_clicked()` (SWCaserne 1),
`on_btnMUnite_clicked()` (2), `on_btnMVehicule_clicked()` (3), `on_btnMMateriel_clicked()` (4),
`on_btnMFormation_clicked()` (5), `on_btnMTableauDeBord_clicked()` (SWEmploye 4),
`on_btnQuitter_clicked()` (retour à SWEmploye 0, Login). Chaque page de module a la flèche
de retour `btnRetourModules` vers le menu.

Pour qu'un membre de l'équipe ajoute son module : il place son interface dans sa page
(`PMission`, `PUnite`, …) et son code dans `caserneconnectee.cpp` / `.h`.
Pour réutiliser ce module dans un autre projet : `DEFINES += MODULE_EMPLOYE_INTEGRE` dans le `.pro`
(le `main()` du module est alors ignoré).

## Comptes de démonstration

Au premier lancement, les 9 employés du tableau deviennent des comptes. **Chaque compte a son
propre mot de passe** (communiqué séparément) : le code ne contient que le sel et l'empreinte
PBKDF2 de chacun, jamais le mot de passe en clair. Un employé ajouté depuis l'application reçoit
le mot de passe saisi lors de son ajout.

| Identifiant | Rôle | Interface Employés (droits par défaut) |
|---|---|---|
| `h.boukhris`, `l.bensalah` | Administrateur | Tous les modules, complet |
| `m.karray`, `a.trabelsi`, `s.gharbi` | Chef de garde | Interface Employés en lecture seule |
| `s.larbi`, `r.nasri`, `k.hamdi`, `k.ayari` | Agent | Aucun accès à Employés (connexion refusée, sauf si l'administrateur le donne dans la fiche) |

Si le fichier de données vient d'une ancienne version (mot de passe commun `Caserne@2026`), les comptes de
démonstration reçoivent automatiquement leur propre mot de passe au démarrage (et sont débloqués).

Les données sont enregistrées dans `caserne_employes_v3.json`, dans le dossier de données de
l'application (Windows : `%APPDATA%\ESPRIT\CaserneConnectee\`). **Supprimer ce fichier remet
la démonstration à zéro.**

## Authentification

- Le mot de passe saisi est haché (**PBKDF2-HMAC-SHA256**, sel aléatoire de 16 octets propre à
  chaque compte, 60 000 itérations) puis comparé à l'empreinte stockée (comparaison à temps
  constant). Le fichier ne contient que le sel et l'empreinte.
- Chaque échec affiche le nombre d'essais restants. **Au 5e échec, le compte est bloqué** (même
  le bon mot de passe est refusé) ; un cadenas rouge apparaît dans le tableau et la carte
  « Comptes bloqués » se met à jour.
- Déblocage : « Mot de passe oublié ? », ou l'administrateur qui enregistre la fiche.

## Mot de passe oublié

1. Le lien ouvre l'interface « Mot de passe oublié » (l'adresse du compte saisi est proposée).
2. « Envoyer le code » génère un **code aléatoire à 6 chiffres** (générateur cryptographique du
   système), **valable 15 minutes** (compte à rebours affiché) et **utilisable une seule fois**.
   Seule l'empreinte du code est conservée ; 5 codes faux annulent le code.
3. Code + nouveau mot de passe (8 caractères minimum, au moins une lettre et un chiffre) :
   le compte est débloqué et l'application revient à la connexion avec un message animé.

> **Envoi de l'e-mail** : le projet n'a pas de serveur de messagerie, l'envoi est donc
> **simulé** par une notification qui affiche le code. Pour un envoi réel, remplacer le bloc
> « Envoi du code » de `Employe::envoyerCode()` par un client SMTP.

## Gestion des employés

- **Ajouter** : 1er clic = fiche vierge + encart « Mot de passe du compte » (**Mot de passe** +
  **Vérification**, obligatoires) ; l'identifiant et l'e-mail se
  remplissent à partir du nom ; 2e clic (« Valider l'ajout ») = contrôle de saisie (champs
  obligatoires, format, doublons, mot de passe) puis message animé **« Employé ajouté avec
  succès »** (coche qui se dessine, étincelles) et la nouvelle ligne s'illumine en vert.
- **Modifier** : 1er clic = mode édition avec l'encart « Modifier le mot de passe » (**Nouveau** +
  **Vérification**, facultatif : vide = l'ancien mot de passe est gardé) ; « Enregistrer » =
  message animé « Employé modifié avec succès ».
- **Supprimer** : confirmation, la ligne rougit puis disparaît, message animé **« Employé
  supprimé »** (corbeille dont le couvercle s'ouvre, débris qui tombent). Toutes ses données
  disparaissent : ligne du tableau, compte, statistiques et **ligne du planning des gardes**.
- Chaque nouvel employé est ajouté au tableau avec **son propre mot de passe** (celui saisi à
  l'ajout), qui reste valable ; ce qu'il voit dépend de son rôle et de ses droits d'accès.
- Protections : impossible de supprimer son propre compte, de changer son propre rôle ou de
  retirer le dernier administrateur.

## Ouverture des interfaces selon les droits

Chaque bouton du menu (Tableau de bord, Employés, Missions, Unités, Véhicules, Matériel, Formation) ouvre
l'interface du module **selon les droits du compte connecté** :
- **Aucun** : le bouton est masqué, l'interface ne s'ouvre pas ;
- **Lecture** : l'interface s'ouvre avec le badge « Lecture seule », boutons Ajouter / Modifier /
  Supprimer désactivés ;
- **Complet** : l'interface s'ouvre avec toutes les actions.

Exemples avec les droits proposés par rôle : l'administrateur ouvre tout en accès complet ; le
chef de garde ouvre l'interface Employés en lecture seule ; un agent n'a pas accès à Employés
(connexion refusée tant que l'administrateur ne lui donne pas ce droit dans sa fiche).

Les modules Missions, Unités, Véhicules, Matériel et Formation sont **marqués « Module non
développé »** : leur page s'ouvre selon les droits (avec le droit du compte affiché : « Accès
complet » ou « Lecture seule »), et chaque équipe y mettra sa vraie interface (fonction
`Employe::afficherModule`, page `PModule`, placée dans la page du module de `SWCaserne`).

## Fonctionnalités de base et métiers basiques (cahier des charges)

- **CRUD** : ajouter, afficher (tableau + fiche), modifier et supprimer un employé et son compte.
- **Attributs** : id, nom, prénom, grade, fonction, statut, date d'entrée en service, e-mail,
  identifiant, mot de passe haché, rôle, habilitations et **temps de repos cumulé** (champ
  « Repos cumulé » de la fiche, affiché aussi sur la carte verte).
- **Trier** : choisir Nom, Grade ou Ancienneté puis « Trier ». Un 2e clic sur le même critère
  inverse l'ordre (Z → A, du plus bas au plus haut grade, les plus récents d'abord).
- **Rechercher** : le tableau se filtre pendant la saisie, par nom, prénom, grade ou habilitation
  (compétence). « Rechercher » signale quand aucun employé ne correspond.
- **Exporter PDF** : enregistre la liste **telle qu'elle est affichée dans le tableau** (après
  recherche et tri) dans un fichier PDF A4 paysage : en-tête de la caserne, date, auteur de
  l'export, critères, tableau avec les mêmes colonnes que l'interface. Le nom proposé est
  `Liste_employes_<date>.pdf` dans le dossier Documents.
- **Planning des gardes** : calculé à partir de la liste des employés (créneaux de 12h, Jour
  07h-19h / Nuit 19h-07h) selon le début, la durée (7, 14 ou 30 jours) et l'effectif minimum.
  Chaque créneau reçoit si possible 1 chef de garde et 1 conducteur ; repos de 12h après un jour
  et de 24h après une nuit ; « En congé » = C ; roulement équitable (colonne « Gardes »). Les
  créneaux incomplets sont signalés sous le tableau (sous-effectif, sans chef, sans conducteur).
  Le planning suit la liste : un employé ajouté y entre, un employé supprimé en disparaît.
  Un agent ne voit que sa propre ligne. « Générer le planning » demande le droit complet.
- **Télécharger PDF (planning)** : enregistre le planning affiché dans un PDF A4 paysage
  (`Planning_gardes_<date>.pdf`) : en-tête, période, cases J / N / R / C colorées, ligne
  « Effectif » par créneau (en rouge si incomplet), légende. Disponible pour tous ceux qui
  voient l'interface Employés (même en lecture seule).
- Les PDF (liste et planning) sont écrits **en arrière-plan** (QtConcurrent) : la fenêtre reste
  fluide, le bouton affiche « Génération… » pendant l'écriture.
- **Statistiques** : calculées à partir de la vraie liste et mises à jour à chaque ajout,
  modification ou suppression — cartes (effectif, disponibles, en intervention), anneau de
  répartition **par statut** et barres de répartition **par fonction** (les 5 fonctions).

## Gestion des droits d'accès (dans la fiche de chaque employé)

- Plus de grande table : chaque fiche employé contient un encart **« Droits d'accès aux
  modules »** avec, pour chaque module (Employés, Missions, Unités, Véhicules, Matériel,
  Formation), un sélecteur **Complet / Lecture / Aucun** (la pastille glisse sous le choix).
- À l'ajout, choisir le **rôle** préremplit les droits ; choisir le **poste** propose le rôle
  (Chef de garde → Chef de garde, Standardiste → Opérateur du standard, Pompier / Chauffeur → Agent) :
  - **Administrateur** (officier responsable) : gère les employés, les comptes et les droits → tout complet ;
  - **Chef de garde** : supervise l'effectif de garde (Employés en lecture), attribue les unités
    et clôture les missions (Missions et Unités complets), lecture sur le reste ;
  - **Opérateur du standard** : reçoit les appels et crée les missions (Missions complet),
    lecture sur Employés, Unités et Véhicules ;
  - **Agent** (pompiers, chauffeurs, recrues) : consulte les informations qui le concernent
    (lecture sur Tableau de bord, Missions, Véhicules, Matériel, Formation ; pas d'accès à Employés
    tant que l'administrateur ne le donne pas).
  - Le **Tableau de bord** (section SUIVI, en haut du menu) est un module comme les autres : il
    s'ouvre selon les droits du compte et il est marqué « Module non développé ». L'administrateur les ajuste ensuite pour cet
  employé, puis « Valider l'ajout » (ou « Enregistrer » en modification).
- **Visibilité** : le menu affiche Employés, Missions, Unités, Véhicules, Matériel et Formation,
  mais seulement les modules autorisés pour le compte connecté (un module à **Aucun** est
  masqué ; ils apparaissent un à un à la connexion). Ce module ne contient que l'identification
  et l'interface Employés : un clic sur un autre module affiche une notification (droit du
  compte + « intégré par l'équipe »). Sans droit sur Employés, la connexion est refusée ; en
  **Lecture**, la fiche est en lecture seule.
- Seul l'administrateur règle les droits ; ses propres droits ne se modifient pas, et un
  administrateur garde toujours le module Employés.

## Brancher les autres modules de l'équipe

Dans Qt Designer, ajouter une propriété dynamique aux boutons :

- `module` = `Employes`, `Missions`, `Unites`, `Vehicules`, `Materiel` ou `Formation` ;
- `action` = `ecriture` pour les boutons qui modifient des données (désactivés sans le droit
  Complet). Sans `action` (bouton du menu), le bouton est masqué si le droit est Aucun.

`Employe::appliquerDroits()` traite automatiquement tous les boutons qui portent ces propriétés.

## Passer à la base Oracle

Seules `Authentification::charger()` et `enregistrer()` lisent / écrivent les données. Pour la
base du projet, les réécrire avec `QSqlQuery`, par exemple :

```sql
CREATE TABLE EMPLOYE (
  ID NUMBER PRIMARY KEY, NOM VARCHAR2(50), PRENOM VARCHAR2(50), GRADE VARCHAR2(30),
  FONCTION VARCHAR2(40), STATUT VARCHAR2(30), ROLE VARCHAR2(30), EMAIL VARCHAR2(100) UNIQUE,
  IDENTIFIANT VARCHAR2(30) UNIQUE, DATE_ENTREE DATE,
  SEL RAW(16), EMPREINTE RAW(32), ESSAIS_ECHOUES NUMBER DEFAULT 0, BLOQUE NUMBER(1) DEFAULT 0,
  EMPREINTE_CODE RAW(32), EXPIRATION_CODE TIMESTAMP, CODE_UTILISE NUMBER(1) DEFAULT 1);
CREATE TABLE DROIT_ACCES (ID_EMPLOYE NUMBER REFERENCES EMPLOYE(ID) ON DELETE CASCADE,
  MODULE VARCHAR2(20), DROIT NUMBER(1), PRIMARY KEY (ID_EMPLOYE, MODULE));   -- 0 aucun, 1 lecture, 2 complet
```

## Intégration dans l'application complète

```cpp
employe = new Employe(ui, this);          // constructeur de la fenêtre
if (!employe->connecter()) return;        // bouton « Se connecter »
employe->appliquerDroits();
```

## Couleurs et animations ajoutées

- Noms et prénoms des employés écrits aux couleurs des braises du fond animé (rouge braise →
  orange → reflet clair), avec un reflet qui défile lentement sur chaque ligne.
- Avatars en dégradé de braise (braise vive, braise rouge, nuit de garde).
- Sélecteurs de droits : la pastille glisse en rebondissant quand on change un droit ou le rôle.
- Connexion : les boutons autorisés du menu apparaissent un à un.

## Zoom et thème

- **Zoom** : boutons **− / 100 % / +** dans l'en-tête de l'interface Employés (ou Ctrl + / Ctrl − /
  Ctrl 0), de 50 % à 150 %. L'application se relance aussitôt avec la nouvelle taille et le compte
  connecté retrouve sa session (jeton à usage unique valable 20 secondes). Le zoom est mémorisé.
- **Messages animés et notifications** : toujours affichés au milieu (ou dans le coin) de la partie
  de la fenêtre visible à l'écran.
- **Thème** : le bouton du thème passe de **clair** → **sombre** → **selon l'horaire** (icône
  horloge jour/nuit). Selon l'horaire : sombre de 19h à 7h (garde de nuit), clair de 7h à 19h
  (garde de jour), avec bascule automatique. Le choix est mémorisé.

## Intro animée et fond qui suit l'heure

- **Au lancement** (avec un son : souffle de flamme, allumage, carillon) et **après la vérification
  de l'accès** (message « Bienvenue, Prénom Nom ») : sur toute la fenêtre, le logo s'embrase du bas
  vers le haut avec des étincelles, ses trois circuits s'allument l'un après l'autre, un anneau de
  feu se trace puis lance une onde de choc, « Caserne Connectée » s'écrit lettre par lettre, puis
  la page s'ouvre par un cercle qui s'agrandit. Un clic passe l'intro (classe `IntroConnexion`).
- Son : `images/intro.wav` (créé pour le projet). Sous Windows il est joué avec l'API `PlaySound`
  (bibliothèque winmm, `LIBS += -lwinmm` dans le .pro) : aucun module Qt supplémentaire n'est requis.
- **Fond qui suit l'heure** (classe `CielHoraire`) : un ciel discret en haut de chaque page — aube
  rose-orange, jour doré, coucher de soleil orange, nuit bleue étoilée — avec un soleil (6h-19h) ou
  une lune (19h-6h) qui traverse la page au fil de la journée. Il suit aussi le thème clair / sombre.

## Tableau de bord (section SUIVI du menu)

Interface reprise du projet de l'équipe (page `PTableauDeBord`, index 4 de `SWEmploye`) et adaptée au style
du module (en-tête sombre, braises et ciel animés, mode sombre / clair / selon l'horaire, arabe).
Elle s'ouvre selon le droit « Tableau de bord » du compte (fonction `Employe::afficherTableauDeBord`).

- **Liée aux employés** : « Pompiers disponibles » (employés de terrain disponibles / effectif de
  terrain), **Effectif de garde** (employés présents, noms aux couleurs des braises, statut coloré),
  **balise SOS** (portée par un employé « En intervention » ; sans intervention, le bandeau disparaît)
  et **À traiter aujourd'hui** (comptes bloqués, créneaux de garde incomplets, employés en congé).
  Tout se met à jour à chaque ajout, modification ou suppression d'un employé.
- Missions, unités, véhicules, interventions de la semaine : exemples de l'équipe, en attendant les
  modules correspondants.
- **Carte des interventions** (classe `CarteInterventions`) : boutons **Plan** (plan illustré, sans
  connexion) et **Carte réelle** (OpenStreetMap, Internet : glisser pour déplacer, molette pour
  zoomer, double-clic pour recentrer ; les tuiles déjà vues restent en cache). Points animés :
  épingles qui tombent à l'ouverture, halos qui pulsent, ondes radar sur la balise SOS, véhicules
  qui roulent sur leur trajet, et une **boussole** (petit cercle qui s'agrandit en boussole, aiguille
  qui se stabilise vers le nord). « Localiser la balise » centre la carte et lance un radar.
- Animations : panneaux en cascade, chiffres qui défilent, barres qui se remplissent l'une après
  l'autre, pastille « Critique » qui clignote, point « En ligne » qui pulse.

## En-têtes : météo et musique

- **Météo** (classe `MeteoEntete`) : température actuelle à Tunis et petite icône animée (soleil,
  lune, nuages, pluie…), données Open-Meteo (gratuit, sans clé), mises à jour toutes les 15 min.
- **Musique douce** (`images/musique.wav`, créée pour le projet) en boucle pendant l'utilisation,
  après l'intro ; bouton ♪ de l'en-tête pour la couper ou la remettre (choix mémorisé).
- Les en-têtes Employés et Tableau de bord ont les mêmes outils : zoom, thème, langue,
  notifications, musique, météo, horloge.

## Fonds animés (toutes les pages)

- **Braises** (classe `FondBraises`) : trois profondeurs (les plus proches sont plus grosses, plus
  rapides et plus vives), scintillement, ondulation, petite traînée lumineuse ; gerbes d'étincelles
  qui jaillissent du bas ; lueur du foyer qui respire ; volutes de fumée chaude ; les braises
  s'écartent autour du pointeur de la souris. Présentes sur la connexion, le mot de passe oublié,
  Employés, Tableau de bord, les modules et le menu.
- **Ciel qui suit l'heure** (classe `CielHoraire`) : rayons du soleil qui tournent lentement et
  nuages qui dérivent le jour ; étoiles qui scintillent et étoiles filantes la nuit.

## Fluidité

Les animations sont optimisées pour ne pas ralentir l'application : seule la partie visible
d'une page est animée, chaque image ne redessine que de petites zones (autour des braises, pas
derrière les panneaux), les halos lumineux (logo, alerte) sont dessinés au lieu d'utiliser des
ombres floues recalculées à chaque image, et les rythmes sont réglés au plus juste (20 images/s
pour les braises, moins pour le ciel et les reflets).


## Page d'accueil des modules

Après la connexion (coche verte animée, puis l'intro du logo), une page animée présente un
**carreau par module** : Tableau de bord, Employés, Missions, Unités, Véhicules, Matériel,
Formation. Chaque carreau montre le droit du compte (Accès complet / Lecture seule) ; un module
non autorisé est grisé avec un cadenas (il tremble si on clique dessus). Survol : le carreau se
soulève, un halo orange l'entoure, une lumière suit la souris. Clic : le carreau s'agrandit
jusqu'à remplir la fenêtre et l'interface du module s'ouvre. Dans chaque interface, la **petite
flèche en haut à gauche** ramène à la page des modules.

## Animation du mot de passe

- **Mot de passe accepté** : la carte s'assombrit, un anneau vert se trace, une coche se dessine,
  des étincelles jaillissent, « Accès vérifié ».
- **Mot de passe refusé** : effet contraire — l'anneau rouge se referme en tremblant, une croix se
  dessine, des éclats retombent, « Accès refusé » (la carte tremble aussi).

## Export Excel

Boutons **Excel** à côté des boutons PDF : liste des employés (telle qu'affichée, après recherche
et tri) et planning des gardes. Le fichier `.xlsx` est écrit par le module lui-même (aucune
bibliothèque à installer) : titre, en-tête figée, couleurs des statuts et des cases J / N / R / C,
ligne « Effectif » pour le planning. Il s'ouvre dans Excel, LibreOffice ou Google Sheets.

## Ciel et mode sombre

- Le ciel (soleil le jour, étoiles la nuit) n'est plus que sur la **page d'identification** ; les
  interfaces des modules gardent seulement les braises (plus fluide).
- Mode sombre : le survol d'une ligne de tableau a maintenant un fond sombre, le texte blanc reste
  lisible sous le curseur.

## Œil des mots de passe et économie de calcul

- Chaque champ mot de passe (connexion, mot de passe oublié, fiche employé) a un **œil** : un clic
  affiche ce qui a été tapé (œil orange), un second clic le masque (œil barré).
- Les animations décoratives se mettent **en pause** quand l'application n'est pas au premier plan ;
  les ombres de survol n'existent que pendant le survol ; le fond de l'intro est préparé une seule
  fois ; moins de braises dans les pages des modules et plus d'étincelles dans les bandeaux.

## Envoi réel du code « mot de passe oublié » (e-mail)

Le code à 6 chiffres est envoyé **par un vrai e-mail** (SMTP sécurisé, avec `QSslSocket`, sans
bibliothèque à installer) dès que l'administrateur a réglé l'envoi :

1. se connecter en administrateur → page des modules → bouton **« ✉ Envoi des e-mails »** ;
2. pour Gmail : serveur `smtp.gmail.com`, port `465`, adresse Gmail, et un **mot de passe
   d'application** (Compte Google → Sécurité → Validation en deux étapes → Mots de passe des
   applications) — le mot de passe normal du compte est refusé par Google ;
3. **« Envoyer un e-mail de test »** pour vérifier, puis **Enregistrer**.

L'adresse de destination est l'**e-mail de la fiche de l'employé** : pour tester, mettez votre vraie
adresse dans la fiche d'un compte. Sans réglage (ou si l'envoi échoue), le code s'affiche dans
une notification pour pouvoir continuer. Le mot de passe d'application est enregistré masqué
dans les réglages de l'application (pas en clair).
