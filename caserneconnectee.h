// =============================================================================
//  Caserne Connectée — MODULE EMPLOYÉ (identification + interface Employés)
//  Fichier d'en-tête unique : toutes les classes du module.
// =============================================================================
#ifndef CASERNECONNECTEE_H
#define CASERNECONNECTEE_H

#include <QString>
#include <QStringList>
#include <QByteArray>
#include <QDate>
#include <QDateTime>
#include <QVector>
#include <QHash>
#include <QObject>
#include <QWidget>
#include <QPixmap>
#include <QPointer>
#include <QTimer>
#include <QEvent>
#include <QCursor>
#include <QEnterEvent>
#include <QPainterPath>
#include <QMouseEvent>
#include <QEasingCurve>
#include <QVariantAnimation>
#include <QRegion>
#include <QPaintEvent>
#include <algorithm>
#include <QResizeEvent>
#include <QPainter>
#include <QRadialGradient>
#include <QRandomGenerator>
#include <QGraphicsDropShadowEffect>
#include <QVariantAnimation>
#include <cmath>
#include <functional>
#include <QStyledItemDelegate>
#include <QMainWindow>

// =============================================================================
//  AUTHENTIFICATION : comptes, mots de passe hachés, codes, droits
// =============================================================================
// =============================================================================
//  AUTHENTIFICATION ET DROITS D'ACCÈS (module Employé)
//
//  - Mots de passe : jamais stockés en clair. Chaque compte a un sel aléatoire ;
//    l'empreinte = PBKDF2-HMAC-SHA256(mot de passe, sel, 60 000 itérations).
//    À la connexion, le mot de passe saisi est haché avec le même sel puis comparé.
//  - Après 5 essais échoués, le compte est bloqué (déblocage : « Mot de passe
//    oublié ? » ou l'administrateur qui enregistre la fiche).
//  - Mot de passe oublié : code aléatoire à 6 chiffres, valable 15 minutes,
//    utilisable une seule fois (seule son empreinte est conservée).
//  - Droits d'accès propres à chaque employé : pour chaque module -> Complet / Lecture / Aucun.
//    À l'ajout, ils sont préremplis selon le rôle choisi puis ajustés dans la fiche ;
//    le menu de l'application ne montre que les modules autorisés.
//
//  Les données sont enregistrées dans un fichier JSON local (dossier de données de
//  l'application). Pour passer à la base Oracle du projet, il suffit de réécrire
//  charger() et enregistrer() avec QSqlQuery : le reste du module ne change pas.
// =============================================================================

enum Module { M_EMPLOYES, M_MISSIONS, M_UNITES, M_VEHICULES, M_MATERIEL, M_FORMATION, M_TABLEAU, NB_MODULES };
enum Droit  { DROIT_AUCUN = 0, DROIT_LECTURE = 1, DROIT_COMPLET = 2 };

// Une fiche employé = l'employé + son compte de connexion
struct FicheEmploye
{
    int id = 0;
    QString nom, prenom, grade, fonction, statut, service, role, email, identifiant, habilitations;
    QDate dateEntree;
    int tempsReposCumule = 0;            // temps de repos cumulé (heures)

    // Compte (le mot de passe lui-même n'est jamais conservé)
    QByteArray sel, empreinte;
    int essaisEchoues = 0;
    bool bloque = false;
    QVector<int> droits;                 // un Droit par module (vide : droits par défaut du rôle)

    // Réinitialisation « mot de passe oublié »
    QByteArray empreinteCode;
    QDateTime expirationCode;
    bool codeUtilise = true;
    int essaisCode = 0;
};

class Authentification
{
public:
    static constexpr int ESSAIS_MAX = 5;          // essais avant blocage
    static constexpr int DUREE_CODE_MINUTES = 15; // validité du code de réinitialisation
    static constexpr int ESSAIS_CODE_MAX = 5;     // un code est annulé après 5 saisies fausses

    explicit Authentification(const QString &fichier = QString());

    // ---- Connexion ----
    enum class Connexion { Ok, IdentifiantInconnu, MotDePasseIncorrect, CompteBloque };
    Connexion connecter(const QString &identifiant, const QString &motDePasse, int *essaisRestants = nullptr);

    // ---- Mot de passe oublié ----
    enum class Reinitialisation { Ok, EmailInconnu, AucunCode, CodeIncorrect, CodeExpire, CodeDejaUtilise, MotDePasseInvalide };
    Reinitialisation genererCode(const QString &email, QString *code);          // code en clair renvoyé une seule fois (envoi)
    Reinitialisation reinitialiser(const QString &email, const QString &code, const QString &nouveauMotDePasse);
    QDateTime expirationCode(const QString &email) const;

    // ---- Employés et comptes ----
    bool estVide() const { return liste.isEmpty(); }
    const QVector<FicheEmploye> &employes() const { return liste; }
    const FicheEmploye *trouver(const QString &identifiant) const;
    const FicheEmploye *trouverParEmail(const QString &email) const;
    int prochainId() const;
    void initialiser(const QVector<FicheEmploye> &fiches);   // 1er lancement (sel + empreinte déjà fournis)
    bool ajouter(FicheEmploye fiche, const QString &motDePasse);
    bool modifier(const QString &identifiant, const FicheEmploye &nouvelle, const QString &nouveauMotDePasse);
    bool supprimer(const QString &identifiant);
    int nombreComptesBloques() const;
    // Ancien fichier de données : un compte de démonstration encore protégé par l'ancien mot de passe
    // commun reçoit sa propre empreinte (et il est débloqué). Renvoie true si le compte a été mis à jour.
    bool remplacerAncienMotDePasse(const QString &identifiant, const QString &ancien, const QByteArray &sel, const QByteArray &empreinte);
    int nombreAdministrateurs() const;

    // ---- Droits d'accès (propres à chaque employé) ----
    Droit droit(const FicheEmploye &compte, int module) const;
    static QVector<int> droitsParDefaut(const QString &role);   // proposés quand on choisit le rôle
    static QStringList roles();                  // Administrateur, Chef de garde, Agent
    static QString cleModule(int module);        // « Employes », « Missions »… (propriété « module » des boutons)

    // Règle commune : 8 caractères minimum, au moins une lettre et un chiffre
    static bool motDePasseValide(const QString &motDePasse, QString *raison = nullptr);

private:
    QString fichier;
    QVector<FicheEmploye> liste;

    static QByteArray hacher(const QString &secret, const QByteArray &sel);
    static bool egales(const QByteArray &a, const QByteArray &b);   // comparaison à temps constant
    static void definirMotDePasse(FicheEmploye &f, const QString &motDePasse);
    FicheEmploye *trouverModifiable(const QString &identifiant);
    FicheEmploye *trouverParEmailModifiable(const QString &email);
    void charger();
    void enregistrer() const;
};

// =============================================================================
//  MODULE EMPLOYÉ : identification, mot de passe oublié, gestion des employés, planning
// =============================================================================
class QPushButton;
class QGridLayout;
class QLabel;


namespace Ui { class CaserneConnectee; }
class QTableWidget;
class QComboBox;
class SelecteurDroit;
class FondBraises;
class CarteInterventions;

// =============================================================================
//  MODULE EMPLOYÉ (lié à la page d'identification)
//
//  Page d'identification (SWEmploye, page 0)
//   - authentification : identifiant + mot de passe ; le mot de passe saisi est haché
//     puis comparé à l'empreinte stockée (jamais de mot de passe en clair) ;
//   - 5 essais échoués : le compte est bloqué ; un identifiant inconnu fait trembler la carte ;
//   - lien « Mot de passe oublié ? » -> page 2.
//
//  Page « Mot de passe oublié » (SWEmploye, page 2)
//   - adresse e-mail -> code aléatoire à 6 chiffres, valable 15 minutes, usage unique ;
//   - code + nouveau mot de passe -> compte débloqué, retour à la connexion.
//
//  Page « Gestion des employés » (SWEmploye, page 1)
//   - ajout / modification / suppression d'un employé et de son compte, avec message animé ;
//   - droits d'accès réglés dans la fiche de chaque employé (préremplis selon le rôle) ;
//   - les boutons non autorisés pour l'utilisateur connecté sont désactivés ou masqués ;
//   - photo, mot de passe avec indicateur de sécurité, planning, anneau animé, notifications.
//
//  Droits sur les boutons : tout bouton qui porte la propriété dynamique « module »
//  (Employes, Missions, Unites, Vehicules, Materiel, Formation) est géré automatiquement :
//    - action = « ecriture » : désactivé si le droit n'est pas Complet ;
//    - sans action (bouton du menu) : masqué si le droit est Aucun.
// =============================================================================
class Employe : public QObject
{
    Q_OBJECT
public:
    Employe(Ui::CaserneConnectee *ui, QWidget *fenetre);

    // ---- Page d'identification ----
    bool connecter();                    // false : connexion refusée (message affiché sur la carte)
    void jouerIntroConnexion(std::function<void()> milieu, std::function<void()> fin);   // logo animé après la connexion
    void afficherTableauDeBord();        // ouvre le tableau de bord (droit « Tableau de bord » requis)
    // ---- Page d'accueil des modules (après la connexion) ----
    void afficherAccueilModules(bool anime = true);   // carreaux des modules selon les droits du compte
    void animerAccueilModules();         // les carreaux arrivent en cascade
    void ouvrirModule(int module);       // depuis un carreau ou la barre latérale
    static int indexPageModule(int module);   // page du module dans SWCaserne
    void animerResultatConnexion(bool accepte);       // coche verte ou croix rouge sur la carte de connexion
    void reglerEnvoiEmails();            // fenêtre « Envoi des e-mails » (administrateur)
    bool reprendreSession(const QString &identifiant);   // après un changement de zoom (relance de l'application)
    QString compteConnecte() const { return identifiantConnecte; }
    void notifier(const QString &titre, const QString &texte) { afficherNotification(titre, texte); }
    void deconnecter();
    void appliquerDroits();              // boutons et panneaux selon le rôle du compte connecté
    void animerConnexion();              // animation de la page d'identification
    void quitterPageConnexion();         // arrête les braises du fond

    // ---- Menu : boutons visibles selon les droits du compte (propriété « module ») ----
    void animerMenu();
    void afficherModule(int module);     // ouvre l'interface d'un module selon le droit du compte                   // les boutons autorisés apparaissent un à un

    // ---- Page « Mot de passe oublié » ----
    void preparerMotDePasseOublie();     // remet la page à l'étape 1 (adresse e-mail)

    // ---- Page « Gestion des employés » ----
    void animerEntreePage();             // l'anneau de disponibilité se remplit
    void definirModeSombre(bool sombre); // thème choisi dans l'en-tête
    void definirLangueArabe(bool arabe); // langue choisie dans l'en-tête

signals:
    void motDePasseReinitialise();       // la fenêtre revient à la page de connexion
    void tableauModifie();               // la fenêtre réapplique les couleurs du thème au tableau
    void planningModifie();              // idem pour le planning des gardes
    void tableauDeBordModifie();         // idem pour les tableaux du tableau de bord
    void deconnexionDemandee();          // bouton « Se déconnecter » de la page d'accueil des modules

private slots:
    // métiers basiques : tri, recherche, export PDF
    void trier();                        // trie par nom, grade ou ancienneté (2e clic : ordre inverse)
    void rechercher();                   // filtre le tableau pendant la saisie
    void rechercherBouton();             // bouton « Rechercher » : prévient si aucun résultat
    void exporterPdf();                  // enregistre la liste affichée dans un fichier PDF
    void exporterExcel();                // enregistre la liste affichée dans un classeur Excel (.xlsx)
    void telechargerPlanningExcel();     // planning des gardes dans un classeur Excel (.xlsx)

    // planning des gardes
    void genererPlanningBouton();        // bouton « Générer le planning » (message de confirmation)
    void telechargerPlanningPdf();       // bouton « Télécharger PDF » : planning dans un fichier PDF

    // gestion des employés
    void ajouterEmploye();
    void modifierCompte();               // 1er clic : mode édition ; 2e clic : enregistrer
    void supprimerEmploye();
    void annuler();                      // quitte le mode édition, recharge la fiche
    void evaluerMotDePasse();            // indicateur de sécurité + correspondance
    void choisirPhoto();                 // photo de l'employé dans le cercle
    void afficherEmploye(int ligne, int colonne);   // la ligne cliquée remplit le formulaire
    void notifications();                // la cloche s'agite + notification glissante
    void identifiantDepuisNom();         // identifiant et e-mail suivent le nom saisi

    // mot de passe oublié
    void envoyerCode();
    void validerNouveauMotDePasse();
    void mettreAJourMinuteur();

private:
    Ui::CaserneConnectee *ui;
    QWidget *fenetre;
    Authentification auth;

    QString identifiantConnecte;         // compte connecté
    QString emailReinitialisation;       // adresse saisie sur la page « Mot de passe oublié »
    QTimer *minuteurCode = nullptr;
    QVector<SelecteurDroit *> selecteurs;        // droits d'accès de la fiche (un par module)
    qreal phaseBraise = 0;                       // reflet qui défile sur les noms des employés
    FondBraises *fondBraises = nullptr;          // braises de la page d'identification
    FondBraises *fondBraisesOublie = nullptr;    // braises de la page « Mot de passe oublié »
    QHash<QString, QPixmap> photos;      // photo choisie pour chaque employé (clé : identifiant)
    int ligneAffichee = 0;               // employé affiché dans le formulaire
    QString critereTri;                  // « Nom », « Grade » ou « Ancienneté » (vide : ordre d'ajout)
    bool triInverse = false;
    QString recherche;                   // texte recherché (nom, prénom, grade, habilitation)
    qreal bornesAnneau[4] = {0.5, 0.7727, 0.9091, 1.0};   // parts cumulées des 4 statuts
    bool modeEdition = false;            // « Modifier » : fiche en cours de modification
    bool modeAjout = false;              // « Ajouter » : fiche vierge du nouvel employé
    QPixmap photoAjout;                  // photo choisie pour le nouvel employé
    bool modeSombre = false;
    bool langueArabe = false;

    QString t(const char *francais) const;       // texte dans la langue choisie
    Droit droitConnecte(int module) const;
    void preparerPage();                 // colonnes, calendriers
    void afficherMotDePasse(bool visible);
    void installerEffets();
    void preparerPhotos();
    void afficherPhoto(int ligne);
    void afficherNotification(const QString &titre, const QString &texte, const QString &icone = QString(), int duree = 3600);
    void animerAnneau(qreal progression);
    void messageConnexion(const QString &texte, bool info = false);
    void messageOublie(const QString &texte, bool info = false);
    void fermerNotifications();

    // données <-> interface
    void chargerEmployes();              // 1er lancement : comptes créés à partir du tableau de Qt Designer
    void remplirTableau(const QString &identifiantSelectionne = QString());
    void remplirLigne(int ligne, const FicheEmploye &f);
    FicheEmploye ficheDuFormulaire() const;
    bool verifierFormulaire(const FicheEmploye &f, const QString &ancienIdentifiant, bool motDePasseObligatoire);
    QString identifiantLigne(int ligne) const;
    void mettreAJourCompteurs();
    void mettreAJourStatistiques();      // cartes, anneau (par statut) et barres (par fonction)
    QVector<int> ordreAffichage() const; // employés visibles (recherche) dans l'ordre du tri
    QString descriptionTri() const;
    QWidget *surlignerLigne(int ligne, const QColor &couleur, int duree, bool disparait);
    void definirModeEdition(bool actif);
    void definirModeAjout(bool actif);

    // tableau de bord : chiffres et tableaux calculés à partir des employés, carte animée
    void preparerTableauDeBord();
    void mettreAJourTableauDeBord();
    CarteInterventions *carte = nullptr;
    // page d'accueil des modules
    void preparerAccueilModules();
    QWidget *pageAccueil = nullptr;
    QGridLayout *grilleModules = nullptr;
    QLabel *lblBonjour = nullptr, *lblCompteAccueil = nullptr, *lblInvitationAccueil = nullptr;
    QPushButton *btnEmailsAccueil = nullptr;

    // planning des gardes : recalculé à partir de la liste des employés (ajout, modification,
    // suppression : la ligne de l'employé apparaît, change ou disparaît)
    void genererPlanning();
    QDate debutPlanning;
    int joursPlanning = 7;
    QVector<int> effectifCreneau;        // nombre d'agents de garde par créneau
    QVector<bool> creneauIncomplet;      // sous-effectif, sans chef de garde ou sans conducteur
    QString alertePlanning, alertePlanningFr;    // raisons (langue affichée / français pour le PDF)
    // PDF écrit dans un fil d'exécution séparé : l'interface reste fluide pendant la génération
    void enregistrerPdf(const QString &html, const QString &chemin, const QString &titre,
                        QPushButton *bouton, std::function<void(bool)> fin);

    // matrice des droits
    void afficherDroitsFiche(const QVector<int> &droits, bool anime);   // sélecteurs de la fiche
    void activerSelecteurs();                    // réglables par l'administrateur uniquement
};

// =============================================================================
//  Effets visuels réutilisés par toute l'application
// =============================================================================
// Page d'identification animée : des braises montent doucement dans le fond,
// les textes et la carte de connexion apparaissent en glissant, le logo luit.
// -----------------------------------------------------------------------------
// Partie d'un widget réellement visible (ses ancêtres la coupent : page défilée, onglet caché…)
inline QRect partieVisible(const QWidget *w)
{
    if (!w->isVisible()) return QRect();
    QRect zone = w->rect();
    for (const QWidget *a = w->parentWidget(); a; a = a->parentWidget()) {
        zone = zone.intersected(QRect(w->mapFrom(a, QPoint(0, 0)), a->size()));
        if (zone.isEmpty() || a->isWindow()) break;
    }
    return zone;
}

// Mode « animations légères » (bouton ⚡ de l'en-tête) : les décors animés des pages des modules
// (braises, liseré de feu, reflets) s'arrêtent ; la connexion, l'intro, la page des modules,
// les messages et les transitions restent animés.
inline bool &animationsLegeres() { static bool legeres = false; return legeres; }

// La fenêtre est-elle au premier plan ? (sinon, les animations décoratives se mettent en pause)
inline bool fenetreActive(const QWidget *w)
{
    const QWidget *f = w->window();
    return f && f->isActiveWindow() && !(f->windowState() & Qt::WindowMinimized);
}

// Panneaux opaques posés sur un fond animé : inutile de redessiner ce qui est caché derrière eux
inline QRegion zonesCouvertes(const QWidget *fond)
{
    QRegion couvert;
    if (!fond->parentWidget()) return couvert;
    static const QStringList opaques = {"panneau", "kpi", "alerte", "carteConnexion", "entete"};
    for (QWidget *w : fond->parentWidget()->findChildren<QWidget *>()) {   // panneaux, même imbriqués dans des mises en page
        if (w == fond || !w->isVisible() || !opaques.contains(w->property("variante").toString())) continue;
        const QPoint coin = w->mapTo(fond->parentWidget(), QPoint(0, 0));
        couvert += QRect(coin, w->size()).adjusted(14, 14, -14, -14);   // bords arrondis et ombres : toujours animés
    }
    return couvert;
}

class FondBraises : public QWidget
{
public:
    // Fond animé « feu de caserne » :
    //  - braises sur trois profondeurs (les plus proches sont plus grosses, plus rapides, plus vives),
    //    qui ondulent, scintillent et laissent une petite traînée ;
    //  - gerbes d'étincelles qui jaillissent du bas de temps en temps ;
    //  - lueur du foyer qui respire en bas de la page et volutes de fumée chaude qui montent ;
    //  - les braises s'écartent doucement autour du pointeur de la souris.
    // Fluidité : seule la partie visible de la page est animée, et à chaque image on ne redessine
    // que les petites zones autour des braises (pas toute la page et ses tableaux).
    explicit FondBraises(QWidget *page, int nombre = 46, qreal intensite = 1.0) : QWidget(page), intensite(intensite)
    {
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setAttribute(Qt::WA_NoSystemBackground);
        setProperty("fondBraises", true);
        QRandomGenerator *g = QRandomGenerator::global();
        for (int i = 0; i < nombre; ++i) {
            Braise b;
            b.x = g->bounded(1.0); b.y = g->bounded(1.0);
            b.profondeur = 0.35 + 0.65 * g->bounded(1.0);
            b.vitesse = (0.03 + g->bounded(0.06)) * (0.5 + b.profondeur);
            b.taille = (0.6 + g->bounded(1.4)) * (0.6 + 0.6 * b.profondeur);
            b.phase = g->bounded(6.28);
            b.frequence = 2 + g->bounded(5.0);
            braises.append(b);
        }
        for (int i = 0; i < 3; ++i) fumees.append({g->bounded(1.0), g->bounded(1.0), 0.008 + g->bounded(0.01), g->bounded(6.28)});
        minuterie = new QTimer(this);
        connect(minuterie, &QTimer::timeout, this, [this]() { image(); });
        page->installEventFilter(this);
        setGeometry(page->rect());
        lower();
    }
    void demarrer() { minuterie->start(50); }
    void arreter()  { minuterie->stop(); }
protected:
    bool eventFilter(QObject *o, QEvent *e) override
    {
        if (e->type() == QEvent::Resize) setGeometry(static_cast<QWidget *>(o)->rect());
        if (e->type() == QEvent::Hide) arreter();
        if (e->type() == QEvent::Show) demarrer();
        return false;
    }
    void paintEvent(QPaintEvent *e) override
    {
        if (zone.isEmpty()) return;
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.setPen(Qt::NoPen);
        p.setClipRect(zone, Qt::IntersectClip);
        const QRect aPeindre = e->rect();

        // 1. lueur du foyer en bas de la partie visible : elle respire (deux rythmes mêlés)
        const qreal hFoyer = qMin<qreal>(zone.height(), 240.0);
        const QRectF bandeFoyer(zone.left(), zone.bottom() - hFoyer, zone.width(), hFoyer);
        if (bandeFoyer.intersects(aPeindre)) {
            const qreal souffle = 0.65 + 0.2 * std::sin(temps * 1.3) + 0.15 * std::sin(temps * 3.1 + 1.0);
            QLinearGradient foyer(0, zone.bottom(), 0, zone.bottom() - hFoyer);
            foyer.setColorAt(0.0, QColor(228, 73, 31, int(55 * intensite * souffle)));
            foyer.setColorAt(0.5, QColor(242, 120, 50, int(18 * intensite * souffle)));
            foyer.setColorAt(1.0, QColor(242, 120, 50, 0));
            p.fillRect(bandeFoyer, foyer);
        }

        // 2. volutes de fumée chaude qui montent lentement
        for (const Fumee &f : fumees) {
            const QPointF c(zone.left() + f.x * zone.width() + std::sin(temps * 0.4 + f.phase) * 40, zone.top() + f.y * zone.height());
            const qreal r = 120 + 60 * std::sin(temps * 0.3 + f.phase);
            if (!QRectF(c.x() - r, c.y() - r, 2 * r, 2 * r).intersects(aPeindre)) continue;
            p.setOpacity(qBound(0.0, f.y * 1.3, 1.0) * intensite * 0.065);
            p.drawPixmap(QRectF(c.x() - r, c.y() - r, 2 * r, 2 * r), sprite(0), QRectF(0, 0, 128, 128));
        }

        // 3. braises (image prête à l'emploi, juste teintée par l'opacité : bien plus rapide qu'un dégradé)
        for (const Braise &b : braises) {
            if (!contour(b).intersects(aPeindre)) continue;
            const QPointF c = position(b);
            const qreal eclat = 0.55 + 0.45 * std::sin(temps * b.frequence + b.phase);      // scintillement
            const qreal vie = qBound(0.0, b.y * 1.4, 1.0);                                   // s'éteint en montant
            const qreal alpha = 0.63 * intensite * vie * (0.45 + 0.55 * b.profondeur) * (0.6 + 0.4 * eclat);
            const qreal r = b.taille * 3.0;
            p.setOpacity(alpha * 0.35);
            p.setBrush(QColor(242, 110, 50));
            for (int k = 1; k <= 3; ++k)                                                      // traînée
                p.drawEllipse(c + QPointF(0, b.vitesse * 140 * k), r * (0.55 - 0.1 * k), r * (0.55 - 0.1 * k));
            p.setOpacity(alpha);
            p.drawPixmap(QRectF(c.x() - 3 * r, c.y() - 3 * r, 6 * r, 6 * r), sprite(1), QRectF(0, 0, 128, 128));
        }

        // 4. étincelles des gerbes
        p.setOpacity(1.0);
        for (const Etincelle &e : etincelles) {
            p.setBrush(QColor(255, 200 + int(40 * e.vie), 120, int(230 * intensite * e.vie)));
            p.drawEllipse(e.position, 1.2 + e.vie, 1.2 + e.vie);
        }
    }
    // Images du halo d'une braise (1) et d'une volute de fumée (0), dessinées une seule fois
    static const QPixmap &sprite(int type)
    {
        static QPixmap images[2];
        if (images[type].isNull()) {
            QPixmap image(128, 128);
            image.fill(Qt::transparent);
            QPainter q(&image);
            q.setRenderHint(QPainter::Antialiasing);
            QRadialGradient g(QPointF(64, 64), 64);
            if (type == 1) {
                g.setColorAt(0.0, QColor(255, 228, 170, 255));
                g.setColorAt(0.18, QColor(255, 138, 91, 255));
                g.setColorAt(0.45, QColor(228, 73, 31, 85));
                g.setColorAt(1.0, QColor(228, 73, 31, 0));
            } else {
                g.setColorAt(0.0, QColor(255, 150, 100, 255));
                g.setColorAt(1.0, QColor(255, 150, 100, 0));
            }
            q.setPen(Qt::NoPen);
            q.setBrush(g);
            q.drawEllipse(QRectF(0, 0, 128, 128));
            images[type] = image;
        }
        return images[type];
    }
private:
    struct Braise { qreal x, y, vitesse, taille, phase, profondeur, frequence; QPointF ecart; };
    struct Fumee { qreal x, y, vitesse, phase; };
    struct Etincelle { QPointF position, vitesse; qreal vie; };
    QVector<Braise> braises;
    QVector<Fumee> fumees;
    QVector<Etincelle> etincelles;
    QTimer *minuterie;
    qreal intensite;
    qreal temps = 0, prochaineGerbe = 1.5;
    QRect zone;                                  // partie visible de la page (coordonnées du fond)
    QRegion couvert;                             // derrière les panneaux : pas redessiné
    int compteur = 0;

    QPointF position(const Braise &b) const
    {
        return QPointF(zone.left() + b.x * zone.width() + std::sin(b.phase) * 14 * b.profondeur + std::sin(b.phase * 0.37) * 8,
                       zone.top() + b.y * zone.height()) + b.ecart;
    }
    QRect contour(const Braise &b) const        // zone peinte par une braise (halo + traînée)
    {
        const QPointF c = position(b);
        const qreal r = b.taille * 9 + 2;
        return QRectF(c.x() - r, c.y() - r, 2 * r, 2 * r + b.vitesse * 420).toAlignedRect();
    }
    void image()
    {
        if (!fenetreActive(this)) return;                             // application en arrière-plan : pause
        if (animationsLegeres() && property("secondaire").toBool()) {  // mode léger : décor des modules arrêté
            if (!zone.isEmpty()) { zone = QRect(); update(); }
            return;
        }
        const QRect avant = zone;
        zone = partieVisible(this);
        if (zone.isEmpty()) return;                                   // page cachée ou hors écran : rien à faire
        if (zone != avant) { avancer(0.05); update(zone); return; }   // la page a défilé : tout redessiner une fois
        QRegion sale;
        for (const Braise &b : braises) sale += contour(b);
        for (const Etincelle &e : etincelles) sale += QRectF(e.position - QPointF(4, 4), QSizeF(8, 8)).toAlignedRect();
        avancer(0.05);
        for (const Braise &b : braises) sale += contour(b);
        for (const Etincelle &e : etincelles) sale += QRectF(e.position - QPointF(4, 4), QSizeF(8, 8)).toAlignedRect();
        // la lueur du foyer et la fumée bougent lentement : redessinées 4 fois par seconde seulement
        if (++compteur % 5 == 0) {
            sale += QRect(zone.left(), zone.bottom() - 240, zone.width(), 241);
            for (const Fumee &f : fumees) {
                const QPointF c(zone.left() + f.x * zone.width(), zone.top() + f.y * zone.height());
                sale += QRectF(c.x() - 230, c.y() - 190, 460, 380).toAlignedRect();
            }
        }
        if (compteur % 20 == 1) couvert = zonesCouvertes(this);     // recalculé une fois par seconde
        update(sale.intersected(zone).subtracted(couvert));
    }
    void avancer(qreal dt)
    {
        temps += dt;
        QRandomGenerator *g = QRandomGenerator::global();
        const QPointF souris = mapFromGlobal(QCursor::pos());
        const bool sourisDedans = zone.contains(souris.toPoint());
        for (Braise &b : braises) {
            b.y -= b.vitesse * dt;
            b.phase += 1.2 * dt;
            if (sourisDedans) {                      // la souris écarte les braises proches
                const QPointF d = position(b) - souris;
                const qreal dist = std::hypot(d.x(), d.y());
                if (dist < 110 && dist > 0.1) b.ecart += d / dist * (110 - dist) * 0.06;
            }
            b.ecart *= 0.94;
            if (b.y < -0.04) { b.y = 1.04; b.x = g->bounded(1.0); b.ecart = QPointF(); }
        }
        for (Fumee &f : fumees) {
            f.y -= f.vitesse * dt;
            if (f.y < -0.3) { f.y = 1.3; f.x = g->bounded(1.0); }
        }
        prochaineGerbe -= dt;                        // gerbe d'étincelles au bas de la partie visible
        if (prochaineGerbe <= 0 && zone.width() > 0) {
            prochaineGerbe = 2.0 + g->bounded(3.0);
            const QPointF depart(zone.left() + g->bounded(qreal(zone.width())), zone.bottom() - 4);
            const int n = int(8 + 8 * intensite);
            for (int i = 0; i < n; ++i)
                etincelles.append({depart, QPointF(-70 + g->bounded(140.0), -(140 + g->bounded(220.0))), 1.0});
        }
        for (Etincelle &e : etincelles) {
            e.position += e.vitesse * dt;
            e.vitesse += QPointF(0, 120 * dt);
            e.vie -= dt * 0.9;
        }
        etincelles.erase(std::remove_if(etincelles.begin(), etincelles.end(), [](const Etincelle &e) { return e.vie <= 0; }),
                         etincelles.end());
    }
};

// -----------------------------------------------------------------------------
// Halo lumineux qui respire autour d'un widget (logo, bandeau d'alerte).
// Il est dessiné par un petit widget placé juste sous la cible : bien plus léger qu'une
// ombre floue (QGraphicsDropShadowEffect) recalculée à chaque image.
// -----------------------------------------------------------------------------
class HaloPulsant : public QWidget
{
public:
    HaloPulsant(QWidget *cible, const QColor &couleur, bool rond, int marge, qreal periode, bool vacille = false)
        : QWidget(cible->parentWidget()), cible(cible), couleur(couleur), rond(rond), marge(marge), periode(periode), vacille(vacille)
    {
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setAttribute(Qt::WA_NoSystemBackground);
        cible->installEventFilter(this);
        placer();
        minuterie = new QTimer(this);
        connect(minuterie, &QTimer::timeout, this, [this]() {
            temps += 0.05;
            if (!fenetreActive(this) || partieVisible(this).isEmpty()) return;
            if (this->rond) update();
            else update(QRegion(rect()).subtracted(QRegion(rect().adjusted(this->marge + 6, this->marge + 6, -this->marge - 6, -this->marge - 6))));
        });
        minuterie->start(50);
    }
protected:
    bool eventFilter(QObject *, QEvent *e) override
    {
        if (e->type() == QEvent::Move || e->type() == QEvent::Resize || e->type() == QEvent::Show) placer();
        if (e->type() == QEvent::Hide) hide();
        return false;
    }
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        qreal force = 0.5 - 0.5 * std::cos(temps * 2 * M_PI / periode);              // respiration
        if (vacille) force = qBound(0.0, force * 0.8 + 0.2 * (0.5 + 0.5 * std::sin(temps * 17.0) * std::sin(temps * 7.3)), 1.0);
        const QRectF c = QRectF(rect()).adjusted(marge, marge, -marge, -marge);
        if (rond) {
            const qreal r = c.width() / 2 + marge * (0.55 + 0.45 * force);
            QRadialGradient g(c.center(), r);
            QColor a = couleur; a.setAlpha(int((150 * force + 30) * couleur.alphaF()));
            QColor b = couleur; b.setAlpha(0);
            g.setColorAt(0.35, a);
            g.setColorAt(1.0, b);
            p.setPen(Qt::NoPen);
            p.setBrush(g);
            p.drawEllipse(c.center(), r, r);
        } else {
            for (int i = 1; i <= marge; i += 2) {                                       // anneaux de plus en plus pâles
                QColor a = couleur;
                a.setAlpha(int((40 + 140 * force) * (1.0 - qreal(i) / marge) * 0.5));
                p.setPen(QPen(a, 2));
                p.setBrush(Qt::NoBrush);
                p.drawRoundedRect(c.adjusted(-i, -i, i, i), 12 + i, 12 + i);
            }
        }
    }
private:
    QWidget *cible;
    QColor couleur;
    bool rond;
    int marge;
    qreal periode, temps = 0;
    bool vacille;
    QTimer *minuterie;
    void placer()
    {
        if (!cible->parentWidget()) return;
        setGeometry(cible->geometry().adjusted(-marge, -marge, marge, marge));
        setVisible(cible->isVisible());
        stackUnder(cible);
    }
};

// -----------------------------------------------------------------------------
// Carreau d'un module sur la page d'accueil des modules : icône, nom, description, droit du
// compte. Survol : le carreau se soulève, un halo orange l'entoure, une lumière suit la souris
// et la flèche « Ouvrir » avance. Module non autorisé : carreau grisé avec un cadenas.
// -----------------------------------------------------------------------------
class TuileModule : public QWidget
{
public:
    TuileModule(const QString &icone, const QString &nom, const QString &description, const QString &droit,
                bool autorise, std::function<void()> ouvrir, QWidget *parent = nullptr)
        : QWidget(parent), image(icone), nom(nom), description(description), droit(droit), autorise(autorise), ouvrir(ouvrir)
    {
        pix = QPixmap(icone);                                    // icône préparée une seule fois
        if (!autorise) {                                         // module non autorisé : icône grisée
            QImage gris = pix.toImage().convertToFormat(QImage::Format_ARGB32);
            for (int y = 0; y < gris.height(); ++y)
                for (int x = 0; x < gris.width(); ++x) {
                    const QRgb c = gris.pixel(x, y);
                    const int g = qGray(c);
                    gris.setPixel(x, y, qRgba(g, g, g, qAlpha(c)));
                }
            pix = QPixmap::fromImage(gris);
        }
        setMinimumSize(230, 170);
        setMaximumHeight(215);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        setFixedHeight(205);
        setMouseTracking(true);
        setCursor(autorise ? Qt::PointingHandCursor : Qt::ForbiddenCursor);
        animation = new QTimer(this);
        connect(animation, &QTimer::timeout, this, [this]() {
            temps += 0.03;
            survol += ((dessus ? 1.0 : 0.0) - survol) * 0.2;
            if (apparition < 1) apparition = qMin(1.0, apparition + 0.06);
            update();
            if (!dessus && survol < 0.01 && apparition >= 1 && secousse <= 0) animation->stop();
            if (secousse > 0) secousse -= 0.03;
        });
    }
    void cacher() { apparition = 0; update(); }   // en attente de l'entrée en cascade
    void apparaitre(int delai)                    // entrée en cascade
    {
        apparition = 0;
        update();
        QTimer::singleShot(delai, this, [this]() { animation->start(30); });
    }
protected:
    void enterEvent(QEnterEvent *) override { dessus = true; animation->start(30); }
    void leaveEvent(QEvent *) override { dessus = false; animation->start(30); }
    void mouseMoveEvent(QMouseEvent *e) override { souris = e->position(); }
    void mouseReleaseEvent(QMouseEvent *e) override
    {
        if (!rect().contains(e->position().toPoint())) return;
        if (autorise) { if (ouvrir) ouvrir(); }
        else { secousse = 0.45; animation->start(30); }            // module non autorisé : le carreau tremble
    }
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.setRenderHint(QPainter::SmoothPixmapTransform);
        const qreal entree = QEasingCurve(QEasingCurve::OutCubic).valueForProgress(apparition);
        p.setOpacity(entree * (autorise ? 1.0 : 0.55));
        const qreal tremble = secousse > 0 ? std::sin(secousse * 60) * 6 * secousse / 0.45 : 0;
        p.translate(tremble, 26 * (1 - entree) - 6 * survol);
        const QRectF carte = QRectF(rect()).adjusted(8, 10, -8, -6);

        // halo orange au survol
        if (survol > 0.01 && autorise)
            for (int i = 1; i <= 8; ++i) {
                p.setPen(QPen(QColor(228, 73, 31, int(26 * survol * (1 - i / 9.0))), 2));
                p.setBrush(Qt::NoBrush);
                p.drawRoundedRect(carte.adjusted(-i, -i, i, i), 16 + i, 16 + i);
            }
        // fond de la carte + lumière qui suit la souris
        QLinearGradient fond(carte.topLeft(), carte.bottomRight());
        fond.setColorAt(0, QColor(31, 39, 50, 235));
        fond.setColorAt(1, QColor(20, 26, 34, 235));
        p.setPen(QPen(QColor(autorise ? (survol > 0.5 ? "#B4532E" : "#2E3946") : "#2A3340"), 1.2));
        p.setBrush(fond);
        p.drawRoundedRect(carte, 16, 16);
        if (survol > 0.01 && autorise) {
            QRadialGradient lumiere(souris, 160);
            lumiere.setColorAt(0, QColor(255, 138, 91, int(45 * survol)));
            lumiere.setColorAt(1, QColor(255, 138, 91, 0));
            p.setBrush(lumiere);
            p.setPen(Qt::NoPen);
            p.drawRoundedRect(carte, 16, 16);
        }
        // icône (elle rebondit au survol)
        const qreal saut = autorise ? std::sin(temps * 6) * 3 * survol : 0;
        const QRectF icone(carte.left() + 18, carte.top() + 18 - saut, 52, 52);
        p.drawPixmap(icone, pix, pix.rect());
        // pastille du droit (en haut à droite)
        QFont petite = font();
        petite.setPointSizeF(8);
        petite.setBold(true);
        p.setFont(petite);
        const QString pastille = autorise ? droit : QString::fromUtf8("Accès non autorisé");
        const qreal largeur = QFontMetricsF(petite).horizontalAdvance(pastille) + (autorise ? 18 : 30);
        const QRectF zonePastille(carte.right() - 16 - largeur, carte.top() + 18, largeur, 22);
        const QColor teinte = !autorise ? QColor("#9AA5B1") : droit.contains("Lecture") ? QColor("#5B8DEF") : QColor("#5FD39B");
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(teinte.red(), teinte.green(), teinte.blue(), 40));
        p.drawRoundedRect(zonePastille, 11, 11);
        p.setPen(teinte);
        if (!autorise) {                                        // petit cadenas
            const QPointF c(zonePastille.left() + 13, zonePastille.center().y() + 1);
            p.setBrush(Qt::NoBrush);
            p.setPen(QPen(teinte, 1.4));
            p.drawArc(QRectF(c.x() - 3.5, c.y() - 8, 7, 8), 0, 180 * 16);
            p.setBrush(teinte);
            p.drawRoundedRect(QRectF(c.x() - 5, c.y() - 3, 10, 7), 1.5, 1.5);
            p.setPen(teinte);
            p.drawText(zonePastille.adjusted(22, 0, -6, 0), Qt::AlignVCenter | Qt::AlignLeft, pastille);
        } else p.drawText(zonePastille, Qt::AlignCenter, pastille);
        // nom et description
        QFont titre = font();
        titre.setPointSizeF(15);
        titre.setBold(true);
        p.setFont(titre);
        p.setPen(QColor("#F4F6F8"));
        p.drawText(QRectF(carte.left() + 18, icone.bottom() + 12 + saut, carte.width() - 36, 28), Qt::AlignLeft | Qt::AlignVCenter, nom);
        QFont texte = font();
        texte.setPointSizeF(9);
        p.setFont(texte);
        p.setPen(QColor("#93A4B2"));
        p.drawText(QRectF(carte.left() + 18, icone.bottom() + 42 + saut, carte.width() - 36, carte.bottom() - icone.bottom() - 70),
                   Qt::AlignLeft | Qt::AlignTop | Qt::TextWordWrap, description);
        // « Ouvrir → » : la flèche avance au survol
        if (autorise) {
            QFont lien = font();
            lien.setPointSizeF(9);
            lien.setBold(true);
            p.setFont(lien);
            p.setPen(QColor(255, 138, 91, int(150 + 105 * survol)));
            const QPointF bas(carte.left() + 18, carte.bottom() - 16);
            p.drawText(bas, QString::fromUtf8("Ouvrir"));
            const qreal x = bas.x() + QFontMetricsF(lien).horizontalAdvance(QString::fromUtf8("Ouvrir")) + 8 + 8 * survol;
            p.setPen(QPen(QColor(255, 138, 91, int(150 + 105 * survol)), 2, Qt::SolidLine, Qt::RoundCap));
            p.drawLine(QPointF(x, bas.y() - 4), QPointF(x + 12, bas.y() - 4));
            p.drawLine(QPointF(x + 7, bas.y() - 9), QPointF(x + 12, bas.y() - 4));
            p.drawLine(QPointF(x + 7, bas.y() + 1), QPointF(x + 12, bas.y() - 4));
        }
    }
private:
    QString image, nom, description, droit;
    QPixmap pix;
    bool autorise;
    std::function<void()> ouvrir;
    QTimer *animation;
    qreal temps = 0, survol = 0, apparition = 1, secousse = 0;
    bool dessus = false;
    QPointF souris;
};

// -----------------------------------------------------------------------------
// Résultat de la vérification du mot de passe, dessiné sur la carte de connexion :
//  - accepté : la carte s'assombrit, un anneau vert se trace, la coche se dessine,
//    des étincelles vertes et orange jaillissent ;
//  - refusé : effet contraire — l'anneau rouge se referme en tremblant, une croix se
//    dessine, des éclats retombent, puis tout s'efface.
// -----------------------------------------------------------------------------
class ResultatConnexion : public QWidget
{
public:
    ResultatConnexion(QWidget *carte, bool accepte) : QWidget(carte), accepte(accepte)
    {
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setGeometry(carte->rect());
        QRandomGenerator *g = QRandomGenerator::global();
        for (int i = 0; i < (accepte ? 28 : 18); ++i) {
            const qreal a = g->bounded(2 * M_PI), v = accepte ? 160 + g->bounded(200.0) : 60 + g->bounded(120.0);
            eclats.append({QPointF(std::cos(a) * v, std::sin(a) * v - (accepte ? 60 : 0)), g->bounded(2.5) + 1.5,
                           QColor(accepte ? (i % 2 ? "#5FD39B" : "#FF8A5B") : (i % 2 ? "#D93636" : "#7A8896"))});
        }
        chrono = new QVariantAnimation(this);
        chrono->setDuration(accepte ? 950 : 900);
        chrono->setStartValue(0.0);
        chrono->setEndValue(1.0);
        connect(chrono, &QVariantAnimation::valueChanged, this, [this](const QVariant &v) { t = v.toReal(); update(); });
        connect(chrono, &QVariantAnimation::finished, this, &QWidget::deleteLater);
        chrono->start();
        show();
        raise();
    }
protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        auto phase = [this](qreal a, qreal b) { return qBound(0.0, (t - a) / (b - a), 1.0); };
        const qreal sortie = accepte ? 1.0 : 1.0 - phase(0.75, 1.0);
        const QColor couleur(accepte ? "#1E9E63" : "#D93636");
        // voile sur la carte
        QPainterPath forme;
        forme.addRoundedRect(QRectF(rect()).adjusted(1, 1, -1, -1), 18, 18);
        p.fillPath(forme, QColor(10, 14, 20, int(205 * phase(0, 0.2) * sortie)));
        // anneau qui se trace (accepté) ou qui tremble en se refermant (refusé)
        const QPointF c = QPointF(rect().center()) + QPointF(accepte ? 0 : std::sin(t * 70) * 7 * (1 - phase(0.2, 0.6)), -10);
        const qreal r = 44;
        const qreal trace = QEasingCurve(QEasingCurve::OutCubic).valueForProgress(phase(0.05, 0.45));
        QRadialGradient fond(c, r * 1.8);
        fond.setColorAt(0, QColor(couleur.red(), couleur.green(), couleur.blue(), int(90 * trace * sortie)));
        fond.setColorAt(1, QColor(couleur.red(), couleur.green(), couleur.blue(), 0));
        p.setPen(Qt::NoPen);
        p.setBrush(fond);
        p.drawEllipse(c, r * 1.8, r * 1.8);
        p.setBrush(QColor(couleur.red(), couleur.green(), couleur.blue(), int(40 * sortie)));
        p.setPen(QPen(QColor(couleur.red(), couleur.green(), couleur.blue(), int(255 * sortie)), 4, Qt::SolidLine, Qt::RoundCap));
        p.drawArc(QRectF(c.x() - r, c.y() - r, 2 * r, 2 * r), 90 * 16, int((accepte ? -360 : 360) * 16 * trace));
        // coche ou croix qui se dessine
        p.setPen(QPen(QColor(255, 255, 255, int(255 * sortie)), 6, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        const qreal d = phase(0.35, 0.7);
        if (accepte) {
            const QPointF a = c + QPointF(-16, 1), b = c + QPointF(-4, 13), e = c + QPointF(18, -12);
            const qreal premier = qMin(1.0, d * 2), second = qMax(0.0, d * 2 - 1);
            if (premier > 0) p.drawLine(a, a + (b - a) * premier);
            if (second > 0) p.drawLine(b, b + (e - b) * second);
        } else {
            const qreal premier = qMin(1.0, d * 2), second = qMax(0.0, d * 2 - 1);
            if (premier > 0) p.drawLine(c + QPointF(-14, -14), c + QPointF(-14, -14) + QPointF(28, 28) * premier);
            if (second > 0) p.drawLine(c + QPointF(14, -14), c + QPointF(14, -14) + QPointF(-28, 28) * second);
        }
        // étincelles qui jaillissent (accepté) ou éclats qui retombent (refusé)
        const qreal e = phase(0.4, 1.0);
        p.setPen(Qt::NoPen);
        for (const Eclat &x : eclats) {
            const QPointF pos = c + x.vitesse * e * 0.6 + QPointF(0, accepte ? 0 : 240 * e * e);
            QColor col = x.couleur;
            col.setAlphaF(qBound(0.0, (1 - e) * (e > 0 ? 1 : 0), 1.0) * sortie);
            p.setBrush(col);
            p.drawEllipse(pos, x.taille, x.taille);
        }
        // message sous l'anneau
        QFont police = font();
        police.setPointSizeF(10.5);
        police.setBold(true);
        p.setFont(police);
        p.setPen(QColor(accepte ? "#5FD39B" : "#F08080").lighter(110));
        p.setOpacity(phase(0.45, 0.7) * sortie);
        p.drawText(QRectF(0, c.y() + r + 14, width(), 24), Qt::AlignCenter,
                   accepte ? QString::fromUtf8("Accès vérifié") : QString::fromUtf8("Accès refusé"));
    }
private:
    struct Eclat { QPointF vitesse; qreal taille; QColor couleur; };
    QVector<Eclat> eclats;
    bool accepte;
    qreal t = 0;
    QVariantAnimation *chrono;
};

// -----------------------------------------------------------------------------
// Voile de couleur qui s'efface (apparition des panneaux) : simple rectangle peint avec une
// transparence qui diminue — beaucoup plus léger qu'un effet d'opacité Qt sur un grand widget.
// -----------------------------------------------------------------------------
class VoileFondu : public QWidget
{
public:
    VoileFondu(QWidget *parent, const QColor &couleur, int delai, int duree) : QWidget(parent), couleur(couleur)
    {
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setAttribute(Qt::WA_NoSystemBackground);
        QVariantAnimation *a = new QVariantAnimation(this);
        a->setDuration(duree);
        a->setStartValue(1.0);
        a->setEndValue(0.0);
        a->setEasingCurve(QEasingCurve::InOutQuad);
        connect(a, &QVariantAnimation::valueChanged, this, [this](const QVariant &v) { opacite = v.toReal(); update(); });
        connect(a, &QVariantAnimation::finished, this, &QWidget::deleteLater);
        QTimer::singleShot(delai, a, [a]() { a->start(); });
    }
protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        QColor c = couleur;
        c.setAlphaF(opacite);
        p.fillRect(rect(), c);
    }
private:
    QColor couleur;
    qreal opacite = 1.0;
};

// -----------------------------------------------------------------------------
// Ouverture d'un module depuis son carreau : l'image du carreau s'agrandit jusqu'à
// remplir la fenêtre en s'effaçant (dessin direct, rapide).
// -----------------------------------------------------------------------------
class ZoomCarreau : public QWidget
{
public:
    ZoomCarreau(QWidget *fenetre, const QPixmap &image, const QRect &depart) : QWidget(fenetre), image(image), depart(depart)
    {
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setAttribute(Qt::WA_NoSystemBackground);
        setGeometry(fenetre->rect());
        QVariantAnimation *a = new QVariantAnimation(this);
        a->setDuration(260);
        a->setStartValue(0.0);
        a->setEndValue(1.0);
        a->setEasingCurve(QEasingCurve::OutCubic);
        connect(a, &QVariantAnimation::valueChanged, this, [this](const QVariant &v) { t = v.toReal(); update(); });
        connect(a, &QVariantAnimation::finished, this, &QWidget::deleteLater);
        a->start();
        show();
        raise();
    }
protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        const QRectF r(depart.left() * (1 - t), depart.top() * (1 - t),
                       depart.width() + (width() - depart.width()) * t, depart.height() + (height() - depart.height()) * t);
        p.setOpacity(1.0 - t * t);
        p.drawPixmap(r, image, image.rect());          // sans lissage : rapide
    }
private:
    QPixmap image;
    QRect depart;
    qreal t = 0;
};

// -----------------------------------------------------------------------------
// Envoi réel des e-mails (code « mot de passe oublié ») par SMTP sécurisé (SSL/TLS), sans
// bibliothèque externe : QSslSocket parle directement au serveur de messagerie.
// Réglages (serveur, port, adresse, mot de passe d'application) : bouton « Envoi des e-mails »
// de la page des modules (administrateur). Gmail : smtp.gmail.com, port 465, mot de passe
// d'application (compte Google > Sécurité > Validation en deux étapes > Mots de passe des applications).
// -----------------------------------------------------------------------------
struct ReglagesEmail
{
    QString serveur = "smtp.gmail.com";
    int port = 465;
    QString adresse, motDePasse, nom = QString::fromUtf8("Caserne Connectée");
    bool configure() const { return !serveur.isEmpty() && !adresse.isEmpty() && !motDePasse.isEmpty(); }
    static ReglagesEmail charger();
    void enregistrer() const;
};

class EnvoiEmail : public QObject
{
public:
    // fin(réussi, message d'erreur lisible)
    static void envoyer(const ReglagesEmail &r, const QString &destinataire, const QString &sujet, const QString &html,
                        std::function<void(bool, QString)> fin);
private:
    EnvoiEmail(const ReglagesEmail &r, const QString &destinataire, const QString &sujet, const QString &html,
               std::function<void(bool, QString)> fin);
    void lire();
    void reponse(int code, const QString &texte);
    void envoyerLigne(const QByteArray &ligne);
    void terminer(bool ok, const QString &message);
    ReglagesEmail reglages;
    QString destinataire, sujet, html;
    std::function<void(bool, QString)> fin;
    class QSslSocket *socket;
    QByteArray tampon;
    int etape = 0;
    bool fini = false;
};

// -----------------------------------------------------------------------------
// Effets de l'interface
// -----------------------------------------------------------------------------

// Survol : la carte se soulève (ombre orange qui grandit), puis redescend
class EffetSurvol : public QObject
{
public:
    // L'ombre n'existe que pendant le survol : une ombre floue attachée en permanence obligerait Qt
    // à recalculer l'image de la carte à chaque fois qu'elle est redessinée (très lent).
    explicit EffetSurvol(QWidget *cible, int flou = 26, int hauteur = 6) : QObject(cible), cible(cible), flouMax(flou), hauteurMax(hauteur)
    {
        cible->setAttribute(Qt::WA_Hover);
        cible->installEventFilter(this);
        animation = new QVariantAnimation(this);
        animation->setDuration(220);
        animation->setEasingCurve(QEasingCurve::OutCubic);
        connect(animation, &QVariantAnimation::valueChanged, this, [this](const QVariant &v) {
            if (!ombre) return;
            t = v.toReal();
            ombre->setBlurRadius(flouMax * t);
            ombre->setOffset(0, hauteurMax * t);
            ombre->setColor(QColor(228, 73, 31, int(70 * t)));
        });
        connect(animation, &QVariantAnimation::finished, this, [this]() {
            if (t <= 0.001 && ombre && this->cible->graphicsEffect() == ombre) this->cible->setGraphicsEffect(nullptr);   // plus d'ombre : plus de coût
        });
    }
protected:
    bool eventFilter(QObject *, QEvent *e) override
    {
        if (e->type() != QEvent::Enter && e->type() != QEvent::Leave) return false;
        if (e->type() == QEvent::Enter && !ombre) {
            if (cible->graphicsEffect()) return false;   // un autre effet est déjà en place
            ombre = new QGraphicsDropShadowEffect(cible);
            ombre->setOffset(0, 0);
            ombre->setBlurRadius(0);
            ombre->setColor(QColor(228, 73, 31, 0));
            cible->setGraphicsEffect(ombre);
            t = 0;
        }
        if (!ombre) return false;
        animation->stop();
        animation->setStartValue(t);
        animation->setEndValue(e->type() == QEvent::Enter ? 1.0 : 0.0);
        animation->start();
        return false;
    }
private:
    QWidget *cible;
    QPointer<QGraphicsDropShadowEffect> ombre;
    QVariantAnimation *animation;
    qreal flouMax, hauteurMax, t = 0;
};

// -----------------------------------------------------------------------------
// Message animé (ajout / suppression / modification d'un employé)
//  - un voile sombre recouvre la fenêtre, une carte apparaît en rebondissant ;
//  - le cercle se trace, puis la coche (succès) ou la corbeille (suppression) se dessine ;
//  - des étincelles jaillissent (succès) ou des débris tombent (suppression) ;
//  - le message disparaît seul après 2,4 s (ou au clic).
// -----------------------------------------------------------------------------
class MessageAnime : public QWidget
{
public:
    enum Type { Succes, Suppression };
    MessageAnime(QWidget *fenetre, Type type, const QString &titre, const QString &texte, bool sombre);
protected:
    void paintEvent(QPaintEvent *) override;
    void mousePressEvent(QMouseEvent *) override;
    bool eventFilter(QObject *o, QEvent *e) override;
private:
    struct Particule { QPointF position, vitesse; QColor couleur; qreal taille; };
    Type type;
    QString titre, texte;
    bool sombre;
    qreal temps = 0;                    // millisecondes écoulées
    QVector<Particule> particules;
    QVariantAnimation *chrono;
    static constexpr qreal DUREE = 2700;
    static qreal phase(qreal t, qreal debut, qreal fin);
};

// -----------------------------------------------------------------------------
// Intro de connexion (après la vérification de l'accès) : sur toute la fenêtre, le logo
// s'embrase du bas vers le haut, ses circuits s'allument, un anneau se trace, le nom de
// l'application s'écrit lettre par lettre, puis la page s'ouvre par un cercle qui s'agrandit.
// Un clic passe l'intro.
// -----------------------------------------------------------------------------
class IntroConnexion : public QWidget
{
public:
    IntroConnexion(QWidget *fenetre, const QString &titre, const QString &bienvenue, const QString &detail,
                   std::function<void()> milieu, std::function<void()> fin);
protected:
    void paintEvent(QPaintEvent *) override;
    void mousePressEvent(QMouseEvent *) override;
    bool eventFilter(QObject *o, QEvent *e) override;
private:
    struct Etincelle { QPointF position, vitesse; qreal vie, taille; QColor couleur; };
    QString titre, bienvenue, detail;
    std::function<void()> milieu, fin;
    bool milieuFait = false, finFaite = false;
    qreal temps = 0, precedent = 0;
    QVector<Etincelle> etincelles;       // étincelles du front de flamme
    QVector<QPointF> braises;            // braises du fond (positions relatives)
    QVector<qreal> vitesses;
    QPixmap logo;                        // logo teinté en dégradé de feu
    QVariantAnimation *chrono;
    static constexpr qreal DUREE = 3400, SORTIE = 2750;
    static qreal phase(qreal t, qreal debut, qreal fin);
};

// -----------------------------------------------------------------------------
// Carte des interventions du tableau de bord : deux modes au choix
//  - Plan : le plan illustré de Tunis Nord (image), sans connexion ;
//  - Carte réelle : tuiles OpenStreetMap (Internet), déplacement à la souris, zoom à la molette.
// Les points importants sont animés : halos qui pulsent sur les interventions et la caserne,
// ondes radar sur la balise SOS, véhicules qui roulent le long de leur trajet.
// -----------------------------------------------------------------------------
class QNetworkAccessManager;
class QNetworkReply;
class CarteInterventions : public QWidget
{
public:
    explicit CarteInterventions(QWidget *parent = nullptr);
    void definirReelle(bool reelle);
    void definirSombre(bool s) { sombre = s; update(); }
    void localiserBalise();                      // centre la carte sur la balise SOS et l'entoure d'un radar
    void definirBalise(const QString &nom) { for (Lieu &l : lieux) if (l.type == 2) l.nom = nom; update(); }
    void animerEntree() { debutEntree = temps; update(); }   // les épingles tombent, la boussole s'ouvre
    void placerCommandes(QWidget *w) { commandes = w; w->setParent(this); w->show(); w->raise(); }   // boutons Plan / Carte réelle
protected:
    void paintEvent(QPaintEvent *) override;
    void mousePressEvent(QMouseEvent *e) override;
    void mouseMoveEvent(QMouseEvent *e) override;
    void mouseReleaseEvent(QMouseEvent *e) override;
    void mouseDoubleClickEvent(QMouseEvent *e) override;
    void wheelEvent(QWheelEvent *e) override;
    void resizeEvent(QResizeEvent *) override
    {
        if (commandes) { commandes->adjustSize(); commandes->move(width() - commandes->width() - 8, 8); }
    }
private:
    QWidget *commandes = nullptr;
    qreal debutEntree = 0;
    QPointF souris{-100, -100};
    void dessinerBoussole(QPainter &p);
    void leaveEvent(QEvent *) override { souris = QPointF(-100, -100); }
    struct Lieu { QString nom; QColor couleur; QPointF plan; double lat, lon; int type; };   // 0 intervention, 1 caserne, 2 balise
    struct Trajet { QString unite; QColor couleur; QVector<QPointF> plan; QVector<QPointF> geo; qreal periode; };
    QVector<Lieu> lieux;
    QVector<Trajet> trajets;
    QPixmap imagePlan, planEchelle;
    bool reelle = false, sombre = false;
    qreal temps = 0;                            // millisecondes (animations)
    qreal debutRadar = -100000;                 // « Localiser la balise » : grand radar pendant 3 s
    QTimer *animation;
    // carte réelle (OpenStreetMap)
    int zoom = 13;
    QPointF centre;                             // centre en coordonnées de tuiles (zoom courant)
    QNetworkAccessManager *reseau = nullptr;
    QHash<QString, QPixmap> tuiles;
    QSet<QString> demandes;
    int erreurs = 0;
    bool glisse = false;
    QPoint dernierePosition;
    QRectF zonePlan() const;
    QPointF versEcran(const Lieu &l) const;
    QPointF versEcranGeo(double lat, double lon) const;
    static QPointF versTuiles(double lat, double lon, int z);
    void centrerSur(double lat, double lon);
    void dessinerTuiles(QPainter &p);
    void dessinerMarqueur(QPainter &p, const QPointF &pos, const Lieu &l, bool etiquette);
    QPointF pointSurTrajet(const QVector<QPointF> &points, qreal t) const;
};

// -----------------------------------------------------------------------------
// Météo de l'en-tête : température actuelle à Tunis et une petite icône animée (soleil, lune,
// nuages, pluie, orage, brouillard, neige). Données Open-Meteo (gratuit, sans clé), mises à
// jour toutes les 15 minutes ; sans connexion, « — °C » s'affiche.
// -----------------------------------------------------------------------------
class MeteoEntete : public QWidget
{
public:
    explicit MeteoEntete(QWidget *parent = nullptr);
    ~MeteoEntete() override;
    QSize sizeHint() const override { return QSize(84, 40); }
protected:
    void paintEvent(QPaintEvent *) override;
private:
    qreal phase = 0;
    static QList<MeteoEntete *> instances;
    static bool connue, jour;
    static double temperature;
    static int code;
    static void demander();
    static QString description();
};

// -----------------------------------------------------------------------------
// Fond qui suit l'heure : un ciel discret derrière les pages (aube rose-orange, jour doré,
// coucher de soleil orange, nuit bleue étoilée) et un soleil / une lune qui traverse le haut
// de la page au fil de la journée. Il se met à jour tout seul et suit le thème clair / sombre.
// -----------------------------------------------------------------------------
class CielHoraire : public QWidget
{
public:
    explicit CielHoraire(QWidget *page);
    static QColor couleurCiel(qreal heure);      // couleur du ciel à une heure (0-24, décimale)
protected:
    void paintEvent(QPaintEvent *) override;
    bool eventFilter(QObject *o, QEvent *e) override;
    void changeEvent(QEvent *e) override;
private:
    QVector<QPointF> etoiles;
    struct Nuage { qreal x, y, echelle, vitesse; };
    QVector<Nuage> nuages;                       // nuages qui dérivent le jour
    QPointF etoileFilante;                       // étoile filante la nuit (position de départ, en fraction)
    qreal debutFilante = -10, prochaineFilante = 4;
    qreal scintillement = 0;                     // temps écoulé (secondes)
    QTimer *minuterie;
};

// -----------------------------------------------------------------------------
// Sélecteur de droit de la fiche : Complet / Lecture / Aucun, pastille qui glisse
// -----------------------------------------------------------------------------
class SelecteurDroit : public QWidget
{
public:
    explicit SelecteurDroit(QWidget *parent = nullptr);
    int droit() const { return 2 - choix; }      // valeur Droit (2 complet, 1 lecture, 0 aucun)
    void definirDroit(int droit, bool anime);
    void definirSombre(bool s) { sombre = s; update(); }
    void definirArabe(bool a) { arabe = a; update(); }
protected:
    void paintEvent(QPaintEvent *) override;
    void mousePressEvent(QMouseEvent *e) override;
private:
    int choix = 0;                               // 0 Complet, 1 Lecture, 2 Aucun
    qreal position = 0;
    bool sombre = false, arabe = false;
    QVariantAnimation *animation;
};

// -----------------------------------------------------------------------------
// Délégué des colonnes Nom / Prénom : texte aux couleurs des braises du fond animé
// -----------------------------------------------------------------------------
class DelegueNomBraise : public QStyledItemDelegate
{
public:
    DelegueNomBraise(QObject *parent, const qreal *phase, bool gras) : QStyledItemDelegate(parent), phase(phase), gras(gras) {}
    void paint(QPainter *p, const QStyleOptionViewItem &option, const QModelIndex &index) const override;
private:
    const qreal *phase;
    bool gras;
};

// =============================================================================
//  FENÊTRE : navigation, thème, langue
// =============================================================================
class QTimer;
class QTableWidget;
class QPushButton;
class Employe;

QT_BEGIN_NAMESPACE
namespace Ui {
class CaserneConnectee;
}
QT_END_NAMESPACE

// =============================================================================
//  Fenêtre principale : toute l'interface est dans caserneconnectee.ui.
//
//  À gauche : barreLaterale = le menu de l'application (boutons btnM...).
//  Elle est masquée sur les pages Login et Mot de passe oublié.
//
//  MODULE EMPLOYÉ : deux interfaces seulement.
//  QStackedWidget principal SWCaserne : 0 PEmploye
//      SWEmploye : 0 Identification (identifiant + mot de passe)
//                  1 Gestion des employés
//                  2 Mot de passe oublié (code à 6 chiffres envoyé par e-mail)
//
//  Les slots ont été créés avec Qt Designer (clic droit -> Aller au slot...) :
//  ils servent uniquement à la navigation entre les pages.
// =============================================================================
class CaserneConnectee : public QMainWindow
{
    Q_OBJECT

public:
    CaserneConnectee(QWidget *parent = nullptr);
    ~CaserneConnectee();

private slots:
    // ---- Page d'identification ----
    void on_btnConnexion_clicked();
    void on_btnMotDePasseOublie_clicked();      // ouvre l'interface « Mot de passe oublié »
    void on_btnRetourConnexion_clicked();       // revient à la page d'identification

    // ---- Menu de l'application (barre latérale) ----
    void on_btnMTableauDeBord_clicked();        // SWEmploye : page 4 (tableau de bord)
    void on_btnMEmploye_clicked();              // SWEmploye : page 3 (CRUD Employé)
    void on_btnMMission_clicked();              // SWCaserne : page 1
    void on_btnMUnite_clicked();                // SWCaserne : page 2
    void on_btnMVehicule_clicked();             // SWCaserne : page 3
    void on_btnMMateriel_clicked();             // SWCaserne : page 4
    void on_btnMFormation_clicked();            // SWCaserne : page 5
    void on_btnQuitter_clicked();               // retour à la page Login (0)


    // ---- Module Employé : en-tête (thème, langue) et formulaire ----
    void on_btnThemeEmploye_clicked();          // mode clair -> sombre -> selon l'horaire
    void on_btnLangueEmploye_clicked();         // français / arabe
    void mettreAJourHorloge();                  // date et heure de l'en-tête

private:
    Ui::CaserneConnectee *ui;
    Employe *employe;            // module Employé (caserneconnectee.h / .cpp)

    // Réglages d'affichage (uniquement l'apparence, aucun traitement de données)
    QString styleClair;          // feuille de style d'origine (celle de Qt Designer)
    bool modeSombre = false;
    bool langueArabe = false;
    QTimer *horloge;

    // Thème : 0 clair, 1 sombre, 2 selon l'horaire (sombre de 19h à 7h, comme la garde de nuit)
    int modeTheme = 2;
    void appliquerTheme(bool sombre, bool anime);
    void mettreAJourBoutonTheme();
    static bool sombreSelonHoraire();

    // Zoom de l'affichage (50 % à 150 %) : boutons − / + de l'en-tête, Ctrl + / Ctrl − / Ctrl 0.
    // Qt applique le facteur au lancement : l'application se relance et le compte connecté
    // retrouve sa session (jeton à usage unique, 20 secondes).
    int zoom = 100;
    QList<QPushButton *> boutonsZoomValeur, boutonsTheme, boutonsLangue;   // un jeu d'outils par en-tête
    void ajouterOutilsEntete(QWidget *avant, bool avecThemeLangue);       // − 100 % + (thème, langue, cloche)
    void ajouterMeteoMusique(QWidget *horloge);                            // météo + musique avant l'horloge
    // Musique douce pendant l'utilisation (boucle) : bouton ♪ de l'en-tête, choix mémorisé
    bool musique = true;
    QList<QPushButton *> boutonsMusique;
    void basculerMusique();
    QList<QPushButton *> boutonsAnimations;
    void basculerAnimations();
    void mettreAJourBoutonsAnimations();
    void mettreAJourBoutonsMusique();
    void changerZoom(int nouveau);
    void reprendreApresZoom(const QString &jeton);

    void animerPanneaux(QWidget *contenu, const QList<QWidget *> &panneaux);   // apparition en fondu
    void transitionDouce(const std::function<void()> &changement);   // fondu enchaîné de toute la fenêtre
    void installerEffetsGlobaux();                    // thème « caserne » animé sur toute l'application
    void animerPageVisible();                         // panneaux + chiffres de la page affichée
    void appliquerCouleursTableau(QTableWidget *table);
    void traduireInterface();                         // applique la langue choisie
    QString versionSombre(const QString &styleClair) const;
};

#endif // CASERNECONNECTEE_H
