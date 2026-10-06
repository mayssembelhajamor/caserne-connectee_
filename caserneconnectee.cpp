// =============================================================================
//  Caserne Connectée — MODULE EMPLOYÉ (identification + interface Employés)
//  Fichier source unique.
// =============================================================================
#include "caserneconnectee.h"
#include "ui_caserneconnectee.h"
#include <QScreen>
#include <QFormLayout>
#include <QDialog>
#include <QSslSocket>
#include <QSslError>
#include <QWheelEvent>
#include <QToolTip>
#include <QNetworkDiskCache>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QNetworkAccessManager>
#include <QTime>
#include <QBoxLayout>
#include <QProcess>
#include <QShortcut>
#include <QSettings>

#include <QCryptographicHash>
#include <QPasswordDigestor>
#include <QRandomGenerator>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QSaveFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QRegularExpression>
#include <QTimer>
#include <QLocale>
#include <QHash>
#include <QRegularExpressionValidator>
#include <QFileDialog>
#include <QMessageBox>
#include <QPainter>
#include <QPainterPath>
#include <QHeaderView>
#include <QCalendarWidget>
#include <QTextCharFormat>
#include <QTableWidget>
#include <QComboBox>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QDateEdit>
#include <QStyledItemDelegate>
#include <QGraphicsOpacityEffect>
#include <QPropertyAnimation>
#include <QVariantAnimation>
#include <QSequentialAnimationGroup>
#include <QParallelAnimationGroup>
#include <QProgressBar>
#include <QStyle>
#include <QAction>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QMouseEvent>
#include <QEasingCurve>
#include <QApplication>
#include <QPdfWriter>
#include <QTextDocument>
#include <QFileInfo>
#include <algorithm>
#include <QGridLayout>
#include <QStackedWidget>
#include <cmath>
#include <memory>
#include <QtConcurrent/QtConcurrentRun>
#include <QFutureWatcher>
#include <QSpinBox>
#include <QDateTime>
#include <QGraphicsDropShadowEffect>
#include <QEvent>
#include <QPointer>
#include <QSet>
#include <QLinearGradient>
#include <QPaintEvent>
#include <QPalette>

// =============================================================================
//  AUTHENTIFICATION
// =============================================================================
static const int ITERATIONS_PBKDF2 = 60000;

Authentification::Authentification(const QString &f) : fichier(f)
{
    if (fichier.isEmpty()) {
        const QString dossier = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        QDir().mkpath(dossier);
        fichier = dossier + "/caserne_employes_v3.json";
    }
    charger();
}

// =============================================================================
// Hachage
// =============================================================================
QByteArray Authentification::hacher(const QString &secret, const QByteArray &sel)
{
    return QPasswordDigestor::deriveKeyPbkdf2(QCryptographicHash::Sha256, secret.toUtf8(), sel, ITERATIONS_PBKDF2, 32);
}

bool Authentification::egales(const QByteArray &a, const QByteArray &b)
{
    if (a.size() != b.size() || a.isEmpty()) return false;
    unsigned char diff = 0;
    for (int i = 0; i < a.size(); ++i) diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}

static QByteArray selAleatoire()
{
    QByteArray sel(16, Qt::Uninitialized);
    for (int i = 0; i < sel.size(); ++i) sel[i] = char(QRandomGenerator::system()->bounded(256));
    return sel;
}

void Authentification::definirMotDePasse(FicheEmploye &f, const QString &motDePasse)
{
    f.sel = selAleatoire();
    f.empreinte = hacher(motDePasse, f.sel);
    f.essaisEchoues = 0;
    f.bloque = false;
}

bool Authentification::motDePasseValide(const QString &mdp, QString *raison)
{
    QString r;
    if (mdp.length() < 8) r = QString::fromUtf8("Le mot de passe doit contenir au moins 8 caractères.");
    else if (!mdp.contains(QRegularExpression("[A-Za-z]")) || !mdp.contains(QRegularExpression("[0-9]")))
        r = QString::fromUtf8("Le mot de passe doit contenir au moins une lettre et un chiffre.");
    if (raison) *raison = r;
    return r.isEmpty();
}

// =============================================================================
// Connexion : le mot de passe saisi est haché avec le sel du compte puis comparé
// =============================================================================
Authentification::Connexion Authentification::connecter(const QString &identifiant, const QString &motDePasse, int *essaisRestants)
{
    if (essaisRestants) *essaisRestants = ESSAIS_MAX;
    FicheEmploye *f = trouverModifiable(identifiant);
    if (!f) return Connexion::IdentifiantInconnu;
    if (f->bloque) { if (essaisRestants) *essaisRestants = 0; return Connexion::CompteBloque; }

    if (egales(hacher(motDePasse, f->sel), f->empreinte)) {
        f->essaisEchoues = 0;
        enregistrer();
        return Connexion::Ok;
    }
    f->essaisEchoues++;
    if (f->essaisEchoues >= ESSAIS_MAX) f->bloque = true;
    if (essaisRestants) *essaisRestants = qMax(0, ESSAIS_MAX - f->essaisEchoues);
    enregistrer();
    return f->bloque ? Connexion::CompteBloque : Connexion::MotDePasseIncorrect;
}

// =============================================================================
// Mot de passe oublié : code à 6 chiffres, 15 minutes, usage unique
// =============================================================================
Authentification::Reinitialisation Authentification::genererCode(const QString &email, QString *code)
{
    FicheEmploye *f = trouverParEmailModifiable(email);
    if (!f) return Reinitialisation::EmailInconnu;
    const QString c = QString("%1").arg(QRandomGenerator::system()->bounded(1000000), 6, 10, QChar('0'));
    f->empreinteCode = hacher(c, f->sel);      // seule l'empreinte du code est gardée
    f->expirationCode = QDateTime::currentDateTimeUtc().addSecs(DUREE_CODE_MINUTES * 60);
    f->codeUtilise = false;
    f->essaisCode = 0;
    enregistrer();
    if (code) *code = c;
    return Reinitialisation::Ok;
}

Authentification::Reinitialisation Authentification::reinitialiser(const QString &email, const QString &code,
                                                                   const QString &nouveauMotDePasse)
{
    FicheEmploye *f = trouverParEmailModifiable(email);
    if (!f) return Reinitialisation::EmailInconnu;
    if (f->empreinteCode.isEmpty()) return Reinitialisation::AucunCode;
    if (f->codeUtilise) return Reinitialisation::CodeDejaUtilise;
    if (QDateTime::currentDateTimeUtc() > f->expirationCode) return Reinitialisation::CodeExpire;
    if (!egales(hacher(code.trimmed(), f->sel), f->empreinteCode)) {
        if (++f->essaisCode >= ESSAIS_CODE_MAX) f->codeUtilise = true;   // trop d'essais : le code est annulé
        enregistrer();
        return f->codeUtilise ? Reinitialisation::CodeDejaUtilise : Reinitialisation::CodeIncorrect;
    }
    if (!motDePasseValide(nouveauMotDePasse)) return Reinitialisation::MotDePasseInvalide;

    definirMotDePasse(*f, nouveauMotDePasse);  // nouveau sel + nouvelle empreinte, compte débloqué
    f->codeUtilise = true;                     // le code ne peut plus servir
    f->empreinteCode.clear();
    enregistrer();
    return Reinitialisation::Ok;
}

QDateTime Authentification::expirationCode(const QString &email) const
{
    const FicheEmploye *f = trouverParEmail(email);
    return f && !f->codeUtilise ? f->expirationCode : QDateTime();
}

// =============================================================================
// Employés et comptes
// =============================================================================
const FicheEmploye *Authentification::trouver(const QString &identifiant) const
{
    for (const FicheEmploye &f : liste)
        if (f.identifiant.compare(identifiant.trimmed(), Qt::CaseInsensitive) == 0) return &f;
    return nullptr;
}

const FicheEmploye *Authentification::trouverParEmail(const QString &email) const
{
    for (const FicheEmploye &f : liste)
        if (f.email.compare(email.trimmed(), Qt::CaseInsensitive) == 0) return &f;
    return nullptr;
}

FicheEmploye *Authentification::trouverModifiable(const QString &identifiant)
{
    return const_cast<FicheEmploye *>(trouver(identifiant));
}

FicheEmploye *Authentification::trouverParEmailModifiable(const QString &email)
{
    return const_cast<FicheEmploye *>(trouverParEmail(email));
}

int Authentification::prochainId() const
{
    int m = 0;
    for (const FicheEmploye &f : liste) m = qMax(m, f.id);
    return m + 1;
}

void Authentification::initialiser(const QVector<FicheEmploye> &fiches)
{
    liste.clear();
    for (FicheEmploye f : fiches) {
        if (f.sel.isEmpty() || f.empreinte.isEmpty()) continue;   // un compte sans mot de passe n'est pas créé
        f.essaisEchoues = 0;
        f.bloque = false;
        if (f.droits.size() != NB_MODULES) f.droits = droitsParDefaut(f.role);
        liste.append(f);
    }
    enregistrer();
}

bool Authentification::ajouter(FicheEmploye fiche, const QString &motDePasse)
{
    if (trouver(fiche.identifiant) || trouverParEmail(fiche.email)) return false;
    fiche.id = prochainId();
    definirMotDePasse(fiche, motDePasse);
    if (fiche.droits.size() != NB_MODULES) fiche.droits = droitsParDefaut(fiche.role);
    liste.append(fiche);
    enregistrer();
    return true;
}

bool Authentification::modifier(const QString &identifiant, const FicheEmploye &n, const QString &nouveauMotDePasse)
{
    FicheEmploye *f = trouverModifiable(identifiant);
    if (!f) return false;
    const FicheEmploye *autre = trouver(n.identifiant);
    if (autre && autre != f) return false;
    autre = trouverParEmail(n.email);
    if (autre && autre != f) return false;

    f->nom = n.nom; f->prenom = n.prenom; f->grade = n.grade; f->fonction = n.fonction; f->statut = n.statut;
    f->role = n.role; f->email = n.email; f->identifiant = n.identifiant; f->habilitations = n.habilitations;
    f->dateEntree = n.dateEntree;
    f->tempsReposCumule = n.tempsReposCumule;
    f->service = n.service.isEmpty() ? f->service : n.service;
    if (n.droits.size() == NB_MODULES) f->droits = n.droits;
    if (!nouveauMotDePasse.isEmpty()) definirMotDePasse(*f, nouveauMotDePasse);
    else { f->essaisEchoues = 0; f->bloque = false; }   // l'administrateur a revu la fiche : compte débloqué
    enregistrer();
    return true;
}

bool Authentification::supprimer(const QString &identifiant)
{
    for (int i = 0; i < liste.size(); ++i)
        if (liste[i].identifiant.compare(identifiant, Qt::CaseInsensitive) == 0) {
            liste.removeAt(i);
            enregistrer();
            return true;
        }
    return false;
}

bool Authentification::remplacerAncienMotDePasse(const QString &identifiant, const QString &ancien,
                                                 const QByteArray &sel, const QByteArray &empreinte)
{
    FicheEmploye *f = trouverModifiable(identifiant);
    if (!f || !egales(hacher(ancien, f->sel), f->empreinte)) return false;
    f->sel = sel;
    f->empreinte = empreinte;
    f->essaisEchoues = 0;
    f->bloque = false;
    enregistrer();
    return true;
}

int Authentification::nombreComptesBloques() const
{
    int n = 0;
    for (const FicheEmploye &f : liste) n += f.bloque ? 1 : 0;
    return n;
}

int Authentification::nombreAdministrateurs() const
{
    int n = 0;
    for (const FicheEmploye &f : liste) n += f.role == "Administrateur" ? 1 : 0;
    return n;
}

// =============================================================================
// Matrice des droits : rôle x module -> Complet / Lecture / Aucun
// =============================================================================
QStringList Authentification::roles()
{
    return {"Administrateur", "Chef de garde", QString::fromUtf8("Opérateur du standard"), "Agent"};
}

QString Authentification::cleModule(int module)
{
    static const char *cles[] = {"Employes", "Missions", "Unites", "Vehicules", "Materiel", "Formation", "Tableau"};
    return module >= 0 && module < NB_MODULES ? QString(cles[module]) : QString();
}

// Droits proposés selon le rôle (l'administrateur les ajuste ensuite dans la fiche)
//  - administrateur (officier responsable) : gère les employés, les comptes et les droits -> tout ;
//  - chef de garde : supervise l'effectif de garde (Employés en lecture), attribue les unités
//    et clôture les missions (Missions et Unités complets) ;
//  - opérateur du standard : reçoit les appels et crée les missions (Missions complet),
//    consulte l'effectif de garde, les unités et les véhicules disponibles ;
//  - agent (pompier, chauffeur, recrue) : consulte les informations qui le concernent ;
//    sans droit sur Employés, sa connexion est refusée jusqu'à ce que l'administrateur lui en donne un.
QVector<int> Authentification::droitsParDefaut(const QString &role)
{
    //                 Employés       Missions       Unités         Véhicules      Matériel       Formation      Tableau de bord
    if (role == "Administrateur")
        return {DROIT_COMPLET, DROIT_COMPLET, DROIT_COMPLET, DROIT_COMPLET, DROIT_COMPLET, DROIT_COMPLET, DROIT_COMPLET};
    if (role == "Chef de garde")
        return {DROIT_LECTURE, DROIT_COMPLET, DROIT_COMPLET, DROIT_LECTURE, DROIT_LECTURE, DROIT_LECTURE, DROIT_LECTURE};
    if (role == QString::fromUtf8("Opérateur du standard"))
        return {DROIT_LECTURE, DROIT_COMPLET, DROIT_LECTURE, DROIT_LECTURE, DROIT_AUCUN,   DROIT_AUCUN,   DROIT_LECTURE};
    return     {DROIT_AUCUN,   DROIT_LECTURE, DROIT_AUCUN,   DROIT_LECTURE, DROIT_LECTURE, DROIT_LECTURE, DROIT_LECTURE};
}

Droit Authentification::droit(const FicheEmploye &compte, int module) const
{
    if (module < 0 || module >= NB_MODULES) return DROIT_AUCUN;
    if (compte.role == "Administrateur" && module == M_EMPLOYES) return DROIT_COMPLET;   // gestion des comptes : jamais retirée
    const QVector<int> d = compte.droits.size() == NB_MODULES ? compte.droits : droitsParDefaut(compte.role);
    return Droit(qBound(0, d[module], 2));
}

// =============================================================================
// Enregistrement (fichier JSON local)
// =============================================================================
void Authentification::charger()
{
    QFile f(fichier);
    if (!f.open(QIODevice::ReadOnly)) return;
    const QJsonObject racine = QJsonDocument::fromJson(f.readAll()).object();

    liste.clear();
    for (const QJsonValue &v : racine.value("employes").toArray()) {
        const QJsonObject o = v.toObject();
        FicheEmploye e;
        e.id = o.value("id").toInt();
        e.nom = o.value("nom").toString();
        e.prenom = o.value("prenom").toString();
        e.grade = o.value("grade").toString();
        e.fonction = o.value("fonction").toString();
        e.statut = o.value("statut").toString();
        e.service = o.value("service").toString();
        e.role = o.value("role").toString();
        e.email = o.value("email").toString();
        e.identifiant = o.value("identifiant").toString();
        e.habilitations = o.value("habilitations").toString();
        e.dateEntree = QDate::fromString(o.value("dateEntree").toString(), Qt::ISODate);
        e.tempsReposCumule = o.value("tempsReposCumule").toInt();
        e.sel = QByteArray::fromBase64(o.value("sel").toString().toLatin1());
        e.empreinte = QByteArray::fromBase64(o.value("empreinte").toString().toLatin1());
        e.essaisEchoues = o.value("essaisEchoues").toInt();
        e.bloque = o.value("bloque").toBool();
        e.empreinteCode = QByteArray::fromBase64(o.value("empreinteCode").toString().toLatin1());
        e.expirationCode = QDateTime::fromString(o.value("expirationCode").toString(), Qt::ISODate);
        e.codeUtilise = o.value("codeUtilise").toBool(true);
        e.essaisCode = o.value("essaisCode").toInt();
        for (const QJsonValue &d : o.value("droits").toArray()) e.droits.append(qBound(0, d.toInt(), 2));
        if (e.droits.size() == M_TABLEAU)                 // fichier d'avant le Tableau de bord : droit ajouté selon le rôle
            e.droits.append(droitsParDefaut(e.role)[M_TABLEAU]);
        if (e.droits.size() != NB_MODULES) e.droits = droitsParDefaut(e.role);
        if (!e.identifiant.isEmpty() && !e.empreinte.isEmpty()) liste.append(e);
    }
}

void Authentification::enregistrer() const
{
    QJsonArray employes;
    for (const FicheEmploye &e : liste) {
        QJsonObject o;
        o["id"] = e.id;
        o["nom"] = e.nom;
        o["prenom"] = e.prenom;
        o["grade"] = e.grade;
        o["fonction"] = e.fonction;
        o["statut"] = e.statut;
        o["service"] = e.service;
        o["role"] = e.role;
        o["email"] = e.email;
        o["identifiant"] = e.identifiant;
        o["habilitations"] = e.habilitations;
        o["dateEntree"] = e.dateEntree.toString(Qt::ISODate);
        o["tempsReposCumule"] = e.tempsReposCumule;
        o["sel"] = QString::fromLatin1(e.sel.toBase64());
        o["empreinte"] = QString::fromLatin1(e.empreinte.toBase64());     // empreinte uniquement, jamais le mot de passe
        o["essaisEchoues"] = e.essaisEchoues;
        o["bloque"] = e.bloque;
        o["empreinteCode"] = QString::fromLatin1(e.empreinteCode.toBase64());
        o["expirationCode"] = e.expirationCode.toString(Qt::ISODate);
        o["codeUtilise"] = e.codeUtilise;
        o["essaisCode"] = e.essaisCode;
        QJsonArray droits;
        for (int d : e.droits) droits.append(d);
        o["droits"] = droits;
        employes.append(o);
    }
    QJsonObject racine;
    racine["employes"] = employes;

    QSaveFile f(fichier);
    if (!f.open(QIODevice::WriteOnly)) return;
    f.write(QJsonDocument(racine).toJson(QJsonDocument::Indented));
    f.commit();
}

// =============================================================================
//  MODULE EMPLOYÉ
// =============================================================================
// =============================================================================
//  MODULE EMPLOYÉ — identification, mot de passe oublié, gestion des employés,
//  droits d'accès (voir caserneconnectee.h pour la liste des fonctionnalités)
// =============================================================================

QString traduireTexte(const QString &francais);   // traduction en arabe (caserneconnectee.cpp)

void jouerSonIntro();   // son de l'intro (défini à la fin du fichier)
static QIcon iconeExcel();   // icône des boutons d'export Excel
void jouerMusique(bool marche);   // musique douce en boucle (définie à la fin du fichier)

// Partie d'un widget réellement visible à l'écran (coordonnées du widget) : sert à placer
// les messages animés et les notifications là où on les voit, même si la fenêtre dépasse l'écran.
static QRect zoneVisible(QWidget *w)
{
    QRect visible = w->rect();
    if (QScreen *ecran = w->screen()) {
        const QRect global(w->mapToGlobal(QPoint(0, 0)), w->size());
        const QRect commun = global.intersected(ecran->availableGeometry());
        if (!commun.isEmpty()) visible = QRect(w->mapFromGlobal(commun.topLeft()), commun.size());
    }
    return visible;
}

// Comptes de démonstration créés au premier lancement : chacun a son propre mot de passe.
// Seuls le sel et l'empreinte PBKDF2 figurent ici : aucun mot de passe n'est écrit en clair,
// ni dans le code ni dans le fichier de données.
struct EmpreinteDemo { const char *identifiant, *sel, *empreinte; };
static const EmpreinteDemo EMPREINTES_DEMO[] = {
        {"h.boukhris", "NSXqnnaveFfjvmyUPxzvuA==", "49A/qhlcjvDV6nEwNlp9jVIXcXUbT/2/DhoZWcZct2E="},
        {"l.bensalah", "VGtdciTKpPhoQOTKi/velQ==", "LA7kI4fXf7GQHTzBplmCo/0NI7qlTFdAvBTWFG5h5mQ="},
        {"m.karray", "oXAawwHkgIq91jT4iEQ1Dw==", "XAFws8v7YZ4oi1LPrXtm4i3DhEV1bmd+5auwhFZS260="},
        {"s.larbi", "WeWZ4B5flEI/UIbpVON9AA==", "AsrG8Zii50UEFlf+suh90SYB9ytTDePQ9MCvNt0dhYE="},
        {"r.nasri", "l3z6WCt3+relGsgj+8PmtA==", "wc77NuUyxzJiF+sybV26zZb1vmxGDxuxbDwL6elFUlE="},
        {"a.trabelsi", "UKTjgeVAy+hlxmUNDFPazg==", "sxiBmSlx9twhS7j7c4F8uq+dee99ElG5X1FqaYd6S+A="},
        {"k.hamdi", "iyMs23nbh6I/Mvjgq9uFhQ==", "18BlbszgVIwTOf5A1E3hqB7APiTIwv81RugbSQ4GQ/w="},
        {"s.gharbi", "AwRcQONos1D4I9r8VKXD4w==", "xkmwjWjrijLI2ID1s3wW2CtULAzE0fSY7vTaLR74vIE="},
        {"k.ayari", "vC/XSJex4ImOuwBl2xRAhQ==", "EotTfzrnym5XqnY+Qb2X/J/m/AoB3Vla9GPy1vxhUVE="},
};

static const int ROLE_IDENTIFIANT = Qt::UserRole + 50;   // identifiant du compte, rangé dans la colonne ID
static const int ROLE_FRANCAIS = Qt::UserRole + 30;      // texte français d'une case (traduction)

// La carte tremble de gauche à droite (saisie refusée)
static void secouer(QWidget *w)
{
    if (w->property("secousseEnCours").toBool()) return;
    w->setProperty("secousseEnCours", true);
    QVariantAnimation *a = new QVariantAnimation(w);
    a->setDuration(420);
    a->setStartValue(0.0);
    a->setEndValue(1.0);
    const QPoint origine = w->pos();
    QObject::connect(a, &QVariantAnimation::valueChanged, w, [w, origine](const QVariant &v) {
        const qreal t = v.toReal();
        w->move(origine + QPoint(int(10 * std::sin(t * 8 * M_PI) * (1 - t)), 0));
    });
    QObject::connect(a, &QVariantAnimation::finished, w, [w, origine]() {
        w->move(origine);
        w->setProperty("secousseEnCours", false);
    });
    a->start(QAbstractAnimation::DeleteWhenStopped);
}

// Avec une feuille de style sur le tableau, Qt ignore la couleur de fond des cases :
// ce délégué la peint lui-même (cases J / N / R du planning).
class FondCasesEmploye : public QStyledItemDelegate
{
public:
    using QStyledItemDelegate::QStyledItemDelegate;
    void paint(QPainter *p, const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        const QVariant fond = index.data(Qt::BackgroundRole);
        if (fond.canConvert<QBrush>() && fond.value<QBrush>().style() != Qt::NoBrush)
            p->fillRect(option.rect.adjusted(3, 3, -3, -3), fond.value<QBrush>());
        QStyledItemDelegate::paint(p, option, index);
    }
};

// « Hédi » -> « hedi » (identifiant et e-mail construits à partir du nom)
static QString simplifier(QString s)
{
    s = s.normalized(QString::NormalizationForm_D).toLower();
    s.remove(QRegularExpression("[^a-z]"));
    return s;
}

// Texte français d'une liste déroulante (même quand l'interface est en arabe)
static QString texteCombo(const QComboBox *cb)
{
    const QVariant fr = cb->currentData(ROLE_FRANCAIS);
    return fr.isValid() ? fr.toString() : cb->currentText();
}

static void choisirDansCombo(QComboBox *cb, const QString &fr)
{
    for (int i = 0; i < cb->count(); ++i) {
        const QString t = cb->itemData(i, ROLE_FRANCAIS).isValid() ? cb->itemData(i, ROLE_FRANCAIS).toString() : cb->itemText(i);
        if (t == fr) { cb->setCurrentIndex(i); return; }
    }
}

static QString serviceParDefaut(const QString &statut)
{
    if (statut == "En repos") return "Repos : 0h / 11h";
    if (statut == QString::fromUtf8("En congé")) return QString::fromUtf8("—");
    return "0h00 / 12h";
}

static bool emailValide(const QString &email)
{
    static const QRegularExpression forme("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    return forme.match(email).hasMatch();
}

// Change le texte d'un bouton en gardant sa version française (pour la traduction)
static void texteBouton(QPushButton *b, const QString &francais, bool arabe)
{
    b->setProperty("texteFrancais", francais);
    b->setText(arabe ? traduireTexte(francais) : francais);
}

QString Employe::t(const char *francais) const
{
    const QString fr = QString::fromUtf8(francais);
    return langueArabe ? traduireTexte(fr) : fr;
}

// =============================================================================
// Construction : données, réglages de la page, connexion, mot de passe oublié, droits
// =============================================================================
// Icône d'œil dessinée (ouvert : mot de passe visible ; barré : mot de passe masqué)
static QIcon iconeOeil(bool ouvert)
{
    QPixmap image(40, 40);
    image.fill(Qt::transparent);
    QPainter p(&image);
    p.setRenderHint(QPainter::Antialiasing);
    const QColor couleur(ouvert ? "#E4491F" : "#8B99A6");
    p.setPen(QPen(couleur, 2.6, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    QPainterPath contour;
    contour.moveTo(5, 20);
    contour.quadTo(20, 6, 35, 20);
    contour.quadTo(20, 34, 5, 20);
    p.drawPath(contour);
    p.setBrush(couleur);
    p.drawEllipse(QPointF(20, 20), 4.6, 4.6);
    if (!ouvert) {
        p.setPen(QPen(couleur, 2.8, Qt::SolidLine, Qt::RoundCap));
        p.drawLine(QPointF(8, 33), QPointF(32, 7));
    }
    return QIcon(image);
}

// Ajoute l'œil à un champ mot de passe (et, s'il y en a un, à son champ de confirmation)
static void ajouterOeil(QLineEdit *champ, QLineEdit *confirmation = nullptr)
{
    QAction *oeil = champ->addAction(iconeOeil(false), QLineEdit::TrailingPosition);
    oeil->setToolTip(QString::fromUtf8("Afficher / masquer le mot de passe"));
    QObject::connect(oeil, &QAction::triggered, champ, [champ, confirmation, oeil]() {
        const bool visible = champ->echoMode() == QLineEdit::Password;
        champ->setEchoMode(visible ? QLineEdit::Normal : QLineEdit::Password);
        if (confirmation) confirmation->setEchoMode(champ->echoMode());
        oeil->setIcon(iconeOeil(visible));
    });
    // le champ est vidé ou remasqué ailleurs (connexion, déconnexion) : l'icône suit
    QObject::connect(champ, &QLineEdit::textChanged, oeil, [champ, oeil]() {
        oeil->setIcon(iconeOeil(champ->echoMode() == QLineEdit::Normal));
    });
}

Employe::Employe(Ui::CaserneConnectee *ui, QWidget *fenetre) : QObject(fenetre), ui(ui), fenetre(fenetre)
{
    preparerPage();

    // Mot de passe : jamais affiché dans la fiche ; les cases n'apparaissent qu'en mode
    // ajout ou modification. Indicateur de sécurité en direct + œil pour afficher.
    ui->cadreMotDePasseEmploye->hide();
    connect(ui->txtMotDePasseEmploye, &QLineEdit::textChanged, this, &Employe::evaluerMotDePasse);
    connect(ui->txtConfirmationMotDePasseEmploye, &QLineEdit::textChanged, this, &Employe::evaluerMotDePasse);
    ajouterOeil(ui->txtMotDePasseEmploye, ui->txtConfirmationMotDePasseEmploye);
    evaluerMotDePasse();

    // Boutons de la page (créés dans Qt Designer, reliés ici)
    connect(ui->btnAjouterEmploye, &QPushButton::clicked, this, &Employe::ajouterEmploye);
    connect(ui->btnModifierEmploye, &QPushButton::clicked, this, &Employe::modifierCompte);
    connect(ui->btnSupprimerEmploye, &QPushButton::clicked, this, &Employe::supprimerEmploye);
    connect(ui->btnAnnulerEmploye, &QPushButton::clicked, this, &Employe::annuler);
    connect(ui->btnPhotoEmploye, &QPushButton::clicked, this, &Employe::choisirPhoto);
    connect(ui->btnNotificationsEmploye, &QPushButton::clicked, this, &Employe::notifications);
    connect(ui->tblEmploye, &QTableWidget::cellClicked, this, &Employe::afficherEmploye);

    // Métiers basiques : recherche (pendant la saisie), tri, export PDF
    ui->txtRechercheEmploye->setClearButtonEnabled(true);
    connect(ui->txtRechercheEmploye, &QLineEdit::textChanged, this, &Employe::rechercher);
    connect(ui->txtRechercheEmploye, &QLineEdit::returnPressed, this, &Employe::rechercherBouton);
    connect(ui->btnRechercherEmploye, &QPushButton::clicked, this, &Employe::rechercherBouton);
    connect(ui->btnTrierEmploye, &QPushButton::clicked, this, &Employe::trier);
    connect(ui->btnExporterPdfEmploye, &QPushButton::clicked, this, &Employe::exporterPdf);
    // boutons « Excel » placés juste à côté des boutons PDF (liste des employés et planning)
    auto boutonExcel = [this](QPushButton *voisin, const QString &texte, const QString &nom) {
        QPushButton *b = new QPushButton(texte);
        b->setObjectName(nom);
        b->setIcon(iconeExcel());
        b->setIconSize(QSize(16, 16));
        b->setCursor(Qt::PointingHandCursor);
        b->setToolTip(QString::fromUtf8("Enregistrer dans un classeur Excel (.xlsx)"));
        for (QBoxLayout *l : this->fenetre->findChildren<QBoxLayout *>())
            if (l->indexOf(voisin) >= 0) { l->insertWidget(l->indexOf(voisin) + 1, b); break; }
        return b;
    };
    connect(boutonExcel(ui->btnExporterPdfEmploye, "Excel", "btnExporterExcelEmploye"), &QPushButton::clicked, this, &Employe::exporterExcel);
    connect(boutonExcel(ui->btnTelechargerPlanningEmploye, "Excel", "btnTelechargerExcelPlanning"), &QPushButton::clicked,
            this, &Employe::telechargerPlanningExcel);

    // Planning des gardes : recalculé quand on change le début, la durée ou l'effectif ;
    // téléchargement en PDF autorisé à tous ceux qui voient l'interface Employés
    connect(ui->btnGenererPlanningEmploye, &QPushButton::clicked, this, &Employe::genererPlanningBouton);
    connect(ui->btnTelechargerPlanningEmploye, &QPushButton::clicked, this, &Employe::telechargerPlanningPdf);
    connect(ui->datePlanningEmploye, &QDateEdit::dateChanged, this, &Employe::genererPlanning);
    connect(ui->cbDureePlanningEmploye, &QComboBox::currentIndexChanged, this, &Employe::genererPlanning);
    connect(ui->spinEffectifPlanningEmploye, &QSpinBox::valueChanged, this, &Employe::genererPlanning);
    connect(ui->txtNomEmploye, &QLineEdit::textEdited, this, &Employe::identifiantDepuisNom);
    connect(ui->txtPrenomEmploye, &QLineEdit::textEdited, this, &Employe::identifiantDepuisNom);

    // Page d'identification : Entrée passe au mot de passe puis valide ; le message s'efface à la saisie
    connect(ui->txtIdentifiant, &QLineEdit::returnPressed, ui->txtMotDePasse, qOverload<>(&QWidget::setFocus));
    connect(ui->txtMotDePasse, &QLineEdit::returnPressed, ui->btnConnexion, &QPushButton::click);
    // Œil dans les champs mot de passe : cliquer pour voir ce qu'on a tapé (œil barré = masqué)
    ajouterOeil(ui->txtMotDePasse);
    ajouterOeil(ui->txtNouveauMotDePasseOublie, ui->txtConfirmationOublie);
    connect(ui->txtIdentifiant, &QLineEdit::textEdited, this, [this]() { messageConnexion(QString()); });
    connect(ui->txtMotDePasse, &QLineEdit::textEdited, this, [this]() { messageConnexion(QString()); });

    // Page « Mot de passe oublié »
    connect(ui->btnEnvoyerCode, &QPushButton::clicked, this, &Employe::envoyerCode);
    connect(ui->btnRenvoyerCode, &QPushButton::clicked, this, &Employe::envoyerCode);
    connect(ui->btnValiderCode, &QPushButton::clicked, this, &Employe::validerNouveauMotDePasse);
    connect(ui->txtEmailOublie, &QLineEdit::returnPressed, this, &Employe::envoyerCode);
    connect(ui->txtConfirmationOublie, &QLineEdit::returnPressed, this, &Employe::validerNouveauMotDePasse);
    ui->txtCodeOublie->setValidator(new QRegularExpressionValidator(QRegularExpression("\\d{0,6}"), ui->txtCodeOublie));
    QFont police = ui->txtCodeOublie->font();
    police.setLetterSpacing(QFont::AbsoluteSpacing, 10);
    ui->txtCodeOublie->setFont(police);
    ui->txtEmailOublie->setLayoutDirection(Qt::LeftToRight);
    minuteurCode = new QTimer(this);
    minuteurCode->setInterval(1000);
    connect(minuteurCode, &QTimer::timeout, this, &Employe::mettreAJourMinuteur);
    fondBraisesOublie = new FondBraises(ui->PMotDePasseOublie);

    // Messages qui changent pendant l'utilisation : la traduction automatique ne les touche pas
    for (QLabel *l : {ui->lblMessageConnexion, ui->lblMessageOublie, ui->lblMinuteurCode, ui->lblTexteOublie,
                      ui->lbl158, ui->lbl161, ui->lblCentreAnneauEmploye, ui->lblValeur1Employe, ui->lblValeur2Employe,
                      ui->lblValeur3Employe, ui->lblValeur4Employe, ui->lbl148, ui->lbl150, ui->lbl152, ui->lbl154,
                      ui->lblValeurFonction5Employe, ui->lblReposServiceEmploye,
                      ui->lblResumePlanningEmploye, ui->lblAlertePlanningEmploye})
        l->setProperty("dynamique", true);
    ui->lblMessageConnexion->hide();
    ui->lblMessageOublie->hide();
    ui->lblLectureSeuleEmploye->hide();

    // Droits : chaque bouton déclare le module auquel il appartient et s'il modifie des données
    for (QPushButton *b : {ui->btnAjouterEmploye, ui->btnModifierEmploye, ui->btnSupprimerEmploye,
                           ui->btnPhotoEmploye, ui->btnGenererPlanningEmploye}) {
        b->setProperty("module", "Employes");
        b->setProperty("action", "ecriture");
    }
    ui->btnMEmploye->setProperty("module", "Employes");

    // Fiche : un sélecteur Complet / Lecture / Aucun par module (droits propres à l'employé)
    static const char *modules[] = {"Employés", "Missions", "Unités", "Véhicules", "Matériel", "Formation", "Tableau de bord"};
    for (int m = 0; m < NB_MODULES; ++m) {
        QLabel *nom = new QLabel(QString::fromUtf8(modules[m]));
        nom->setProperty("variante", "moduleAcces");
        SelecteurDroit *choix = new SelecteurDroit;
        const int rangee = m == M_TABLEAU ? 0 : m + 1;   // même ordre que le menu : Tableau de bord en tête
        ui->grilleAccesEmploye->addWidget(nom, rangee, 0);
        ui->grilleAccesEmploye->addWidget(choix, rangee, 1);
        selecteurs.append(choix);
    }
    ui->grilleAccesEmploye->setColumnStretch(1, 1);
    // Choisir le rôle propose ses droits (les sélecteurs glissent vers leur nouvelle valeur)
    connect(ui->cbRoleEmploye, &QComboBox::activated, this, [this]() {
        afficherDroitsFiche(Authentification::droitsParDefaut(texteCombo(this->ui->cbRoleEmploye)), true);
        activerSelecteurs();
    });
    // Choisir le poste propose le rôle correspondant (sauf pour un administrateur) :
    // chef de garde -> Chef de garde, standardiste -> Opérateur du standard, pompier / chauffeur -> Agent
    connect(ui->cbFonctionEmploye, &QComboBox::activated, this, [this]() {
        if (!this->ui->cbRoleEmploye->isEnabled() || texteCombo(this->ui->cbRoleEmploye) == "Administrateur") return;
        const QString poste = texteCombo(this->ui->cbFonctionEmploye);
        QString role;
        if (poste == "Chef de garde") role = "Chef de garde";
        else if (poste == "Standardiste") role = QString::fromUtf8("Opérateur du standard");
        else if (poste == "Chauffeur" || poste == QString::fromUtf8("Pompier opérationnel")) role = "Agent";
        if (role.isEmpty() || role == texteCombo(this->ui->cbRoleEmploye)) return;
        choisirDansCombo(this->ui->cbRoleEmploye, role);
        afficherDroitsFiche(Authentification::droitsParDefaut(role), true);
        activerSelecteurs();
    });

    // Noms des employés aux couleurs des braises du fond animé (reflet qui défile lentement)
    ui->tblEmploye->setItemDelegateForColumn(1, new DelegueNomBraise(ui->tblEmploye, &phaseBraise, true));
    ui->tblEmploye->setItemDelegateForColumn(2, new DelegueNomBraise(ui->tblEmploye, &phaseBraise, false));
    QTimer *reflet = new QTimer(this);
    connect(reflet, &QTimer::timeout, this, [this]() {
        phaseBraise += 3.6;
        if (!fenetreActive(this->ui->tblEmploye) || animationsLegeres()) return;   // arrière-plan ou mode léger : pas de reflet
        QTableWidget *effectif = this->ui->tblEffectifDashboard;   // noms du tableau de bord aux couleurs des braises
        if (effectif->isVisible())
            effectif->viewport()->update(QRect(0, 0, effectif->columnWidth(0), effectif->viewport()->height()));
        QTableWidget *t = this->ui->tblEmploye;
        if (!t->isVisible() || t->rowCount() == 0) return;
        const int x = t->columnViewportPosition(1), largeur = t->columnWidth(1) + t->columnWidth(2);
        t->viewport()->update(QRect(x, 0, largeur, t->viewport()->height()));
    });
    reflet->start(140);

    // Menu (barre latérale) : la navigation est faite par les slots on_btnM..._clicked() de la fenêtre
    // (créés avec Qt Designer, comme le demande le guide d'intégration).
    // boutons de l'interface d'un module : la vraie action sera reliée par l'équipe
    for (QPushButton *b : {ui->btnAjouterModule, ui->btnModifierModule, ui->btnSupprimerModule})
        connect(b, &QPushButton::clicked, this, [this, b]() {
            afficherNotification(this->ui->lblTitreModule->text(),
                                 t("« %1 » autorisé pour votre compte : l'action sera reliée par l'équipe du module.").arg(b->text().trimmed()),
                                 ":/images/icones/tuile_shield_clair.png");
        });
    for (QLabel *l : {ui->lblTitreModule, ui->lblNomModule, ui->lblTexteModule, ui->lblLectureSeuleModule, ui->lblNonDeveloppeModule})
        l->setProperty("dynamique", true);
    // les autres modules ne sont pas encore développés : info-bulle dans le menu
    for (QPushButton *b : {ui->btnMMission, ui->btnMUnite, ui->btnMVehicule, ui->btnMMateriel, ui->btnMFormation})
        b->setToolTip(QString::fromUtf8("Module non développé"));
    ui->tblModule->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    preparerTableauDeBord();
    preparerAccueilModules();
    chargerEmployes();
    installerEffets();
    animerConnexion();            // la page d'identification s'anime dès le lancement
}

// =============================================================================
// Données : fiches employés + comptes (Authentification) <-> tableau de l'interface
// =============================================================================
void Employe::chargerEmployes()
{
    if (auth.estVide()) {
        // Premier lancement : les employés du tableau de Qt Designer deviennent des comptes
        static const char *postes[] = {"Chef de garde", "Agent administratif", "Pompier opérationnel", "Pompier opérationnel",
                                       "Pompier opérationnel", "Chef de garde", "Chauffeur", "Standardiste", "Standardiste"};
        QTableWidget *t = ui->tblEmploye;
        QVector<FicheEmploye> fiches;
        auto texte = [t](int l, int c) { return t->item(l, c) ? t->item(l, c)->text().trimmed() : QString(); };
        for (int l = 0; l < t->rowCount(); ++l) {
            FicheEmploye f;
            f.id = texte(l, 0).toInt();
            f.nom = texte(l, 1);
            f.prenom = texte(l, 2);
            f.grade = texte(l, 3);
            f.statut = texte(l, 4).remove(QString::fromUtf8("●")).trimmed();
            f.service = texte(l, 6);
            f.role = texte(l, 7);
            f.fonction = QString::fromUtf8(l < 9 ? postes[l] : "Pompier opérationnel");
            const int ans = texte(l, 5).section(' ', 0, 0).toInt();
            f.dateEntree = QDate::currentDate().addYears(-ans).addMonths(-2);
            static const int repos[] = {9, 6, 4, 2, 7, 11, 3, 5, 0};
            f.tempsReposCumule = l < 9 ? repos[l] : 0;
            f.identifiant = simplifier(f.prenom).left(1) + "." + simplifier(f.nom);
            f.email = simplifier(f.prenom) + "." + simplifier(f.nom) + "@protectioncivile.tn";
            fiches.append(f);
        }
        for (FicheEmploye &f : fiches)
            for (const EmpreinteDemo &d : EMPREINTES_DEMO)
                if (f.identifiant == QLatin1String(d.identifiant)) {
                    f.sel = QByteArray::fromBase64(d.sel);
                    f.empreinte = QByteArray::fromBase64(d.empreinte);
                }
        auth.initialiser(fiches);
    } else {
        // Fichier créé par une ancienne version (mot de passe commun « Caserne@2026 ») :
        // chaque compte de démonstration reçoit son propre mot de passe.
        for (const EmpreinteDemo &d : EMPREINTES_DEMO)
            auth.remplacerAncienMotDePasse(QLatin1String(d.identifiant), QString::fromUtf8("Caserne@2026"),
                                           QByteArray::fromBase64(d.sel), QByteArray::fromBase64(d.empreinte));
    }
    remplirTableau();
}

void Employe::remplirTableau(const QString &identifiantSelectionne)
{
    QTableWidget *t = ui->tblEmploye;
    t->setRowCount(0);
    const QVector<FicheEmploye> &liste = auth.employes();
    const QVector<int> ordre = ordreAffichage();          // employés trouvés, dans l'ordre du tri
    t->setRowCount(ordre.size());
    ligneAffichee = -1;
    for (int l = 0; l < ordre.size(); ++l) {
        remplirLigne(l, liste[ordre[l]]);
        if (liste[ordre[l]].identifiant == identifiantSelectionne) ligneAffichee = l;
    }
    preparerPhotos();
    // l'employé de la fiche n'est plus dans la liste affichée : on affiche le premier trouvé
    if (ligneAffichee < 0 && !ordre.isEmpty() && !modeAjout) afficherEmploye(0, 0);
    if (ligneAffichee < 0 && !ordre.isEmpty()) ligneAffichee = 0;
    mettreAJourCompteurs();
    emit tableauModifie();
}

void Employe::remplirLigne(int l, const FicheEmploye &f)
{
    QTableWidget *t = ui->tblEmploye;
    auto cellule = [&](int c, const QString &fr) {
        QTableWidgetItem *it = new QTableWidgetItem(langueArabe ? traduireTexte(fr) : fr);
        it->setData(ROLE_FRANCAIS, fr);
        t->setItem(l, c, it);
        return it;
    };
    QFont gras = t->font();
    gras.setBold(true);

    cellule(0, QString::number(f.id))->setData(ROLE_IDENTIFIANT, f.identifiant);
    cellule(1, f.nom);
    cellule(2, f.prenom);
    cellule(3, f.grade);

    // Statut : pastille colorée (vert disponible, ambre en intervention, gris repos / congé)
    QTableWidgetItem *statut = cellule(4, QString::fromUtf8("● ") + f.statut);
    statut->setFont(gras);
    const bool intervention = f.statut == "En intervention", disponible = f.statut == "Disponible";
    statut->setForeground(QColor(disponible ? QColor(30, 158, 99) : intervention ? QColor(212, 138, 18) : QColor(122, 136, 150)));

    const int ans = f.dateEntree.isValid() ? int(f.dateEntree.daysTo(QDate::currentDate()) / 365.25) : 0;
    cellule(5, ans < 1 ? QString("Nouveau") : QString("%1 %2").arg(ans).arg(ans == 1 ? "an" : "ans"));

    QTableWidgetItem *service = cellule(6, f.service.isEmpty() ? QString::fromUtf8("—") : f.service);
    if (intervention) { service->setFont(gras); service->setForeground(QColor(224, 142, 11)); }
    else service->setForeground(disponible ? QColor(69, 80, 92) : QColor(122, 136, 150));

    // Rôle : cadenas rouge si le compte est bloqué (5 essais échoués)
    QTableWidgetItem *role = cellule(7, f.role);
    if (f.bloque) {
        role->setIcon(QIcon(":/images/icones/tuile_lock_rouge.png"));
        role->setForeground(QColor(217, 54, 54));
        role->setFont(gras);
        role->setToolTip(QString::fromUtf8("Compte bloqué après 5 essais échoués"));
    }
}

QString Employe::identifiantLigne(int ligne) const
{
    QTableWidgetItem *it = ui->tblEmploye->item(ligne, 0);
    return it ? it->data(ROLE_IDENTIFIANT).toString() : QString();
}

FicheEmploye Employe::ficheDuFormulaire() const
{
    FicheEmploye f;
    f.nom = ui->txtNomEmploye->text().trimmed();
    f.prenom = ui->txtPrenomEmploye->text().trimmed();
    f.grade = texteCombo(ui->cbGradeEmploye);
    f.fonction = texteCombo(ui->cbFonctionEmploye);
    f.statut = texteCombo(ui->cbStatutEmploye);
    f.role = texteCombo(ui->cbRoleEmploye);
    f.dateEntree = ui->dateEntreeEmploye->date();
    f.email = ui->txtEmailEmploye->text().trimmed().toLower();
    f.identifiant = ui->txtIdentifiantEmploye->text().trimmed().toLower();
    f.habilitations = ui->txtHabilitationsEmploye->text().trimmed();
    f.tempsReposCumule = ui->spinReposEmploye->value();
    for (SelecteurDroit *choix : selecteurs) f.droits.append(choix->droit());
    if (f.role == "Administrateur") f.droits[M_EMPLOYES] = DROIT_COMPLET;
    return f;
}

// Contrôle de saisie : champs obligatoires, formats, doublons, mot de passe
bool Employe::verifierFormulaire(const FicheEmploye &f, const QString &ancienIdentifiant, bool motDePasseObligatoire)
{
    QString erreur;
    QWidget *champ = nullptr;
    static const QRegularExpression formeIdentifiant("^[a-z0-9._-]{3,30}$");
    const FicheEmploye *memeIdentifiant = auth.trouver(f.identifiant);
    const FicheEmploye *memeEmail = auth.trouverParEmail(f.email);
    const QString mdp = ui->txtMotDePasseEmploye->text();
    QString raison;

    if (f.nom.isEmpty())                     { erreur = t("Le nom est obligatoire."); champ = ui->txtNomEmploye; }
    else if (f.prenom.isEmpty())             { erreur = t("Le prénom est obligatoire."); champ = ui->txtPrenomEmploye; }
    else if (!emailValide(f.email))          { erreur = t("L'adresse e-mail n'est pas valide."); champ = ui->txtEmailEmploye; }
    else if (!formeIdentifiant.match(f.identifiant).hasMatch())
        { erreur = t("L'identifiant doit contenir 3 à 30 caractères (lettres minuscules, chiffres, point)."); champ = ui->txtIdentifiantEmploye; }
    else if (memeIdentifiant && memeIdentifiant->identifiant != ancienIdentifiant)
        { erreur = t("Cet identifiant est déjà utilisé par un autre compte."); champ = ui->txtIdentifiantEmploye; }
    else if (memeEmail && memeEmail->identifiant != ancienIdentifiant)
        { erreur = t("Cette adresse e-mail est déjà utilisée par un autre compte."); champ = ui->txtEmailEmploye; }
    else if ((motDePasseObligatoire || !mdp.isEmpty()) && !Authentification::motDePasseValide(mdp, &raison))
        { erreur = langueArabe ? traduireTexte(raison) : raison; champ = ui->txtMotDePasseEmploye; }
    else if ((motDePasseObligatoire || !mdp.isEmpty()) && ui->txtConfirmationMotDePasseEmploye->text() != mdp)
        { erreur = t("Les mots de passe ne correspondent pas."); champ = ui->txtConfirmationMotDePasseEmploye; }

    if (erreur.isEmpty()) return true;
    secouer(ui->cadreFormulaireEmploye);
    afficherNotification(t("Fiche incomplète"), erreur);
    if (champ) champ->setFocus();
    return false;
}

// Mode ajout : l'identifiant et l'e-mail suivent le nom et le prénom saisis
void Employe::identifiantDepuisNom()
{
    if (!modeAjout) return;
    const QString prenom = simplifier(ui->txtPrenomEmploye->text()), nom = simplifier(ui->txtNomEmploye->text());
    ui->txtIdentifiantEmploye->setText(prenom.isEmpty() || nom.isEmpty() ? QString() : prenom.left(1) + "." + nom);
    ui->txtEmailEmploye->setText(prenom.isEmpty() || nom.isEmpty() ? QString() : prenom + "." + nom + "@protectioncivile.tn");
}

// Comptes bloqués (carte de chiffres clés) et nombre d'employés de la liste
void Employe::mettreAJourCompteurs()
{
    const QString bloques = QString::number(auth.nombreComptesBloques());
    ui->lbl166->setText(bloques);
    ui->lbl166->setProperty("valeurCible", bloques);
    for (QLabel *l : ui->cadreListeEmploye->findChildren<QLabel *>()) {
        const QString fr = l->property("texteFrancais").isValid() ? l->property("texteFrancais").toString() : l->text();
        if (!fr.contains(QString::fromUtf8("employés · Caserne Centrale")) && !l->property("compteurEmployes").toBool()) continue;
        l->setProperty("compteurEmployes", true);
        l->setProperty("dynamique", true);
        if (recherche.isEmpty())
            l->setText(t("%1 employés · Caserne Centrale").arg(auth.employes().size()));
        else
            l->setText(t("%1 employé(s) trouvé(s) sur %2").arg(ui->tblEmploye->rowCount()).arg(auth.employes().size()));
    }
    mettreAJourStatistiques();
    genererPlanning();    // le planning suit la liste : un employé supprimé en disparaît
    mettreAJourTableauDeBord();   // le tableau de bord suit aussi la liste des employés
}

// =============================================================================
// Statistiques calculées à partir de la liste des employés
//  - cartes : effectif total, disponibles, en intervention ;
//  - anneau + légende : répartition par statut ;
//  - barres : répartition par fonction.
// =============================================================================
void Employe::mettreAJourStatistiques()
{
    const QVector<FicheEmploye> &liste = auth.employes();
    const int total = liste.size();
    const char *statuts[4] = {"Disponible", "En intervention", "En repos", "En congé"};
    const char *fonctions[5] = {"Pompier opérationnel", "Chauffeur", "Chef de garde", "Standardiste", "Agent administratif"};
    int parStatut[4] = {0, 0, 0, 0}, parFonction[5] = {0, 0, 0, 0, 0};
    for (const FicheEmploye &f : liste) {
        for (int i = 0; i < 4; ++i) if (f.statut == QString::fromUtf8(statuts[i])) parStatut[i]++;
        for (int i = 0; i < 5; ++i) if (f.fonction == QString::fromUtf8(fonctions[i])) parFonction[i]++;
    }
    auto pourcent = [total](int n) { return total > 0 ? qRound(100.0 * n / total) : 0; };

    // cartes de chiffres clés (le chiffre défile à l'entrée de la page)
    QLabel *cartes[3] = {ui->lbl157, ui->lbl160, ui->lbl163};
    const int valeurs[3] = {total, parStatut[0], parStatut[1]};
    for (int i = 0; i < 3; ++i) {
        cartes[i]->setText(QString::number(valeurs[i]));
        cartes[i]->setProperty("valeurCible", QString::number(valeurs[i]));
    }
    ui->lbl158->setText(t("dont %1 opérationnels").arg(parFonction[0] + parFonction[1] + parFonction[2]));
    ui->lbl161->setText(t("%1 % de l'effectif").arg(pourcent(parStatut[0])));

    // anneau : parts cumulées de chaque statut + légende
    QLabel *legende[4] = {ui->lblValeur1Employe, ui->lblValeur2Employe, ui->lblValeur3Employe, ui->lblValeur4Employe};
    qreal cumul = 0;
    for (int i = 0; i < 4; ++i) {
        cumul += total > 0 ? qreal(parStatut[i]) / total : 0.25;
        bornesAnneau[i] = cumul;
        legende[i]->setText(QString("%1  (%2 %)").arg(parStatut[i]).arg(pourcent(parStatut[i])));
    }
    bornesAnneau[3] = 1.0;
    ui->lblCentreAnneauEmploye->setText(QString("<span style=\"font-size:17pt; font-weight:bold\">%1 %</span><br/>"
                                                "<span style=\"font-size:8pt; font-weight:normal; color:#7A8896\">%2</span>")
                                            .arg(pourcent(parStatut[0])).arg(t("disponibles")));
    animerAnneau(1.0);

    // barres par fonction (elles glissent jusqu'à leur nouvelle valeur)
    QProgressBar *barres[5] = {ui->jauge20, ui->jauge21, ui->jauge22, ui->jauge23, ui->jauge24};
    QLabel *nombres[5] = {ui->lbl148, ui->lbl150, ui->lbl152, ui->lbl154, ui->lblValeurFonction5Employe};
    for (int i = 0; i < 5; ++i) {
        barres[i]->setMaximum(qMax(1, total));
        QPropertyAnimation *a = new QPropertyAnimation(barres[i], "value", barres[i]);
        a->setDuration(500);
        a->setEndValue(parFonction[i]);
        a->setEasingCurve(QEasingCurve::OutCubic);
        a->start(QAbstractAnimation::DeleteWhenStopped);
        nombres[i]->setText(QString::number(parFonction[i]));
    }
}

// =============================================================================
// Métiers basiques : recherche, tri, export PDF
// =============================================================================

// Employés à afficher : ceux qui correspondent à la recherche (nom, prénom, grade ou
// habilitation), rangés selon le tri choisi
QVector<int> Employe::ordreAffichage() const
{
    const QVector<FicheEmploye> &liste = auth.employes();
    const QString cle = simplifier(recherche);
    QVector<int> ordre;
    for (int i = 0; i < liste.size(); ++i) {
        const FicheEmploye &f = liste[i];
        const bool trouve = cle.isEmpty() || simplifier(f.nom).contains(cle) || simplifier(f.prenom).contains(cle)
                            || simplifier(f.prenom + f.nom).contains(cle) || simplifier(f.nom + f.prenom).contains(cle)
                            || simplifier(f.grade).contains(cle) || simplifier(f.habilitations).contains(cle);
        if (trouve) ordre.append(i);
    }
    // grades du plus haut au plus bas
    static const QStringList grades = {"Capitaine", "Lieutenant", "Adjudant-chef", "Sergent-chef", "Sergent", "Caporal", "Sapeur"};
    const QString critere = critereTri;
    std::stable_sort(ordre.begin(), ordre.end(), [&liste, critere](int a, int b) {
        const FicheEmploye &x = liste[a], &y = liste[b];
        if (critere == "Grade") return grades.indexOf(x.grade) < grades.indexOf(y.grade);
        if (critere == QString::fromUtf8("Ancienneté")) return x.dateEntree < y.dateEntree;   // les plus anciens d'abord
        if (critere == "Nom") {
            const int c = QString::localeAwareCompare(x.nom, y.nom);
            return c != 0 ? c < 0 : QString::localeAwareCompare(x.prenom, y.prenom) < 0;
        }
        return false;
    });
    if (triInverse) std::reverse(ordre.begin(), ordre.end());
    return ordre;
}

QString Employe::descriptionTri() const
{
    if (critereTri == "Nom") return triInverse ? t("par nom (Z → A)") : t("par nom (A → Z)");
    if (critereTri == "Grade") return triInverse ? t("par grade (du plus bas au plus haut)") : t("par grade (du plus haut au plus bas)");
    if (critereTri == QString::fromUtf8("Ancienneté"))
        return triInverse ? t("par ancienneté (les plus récents d'abord)") : t("par ancienneté (les plus anciens d'abord)");
    return t("dans l'ordre d'ajout");
}

// Bouton « Trier » : critère choisi dans la liste ; un 2e clic sur le même critère inverse l'ordre
void Employe::trier()
{
    const QString choix = texteCombo(ui->cbTriEmploye);
    triInverse = (choix == critereTri) ? !triInverse : false;
    critereTri = choix;
    remplirTableau(identifiantLigne(ligneAffichee));

    // le tableau réapparaît en fondu dans son nouvel ordre
    QGraphicsOpacityEffect *effet = new QGraphicsOpacityEffect(ui->tblEmploye);
    ui->tblEmploye->setGraphicsEffect(effet);
    QPropertyAnimation *fondu = new QPropertyAnimation(effet, "opacity", ui->tblEmploye);
    fondu->setDuration(380);
    fondu->setStartValue(0.15);
    fondu->setEndValue(1.0);
    connect(fondu, &QPropertyAnimation::finished, ui->tblEmploye, [this]() { ui->tblEmploye->setGraphicsEffect(nullptr); });
    fondu->start(QAbstractAnimation::DeleteWhenStopped);
    fermerNotifications();                                // une seule notification de tri à la fois
    afficherNotification(t("Liste triée"), t("Employés triés %1.").arg(descriptionTri()), ":/images/icones/tuile_grid_bleu.png");
}

// Recherche pendant la saisie : le tableau ne garde que les employés correspondants
void Employe::rechercher()
{
    recherche = ui->txtRechercheEmploye->text().trimmed();
    remplirTableau(identifiantLigne(ligneAffichee));
}

void Employe::rechercherBouton()
{
    rechercher();
    if (!recherche.isEmpty() && ui->tblEmploye->rowCount() == 0) {
        secouer(ui->txtRechercheEmploye);
        afficherNotification(t("Aucun résultat"), t("Aucun employé ne correspond à « %1 ».").arg(recherche));
    }
}

// Export PDF : la liste affichée (après recherche et tri) est enregistrée dans un fichier PDF
void Employe::exporterPdf()
{
    QTableWidget *table = ui->tblEmploye;
    if (table->rowCount() == 0) {
        afficherNotification(t("Export impossible"), t("La liste affichée est vide."));
        return;
    }
    const QString dossier = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    QString chemin = QFileDialog::getSaveFileName(fenetre, t("Exporter la liste des employés"),
                                                  dossier + "/Liste_employes_" + QDate::currentDate().toString("yyyy-MM-dd") + ".pdf",
                                                  "PDF (*.pdf)");
    if (chemin.isEmpty()) return;
    if (!chemin.endsWith(".pdf", Qt::CaseInsensitive)) chemin += ".pdf";

    // 1. le contenu : en-tête, critères, tableau (mêmes colonnes que l'interface), pied de page
    const FicheEmploye *c = auth.trouver(identifiantConnecte);
    QString html = "<html><body style='font-family:Arial; color:#16202A; font-size:9pt'>";
    html += "<table width='100%' cellpadding='10' cellspacing='0' bgcolor='#16202A'><tr>"
            "<td><span style='color:#FF8A5B; font-size:8pt; font-weight:bold'>PROTECTION CIVILE · CASERNE CENTRALE — TUNIS NORD</span><br/>"
            "<span style='color:#FFFFFF; font-size:17pt; font-weight:bold'>Liste des employés</span></td>"
            "<td align='right' style='color:#C9D3DC; font-size:8pt'>Exportée le " + QDate::currentDate().toString("dd/MM/yyyy")
            + " à " + QTime::currentTime().toString("HH:mm") + "<br/>par "
            + (c ? (c->prenom + " " + c->nom + " (" + c->role + ")").toHtmlEscaped() : QString("—")) + "</td></tr></table>";
    html += "<table width='100%' cellpadding='0' cellspacing='0' bgcolor='#E4491F'><tr><td height='3'></td></tr></table>";
    html += "<p style='color:#5B6B7A'><b>" + QString::number(table->rowCount()) + " employé(s)</b> · tri : "
            + descriptionTri().toHtmlEscaped()
            + (recherche.isEmpty() ? QString() : " · recherche : « " + recherche.toHtmlEscaped() + " »") + "</p>";
    html += "<table width='100%' cellpadding='6' cellspacing='0' border='0'><tr bgcolor='#F4F6F9'>";
    for (int col = 0; col < table->columnCount(); ++col) {
        const QTableWidgetItem *entete = table->horizontalHeaderItem(col);
        const QString texte = entete ? (entete->data(ROLE_FRANCAIS).isValid() ? entete->data(ROLE_FRANCAIS).toString() : entete->text()) : QString();
        html += "<th align='left' style='color:#5B6B7A; font-size:8pt'>" + texte.toUpper().toHtmlEscaped() + "</th>";
    }
    html += "</tr>";
    for (int l = 0; l < table->rowCount(); ++l) {
        html += QString("<tr bgcolor='%1'>").arg(l % 2 ? "#F8FAFC" : "#FFFFFF");
        for (int col = 0; col < table->columnCount(); ++col) {
            const QTableWidgetItem *it = table->item(l, col);
            const QString texte = it ? (it->data(ROLE_FRANCAIS).isValid() ? it->data(ROLE_FRANCAIS).toString() : it->text()) : QString();
            QString style;
            if (col == 1) style = "font-weight:bold; color:#C7341A";                         // nom aux couleurs des braises
            if (col == 4) {                                                                   // statut coloré
                const QString couleur = texte.contains("Disponible") ? "#1E9E63" : texte.contains("intervention") ? "#D48A12" : "#7A8896";
                style = "font-weight:bold; color:" + couleur;
            }
            html += "<td style='" + style + "'>" + texte.toHtmlEscaped() + "</td>";
        }
        html += "</tr>";
    }
    html += "</table>";
    html += "<p style='color:#8B99A6; font-size:7pt'>Document généré par Caserne Connectée — module Employé. "
            "Les mots de passe ne figurent jamais dans ce document.</p></body></html>";

    // 2. l'écriture du fichier PDF (A4 paysage), sans bloquer l'interface
    const int nombre = table->rowCount();
    enregistrerPdf(html, chemin, "Liste des employés — Caserne Connectée", ui->btnExporterPdfEmploye,
                   [this, chemin, nombre](bool ok) {
        if (!ok) {
            afficherNotification(t("Export impossible"), t("Le fichier PDF n'a pas pu être enregistré."));
            return;
        }
        new MessageAnime(fenetre, MessageAnime::Succes, t("Liste exportée en PDF"),
                         t("%1 employé(s) · %2").arg(nombre).arg(QFileInfo(chemin).fileName()), modeSombre);
        afficherNotification(t("PDF enregistré"), QDir::toNativeSeparators(chemin), ":/images/icones/file_gris.png", 6000);
    });
}

// -----------------------------------------------------------------------------
// Écriture d'un PDF (A4 paysage) dans un fil d'exécution séparé (QtConcurrent) :
// la fenêtre reste utilisable ; le bouton affiche « Génération… » jusqu'à la fin.
// -----------------------------------------------------------------------------
void Employe::enregistrerPdf(const QString &html, const QString &chemin, const QString &titre,
                             QPushButton *bouton, std::function<void(bool)> fin)
{
    const QString texteBouton = bouton->text();
    bouton->setEnabled(false);
    bouton->setText(t("Génération…"));
    QFutureWatcher<bool> *suivi = new QFutureWatcher<bool>(this);
    connect(suivi, &QFutureWatcher<bool>::finished, this, [suivi, bouton, texteBouton, fin]() {
        bouton->setText(texteBouton);
        bouton->setEnabled(true);
        fin(suivi->result());
        suivi->deleteLater();
    });
    suivi->setFuture(QtConcurrent::run([html, chemin, titre]() {
        {
            QPdfWriter pdf(chemin);
            pdf.setPageSize(QPageSize(QPageSize::A4));
            pdf.setPageOrientation(QPageLayout::Landscape);
            pdf.setPageMargins(QMarginsF(12, 12, 12, 12), QPageLayout::Millimeter);
            pdf.setTitle(titre);
            pdf.setCreator("Caserne Connectée");
            QTextDocument document;
            document.setHtml(html);
            document.print(&pdf);
        }   // le fichier est fermé ici
        return QFileInfo::exists(chemin) && QFileInfo(chemin).size() > 0;
    }));
}

// =============================================================================
// Planning des gardes (créneaux de 12h : Jour 07h-19h, Nuit 19h-07h)
//  - une ligne par employé de la caserne (sauf les agents administratifs, en horaire de bureau) ;
//  - « En congé » : C sur toute la période ;
//  - repos réglementaire : 12h au minimum après une garde de jour, 24h après une garde de nuit ;
//  - chaque créneau reçoit l'effectif minimum, dont 1 chef de garde et 1 conducteur si possible,
//    en choisissant d'abord ceux qui ont le moins de gardes (roulement équitable) ;
//  - le planning est recalculé à chaque ajout, modification ou suppression d'un employé :
//    un employé supprimé disparaît du planning, un nouvel employé y entre.
//  - un agent (rôle « Agent ») ne voit que sa propre ligne.
// =============================================================================
static bool estChefDeGarde(const FicheEmploye &f)
{
    return f.fonction == QString::fromUtf8("Chef de garde") || f.role == "Chef de garde";
}

static bool estConducteur(const FicheEmploye &f)
{
    const QString h = f.habilitations.toLower();
    return f.fonction == "Chauffeur" || h.contains("permis") || h.contains("conduc") || h.contains("poids lourd");
}

void Employe::genererPlanning()
{
    static const char *joursSemaine[] = {"lun", "mar", "mer", "jeu", "ven", "sam", "dim"};
    QTableWidget *table = ui->tblPlanningEmploye;
    debutPlanning = ui->datePlanningEmploye->date();
    const int choix = ui->cbDureePlanningEmploye->currentIndex();
    joursPlanning = choix == 2 ? 30 : choix == 1 ? 14 : 7;
    const int creneaux = joursPlanning * 2;
    const int minimum = ui->spinEffectifPlanningEmploye->value();

    // 1. les employés concernés
    QVector<const FicheEmploye *> agents;
    for (const FicheEmploye &f : auth.employes())
        if (f.fonction != "Agent administratif") agents.append(&f);
    std::stable_sort(agents.begin(), agents.end(), [](const FicheEmploye *a, const FicheEmploye *b) {
        if (estChefDeGarde(*a) != estChefDeGarde(*b)) return estChefDeGarde(*a);   // chefs de garde en tête
        return a->nom.localeAwareCompare(b->nom) < 0;
    });

    // 2. la répartition, créneau par créneau
    const int n = agents.size();
    QVector<QVector<char>> cases(n, QVector<char>(creneaux, 'R'));
    QVector<int> gardes(n, 0);
    effectifCreneau = QVector<int>(creneaux, 0);
    creneauIncomplet = QVector<bool>(creneaux, false);
    int sansChef = 0, sansConducteur = 0, sousEffectif = 0;
    for (int a = 0; a < n; ++a)
        if (agents[a]->statut.contains(QString::fromUtf8("congé"))) cases[a].fill('C');
    for (int c = 0; c < creneaux; ++c) {
        auto disponible = [&](int a) {   // 12h de repos après une garde de jour, 24h après une nuit
            if (cases[a][c] != 'R') return false;
            if (c >= 1 && (cases[a][c - 1] == 'J' || cases[a][c - 1] == 'N')) return false;
            return !(c >= 2 && cases[a][c - 2] == 'N');
        };
        auto choisir = [&](std::function<bool(const FicheEmploye &)> condition) {
            int meilleur = -1;
            for (int a = 0; a < n; ++a)
                if (disponible(a) && condition(*agents[a]) && (meilleur < 0 || gardes[a] < gardes[meilleur])) meilleur = a;
            if (meilleur >= 0) { cases[meilleur][c] = (c % 2 == 0) ? 'J' : 'N'; gardes[meilleur]++; effectifCreneau[c]++; }
            return meilleur >= 0;
        };
        const bool chef = choisir(estChefDeGarde);
        const bool conducteur = choisir(estConducteur);
        while (effectifCreneau[c] < minimum && choisir([](const FicheEmploye &) { return true; })) {}
        creneauIncomplet[c] = !chef || !conducteur || effectifCreneau[c] < minimum;
        sansChef += chef ? 0 : 1;
        sansConducteur += conducteur ? 0 : 1;
        sousEffectif += effectifCreneau[c] < minimum ? 1 : 0;
    }

    // 3. l'affichage (un agent ne voit que sa ligne)
    const FicheEmploye *connecte = auth.trouver(identifiantConnecte);
    const bool seulementMoi = connecte && connecte->role == "Agent";
    auto traduit = [this](const QString &fr) { return langueArabe ? traduireTexte(fr) : fr; };
    auto caseTexte = [&](const QString &fr) {
        QTableWidgetItem *it = new QTableWidgetItem(traduit(fr));
        it->setData(ROLE_FRANCAIS, fr);
        return it;
    };
    table->clear();
    table->setColumnCount(creneaux + 2);
    table->setHorizontalHeaderItem(0, caseTexte("Agent"));
    for (int c = 0; c < creneaux; ++c) {
        const QDate jour = debutPlanning.addDays(c / 2);
        const QString fr = QString::fromUtf8(joursSemaine[jour.dayOfWeek() - 1]) + " " + jour.toString("dd")
                         + "\n" + (c % 2 == 0 ? "Jour" : "Nuit");
        QTableWidgetItem *entete = caseTexte(fr);
        if (creneauIncomplet[c]) {
            entete->setForeground(QColor("#D93636"));
            entete->setToolTip(t("Créneau incomplet : %1 agent(s) de garde").arg(effectifCreneau[c]));
        }
        table->setHorizontalHeaderItem(c + 1, entete);
    }
    table->setHorizontalHeaderItem(creneaux + 1, caseTexte("Gardes"));

    static const QHash<char, QPair<QString, QString>> couleurs = {   // fond, texte (thème clair)
        {'J', {"#FDE9E1", "#E4491F"}}, {'N', {"#E3ECFB", "#2F6FE0"}},
        {'R', {"#EEF1F4", "#7A8896"}}, {'C', {"#F4F6F9", "#9AA5B1"}}};
    QFont gras = table->font();
    gras.setBold(true);
    int ligne = 0;
    table->setRowCount(0);
    for (int a = 0; a < n; ++a) {
        if (seulementMoi && agents[a]->identifiant != connecte->identifiant) continue;
        table->insertRow(ligne);
        QTableWidgetItem *nom = new QTableWidgetItem(agents[a]->prenom + " " + agents[a]->nom);
        nom->setFont(gras);
        nom->setData(Qt::UserRole + 50, agents[a]->identifiant);
        nom->setToolTip(traduit(agents[a]->fonction));
        table->setItem(ligne, 0, nom);
        for (int c = 0; c < creneaux; ++c) {
            const char lettre = cases[a][c];
            QTableWidgetItem *it = new QTableWidgetItem(QString(QChar(lettre)));
            it->setTextAlignment(Qt::AlignCenter);
            it->setFont(gras);
            it->setBackground(QColor(couleurs[lettre].first));
            it->setForeground(QColor(couleurs[lettre].second));
            table->setItem(ligne, c + 1, it);
        }
        QTableWidgetItem *total = new QTableWidgetItem(QString::number(gardes[a]));
        total->setTextAlignment(Qt::AlignCenter);
        total->setFont(gras);
        table->setItem(ligne, creneaux + 1, total);
        ++ligne;
    }

    // largeurs : 7 jours tiennent dans la largeur ; au-delà, défilement horizontal
    QHeaderView *entete = table->horizontalHeader();
    entete->setSectionResizeMode(joursPlanning <= 7 ? QHeaderView::Stretch : QHeaderView::Fixed);
    entete->setSectionResizeMode(0, QHeaderView::Fixed);
    entete->setSectionResizeMode(creneaux + 1, QHeaderView::Fixed);
    if (joursPlanning > 7) for (int c = 1; c <= creneaux; ++c) table->setColumnWidth(c, 58);
    table->setColumnWidth(0, 150);
    table->setColumnWidth(creneaux + 1, 70);
    table->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    // résumé et alerte sous le tableau
    const int incomplets = int(std::count(creneauIncomplet.begin(), creneauIncomplet.end(), true));
    ui->lblResumePlanningEmploye->setText(
        t("Du %1 au %2 · %3 créneaux de 12h · effectif minimum %4 (dont 1 chef de garde et 1 conducteur)")
            .arg(debutPlanning.toString("dd/MM/yyyy"), debutPlanning.addDays(joursPlanning - 1).toString("dd/MM/yyyy"))
            .arg(creneaux).arg(minimum)
        + (seulementMoi ? t(" · votre planning personnel") : QString()));
    QStringList raisons;
    if (sousEffectif) raisons << t("%1 en sous-effectif").arg(sousEffectif);
    if (sansChef) raisons << t("%1 sans chef de garde").arg(sansChef);
    if (sansConducteur) raisons << t("%1 sans conducteur").arg(sansConducteur);
    alertePlanning = raisons.join(", ");
    alertePlanningFr = QStringList({sousEffectif ? QString("%1 en sous-effectif").arg(sousEffectif) : QString(),
                                    sansChef ? QString("%1 sans chef de garde").arg(sansChef) : QString(),
                                    sansConducteur ? QString("%1 sans conducteur").arg(sansConducteur) : QString()})
                           .filter(QRegularExpression(".+")).join(", ");
    ui->lblAlertePlanningEmploye->setText(incomplets == 0 ? t("· effectif complet sur tous les créneaux")
                                                          : t("· créneaux incomplets : %1").arg(alertePlanning));
    ui->lblAlertePlanningEmploye->setProperty("variante", incomplets == 0 ? "texteSucces" : "texteAlerte");
    ui->lblAlertePlanningEmploye->style()->unpolish(ui->lblAlertePlanningEmploye);
    ui->lblAlertePlanningEmploye->style()->polish(ui->lblAlertePlanningEmploye);
    emit planningModifie();
}

void Employe::genererPlanningBouton()
{
    genererPlanning();
    // le planning réapparaît en fondu
    QTableWidget *table = ui->tblPlanningEmploye;
    QGraphicsOpacityEffect *effet = new QGraphicsOpacityEffect(table);
    table->setGraphicsEffect(effet);
    QPropertyAnimation *apparition = new QPropertyAnimation(effet, "opacity", effet);
    apparition->setDuration(450);
    apparition->setStartValue(0.0);
    apparition->setEndValue(1.0);
    connect(apparition, &QPropertyAnimation::finished, table, [table]() { table->setGraphicsEffect(nullptr); });
    apparition->start();
    afficherNotification(t("Planning généré"), ui->lblResumePlanningEmploye->text(), ":/images/icones/bolt_blanc.png");
}

// =============================================================================
// Export Excel (.xlsx) sans bibliothèque externe
//  Un fichier .xlsx est une archive ZIP de quelques fichiers XML (format Office Open XML).
//  On écrit ces fichiers nous-mêmes (cellules, styles, couleurs, largeurs de colonnes,
//  ligne d'en-tête figée), puis on les range dans une archive ZIP « stockée » (sans compression).
// =============================================================================
namespace Excel {
enum Style { Normal = 0, Entete, Titre, Sous, J, N, R, C, Nom, Vert, Ambre, Gris, Centre, Rouge, VertGras };
struct Cellule { QString texte; int style = Normal; };

static quint32 crc32(const QByteArray &d)
{
    static quint32 table[256];
    static bool prete = false;
    if (!prete) {
        for (quint32 i = 0; i < 256; ++i) {
            quint32 c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        prete = true;
    }
    quint32 c = 0xFFFFFFFFu;
    for (char octet : d) c = table[(c ^ quint8(octet)) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

// Archive ZIP minimale (fichiers stockés tels quels)
static QByteArray zip(const QVector<QPair<QString, QByteArray>> &fichiers)
{
    QByteArray sortie, central;
    auto u16 = [](QByteArray &b, quint16 v) { b.append(char(v & 0xFF)); b.append(char(v >> 8)); };
    auto u32 = [](QByteArray &b, quint32 v) { for (int i = 0; i < 4; ++i) b.append(char((v >> (8 * i)) & 0xFF)); };
    const QDateTime t = QDateTime::currentDateTime();
    const quint16 heure = quint16((t.time().hour() << 11) | (t.time().minute() << 5) | (t.time().second() / 2));
    const quint16 date = quint16(((t.date().year() - 1980) << 9) | (t.date().month() << 5) | t.date().day());
    for (const auto &f : fichiers) {
        const QByteArray nom = f.first.toUtf8();
        const quint32 crc = crc32(f.second), taille = quint32(f.second.size()), position = quint32(sortie.size());
        u32(sortie, 0x04034b50); u16(sortie, 20); u16(sortie, 0x0800); u16(sortie, 0); u16(sortie, heure); u16(sortie, date);
        u32(sortie, crc); u32(sortie, taille); u32(sortie, taille); u16(sortie, quint16(nom.size())); u16(sortie, 0);
        sortie += nom;
        sortie += f.second;
        u32(central, 0x02014b50); u16(central, 20); u16(central, 20); u16(central, 0x0800); u16(central, 0);
        u16(central, heure); u16(central, date); u32(central, crc); u32(central, taille); u32(central, taille);
        u16(central, quint16(nom.size())); u16(central, 0); u16(central, 0); u16(central, 0); u16(central, 0);
        u32(central, 0); u32(central, position);
        central += nom;
    }
    const quint32 debutCentral = quint32(sortie.size());
    sortie += central;
    u32(sortie, 0x06054b50); u16(sortie, 0); u16(sortie, 0); u16(sortie, quint16(fichiers.size())); u16(sortie, quint16(fichiers.size()));
    u32(sortie, quint32(central.size())); u32(sortie, debutCentral); u16(sortie, 0);
    return sortie;
}

static QString colonne(int c)                 // 0 -> A, 25 -> Z, 26 -> AA…
{
    QString nom;
    for (++c; c > 0; c = (c - 1) / 26) nom.prepend(QChar('A' + (c - 1) % 26));
    return nom;
}

// lignes : tableau de cellules ; entete : numéro (0…) de la ligne d'en-tête, figée à l'écran
static bool ecrire(const QString &chemin, const QString &feuille, const QVector<QVector<Cellule>> &lignes,
                   const QVector<double> &largeurs, int entete)
{
    auto x = [](QString t) { return t.toHtmlEscaped(); };
    int colonnes = 0;
    for (const auto &l : lignes) colonnes = qMax(colonnes, int(l.size()));
    QString s = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
                "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" "
                "xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">";
    s += QString("<sheetViews><sheetView workbookViewId=\"0\"><pane ySplit=\"%1\" topLeftCell=\"A%2\" activePane=\"bottomLeft\" state=\"frozen\"/>"
                 "</sheetView></sheetViews>").arg(entete + 1).arg(entete + 2);
    s += "<cols>";
    for (int c = 0; c < largeurs.size(); ++c) s += QString("<col min=\"%1\" max=\"%1\" width=\"%2\" customWidth=\"1\"/>").arg(c + 1).arg(largeurs[c]);
    s += "</cols><sheetData>";
    for (int l = 0; l < lignes.size(); ++l) {
        const bool haute = l == entete || l == 0;
        s += QString("<row r=\"%1\"%2>").arg(l + 1).arg(haute ? QString(" ht=\"%1\" customHeight=\"1\"").arg(l == 0 ? 24 : 32) : QString());
        for (int c = 0; c < lignes[l].size(); ++c) {
            const Cellule &cell = lignes[l][c];
            const QString ref = colonne(c) + QString::number(l + 1);
            bool estNombre = false;
            cell.texte.toDouble(&estNombre);
            if (cell.texte.isEmpty()) s += QString("<c r=\"%1\" s=\"%2\"/>").arg(ref).arg(cell.style);
            else if (estNombre) s += QString("<c r=\"%1\" s=\"%2\"><v>%3</v></c>").arg(ref).arg(cell.style).arg(cell.texte);
            else s += QString("<c r=\"%1\" s=\"%2\" t=\"inlineStr\"><is><t xml:space=\"preserve\">%3</t></is></c>").arg(ref).arg(cell.style).arg(x(cell.texte));
        }
        s += "</row>";
    }
    s += "</sheetData>";
    if (colonnes > 1)                                // titre et sous-titre sur toute la largeur
        s += "<mergeCells count=\"2\"><mergeCell ref=\"A1:" + colonne(colonnes - 1) + "1\"/><mergeCell ref=\"A2:"
             + colonne(colonnes - 1) + "2\"/></mergeCells>";
    s += "<pageMargins left=\"0.4\" right=\"0.4\" top=\"0.5\" bottom=\"0.5\" header=\"0.3\" footer=\"0.3\"/>"
         "<pageSetup orientation=\"landscape\" paperSize=\"9\" fitToWidth=\"1\" fitToHeight=\"0\"/></worksheet>";

    // styles : polices, remplissages, bordures, puis les combinaisons utilisées (dans l'ordre de l'énumération Style)
    const QString styles = QString::fromUtf8(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
        "<styleSheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">"
        "<fonts count=\"12\">"
        "<font><sz val=\"10\"/><color rgb=\"FF16202A\"/><name val=\"Arial\"/></font>"
        "<font><b/><sz val=\"10\"/><color rgb=\"FFFFFFFF\"/><name val=\"Arial\"/></font>"
        "<font><b/><sz val=\"15\"/><color rgb=\"FFE4491F\"/><name val=\"Arial\"/></font>"
        "<font><i/><sz val=\"9\"/><color rgb=\"FF5B6B7A\"/><name val=\"Arial\"/></font>"
        "<font><b/><sz val=\"10\"/><color rgb=\"FFE4491F\"/><name val=\"Arial\"/></font>"
        "<font><b/><sz val=\"10\"/><color rgb=\"FF2F6FE0\"/><name val=\"Arial\"/></font>"
        "<font><b/><sz val=\"10\"/><color rgb=\"FF7A8896\"/><name val=\"Arial\"/></font>"
        "<font><b/><sz val=\"10\"/><color rgb=\"FF9AA5B1\"/><name val=\"Arial\"/></font>"
        "<font><b/><sz val=\"10\"/><color rgb=\"FFC7341A\"/><name val=\"Arial\"/></font>"
        "<font><b/><sz val=\"10\"/><color rgb=\"FF1E9E63\"/><name val=\"Arial\"/></font>"
        "<font><b/><sz val=\"10\"/><color rgb=\"FFD48A12\"/><name val=\"Arial\"/></font>"
        "<font><b/><sz val=\"10\"/><color rgb=\"FFD93636\"/><name val=\"Arial\"/></font>"
        "</fonts>"
        "<fills count=\"7\"><fill><patternFill patternType=\"none\"/></fill><fill><patternFill patternType=\"gray125\"/></fill>"
        "<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FF16202A\"/></patternFill></fill>"
        "<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FFFDE9E1\"/></patternFill></fill>"
        "<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FFE3ECFB\"/></patternFill></fill>"
        "<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FFEEF1F4\"/></patternFill></fill>"
        "<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FFF4F6F9\"/></patternFill></fill></fills>"
        "<borders count=\"2\"><border/><border><left style=\"thin\"><color rgb=\"FFE1E6EC\"/></left><right style=\"thin\"><color rgb=\"FFE1E6EC\"/></right>"
        "<top style=\"thin\"><color rgb=\"FFE1E6EC\"/></top><bottom style=\"thin\"><color rgb=\"FFE1E6EC\"/></bottom></border></borders>"
        "<cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs>"
        "<cellXfs count=\"15\">"
        "<xf fontId=\"0\" fillId=\"0\" borderId=\"1\" applyBorder=\"1\"><alignment vertical=\"center\"/></xf>"                                   // Normal
        "<xf fontId=\"1\" fillId=\"2\" borderId=\"1\" applyFont=\"1\" applyFill=\"1\" applyAlignment=\"1\"><alignment horizontal=\"center\" vertical=\"center\" wrapText=\"1\"/></xf>"   // Entete
        "<xf fontId=\"2\" fillId=\"0\" borderId=\"0\" applyFont=\"1\"><alignment vertical=\"center\"/></xf>"                                      // Titre
        "<xf fontId=\"3\" fillId=\"0\" borderId=\"0\" applyFont=\"1\"/>"                                                                        // Sous
        "<xf fontId=\"4\" fillId=\"3\" borderId=\"1\" applyFont=\"1\" applyFill=\"1\" applyAlignment=\"1\"><alignment horizontal=\"center\"/></xf>"  // J
        "<xf fontId=\"5\" fillId=\"4\" borderId=\"1\" applyFont=\"1\" applyFill=\"1\" applyAlignment=\"1\"><alignment horizontal=\"center\"/></xf>"  // N
        "<xf fontId=\"6\" fillId=\"5\" borderId=\"1\" applyFont=\"1\" applyFill=\"1\" applyAlignment=\"1\"><alignment horizontal=\"center\"/></xf>"  // R
        "<xf fontId=\"7\" fillId=\"6\" borderId=\"1\" applyFont=\"1\" applyFill=\"1\" applyAlignment=\"1\"><alignment horizontal=\"center\"/></xf>"  // C
        "<xf fontId=\"8\" fillId=\"0\" borderId=\"1\" applyFont=\"1\"/>"                                                                        // Nom
        "<xf fontId=\"9\" fillId=\"0\" borderId=\"1\" applyFont=\"1\"/>"                                                                        // Vert
        "<xf fontId=\"10\" fillId=\"0\" borderId=\"1\" applyFont=\"1\"/>"                                                                       // Ambre
        "<xf fontId=\"6\" fillId=\"0\" borderId=\"1\" applyFont=\"1\"/>"                                                                        // Gris
        "<xf fontId=\"0\" fillId=\"0\" borderId=\"1\" applyAlignment=\"1\"><alignment horizontal=\"center\"/></xf>"                              // Centre
        "<xf fontId=\"11\" fillId=\"0\" borderId=\"1\" applyFont=\"1\" applyAlignment=\"1\"><alignment horizontal=\"center\"/></xf>"             // Rouge
        "<xf fontId=\"9\" fillId=\"0\" borderId=\"1\" applyFont=\"1\" applyAlignment=\"1\"><alignment horizontal=\"center\"/></xf>"              // VertGras
        "</cellXfs><cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles></styleSheet>");

    const QString nomFeuille = x(feuille.left(31));
    QVector<QPair<QString, QByteArray>> fichiers = {
        {"[Content_Types].xml", QByteArray(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
            "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
            "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
            "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
            "<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>"
            "<Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>"
            "<Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/>"
            "</Types>")},
        {"_rels/.rels", QByteArray(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
            "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
            "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/>"
            "</Relationships>")},
        {"xl/workbook.xml", QString(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
            "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" "
            "xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">"
            "<sheets><sheet name=\"%1\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>").arg(nomFeuille).toUtf8()},
        {"xl/_rels/workbook.xml.rels", QByteArray(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
            "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
            "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/>"
            "<Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/>"
            "</Relationships>")},
        {"xl/styles.xml", styles.toUtf8()},
        {"xl/worksheets/sheet1.xml", s.toUtf8()},
    };
    QFile fichier(chemin);
    if (!fichier.open(QIODevice::WriteOnly)) return false;
    fichier.write(zip(fichiers));
    return fichier.error() == QFile::NoError;
}
} // namespace Excel

// Icône « Excel » des boutons d'export (feuille verte)
static QIcon iconeExcel()
{
    QPixmap image(32, 32);
    image.fill(Qt::transparent);
    QPainter p(&image);
    p.setRenderHint(QPainter::Antialiasing);
    p.setPen(Qt::NoPen);
    p.setBrush(QColor("#1E7A4F"));
    p.drawRoundedRect(QRectF(4, 3, 24, 26), 4, 4);
    p.setPen(QPen(Qt::white, 3.2, Qt::SolidLine, Qt::RoundCap));
    p.drawLine(QPointF(11, 10), QPointF(21, 22));
    p.drawLine(QPointF(21, 10), QPointF(11, 22));
    return QIcon(image);
}

static QString demanderCheminExcel(QWidget *parent, const QString &titre, const QString &nom)
{
    const QString dossier = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    QString chemin = QFileDialog::getSaveFileName(parent, titre, dossier + "/" + nom, "Classeur Excel (*.xlsx)");
    if (!chemin.isEmpty() && !chemin.endsWith(".xlsx", Qt::CaseInsensitive)) chemin += ".xlsx";
    return chemin;
}

void Employe::exporterExcel()
{
    QTableWidget *table = ui->tblEmploye;
    if (table->rowCount() == 0) {
        afficherNotification(t("Export impossible"), t("La liste affichée est vide."));
        return;
    }
    const QString chemin = demanderCheminExcel(fenetre, t("Exporter la liste des employés (Excel)"),
                                               "Liste_employes_" + QDate::currentDate().toString("yyyy-MM-dd") + ".xlsx");
    if (chemin.isEmpty()) return;
    auto francais = [](const QTableWidgetItem *it) {
        return it ? (it->data(ROLE_FRANCAIS).isValid() ? it->data(ROLE_FRANCAIS).toString() : it->text()) : QString();
    };
    const FicheEmploye *c = auth.trouver(identifiantConnecte);
    QVector<QVector<Excel::Cellule>> lignes;
    lignes.append({{QString::fromUtf8("Liste des employés — Caserne Centrale, Tunis Nord"), Excel::Titre}});
    lignes.append({{QString::fromUtf8("Exportée le %1 à %2 par %3 · %4 employé(s) · tri : %5%6")
                        .arg(QDate::currentDate().toString("dd/MM/yyyy"), QTime::currentTime().toString("HH:mm"),
                             c ? c->prenom + " " + c->nom : QString("—")).arg(table->rowCount()).arg(descriptionTri())
                        .arg(recherche.isEmpty() ? QString() : QString::fromUtf8(" · recherche : « %1 »").arg(recherche)), Excel::Sous}});
    lignes.append(QVector<Excel::Cellule>());
    QVector<Excel::Cellule> entete;
    for (int col = 0; col < table->columnCount(); ++col) entete.append({francais(table->horizontalHeaderItem(col)), Excel::Entete});
    lignes.append(entete);
    for (int l = 0; l < table->rowCount(); ++l) {
        QVector<Excel::Cellule> ligne;
        for (int col = 0; col < table->columnCount(); ++col) {
            QString texte = francais(table->item(l, col));
            int style = Excel::Normal;
            if (col == 0) style = Excel::Centre;
            if (col == 1) style = Excel::Nom;
            if (col == 4) {
                texte.remove(QString::fromUtf8("●")).replace(QRegularExpression("^\\s+"), QString());
                style = texte == "Disponible" ? Excel::Vert : texte == "En intervention" ? Excel::Ambre : Excel::Gris;
            }
            ligne.append({texte, style});
        }
        lignes.append(ligne);
    }
    if (!Excel::ecrire(chemin, QString::fromUtf8("Employés"), lignes, {6, 16, 14, 15, 18, 12, 16, 16}, 3)) {
        afficherNotification(t("Export impossible"), t("Le fichier Excel n'a pas pu être enregistré."));
        return;
    }
    new MessageAnime(fenetre, MessageAnime::Succes, t("Liste exportée en Excel"),
                     t("%1 employé(s) · %2").arg(table->rowCount()).arg(QFileInfo(chemin).fileName()), modeSombre);
    afficherNotification(t("Excel enregistré"), QDir::toNativeSeparators(chemin), ":/images/icones/file_gris.png", 6000);
}

void Employe::telechargerPlanningExcel()
{
    QTableWidget *table = ui->tblPlanningEmploye;
    if (table->rowCount() == 0) {
        afficherNotification(t("Export impossible"), t("Le planning est vide."));
        return;
    }
    const QString chemin = demanderCheminExcel(fenetre, t("Télécharger le planning des gardes (Excel)"),
                                               "Planning_gardes_" + debutPlanning.toString("yyyy-MM-dd") + ".xlsx");
    if (chemin.isEmpty()) return;
    auto francais = [](const QTableWidgetItem *it) {
        return it ? (it->data(ROLE_FRANCAIS).isValid() ? it->data(ROLE_FRANCAIS).toString() : it->text()) : QString();
    };
    const int creneaux = joursPlanning * 2;
    QVector<QVector<Excel::Cellule>> lignes;
    lignes.append({{QString::fromUtf8("Planning des gardes — Caserne Centrale, Tunis Nord"), Excel::Titre}});
    lignes.append({{QString::fromUtf8("Du %1 au %2 · %3 créneaux de 12h (J : 07h-19h, N : 19h-07h, R : repos, C : congé) · effectif minimum %4")
                        .arg(debutPlanning.toString("dd/MM/yyyy"), debutPlanning.addDays(joursPlanning - 1).toString("dd/MM/yyyy"))
                        .arg(creneaux).arg(ui->spinEffectifPlanningEmploye->value()), Excel::Sous}});
    lignes.append(QVector<Excel::Cellule>());
    QVector<Excel::Cellule> entete;
    for (int col = 0; col < table->columnCount(); ++col) entete.append({francais(table->horizontalHeaderItem(col)), Excel::Entete});
    lignes.append(entete);
    for (int l = 0; l < table->rowCount(); ++l) {
        QVector<Excel::Cellule> ligne;
        for (int col = 0; col < table->columnCount(); ++col) {
            const QString texte = francais(table->item(l, col));
            int style = Excel::Centre;
            if (col == 0) style = Excel::Nom;
            else if (texte == "J") style = Excel::J;
            else if (texte == "N") style = Excel::N;
            else if (texte == "R") style = Excel::R;
            else if (texte == "C") style = Excel::C;
            ligne.append({texte, style});
        }
        lignes.append(ligne);
    }
    QVector<Excel::Cellule> effectif = {{"Effectif", Excel::Entete}};
    for (int k = 0; k < creneaux; ++k)
        effectif.append({QString::number(effectifCreneau.value(k)), creneauIncomplet.value(k) ? Excel::Rouge : Excel::VertGras});
    lignes.append(effectif);
    QVector<double> largeurs = {20};
    for (int k = 0; k < creneaux; ++k) largeurs.append(7.5);
    largeurs.append(9);
    if (!Excel::ecrire(chemin, "Planning", lignes, largeurs, 3)) {
        afficherNotification(t("Export impossible"), t("Le fichier Excel n'a pas pu être enregistré."));
        return;
    }
    new MessageAnime(fenetre, MessageAnime::Succes, t("Planning téléchargé en Excel"), QFileInfo(chemin).fileName(), modeSombre);
    afficherNotification(t("Excel enregistré"), QDir::toNativeSeparators(chemin), ":/images/icones/file_gris.png", 6000);
}

void Employe::telechargerPlanningPdf()
{
    QTableWidget *table = ui->tblPlanningEmploye;
    if (table->rowCount() == 0) {
        afficherNotification(t("Export impossible"), t("Le planning est vide."));
        return;
    }
    const QString dossier = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    QString chemin = QFileDialog::getSaveFileName(fenetre, t("Télécharger le planning des gardes"),
                                                  dossier + "/Planning_gardes_" + debutPlanning.toString("yyyy-MM-dd") + ".pdf",
                                                  "PDF (*.pdf)");
    if (chemin.isEmpty()) return;
    if (!chemin.endsWith(".pdf", Qt::CaseInsensitive)) chemin += ".pdf";

    const int creneaux = joursPlanning * 2;
    const int taille = joursPlanning <= 7 ? 9 : joursPlanning <= 14 ? 7 : 5;   // 30 jours : police réduite
    const FicheEmploye *c = auth.trouver(identifiantConnecte);
    auto francais = [](const QTableWidgetItem *it) {
        return it ? (it->data(ROLE_FRANCAIS).isValid() ? it->data(ROLE_FRANCAIS).toString() : it->text()) : QString();
    };
    QString html = QString("<html><body style='font-family:Arial; color:#16202A; font-size:%1pt'>").arg(taille);
    html += "<table width='100%' cellpadding='10' cellspacing='0' bgcolor='#16202A'><tr>"
            "<td><span style='color:#FF8A5B; font-size:8pt; font-weight:bold'>PROTECTION CIVILE · CASERNE CENTRALE — TUNIS NORD</span><br/>"
            "<span style='color:#FFFFFF; font-size:17pt; font-weight:bold'>Planning des gardes</span></td>"
            "<td align='right' style='color:#C9D3DC; font-size:8pt'>Téléchargé le " + QDate::currentDate().toString("dd/MM/yyyy")
            + " à " + QTime::currentTime().toString("HH:mm") + "<br/>par "
            + (c ? (c->prenom + " " + c->nom + " (" + c->role + ")").toHtmlEscaped() : QString("—")) + "</td></tr></table>";
    html += "<table width='100%' cellpadding='0' cellspacing='0' bgcolor='#E4491F'><tr><td height='3'></td></tr></table>";
    html += "<p style='color:#5B6B7A; font-size:9pt'>" +
            QString("Du <b>%1</b> au <b>%2</b> · %3 créneaux de 12h · effectif minimum %4 (dont 1 chef de garde et 1 conducteur)")
                .arg(debutPlanning.toString("dd/MM/yyyy"), debutPlanning.addDays(joursPlanning - 1).toString("dd/MM/yyyy"))
                .arg(creneaux).arg(ui->spinEffectifPlanningEmploye->value()) + "</p>";

    html += "<table width='100%' cellpadding='3' cellspacing='1' bgcolor='#E3E8EE'><tr bgcolor='#F4F6F9'>";
    for (int col = 0; col < table->columnCount(); ++col) {
        QString texte = francais(table->horizontalHeaderItem(col)).toHtmlEscaped();
        texte.replace("\n", "<br/>");
        const bool alerte = col >= 1 && col <= creneaux && creneauIncomplet.value(col - 1);
        html += QString("<th align='center'%4 style='color:%1; font-size:%2pt'>%3</th>")
                    .arg(alerte ? "#D93636" : "#5B6B7A").arg(taille - 1).arg(texte)
                    .arg(col == 0 ? QString(" width='%1%'").arg(joursPlanning <= 7 ? 13 : 9) : QString());
    }
    html += "</tr>";
    static const QHash<QString, QString> fonds = {{"J", "#FDE9E1"}, {"N", "#E3ECFB"}, {"R", "#EEF1F4"}, {"C", "#F4F6F9"}};
    static const QHash<QString, QString> textes = {{"J", "#E4491F"}, {"N", "#2F6FE0"}, {"R", "#7A8896"}, {"C", "#9AA5B1"}};
    for (int l = 0; l < table->rowCount(); ++l) {
        html += "<tr bgcolor='#FFFFFF'>";
        for (int col = 0; col < table->columnCount(); ++col) {
            const QString texte = francais(table->item(l, col));
            if (col == 0)
                html += "<td style='font-weight:bold; color:#C7341A' nowrap>" + texte.toHtmlEscaped() + "</td>";
            else if (fonds.contains(texte))
                html += QString("<td align='center' bgcolor='%1' style='font-weight:bold; color:%2'>%3</td>")
                            .arg(fonds[texte], textes[texte], texte);
            else
                html += "<td align='center' style='font-weight:bold'>" + texte.toHtmlEscaped() + "</td>";
        }
        html += "</tr>";
    }
    // dernière ligne : effectif de chaque créneau (en rouge s'il est incomplet)
    html += "<tr bgcolor='#F4F6F9'><td style='font-weight:bold; color:#5B6B7A'>Effectif</td>";
    for (int k = 0; k < creneaux; ++k)
        html += QString("<td align='center' style='font-weight:bold; color:%1'>%2</td>")
                    .arg(creneauIncomplet.value(k) ? "#D93636" : "#1E9E63").arg(effectifCreneau.value(k));
    html += "<td></td></tr></table>";
    const int incomplets = int(std::count(creneauIncomplet.begin(), creneauIncomplet.end(), true));
    html += "<p style='font-size:8pt'><b style='color:#E4491F'>J</b> Jour 07h-19h &#160;&#160; <b style='color:#2F6FE0'>N</b> Nuit 19h-07h"
            " &#160;&#160; <b style='color:#7A8896'>R</b> Repos &#160;&#160; <b style='color:#9AA5B1'>C</b> Congé &#160;&#160; · "
            + (incomplets == 0 ? QString("<span style='color:#1E9E63'>effectif complet sur tous les créneaux</span>")
                               : QString("<span style='color:#D93636'>créneaux incomplets (en rouge) : %1</span>").arg(alertePlanningFr.toHtmlEscaped()))
            + "</p><p style='color:#8B99A6; font-size:7pt'>Document généré par Caserne Connectée — module Employé.</p></body></html>";

    enregistrerPdf(html, chemin, "Planning des gardes — Caserne Connectée", ui->btnTelechargerPlanningEmploye,
                   [this, chemin](bool ok) {
        if (!ok) {
            afficherNotification(t("Export impossible"), t("Le fichier PDF n'a pas pu être enregistré."));
            return;
        }
        new MessageAnime(fenetre, MessageAnime::Succes, t("Planning téléchargé en PDF"),
                         QFileInfo(chemin).fileName(), modeSombre);
        afficherNotification(t("PDF enregistré"), QDir::toNativeSeparators(chemin), ":/images/icones/file_gris.png", 6000);
    });
}

// Une bande colorée recouvre la ligne puis s'efface (ajout, modification, suppression)
QWidget *Employe::surlignerLigne(int ligne, const QColor &couleur, int duree, bool disparait)
{
    QTableWidget *t = ui->tblEmploye;
    if (ligne < 0 || ligne >= t->rowCount()) return nullptr;
    t->scrollToItem(t->item(ligne, 0));
    const QRect zone = t->visualItemRect(t->item(ligne, 0)).united(t->visualItemRect(t->item(ligne, t->columnCount() - 1)));
    QWidget *bande = new QWidget(t->viewport());
    bande->setAttribute(Qt::WA_TransparentForMouseEvents);
    bande->setStyleSheet(QString("background: rgba(%1, %2, %3, 70); border-left: 4px solid %4;")
                             .arg(couleur.red()).arg(couleur.green()).arg(couleur.blue()).arg(couleur.name()));
    bande->setGeometry(zone.left(), zone.top(), t->viewport()->width(), zone.height());
    QGraphicsOpacityEffect *effet = new QGraphicsOpacityEffect(bande);
    bande->setGraphicsEffect(effet);
    bande->show();
    QVariantAnimation *a = new QVariantAnimation(bande);
    a->setDuration(duree);
    a->setStartValue(0.0);
    a->setEndValue(1.0);
    connect(a, &QVariantAnimation::valueChanged, bande, [effet, disparait](const QVariant &v) {
        const qreal x = v.toReal();
        effet->setOpacity(disparait ? (x < 0.2 ? x / 0.2 : 1.0 - (x - 0.2) / 0.8) : x);
    });
    if (disparait) connect(a, &QVariantAnimation::finished, bande, &QWidget::deleteLater);
    a->start(QAbstractAnimation::DeleteWhenStopped);
    return bande;
}

// =============================================================================
// Authentification : identifiant + mot de passe (haché puis comparé à l'empreinte)
// =============================================================================
void Employe::messageConnexion(const QString &texte, bool info)
{
    ui->lblMessageConnexion->setText(texte);
    ui->lblMessageConnexion->setProperty("etat", info ? "info" : "");
    ui->lblMessageConnexion->style()->unpolish(ui->lblMessageConnexion);
    ui->lblMessageConnexion->style()->polish(ui->lblMessageConnexion);
    ui->lblMessageConnexion->setVisible(!texte.isEmpty());
}

bool Employe::connecter()
{
    const QString identifiant = ui->txtIdentifiant->text().trimmed().toLower();
    const QString motDePasse = ui->txtMotDePasse->text();
    if (identifiant.isEmpty() || motDePasse.isEmpty()) {
        secouer(ui->cadreConnexion);
        messageConnexion(t("Saisissez votre identifiant et votre mot de passe."));
        return false;
    }

    int restants = 0;
    const Authentification::Connexion resultat = auth.connecter(identifiant, motDePasse, &restants);
    ui->txtMotDePasse->clear();

    switch (resultat) {
    case Authentification::Connexion::IdentifiantInconnu:
        secouer(ui->cadreConnexion);
        messageConnexion(t("Identifiant inconnu."));
        ui->txtIdentifiant->setFocus();
        return false;
    case Authentification::Connexion::MotDePasseIncorrect:
        secouer(ui->cadreConnexion);
        messageConnexion(restants == 1 ? t("Mot de passe incorrect : dernier essai avant le blocage du compte.")
                                       : t("Mot de passe incorrect : %1 essais restants avant le blocage du compte.").arg(restants));
        ui->txtMotDePasse->setFocus();
        return false;
    case Authentification::Connexion::CompteBloque:
        secouer(ui->cadreConnexion);
        messageConnexion(t("Compte bloqué après 5 essais échoués. Cliquez sur « Mot de passe oublié ? » pour le débloquer."));
        afficherNotification(t("Compte bloqué"), t("Trop d'essais échoués : ce compte est bloqué jusqu'à la réinitialisation du mot de passe."),
                             ":/images/icones/tuile_lock_rouge.png");
        return false;
    case Authentification::Connexion::Ok:
        break;
    }

    // Mot de passe correct : le droit « Employés » de ce compte doit être Complet ou Lecture
    // (dans l'application complète, les autres modules s'ouvrent selon leurs propres droits)
    const FicheEmploye *compte = auth.trouver(identifiant);
    if (auth.droit(*compte, M_EMPLOYES) == DROIT_AUCUN) {
        secouer(ui->cadreConnexion);
        const QString texte = t("Ce compte n'a pas accès à l'interface Employés.");
        messageConnexion(texte);
        afficherNotification(t("Accès refusé"), texte, ":/images/icones/tuile_lock_rouge.png");
        return false;
    }
    identifiantConnecte = compte->identifiant;
    messageConnexion(QString());
    fermerNotifications();                        // le code reçu par e-mail ne reste pas affiché
    remplirTableau(identifiantConnecte);          // l'employé connecté voit sa propre fiche
    afficherEmploye(ligneAffichee, 0);
    return true;
}

// =============================================================================
// Tableau de bord (section SUIVI du menu)
//  - chiffres, effectif de garde, alertes « Employés » et balise SOS calculés à partir des
//    employés (ils changent à chaque ajout, modification ou suppression) ;
//  - missions, unités, véhicules : exemples, en attendant les modules de l'équipe ;
//  - carte animée : plan illustré ou carte réelle (OpenStreetMap).
// =============================================================================
void Employe::preparerTableauDeBord()
{
    // la carte animée remplace l'image fixe de Qt Designer
    carte = new CarteInterventions;
    if (auto *colonne = qobject_cast<QBoxLayout *>(ui->imgCarteInterventions->parentWidget()->layout())) {
        for (QBoxLayout *l : ui->imgCarteInterventions->parentWidget()->findChildren<QBoxLayout *>())
            if (l->indexOf(ui->imgCarteInterventions) >= 0) colonne = l;
        colonne->insertWidget(colonne->indexOf(ui->imgCarteInterventions), carte, 1);
    }
    ui->imgCarteInterventions->hide();
    // boutons « Plan / Carte réelle » posés sur la carte, en haut à droite
    QWidget *choixCarte = new QWidget;
    QHBoxLayout *rangee = new QHBoxLayout(choixCarte);
    rangee->setContentsMargins(0, 0, 0, 0);
    rangee->setSpacing(6);
    rangee->addWidget(ui->btnPlanCarteDashboard);
    rangee->addWidget(ui->btnCarteReelleDashboard);
    carte->placerCommandes(choixCarte);
    for (QLabel *l : {ui->lbl102, ui->lbl104, ui->lbl101, ui->lbl106, ui->lbl108, ui->lbl118}) l->setWordWrap(true);
    connect(ui->btnPlanCarteDashboard, &QPushButton::clicked, this, [this]() { carte->definirReelle(false); });
    connect(ui->btnCarteReelleDashboard, &QPushButton::clicked, this, [this]() {
        carte->definirReelle(true);
        afficherNotification(t("Carte réelle"), t("Faites glisser la carte, molette pour zoomer, double-clic pour recentrer."),
                             ":/images/icones/tuile_map_bleu.png");
    });
    connect(ui->btnLocaliserBalise, &QPushButton::clicked, this, [this]() {
        carte->localiserBalise();
        afficherNotification(t("Balise localisée"), ui->lbl84->text(), ":/images/icones/tuile_alert_rouge.png");
    });

    // tableaux : colonnes réparties, lecture seule ; noms de l'effectif aux couleurs des braises
    for (QTableWidget *table : {ui->tblMissionsDashboard, ui->tblEffectifDashboard, ui->tblAlertesDashboard}) {
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    }
    ui->tblAlertesDashboard->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tblEffectifDashboard->setItemDelegateForColumn(0, new DelegueNomBraise(ui->tblEffectifDashboard, &phaseBraise, true));

    // missions critiques : la pastille rouge clignote
    QTimer *clignotement = new QTimer(this);
    connect(clignotement, &QTimer::timeout, this, [this]() {
        static bool allume = true;
        allume = !allume;
        QTableWidget *table = ui->tblMissionsDashboard;
        for (int l = 0; l < table->rowCount(); ++l)
            if (QTableWidgetItem *it = table->item(l, 3))
                if (it->text().contains("Critique") || it->text().contains(QString::fromUtf8("حرج")))
                    it->setForeground(QColor(217, 54, 54, allume ? 255 : 90));
    });
    clignotement->start(650);

    // braises dans le fond de la page, comme sur la page d'identification
    FondBraises *braises = new FondBraises(ui->contenuDefilant1, 14, 0.5);
    braises->setProperty("secondaire", true);
    braises->lower();

    // « En ligne » : le point pulse
    ui->lbl121->setProperty("dynamique", true);
    QTimer *pouls = new QTimer(this);                 // 8 images par seconde suffisent pour un point qui pulse
    connect(pouls, &QTimer::timeout, this, [this]() {
        if (!ui->lbl121->isVisible()) return;
        static qreal phase = 0;
        phase += 0.5;
        const int a = int(162 + 92 * std::cos(phase));
        ui->lbl121->setText(QString("<span style='color: rgba(30, 158, 99, %1)'>●</span>&#160;&#160;%2").arg(a).arg(t("En ligne")));
    });
    pouls->start(120);

    for (QLabel *l : {ui->lbl84, ui->lbl86, ui->lbl87}) l->setProperty("dynamique", true);
    for (QProgressBar *j : {ui->jauge12, ui->jauge13, ui->jauge14, ui->jauge15}) j->setProperty("valeurCible", j->value());
}

void Employe::mettreAJourTableauDeBord()
{
    const QVector<FicheEmploye> &liste = auth.employes();
    auto traduit = [this](const QString &fr) { return langueArabe ? traduireTexte(fr) : fr; };

    // 1. carte « Pompiers disponibles » : employés de terrain disponibles / effectif de terrain
    int terrain = 0, disponibles = 0;
    for (const FicheEmploye &f : liste) {
        if (f.fonction == "Agent administratif") continue;
        terrain++;
        if (f.statut == "Disponible") disponibles++;
    }
    ui->lbl86->setProperty("valeurCible", QString::number(disponibles));
    ui->lbl86->setText(QString::number(disponibles));
    ui->lbl87->setText(t("sur %1 · équipe B").arg(terrain));

    // 2. effectif de garde : employés de terrain présents (disponibles, puis en intervention, puis en repos)
    QVector<const FicheEmploye *> garde;
    for (const FicheEmploye &f : liste)
        if (f.fonction != "Agent administratif" && !f.statut.contains(QString::fromUtf8("congé"))) garde << &f;
    auto rang = [](const QString &statut) { return statut == "Disponible" ? 0 : statut == "En intervention" ? 1 : 2; };
    std::stable_sort(garde.begin(), garde.end(), [&](const FicheEmploye *a, const FicheEmploye *b) { return rang(a->statut) < rang(b->statut); });
    QTableWidget *effectif = ui->tblEffectifDashboard;
    effectif->setRowCount(0);
    effectif->setRowCount(garde.size());
    QFont gras = effectif->font();
    gras.setBold(true);
    for (int l = 0; l < garde.size(); ++l) {
        auto cellule = [&](int c, const QString &fr) {
            QTableWidgetItem *it = new QTableWidgetItem(traduit(fr));
            it->setData(ROLE_FRANCAIS, fr);
            effectif->setItem(l, c, it);
            return it;
        };
        cellule(0, garde[l]->prenom + " " + garde[l]->nom);
        cellule(1, garde[l]->grade);
        QTableWidgetItem *statut = cellule(2, QString::fromUtf8("● ") + garde[l]->statut);
        statut->setFont(gras);
        statut->setForeground(garde[l]->statut == "Disponible" ? QColor(30, 158, 99)
                              : garde[l]->statut == "En intervention" ? QColor(212, 138, 18) : QColor(122, 136, 150));
    }

    // 3. balise SOS : portée par le premier employé en intervention (sinon le bandeau disparaît)
    const FicheEmploye *porteur = nullptr;
    for (const FicheEmploye &f : liste) if (f.statut == "En intervention") { porteur = &f; break; }
    ui->cadreAlerteBalise->setVisible(porteur != nullptr);
    if (porteur) {
        const QString nom = porteur->prenom.left(1) + ". " + porteur->nom;
        ui->lbl84->setText(t("%1 · balise portée au cou · position GPS transmise · zone industrielle, secteur 4").arg(nom));
        carte->definirBalise(t("%1 · balise SOS").arg(nom));
    }

    // 4. « À traiter aujourd'hui » : alertes Employés calculées + exemples des autres modules
    QVector<QPair<QString, QString>> alertes;
    for (const FicheEmploye &f : liste)
        if (f.bloque) alertes.append({"Employés", QString::fromUtf8("Compte %1 bloqué").arg(f.identifiant)});
    const int incomplets = int(std::count(creneauIncomplet.begin(), creneauIncomplet.end(), true));
    if (incomplets > 0)
        alertes.append({"Employés", QString::fromUtf8("Planning : %1 créneau(x) de garde incomplet(s)").arg(incomplets)});
    for (const FicheEmploye &f : liste)
        if (f.statut.contains(QString::fromUtf8("congé"))) alertes.append({"Employés", QString::fromUtf8("%1 %2 en congé").arg(f.prenom, f.nom)});
    alertes.append({"Unités", QString::fromUtf8("VSR-01 et FPT-03 sous l'effectif minimum")});
    alertes.append({"Matériel", QString::fromUtf8("4 équipements périmés")});
    alertes.append({"Matériel", QString::fromUtf8("3 consommables sous le seuil")});
    alertes.append({"Missions", QString::fromUtf8("INT-0422 : doublon probable")});
    QTableWidget *table = ui->tblAlertesDashboard;
    table->setRowCount(0);
    table->setRowCount(alertes.size());
    for (int l = 0; l < alertes.size(); ++l) {
        QTableWidgetItem *module = new QTableWidgetItem(traduit(alertes[l].first));
        module->setData(ROLE_FRANCAIS, alertes[l].first);
        module->setFont(gras);
        if (alertes[l].first == QString::fromUtf8("Employés")) module->setForeground(QColor("#C7341A"));
        table->setItem(l, 0, module);
        QTableWidgetItem *texte = new QTableWidgetItem(alertes[l].second);
        texte->setData(ROLE_FRANCAIS, alertes[l].second);
        table->setItem(l, 1, texte);
    }
    emit tableauDeBordModifie();
}

// =============================================================================
// Page d'accueil des modules : après la connexion, un carreau par module (selon les droits).
// Chaque interface a une petite flèche en haut à gauche pour revenir à cette page.
// =============================================================================
void Employe::preparerAccueilModules()
{
    pageAccueil = ui->PMenu;                      // page 1 de SWEmploye : menu de l'application (guide d'intégration)
    pageAccueil->setAttribute(Qt::WA_StyledBackground, true);
    pageAccueil->setStyleSheet("#PMenu { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0E1319, stop:0.55 #141A22, stop:1 #24150F); }"
                               "#PMenu QLabel { background: transparent; }");
    QVBoxLayout *colonne = qobject_cast<QVBoxLayout *>(pageAccueil->layout());   // mise en page créée dans Qt Designer
    if (!colonne) colonne = new QVBoxLayout(pageAccueil);
    colonne->setContentsMargins(44, 26, 44, 22);
    colonne->setSpacing(10);

    // barre du haut : logo + nom, compte connecté, déconnexion
    QHBoxLayout *haut = new QHBoxLayout;
    QLabel *logo = new QLabel;
    logo->setPixmap(QPixmap(":/images/logo.png").scaled(40, 40, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    QLabel *marque = new QLabel(QString::fromUtf8("<span style='color:#F4F6F8; font-size:14pt; font-weight:bold'>Caserne Connectée</span><br/>"
                                                  "<span style='color:#FF8A5B; font-size:8pt; font-weight:bold'>CONSOLE DE GARDE</span>"));
    marque->setProperty("dynamique", true);
    lblCompteAccueil = new QLabel;
    lblCompteAccueil->setProperty("dynamique", true);
    QPushButton *quitter = new QPushButton(QString::fromUtf8("✕  Se déconnecter"));
    quitter->setObjectName("btnQuitterAccueil");
    quitter->setCursor(Qt::PointingHandCursor);
    quitter->setStyleSheet("QPushButton { background: transparent; color: #FF8A8A; border: 1px solid #5A2A2A; border-radius: 10px; padding: 8px 14px; font-weight: bold; }"
                           "QPushButton:hover { background: #3A1C1C; }");
    connect(quitter, &QPushButton::clicked, this, &Employe::deconnexionDemandee);
    btnEmailsAccueil = new QPushButton(QString::fromUtf8("✉  Envoi des e-mails"));
    btnEmailsAccueil->setObjectName("btnEmailsAccueil");
    btnEmailsAccueil->setCursor(Qt::PointingHandCursor);
    btnEmailsAccueil->setStyleSheet("QPushButton { background: transparent; color: #C9D3DC; border: 1px solid #2E3946; border-radius: 10px; padding: 8px 14px; font-weight: bold; }"
                                    "QPushButton:hover { background: #3A2219; border-color: #B4532E; color: #FFB08F; }");
    connect(btnEmailsAccueil, &QPushButton::clicked, this, &Employe::reglerEnvoiEmails);
    haut->addWidget(logo);
    haut->addWidget(marque);
    haut->addStretch(1);
    haut->addWidget(lblCompteAccueil);
    haut->addSpacing(12);
    haut->addWidget(btnEmailsAccueil);
    haut->addWidget(quitter);
    colonne->addLayout(haut);
    colonne->addSpacing(18);

    // titre
    lblBonjour = new QLabel;
    lblBonjour->setProperty("dynamique", true);
    lblBonjour->setStyleSheet("color: #F4F6F8; font-size: 25pt; font-weight: bold;");
    lblInvitationAccueil = new QLabel;
    lblInvitationAccueil->setProperty("dynamique", true);
    lblInvitationAccueil->setStyleSheet("color: #93A4B2; font-size: 11pt;");
    colonne->addWidget(lblBonjour);
    colonne->addWidget(lblInvitationAccueil);
    colonne->addSpacing(14);

    // grille des carreaux
    grilleModules = new QGridLayout;
    grilleModules->setSpacing(6);
    colonne->addLayout(grilleModules);
    colonne->addStretch(1);
    QLabel *pied = new QLabel(QString::fromUtf8("Protection civile · Caserne Centrale — Tunis Nord"));
    pied->setProperty("dynamique", true);
    pied->setStyleSheet("color: #5B6B7A; font-size: 8.5pt;");
    pied->setAlignment(Qt::AlignCenter);
    colonne->addWidget(pied);

    FondBraises *braises = new FondBraises(pageAccueil, 40, 0.9);   // page animée, comme la connexion
    braises->lower();

    // petite flèche « retour aux modules » en haut à gauche de chaque interface
    for (QFrame *entete : fenetre->findChildren<QFrame *>()) {
        if (entete->property("variante").toString() != "entete" || !entete->layout()) continue;
        auto *rangee = qobject_cast<QBoxLayout *>(entete->layout());
        if (!rangee) continue;
        QPushButton *retour = new QPushButton;
        retour->setObjectName("btnRetourModules");
        retour->setFixedSize(36, 36);
        retour->setCursor(Qt::PointingHandCursor);
        retour->setToolTip(QString::fromUtf8("Retour aux modules"));
        retour->setProperty("infobulleFrancais", QString::fromUtf8("Retour aux modules"));
        QPixmap fleche(64, 64);
        fleche.fill(Qt::transparent);
        {
            QPainter q(&fleche);
            q.setRenderHint(QPainter::Antialiasing);
            q.setPen(QPen(QColor("#FF8A5B"), 6.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
            q.drawLine(QPointF(44, 32), QPointF(20, 32));
            q.drawLine(QPointF(31, 20), QPointF(19, 32));
            q.drawLine(QPointF(31, 44), QPointF(19, 32));
        }
        retour->setIcon(QIcon(fleche));
        retour->setIconSize(QSize(20, 20));
        retour->setStyleSheet("QPushButton { background: #222B36; border: 1px solid #2E3946; border-radius: 18px; }"
                              "QPushButton:hover { background: #3A2219; border-color: #B4532E; }");
        connect(retour, &QPushButton::clicked, this, [this]() { afficherAccueilModules(true); });
        rangee->insertWidget(0, retour);
        rangee->insertSpacing(1, 4);
    }
}

void Employe::afficherAccueilModules(bool anime)
{
    const FicheEmploye *c = auth.trouver(identifiantConnecte);
    if (!c) return;
    const int heure = QTime::currentTime().hour();
    lblBonjour->setText((heure >= 18 || heure < 5 ? t("Bonsoir, %1") : t("Bonjour, %1")).arg(c->prenom));
    lblInvitationAccueil->setText(t("Choisissez le module dont vous avez besoin."));
    lblCompteAccueil->setText(QString("<span style='color:#F4F6F8; font-weight:bold'>%1 %2</span><br/>"
                                      "<span style='color:#93A4B2; font-size:8.5pt'>%3</span>")
                                  .arg(c->prenom.left(1) + ".", c->nom.toHtmlEscaped(), t(c->role.toUtf8().constData())));
    lblCompteAccueil->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    btnEmailsAccueil->setVisible(c->role == "Administrateur");   // réglage réservé à l'administrateur

    // carreaux reconstruits à chaque affichage (droits à jour)
    while (QLayoutItem *element = grilleModules->takeAt(0)) {
        if (element->widget()) element->widget()->deleteLater();
        delete element;
    }
    struct Infos { int module; const char *icone, *nom, *description; };
    static const Infos modules[] = {
        {M_TABLEAU, "tableau", "Tableau de bord", "Vue d'ensemble de la garde : alertes, carte des interventions, effectif."},
        {M_EMPLOYES, "user", "Employés", "Personnel, comptes, droits d'accès et planning des gardes."},
        {M_MISSIONS, "missions", "Missions", "Appels reçus, interventions en cours et clôtures."},
        {M_UNITES, "unites", "Unités", "Équipes d'intervention et affectations."},
        {M_VEHICULES, "vehicules", "Véhicules", "Flotte, disponibilité et localisation des engins."},
        {M_MATERIEL, "materiel", "Matériel", "Équipements, stocks et dates de péremption."},
        {M_FORMATION, "formation", "Formation", "Sessions, habilitations et recyclages."},
    };
    int rang = 0;
    for (const Infos &m : modules) {
        const Droit d = droitConnecte(m.module);
        const int module = m.module;
        TuileModule *tuile = new TuileModule(QString(":/images/icones/tuile_%1_orange.png").arg(m.icone), t(m.nom), t(m.description),
                                             d == DROIT_COMPLET ? t("Accès complet") : t("Lecture seule"), d != DROIT_AUCUN,
                                             [this, module]() { ouvrirModule(module); });
        tuile->setObjectName(QString("tuile_%1").arg(m.icone));
        grilleModules->addWidget(tuile, rang / 4, rang % 4);
        if (anime) tuile->apparaitre(120 + 90 * rang);
        else tuile->cacher();                       // la cascade sera lancée par animerAccueilModules()
        ++rang;
    }
    ui->barreLaterale->hide();
    ui->SWCaserne->setCurrentIndex(0);            // module Employé
    ui->SWEmploye->setCurrentIndex(1);            // page 1 : menu de l'application
}

void Employe::animerAccueilModules()
{
    int rang = 0;
    for (int i = 0; i < grilleModules->count(); ++i)
        if (auto *tuile = dynamic_cast<TuileModule *>(grilleModules->itemAt(i)->widget())) tuile->apparaitre(120 + 90 * rang++);
}

// Ouvre un module : le carreau s'agrandit jusqu'à remplir la fenêtre, puis l'interface apparaît
void Employe::ouvrirModule(int module)
{
    if (droitConnecte(module) == DROIT_AUCUN) return;
    auto ouvrir = [this, module]() {
        ui->barreLaterale->show();
        appliquerDroits();
        if (module == M_EMPLOYES) {
            ui->SWCaserne->setCurrentIndex(0);
            ui->SWEmploye->setCurrentIndex(3);    // page 3 : CRUD et métiers du module Employé
            ui->btnMEmploye->setChecked(true);
            animerEntreePage();
        } else if (module == M_TABLEAU) afficherTableauDeBord();
        else afficherModule(module);
        animerMenu();
    };
    TuileModule *tuile = nullptr;
    for (QWidget *w : pageAccueil->findChildren<QWidget *>())
        if (w->underMouse() && dynamic_cast<TuileModule *>(w)) tuile = dynamic_cast<TuileModule *>(w);
    if (!tuile || !pageAccueil->isVisible()) { ouvrir(); return; }

    // zoom du carreau vers toute la fenêtre, puis l'interface s'ouvre dessous
    new ZoomCarreau(fenetre, tuile->grab(), QRect(tuile->mapTo(fenetre, QPoint(0, 0)), tuile->size()));
    QTimer::singleShot(110, this, ouvrir);
}

// Mot de passe vérifié : coche verte (accepté) ou croix rouge (refusé) sur la carte de connexion
void Employe::animerResultatConnexion(bool accepte)
{
    new ResultatConnexion(ui->cadreConnexion, accepte);
}

void Employe::afficherTableauDeBord()
{
    if (droitConnecte(M_TABLEAU) == DROIT_AUCUN) return;
    mettreAJourTableauDeBord();
    ui->btnMTableauDeBord->setChecked(true);
    ui->SWCaserne->setCurrentIndex(0);
    ui->SWEmploye->setCurrentIndex(4);            // page 4 : tableau de bord
    carte->animerEntree();
    // barres « Interventions de la semaine » : elles se remplissent l'une après l'autre
    int rang = 0;
    for (QProgressBar *j : {ui->jauge12, ui->jauge13, ui->jauge14, ui->jauge15}) {
        j->setValue(0);
        QPropertyAnimation *a = new QPropertyAnimation(j, "value", j);
        a->setDuration(900);
        a->setStartValue(0);
        a->setEndValue(j->property("valeurCible").toInt());
        a->setEasingCurve(QEasingCurve::OutCubic);
        QTimer::singleShot(250 + 120 * rang++, a, [a]() { a->start(QAbstractAnimation::DeleteWhenStopped); });
    }
}

// Accès vérifié : le logo s'embrase sur toute la fenêtre, puis l'interface Employés s'ouvre
void Employe::jouerIntroConnexion(std::function<void()> milieu, std::function<void()> fin)
{
    const FicheEmploye *c = auth.trouver(identifiantConnecte);
    const QString nom = c ? c->prenom + " " + c->nom : QString();
    const QString role = c ? (langueArabe ? traduireTexte(c->role) : c->role) : QString();
    new IntroConnexion(fenetre, t("Caserne Connectée"), t("Bienvenue, %1").arg(nom),
                       t("%1 · accès vérifié").arg(role), milieu, fin);
}

// Le zoom relance l'application : le compte connecté retrouve sa session sans retaper son
// mot de passe (jeton à usage unique valable 20 secondes, vérifié par CaserneConnectee).
bool Employe::reprendreSession(const QString &identifiant)
{
    const FicheEmploye *compte = auth.trouver(identifiant);
    if (!compte || compte->bloque || auth.droit(*compte, M_EMPLOYES) == DROIT_AUCUN) return false;
    identifiantConnecte = compte->identifiant;
    remplirTableau(identifiantConnecte);
    afficherEmploye(ligneAffichee, 0);
    return true;
}

void Employe::fermerNotifications()
{
    for (QFrame *toast : fenetre->findChildren<QFrame *>(QString(), Qt::FindDirectChildrenOnly))
        if (toast->property("variante").toString() == "toast") toast->deleteLater();
}

void Employe::deconnecter()
{
    fermerNotifications();
    modeAjout = false;
    definirModeEdition(false);
    identifiantConnecte.clear();
    ui->txtMotDePasse->clear();
    messageConnexion(QString());
}

void Employe::quitterPageConnexion()
{
    if (fondBraises) fondBraises->hide();
}

// Thème et langue choisis dans l'en-tête : la page se met à jour
void Employe::definirModeSombre(bool sombre)
{
    modeSombre = sombre;
    for (SelecteurDroit *choix : selecteurs) choix->definirSombre(sombre);
    if (carte) carte->definirSombre(sombre);
    preparerPage();
    evaluerMotDePasse();
    appliquerDroits();
}

void Employe::definirLangueArabe(bool arabe)
{
    langueArabe = arabe;
    preparerPage();       // calendriers dans la langue choisie
    evaluerMotDePasse();
    appliquerDroits();
    texteBouton(ui->btnAjouterEmploye, modeAjout ? QString::fromUtf8("Valider l'ajout") : QString("Ajouter"), langueArabe);
    texteBouton(ui->btnModifierEmploye, modeEdition ? QString("Enregistrer") : QString("Modifier"), langueArabe);
    mettreAJourCompteurs();
    if (const FicheEmploye *f = auth.trouver(identifiantLigne(ligneAffichee)))
        ui->lblReposServiceEmploye->setText(t("Repos cumulé : %1 h · alerte à 80 % de 12h").arg(f->tempsReposCumule));
    messageConnexion(QString());
    messageOublie(QString());
    for (SelecteurDroit *choix : selecteurs) choix->definirArabe(langueArabe);
    activerSelecteurs();
}

// =============================================================================
// Mot de passe oublié : e-mail -> code à 6 chiffres (15 min, usage unique) -> nouveau mot de passe
// =============================================================================
void Employe::messageOublie(const QString &texte, bool info)
{
    ui->lblMessageOublie->setText(texte);
    ui->lblMessageOublie->setProperty("etat", info ? "info" : "");
    ui->lblMessageOublie->style()->unpolish(ui->lblMessageOublie);
    ui->lblMessageOublie->style()->polish(ui->lblMessageOublie);
    ui->lblMessageOublie->setVisible(!texte.isEmpty());
}

// La pile des étapes prend la hauteur de l'étape affichée (pas celle de la plus grande)
static void afficherEtape(QStackedWidget *pile, int etape)
{
    pile->setCurrentIndex(etape);
    for (int i = 0; i < pile->count(); ++i)
        pile->widget(i)->setSizePolicy(QSizePolicy::Preferred, i == etape ? QSizePolicy::Preferred : QSizePolicy::Ignored);
    pile->adjustSize();
    pile->updateGeometry();
}

void Employe::preparerMotDePasseOublie()
{
    minuteurCode->stop();
    emailReinitialisation.clear();
    fermerNotifications();
    afficherEtape(ui->pileEtapesOublie, 0);
    ui->lblTexteOublie->setText(t("Saisissez l'adresse e-mail de votre compte : vous recevrez un code à 6 chiffres valable 15 minutes."));
    // l'adresse du compte saisi sur la page de connexion est proposée
    const FicheEmploye *f = auth.trouver(ui->txtIdentifiant->text());
    ui->txtEmailOublie->setText(f ? f->email : QString());
    ui->txtCodeOublie->clear();
    ui->txtNouveauMotDePasseOublie->clear();
    ui->txtConfirmationOublie->clear();
    messageOublie(QString());
    messageConnexion(QString());
    ui->txtEmailOublie->setFocus();
}

// =============================================================================
// Envoi réel des e-mails (SMTP sécurisé)
// =============================================================================
static QByteArray masquer(const QString &texte)          // le mot de passe n'est pas gardé en clair dans les réglages
{
    QByteArray d = texte.toUtf8();
    const QByteArray cle = QByteArray("CaserneConnectee-ESPRIT-2A27");
    for (int i = 0; i < d.size(); ++i) d[i] = char(d[i] ^ cle[i % cle.size()]);
    return d.toBase64();
}
static QString demasquer(const QByteArray &b64)
{
    QByteArray d = QByteArray::fromBase64(b64);
    const QByteArray cle = QByteArray("CaserneConnectee-ESPRIT-2A27");
    for (int i = 0; i < d.size(); ++i) d[i] = char(d[i] ^ cle[i % cle.size()]);
    return QString::fromUtf8(d);
}

ReglagesEmail ReglagesEmail::charger()
{
    QSettings q("ESPRIT", "CaserneConnectee");
    ReglagesEmail r;
    r.serveur = q.value("email/serveur", r.serveur).toString();
    r.port = q.value("email/port", r.port).toInt();
    r.adresse = q.value("email/adresse").toString();
    r.motDePasse = demasquer(q.value("email/motDePasse").toByteArray());
    r.nom = q.value("email/nom", r.nom).toString();
    return r;
}

void ReglagesEmail::enregistrer() const
{
    QSettings q("ESPRIT", "CaserneConnectee");
    q.setValue("email/serveur", serveur);
    q.setValue("email/port", port);
    q.setValue("email/adresse", adresse);
    q.setValue("email/motDePasse", masquer(motDePasse));
    q.setValue("email/nom", nom);
}

void EnvoiEmail::envoyer(const ReglagesEmail &r, const QString &destinataire, const QString &sujet, const QString &html,
                         std::function<void(bool, QString)> fin)
{
    new EnvoiEmail(r, destinataire, sujet, html, fin);      // il se détruit tout seul à la fin
}

EnvoiEmail::EnvoiEmail(const ReglagesEmail &r, const QString &destinataire, const QString &sujet, const QString &html,
                       std::function<void(bool, QString)> fin)
    : QObject(qApp), reglages(r), destinataire(destinataire), sujet(sujet), html(html), fin(fin)
{
    socket = new QSslSocket(this);
    connect(socket, &QSslSocket::readyRead, this, [this]() { lire(); });
    connect(socket, &QAbstractSocket::errorOccurred, this, [this]() {
        terminer(false, QString::fromUtf8("Connexion au serveur impossible : %1").arg(socket->errorString()));
    });
    connect(socket, &QSslSocket::encrypted, this, [this]() { if (etape == 3) { etape = 4; envoyerLigne("EHLO caserne-connectee"); } });
    connect(socket, &QSslSocket::sslErrors, this, [this](const QList<QSslError> &erreurs) {
        QStringList textes;
        for (const QSslError &e : erreurs) textes << e.errorString();
        terminer(false, QString::fromUtf8("Connexion sécurisée refusée : %1").arg(textes.join(", ")));
    });
    QTimer::singleShot(25000, this, [this]() { terminer(false, QString::fromUtf8("Le serveur ne répond pas (délai dépassé).")); });
    if (reglages.port == 465) socket->connectToHostEncrypted(reglages.serveur, quint16(reglages.port));   // SSL direct
    else socket->connectToHost(reglages.serveur, quint16(reglages.port));                                 // STARTTLS (587)
}

void EnvoiEmail::envoyerLigne(const QByteArray &ligne) { socket->write(ligne + "\r\n"); }

// Les réponses du serveur : « 250-… » (suite) puis « 250 … » (dernière ligne)
void EnvoiEmail::lire()
{
    tampon += socket->readAll();
    while (true) {
        const int fin = int(tampon.indexOf("\r\n"));
        if (fin < 0) return;
        const QByteArray ligne = tampon.left(fin);
        tampon.remove(0, fin + 2);
        if (ligne.size() >= 4 && ligne[3] == '-') continue;
        reponse(ligne.left(3).toInt(), QString::fromUtf8(ligne.mid(4)));
    }
}

void EnvoiEmail::reponse(int code, const QString &texte)
{
    auto attendu = [&](int voulu) {
        if (code == voulu) return true;
        QString explication = texte;
        if (code == 535 || code == 534) explication = QString::fromUtf8("adresse ou mot de passe refusé (pour Gmail : utilisez un « mot de passe d'application »)");
        terminer(false, QString::fromUtf8("Le serveur a refusé l'envoi (%1 : %2)").arg(code).arg(explication));
        return false;
    };
    const bool starttls = reglages.port != 465;
    switch (etape) {
    case 0: if (!attendu(220)) return; etape = 1; envoyerLigne("EHLO caserne-connectee"); break;
    case 1: if (!attendu(250)) return;
        if (starttls) { etape = 2; envoyerLigne("STARTTLS"); }
        else { etape = 5; envoyerLigne("AUTH LOGIN"); }
        break;
    case 2: if (!attendu(220)) return; etape = 3; socket->startClientEncryption(); break;   // puis EHLO (signal encrypted)
    case 4: if (!attendu(250)) return; etape = 5; envoyerLigne("AUTH LOGIN"); break;
    case 5: if (!attendu(334)) return; etape = 6; envoyerLigne(reglages.adresse.toUtf8().toBase64()); break;
    case 6: if (!attendu(334)) return; etape = 7; envoyerLigne(reglages.motDePasse.toUtf8().toBase64()); break;
    case 7: if (!attendu(235)) return; etape = 8; envoyerLigne("MAIL FROM:<" + reglages.adresse.toUtf8() + ">"); break;
    case 8: if (!attendu(250)) return; etape = 9; envoyerLigne("RCPT TO:<" + destinataire.toUtf8() + ">"); break;
    case 9: if (code != 250 && code != 251) { attendu(250); return; } etape = 10; envoyerLigne("DATA"); break;
    case 10: {
        if (!attendu(354)) return;
        etape = 11;
        auto entete = [](const QString &t) { return "=?UTF-8?B?" + t.toUtf8().toBase64() + "?="; };
        QByteArray corps = html.toUtf8().toBase64();
        QByteArray decoupe;
        for (int i = 0; i < corps.size(); i += 76) decoupe += corps.mid(i, 76) + "\r\n";
        QByteArray message;
        message += "From: " + entete(reglages.nom) + " <" + reglages.adresse.toUtf8() + ">\r\n";
        message += "To: <" + destinataire.toUtf8() + ">\r\n";
        message += "Subject: " + entete(sujet) + "\r\n";
        const QDateTime maintenant = QDateTime::currentDateTime();
        const int decalage = maintenant.offsetFromUtc() / 60;            // fuseau horaire au format +0100
        const QString fuseau = QString("%1%2%3").arg(decalage < 0 ? '-' : '+').arg(qAbs(decalage) / 60, 2, 10, QChar('0')).arg(qAbs(decalage) % 60, 2, 10, QChar('0'));
        message += "Date: " + QLocale::c().toString(maintenant, "ddd, dd MMM yyyy HH:mm:ss").toUtf8() + " " + fuseau.toUtf8() + "\r\n";
        message += "Message-ID: <" + QByteArray::number(QDateTime::currentMSecsSinceEpoch()) + "@caserne-connectee>\r\n";
        message += "MIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n";
        message += decoupe;
        socket->write(message + "\r\n.\r\n");
        break;
    }
    case 11: if (!attendu(250)) return; envoyerLigne("QUIT"); terminer(true, QString()); break;
    default: break;
    }
}

void EnvoiEmail::terminer(bool ok, const QString &message)
{
    if (fini) return;
    fini = true;
    if (fin) fin(ok, message);
    socket->disconnectFromHost();
    deleteLater();
}

// Fenêtre « Envoi des e-mails » : réglages SMTP + e-mail de test
void Employe::reglerEnvoiEmails()
{
    ReglagesEmail r = ReglagesEmail::charger();
    QDialog fenetreReglages(fenetre);
    fenetreReglages.setWindowTitle(t("Envoi des e-mails"));
    fenetreReglages.setMinimumWidth(470);
    fenetreReglages.setStyleSheet("QDialog { background: #19212A; } QLabel { color: #E6EBF0; background: transparent; }"
                                  "QLineEdit, QSpinBox { background: #0F141A; color: #F4F6F8; border: 1px solid #2E3946; border-radius: 8px; padding: 6px 8px; }"
                                  "QLineEdit:focus, QSpinBox:focus { border-color: #E4491F; }"
                                  "QPushButton { background: #222B36; color: #E6EBF0; border: 1px solid #2E3946; border-radius: 9px; padding: 8px 14px; font-weight: bold; }"
                                  "QPushButton:hover { background: #3A2219; border-color: #B4532E; }"
                                  "QPushButton#principal { background: #E4491F; border-color: #E4491F; color: white; }");
    QVBoxLayout *colonne = new QVBoxLayout(&fenetreReglages);
    QLabel *titre = new QLabel(t("Envoi réel des codes « mot de passe oublié »"));
    titre->setStyleSheet("font-size: 13pt; font-weight: bold; color: #F4F6F8;");
    QLabel *aide = new QLabel(t("Gmail : serveur smtp.gmail.com, port 465. Activez la validation en deux étapes de votre compte Google, "
                                "puis créez un « mot de passe d'application » (Compte Google > Sécurité > Mots de passe des applications) "
                                "et collez-le ci-dessous."));
    aide->setWordWrap(true);
    aide->setStyleSheet("color: #93A4B2; font-size: 9pt;");
    QFormLayout *formulaire = new QFormLayout;
    QLineEdit *serveur = new QLineEdit(r.serveur);
    QSpinBox *port = new QSpinBox;
    port->setRange(1, 65535);
    port->setValue(r.port);
    port->setButtonSymbols(QAbstractSpinBox::NoButtons);
    QLineEdit *adresse = new QLineEdit(r.adresse);
    adresse->setPlaceholderText("exemple@gmail.com");
    QLineEdit *motDePasse = new QLineEdit(r.motDePasse);
    motDePasse->setEchoMode(QLineEdit::Password);
    motDePasse->setPlaceholderText(t("mot de passe d'application (16 lettres)"));
    ajouterOeil(motDePasse);
    QLineEdit *nom = new QLineEdit(r.nom);
    formulaire->addRow(t("Serveur SMTP"), serveur);
    formulaire->addRow(t("Port (465 ou 587)"), port);
    formulaire->addRow(t("Adresse d'envoi"), adresse);
    formulaire->addRow(t("Mot de passe"), motDePasse);
    formulaire->addRow(t("Nom de l'expéditeur"), nom);
    QLabel *etat = new QLabel;
    etat->setWordWrap(true);
    QHBoxLayout *boutons = new QHBoxLayout;
    QPushButton *test = new QPushButton(t("Envoyer un e-mail de test"));
    QPushButton *annuler = new QPushButton(t("Annuler"));
    QPushButton *enregistrer = new QPushButton(t("Enregistrer"));
    enregistrer->setObjectName("principal");
    boutons->addWidget(test);
    boutons->addStretch(1);
    boutons->addWidget(annuler);
    boutons->addWidget(enregistrer);
    colonne->addWidget(titre);
    colonne->addWidget(aide);
    colonne->addSpacing(6);
    colonne->addLayout(formulaire);
    colonne->addWidget(etat);
    colonne->addLayout(boutons);
    auto lireFormulaire = [&]() {
        ReglagesEmail x;
        x.serveur = serveur->text().trimmed();
        x.port = port->value();
        x.adresse = adresse->text().trimmed();
        x.motDePasse = motDePasse->text().remove(' ');
        x.nom = nom->text().trimmed();
        return x;
    };
    connect(annuler, &QPushButton::clicked, &fenetreReglages, &QDialog::reject);
    connect(enregistrer, &QPushButton::clicked, &fenetreReglages, [&]() { lireFormulaire().enregistrer(); fenetreReglages.accept(); });
    QPointer<QLabel> etatSur(etat);
    QPointer<QPushButton> testSur(test);
    connect(test, &QPushButton::clicked, &fenetreReglages, [&, etatSur, testSur]() {
        const ReglagesEmail x = lireFormulaire();
        if (!x.configure()) { etat->setStyleSheet("color: #F08080;"); etat->setText(t("Remplissez l'adresse et le mot de passe.")); return; }
        etat->setStyleSheet("color: #93A4B2;");
        etat->setText(t("Envoi en cours…"));
        test->setEnabled(false);
        EnvoiEmail::envoyer(x, x.adresse, QString::fromUtf8("Caserne Connectée — e-mail de test"),
                            QString::fromUtf8("<p>Bonjour,</p><p>L'envoi des e-mails de <b>Caserne Connectée</b> fonctionne.</p>"),
                            [this, etatSur, testSur, x](bool ok, const QString &erreur) {
            if (testSur) testSur->setEnabled(true);
            if (!etatSur) return;
            etatSur->setStyleSheet(ok ? "color: #5FD39B;" : "color: #F08080;");
            etatSur->setText(ok ? t("E-mail de test envoyé à %1.").arg(x.adresse) : erreur);
        });
    });
    fenetreReglages.exec();
}

void Employe::envoyerCode()
{
    const bool renvoi = sender() == ui->btnRenvoyerCode;
    const QString email = renvoi ? emailReinitialisation : ui->txtEmailOublie->text().trimmed().toLower();
    if (!emailValide(email)) {
        secouer(ui->cadreMotDePasseOublie);
        messageOublie(t("Saisissez une adresse e-mail valide."));
        return;
    }
    QString code;
    if (auth.genererCode(email, &code) == Authentification::Reinitialisation::EmailInconnu) {
        secouer(ui->cadreMotDePasseOublie);
        messageOublie(t("Aucun compte n'est associé à cette adresse e-mail."));
        return;
    }
    emailReinitialisation = email;

    // ---- Envoi du code ----
    // Envoi réel par SMTP si l'administrateur a réglé l'envoi des e-mails (page des modules) ;
    // sinon (ou si l'envoi échoue), le code est affiché dans une notification pour pouvoir continuer.
    const ReglagesEmail reglages = ReglagesEmail::charger();
    if (reglages.configure()) {
        const QString html = QString::fromUtf8(
            "<div style='font-family:Arial,sans-serif;max-width:520px;margin:auto;border:1px solid #E1E6EC;border-radius:12px;overflow:hidden'>"
            "<div style='background:#16202A;padding:18px 22px'><span style='color:#FF8A5B;font-size:11px;font-weight:bold'>PROTECTION CIVILE · CASERNE CENTRALE</span><br/>"
            "<span style='color:#FFFFFF;font-size:20px;font-weight:bold'>Caserne Connectée</span></div>"
            "<div style='padding:22px;color:#16202A'><p>Bonjour,</p><p>Voici votre code pour choisir un nouveau mot de passe :</p>"
            "<p style='font-size:30px;font-weight:bold;letter-spacing:8px;color:#E4491F;text-align:center;margin:18px 0'>%1</p>"
            "<p>Ce code est valable <b>15 minutes</b> et ne peut servir <b>qu'une seule fois</b>.</p>"
            "<p style='color:#7A8896;font-size:12px'>Si vous n'avez rien demandé, ignorez cet e-mail : votre mot de passe ne change pas.</p></div></div>").arg(code);
        messageOublie(t("Envoi de l'e-mail en cours…"), true);
        QPointer<Employe> moi(this);
        EnvoiEmail::envoyer(reglages, email, QString::fromUtf8("Votre code Caserne Connectée"), html,
                            [moi, email, code](bool ok, const QString &erreur) {
            if (!moi) return;
            if (ok) {
                moi->messageOublie(moi->t("Code envoyé par e-mail à %1.").arg(email), true);
                moi->afficherNotification(moi->t("E-mail envoyé"), moi->t("Le code a été envoyé à %1. Pensez à vérifier les courriers indésirables.").arg(email),
                                          ":/images/icones/tuile_bell_rouge.png", 8000);
            } else {
                moi->messageOublie(moi->t("L'e-mail n'a pas pu être envoyé."));
                moi->afficherNotification(moi->t("Envoi impossible — code affiché ici"),
                                          erreur + "\n" + moi->t("Votre code : %1 (valable 15 minutes, usage unique)").arg(code),
                                          ":/images/icones/tuile_bell_rouge.png", 20000);
            }
        });
    } else {
        afficherNotification(t("E-mail envoyé (simulation)"),
                             t("À %1 — votre code : %2 (valable 15 minutes, usage unique). Pour un envoi réel, l'administrateur règle « Envoi des e-mails » sur la page des modules.").arg(email, code),
                             ":/images/icones/tuile_bell_rouge.png", 15000);
    }

    // Étape 2 : le code + le nouveau mot de passe (la carte glisse vers l'étape suivante)
    ui->lblTexteOublie->setText(t("Un code à 6 chiffres a été envoyé à %1. Saisissez-le puis choisissez un nouveau mot de passe.").arg(email));
    ui->txtCodeOublie->clear();
    messageOublie(renvoi ? t("Nouveau code envoyé : l'ancien n'est plus valable.") : QString(), true);
    if (ui->pileEtapesOublie->currentIndex() != 1) {
        afficherEtape(ui->pileEtapesOublie, 1);
        QWidget *etape = ui->pileEtapesOublie->currentWidget();
        QGraphicsOpacityEffect *effet = new QGraphicsOpacityEffect(etape);
        etape->setGraphicsEffect(effet);
        QPropertyAnimation *fondu = new QPropertyAnimation(effet, "opacity", etape);
        fondu->setDuration(380);
        fondu->setStartValue(0.0);
        fondu->setEndValue(1.0);
        fondu->setEasingCurve(QEasingCurve::OutCubic);
        connect(fondu, &QPropertyAnimation::finished, etape, [etape]() { etape->setGraphicsEffect(nullptr); });
        fondu->start(QAbstractAnimation::DeleteWhenStopped);
    }
    minuteurCode->start();
    mettreAJourMinuteur();
    ui->txtCodeOublie->setFocus();
}

void Employe::mettreAJourMinuteur()
{
    QLabel *l = ui->lblMinuteurCode;
    const QDateTime fin = auth.expirationCode(emailReinitialisation);
    const qint64 secondes = fin.isValid() ? QDateTime::currentDateTimeUtc().secsTo(fin) : -1;
    QString etat;
    if (secondes > 0) {
        l->setText(t("Code valable encore %1").arg(QString("%1:%2").arg(secondes / 60, 2, 10, QChar('0')).arg(secondes % 60, 2, 10, QChar('0'))));
    } else {
        l->setText(fin.isValid() ? t("Code expiré : cliquez sur « Renvoyer un code ».") : t("Code annulé : cliquez sur « Renvoyer un code »."));
        etat = "expire";
        minuteurCode->stop();
    }
    if (l->property("etat").toString() != etat) {
        l->setProperty("etat", etat);
        l->style()->unpolish(l);
        l->style()->polish(l);
    }
}

void Employe::validerNouveauMotDePasse()
{
    const QString code = ui->txtCodeOublie->text().trimmed();
    const QString nouveau = ui->txtNouveauMotDePasseOublie->text();
    QString raison;
    auto refuser = [this](const QString &texte, QWidget *champ) {
        secouer(ui->cadreMotDePasseOublie);
        messageOublie(texte);
        if (champ) champ->setFocus();
    };
    if (code.length() != 6) return refuser(t("Le code contient 6 chiffres."), ui->txtCodeOublie);
    if (!Authentification::motDePasseValide(nouveau, &raison))
        return refuser(langueArabe ? traduireTexte(raison) : raison, ui->txtNouveauMotDePasseOublie);
    if (ui->txtConfirmationOublie->text() != nouveau)
        return refuser(t("Les mots de passe ne correspondent pas."), ui->txtConfirmationOublie);

    switch (auth.reinitialiser(emailReinitialisation, code, nouveau)) {
    case Authentification::Reinitialisation::Ok:
        break;
    case Authentification::Reinitialisation::CodeIncorrect:
        ui->txtCodeOublie->selectAll();
        return refuser(t("Code incorrect. Vérifiez le code reçu par e-mail."), ui->txtCodeOublie);
    case Authentification::Reinitialisation::CodeExpire:
        mettreAJourMinuteur();
        return refuser(t("Ce code a expiré (15 minutes) : demandez un nouveau code."), nullptr);
    case Authentification::Reinitialisation::MotDePasseInvalide:
        return refuser(langueArabe ? traduireTexte(raison) : raison, ui->txtNouveauMotDePasseOublie);
    default:   // code déjà utilisé, annulé après trop d'essais, ou aucun code
        mettreAJourMinuteur();
        return refuser(t("Ce code n'est plus valable (déjà utilisé ou trop d'essais) : demandez un nouveau code."), nullptr);
    }

    // Réussite : le code est consommé, le compte est débloqué, retour à la connexion
    minuteurCode->stop();
    fermerNotifications();
    const FicheEmploye *f = auth.trouverParEmail(emailReinitialisation);
    if (f) ui->txtIdentifiant->setText(f->identifiant);
    ui->txtCodeOublie->clear();
    ui->txtNouveauMotDePasseOublie->clear();
    ui->txtConfirmationOublie->clear();
    emailReinitialisation.clear();
    remplirTableau(identifiantLigne(ligneAffichee));
    emit motDePasseReinitialise();
    messageConnexion(t("Mot de passe réinitialisé : vous pouvez vous connecter."), true);
    ui->txtMotDePasse->setFocus();
    new MessageAnime(fenetre, MessageAnime::Succes, t("Mot de passe modifié"),
                     t("Votre compte est débloqué. Connectez-vous avec votre nouveau mot de passe."), false);
}

// =============================================================================
// Gestion des employés : ajouter, modifier, supprimer (avec message animé)
// =============================================================================
void Employe::ajouterEmploye()
{
    if (droitConnecte(M_EMPLOYES) != DROIT_COMPLET) return;
    if (!modeAjout) {                              // 1er clic : fiche vierge + mot de passe du nouveau compte
        definirModeAjout(true);
        afficherNotification(t("Nouvel employé"), t("Remplissez la fiche et choisissez un mot de passe, puis cliquez sur « Valider l'ajout »."),
                             ":/images/icones/tuile_user_orange.png");
        return;
    }
    FicheEmploye f = ficheDuFormulaire();
    if (!ui->cbRoleEmploye->isEnabled()) { f.role = "Agent"; f.droits = Authentification::droitsParDefaut("Agent"); }
    if (!verifierFormulaire(f, QString(), true)) return;
    f.service = serviceParDefaut(f.statut);
    if (!auth.ajouter(f, ui->txtMotDePasseEmploye->text())) {
        afficherNotification(t("Ajout impossible"), t("Cet identifiant ou cette adresse e-mail est déjà utilisé."));
        return;
    }
    if (!photoAjout.isNull()) photos.insert(f.identifiant, photoAjout);
    definirModeAjout(false);
    ui->txtRechercheEmploye->blockSignals(true);         // le nouvel employé doit être visible
    ui->txtRechercheEmploye->clear();
    ui->txtRechercheEmploye->blockSignals(false);
    recherche.clear();
    remplirTableau(f.identifiant);
    afficherEmploye(ligneAffichee, 0);
    appliquerDroits();
    surlignerLigne(ligneAffichee, QColor("#E4491F"), 1800, true);
    new MessageAnime(fenetre, MessageAnime::Succes, t("Employé ajouté avec succès"),
                     t("%1 %2 · compte « %3 » créé").arg(f.prenom, f.nom, f.identifiant), modeSombre);
}

void Employe::modifierCompte()
{
    if (droitConnecte(M_EMPLOYES) != DROIT_COMPLET || modeAjout) return;
    if (!modeEdition) { definirModeEdition(true); return; }   // 1er clic : mode édition (mot de passe facultatif)

    const QString ancien = identifiantLigne(ligneAffichee);
    const FicheEmploye *avant = auth.trouver(ancien);
    if (!avant) return;
    FicheEmploye f = ficheDuFormulaire();
    if (!verifierFormulaire(f, ancien, false)) return;
    if (ancien == identifiantConnecte && f.role != avant->role) {
        secouer(ui->cadreFormulaireEmploye);
        afficherNotification(t("Modification refusée"), t("Vous ne pouvez pas changer le rôle de votre propre compte."));
        return;
    }
    if (avant->role == "Administrateur" && f.role != "Administrateur" && auth.nombreAdministrateurs() <= 1) {
        secouer(ui->cadreFormulaireEmploye);
        afficherNotification(t("Modification refusée"), t("La caserne doit garder au moins un administrateur."));
        return;
    }
    f.service = f.statut == avant->statut ? avant->service : serviceParDefaut(f.statut);
    const bool etaitBloque = avant->bloque;
    const QString nouveauMotDePasse = ui->txtMotDePasseEmploye->text();
    if (!auth.modifier(ancien, f, nouveauMotDePasse)) return;

    if (ancien == identifiantConnecte) identifiantConnecte = f.identifiant;
    if (photos.contains(ancien) && ancien != f.identifiant) photos.insert(f.identifiant, photos.take(ancien));
    definirModeEdition(false);
    remplirTableau(f.identifiant);
    afficherEmploye(ligneAffichee, 0);
    appliquerDroits();
    surlignerLigne(ligneAffichee, QColor("#E4491F"), 1500, true);
    QString detail = t("%1 %2 · fiche enregistrée").arg(f.prenom, f.nom);
    if (!nouveauMotDePasse.isEmpty()) detail += t(" · mot de passe changé");
    if (etaitBloque) detail += t(" · compte débloqué");
    new MessageAnime(fenetre, MessageAnime::Succes, t("Employé ajouté avec succès"), detail, modeSombre);
}

// Pastille rouge avec une corbeille (boîte de confirmation de suppression)
static QPixmap iconeSuppression(int taille, qreal ratio)
{
    QPixmap image(QSize(taille, taille) * ratio);
    image.setDevicePixelRatio(ratio);
    image.fill(Qt::transparent);
    QPainter p(&image);
    p.setRenderHint(QPainter::Antialiasing);
    p.setPen(Qt::NoPen);
    p.setBrush(QColor("#FCE9E9"));
    p.drawEllipse(QRectF(0, 0, taille, taille));
    p.translate(taille / 2.0, taille / 2.0);
    p.scale(taille / 64.0, taille / 64.0);
    p.setPen(QPen(QColor("#D93636"), 3.2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    p.setBrush(Qt::NoBrush);
    QPainterPath corps;
    corps.moveTo(-11, -7);
    corps.lineTo(-9, 15);
    corps.lineTo(9, 15);
    corps.lineTo(11, -7);
    p.drawPath(corps);
    p.drawLine(QPointF(-4, -1), QPointF(-3.5, 9));
    p.drawLine(QPointF(4, -1), QPointF(3.5, 9));
    p.drawLine(QPointF(-15, -11), QPointF(15, -11));
    p.drawLine(QPointF(-5, -11), QPointF(-4, -16));
    p.drawLine(QPointF(-4, -16), QPointF(4, -16));
    p.drawLine(QPointF(4, -16), QPointF(5, -11));
    return image;
}

void Employe::supprimerEmploye()
{
    if (droitConnecte(M_EMPLOYES) != DROIT_COMPLET) return;
    if (modeAjout || modeEdition) annuler();
    const int ligne = ligneAffichee;
    const QString identifiant = identifiantLigne(ligne);
    const FicheEmploye *f = auth.trouver(identifiant);
    if (!f) return;
    if (identifiant == identifiantConnecte) {
        secouer(ui->cadreFormulaireEmploye);
        afficherNotification(t("Suppression refusée"), t("Impossible de supprimer le compte avec lequel vous êtes connecté."));
        return;
    }
    if (f->role == "Administrateur" && auth.nombreAdministrateurs() <= 1) {
        afficherNotification(t("Suppression refusée"), t("La caserne doit garder au moins un administrateur."));
        return;
    }

    const QString nomComplet = f->prenom + " " + f->nom;
    QMessageBox confirmation(QMessageBox::NoIcon, t("Supprimer un employé"),
                             t("Supprimer %1 et son compte « %2 » ? Cette action est définitive.").arg(nomComplet, identifiant),
                             QMessageBox::NoButton, fenetre);
    confirmation.setIconPixmap(iconeSuppression(48, fenetre->devicePixelRatioF()));
    confirmation.setProperty("variante", "confirmation");
    QPushButton *oui = confirmation.addButton(t("Supprimer"), QMessageBox::DestructiveRole);
    oui->setProperty("variante", "dangerPlein");
    oui->style()->unpolish(oui);
    oui->style()->polish(oui);
    oui->setCursor(Qt::PointingHandCursor);
    QPushButton *non = confirmation.addButton(t("Annuler"), QMessageBox::RejectRole);
    non->setCursor(Qt::PointingHandCursor);
    confirmation.setDefaultButton(non);
    confirmation.exec();
    if (confirmation.clickedButton() != oui) return;

    // La ligne rougit puis disparaît ; le message animé confirme la suppression
    QWidget *bande = surlignerLigne(ligne, QColor("#D93636"), 420, false);
    QTimer::singleShot(440, this, [this, ligne, identifiant, nomComplet, bande]() {
        if (bande) bande->deleteLater();
        auth.supprimer(identifiant);
        photos.remove(identifiant);
        const int suivante = qMin(ligne, int(auth.employes().size()) - 1);
        remplirTableau(suivante >= 0 ? auth.employes()[suivante].identifiant : QString());
        if (suivante >= 0) afficherEmploye(ligneAffichee, 0);
        new MessageAnime(fenetre, MessageAnime::Suppression, t("Employé supprimé"),
                         t("%1 et son compte « %2 » ont été supprimés").arg(nomComplet, identifiant), modeSombre);
    });
}

void Employe::annuler()
{
    definirModeAjout(false);
    definirModeEdition(false);
    afficherEmploye(ligneAffichee, 0);
}

void Employe::definirModeEdition(bool actif)
{
    modeEdition = actif;
    afficherMotDePasse(actif);
    texteBouton(ui->btnModifierEmploye, actif ? QString("Enregistrer") : QString("Modifier"), langueArabe);
}

void Employe::definirModeAjout(bool actif)
{
    modeAjout = actif;
    texteBouton(ui->btnAjouterEmploye, actif ? QString::fromUtf8("Valider l'ajout") : QString("Ajouter"), langueArabe);
    photoAjout = QPixmap();
    if (!actif) return;
    definirModeEdition(false);
    ui->tblEmploye->clearSelection();
    for (QLineEdit *e : {ui->txtNomEmploye, ui->txtPrenomEmploye, ui->txtEmailEmploye, ui->txtIdentifiantEmploye,
                         ui->txtHabilitationsEmploye}) e->clear();
    choisirDansCombo(ui->cbGradeEmploye, "Sapeur");
    choisirDansCombo(ui->cbFonctionEmploye, QString::fromUtf8("Pompier opérationnel"));
    choisirDansCombo(ui->cbStatutEmploye, "Disponible");
    choisirDansCombo(ui->cbRoleEmploye, "Agent");
    afficherDroitsFiche(Authentification::droitsParDefaut("Agent"), true);
    activerSelecteurs();
    ui->dateEntreeEmploye->setDate(QDate::currentDate());
    ui->spinReposEmploye->setValue(0);
    ui->btnPhotoEmploye->setIcon(QIcon(":/images/icones/photo_orange.png"));
    ui->btnPhotoEmploye->setIconSize(QSize(28, 28));
    afficherMotDePasse(true);
    ui->txtNomEmploye->setFocus();
}

void Employe::preparerPage()
{
    // Tableau des employés : les colonnes se partagent la largeur, l'ID reste étroit
    QHeaderView *entete = ui->tblEmploye->horizontalHeader();
    entete->setSectionResizeMode(QHeaderView::Stretch);
    entete->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    entete->setSectionResizeMode(4, QHeaderView::ResizeToContents);   // « ● En intervention » sur une ligne

    // Les cases colorées (J / N / R du planning) gardent leur couleur de fond malgré la
    // feuille de style : ce délégué peint lui-même le fond de chaque case.
    ui->tblPlanningEmploye->setItemDelegate(new FondCasesEmploye(ui->tblPlanningEmploye));

    // Planning : les largeurs de colonnes sont réglées par genererPlanning()
    ui->tblPlanningEmploye->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);

    // Calendriers aux couleurs de la charte : jours de la semaine en gris, week-end en orange
    for (QDateEdit *date : {ui->dateEntreeEmploye, ui->datePlanningEmploye}) {
        QCalendarWidget *calendrier = date->calendarWidget();
        calendrier->setLocale(langueArabe ? QLocale(QLocale::Arabic, QLocale::Tunisia) : QLocale(QLocale::French, QLocale::France));
        calendrier->setFirstDayOfWeek(Qt::Monday);
        calendrier->setVerticalHeaderFormat(QCalendarWidget::NoVerticalHeader);
        calendrier->setGridVisible(false);
        QTextCharFormat jours;
        jours.setForeground(QColor(modeSombre ? "#7F8C99" : "#8B99A6"));
        jours.setFontWeight(QFont::Bold);
        calendrier->setHeaderTextFormat(jours);
        QTextCharFormat weekend;
        weekend.setForeground(QColor("#E4491F"));
        calendrier->setWeekdayTextFormat(Qt::Saturday, weekend);
        calendrier->setWeekdayTextFormat(Qt::Sunday, weekend);
    }

}

// Les cases « nouveau mot de passe » apparaissent en douceur (fondu + dépliage)
void Employe::afficherMotDePasse(bool visible)
{
    QFrame *cadre = ui->cadreMotDePasseEmploye;
    ui->txtMotDePasseEmploye->clear();
    ui->txtConfirmationMotDePasseEmploye->clear();
    ui->txtMotDePasseEmploye->setEchoMode(QLineEdit::Password);
    ui->txtConfirmationMotDePasseEmploye->setEchoMode(QLineEdit::Password);
    if (!visible) { cadre->hide(); return; }

    // Ajout : mot de passe du compte + vérification (obligatoires).
    // Modification (bouton « Modifier ») : nouveau mot de passe facultatif + vérification.
    auto libelle = [this](QLabel *l, const char *fr) {
        l->setProperty("texteFrancais", QString::fromUtf8(fr));
        l->setText(t(fr));
    };
    auto indice = [this](QLineEdit *e, const char *fr) {
        e->setProperty("indiceFrancais", QString::fromUtf8(fr));
        e->setPlaceholderText(t(fr));
    };
    if (modeAjout) {
        libelle(ui->lblTitreMotDePasseEmploye, "MOT DE PASSE DU COMPTE");
        libelle(ui->lblMotDePasseEmploye, "Mot de passe");
        indice(ui->txtMotDePasseEmploye, "8 caractères minimum");
        libelle(ui->lblNoteMotDePasseEmploye, "Obligatoire : l'employé se connectera avec ce mot de passe. "
                                              "Il est haché avant l'enregistrement et n'est jamais affiché.");
    } else {
        libelle(ui->lblTitreMotDePasseEmploye, "MODIFIER LE MOT DE PASSE");
        libelle(ui->lblMotDePasseEmploye, "Nouveau");
        indice(ui->txtMotDePasseEmploye, "Laisser vide pour le garder");
        libelle(ui->lblNoteMotDePasseEmploye, "Facultatif : laisser vide pour garder le mot de passe actuel. "
                                              "Il est haché avant l'enregistrement et n'est jamais affiché.");
    }
    libelle(ui->lblConfirmationEmploye, "Vérification");
    indice(ui->txtConfirmationMotDePasseEmploye, "Retaper le mot de passe");
    if (cadre->isVisible()) { ui->txtMotDePasseEmploye->setFocus(); return; }

    cadre->setMaximumHeight(0);
    cadre->show();
    const int hauteur = cadre->sizeHint().height();
    QPropertyAnimation *depliage = new QPropertyAnimation(cadre, "maximumHeight", cadre);
    depliage->setDuration(320);
    depliage->setStartValue(0);
    depliage->setEndValue(hauteur);
    depliage->setEasingCurve(QEasingCurve::OutCubic);
    connect(depliage, &QPropertyAnimation::finished, cadre, [cadre]() { cadre->setMaximumHeight(QWIDGETSIZE_MAX); });
    depliage->start(QAbstractAnimation::DeleteWhenStopped);

    QGraphicsOpacityEffect *effet = new QGraphicsOpacityEffect(cadre);
    cadre->setGraphicsEffect(effet);
    QPropertyAnimation *fondu = new QPropertyAnimation(effet, "opacity", cadre);
    fondu->setDuration(420);
    fondu->setStartValue(0.0);
    fondu->setEndValue(1.0);
    connect(fondu, &QPropertyAnimation::finished, cadre, [cadre]() { cadre->setGraphicsEffect(nullptr); });
    fondu->start(QAbstractAnimation::DeleteWhenStopped);
    ui->txtMotDePasseEmploye->setFocus();
}



// Change une propriété de style (niveau, état, variante) et rafraîchit l'apparence
static void definirStyle(QWidget *w, const char *propriete, const QString &valeur)
{
    if (w->property(propriete).toString() == valeur) return;
    w->setProperty(propriete, valeur);
    w->style()->unpolish(w);
    w->style()->polish(w);
    w->update();
}

// Indicateur de sécurité : longueur, majuscule, minuscule, chiffre, symbole
void Employe::evaluerMotDePasse()
{
    const QString mdp = ui->txtMotDePasseEmploye->text();
    int score = 0;
    if (mdp.length() >= 8) score++;
    if (mdp.length() >= 12) score++;
    if (mdp.contains(QRegularExpression("[A-Z]")) && mdp.contains(QRegularExpression("[a-z]"))) score++;
    if (mdp.contains(QRegularExpression("[0-9]"))) score++;
    if (mdp.contains(QRegularExpression("[^A-Za-z0-9]"))) score++;
    if (mdp.length() < 8) score = qMin(score, 1);           // trop court : toujours faible

    QString niveau, texte, variante;
    if (mdp.isEmpty())   { niveau = "";       texte = QString::fromUtf8("Sécurité : —");      variante = "rouge"; }
    else if (score <= 2) { niveau = "faible"; texte = QString::fromUtf8("Sécurité : faible");  variante = "rouge"; }
    else if (score <= 3) { niveau = "moyen";  texte = QString::fromUtf8("Sécurité : moyenne"); variante = "ambre"; }
    else                 { niveau = "eleve";  texte = QString::fromUtf8("Sécurité : élevée");  variante = "vert"; }
    if (langueArabe) {
        static const QHash<QString, QString> ar = {{"", "الأمان: —"}, {"faible", "الأمان: ضعيف"},
                                                   {"moyen", "الأمان: متوسط"}, {"eleve", "الأمان: مرتفع"}};
        texte = ar.value(niveau);
    }
    ui->lblForceMotDePasseEmploye->setText(texte);
    definirStyle(ui->lblForceMotDePasseEmploye, "niveau", niveau);
    definirStyle(ui->jaugeForceMotDePasseEmploye, "variante", variante);

    // la jauge glisse jusqu'à sa nouvelle valeur
    QPropertyAnimation *jauge = new QPropertyAnimation(ui->jaugeForceMotDePasseEmploye, "value", this);
    jauge->setDuration(250);
    jauge->setEndValue(mdp.isEmpty() ? 0 : qMax(1, score));
    jauge->start(QAbstractAnimation::DeleteWhenStopped);

    // correspondance avec la confirmation
    const QString conf = ui->txtConfirmationMotDePasseEmploye->text();
    if (conf.isEmpty()) {
        ui->lblCorrespondanceEmploye->clear();
        definirStyle(ui->lblCorrespondanceEmploye, "etat", "");
    } else if (conf == mdp) {
        ui->lblCorrespondanceEmploye->setText(langueArabe ? QString::fromUtf8("✓ كلمتا المرور متطابقتان")
                                                          : QString::fromUtf8("✓ Les mots de passe correspondent"));
        definirStyle(ui->lblCorrespondanceEmploye, "etat", "ok");
    } else {
        ui->lblCorrespondanceEmploye->setText(langueArabe ? QString::fromUtf8("✗ كلمتا المرور غير متطابقتين")
                                                          : QString::fromUtf8("✗ Les mots de passe ne correspondent pas"));
        definirStyle(ui->lblCorrespondanceEmploye, "etat", "ko");
    }
}


// =============================================================================
// Gestion des droits d'accès : matrice rôle x module (Complet / Lecture / Aucun)
// =============================================================================
Droit Employe::droitConnecte(int module) const
{
    const FicheEmploye *c = auth.trouver(identifiantConnecte);
    return c ? auth.droit(*c, module) : DROIT_AUCUN;
}

// Droits de la fiche affichée dans les sélecteurs (glissement animé)
void Employe::afficherDroitsFiche(const QVector<int> &droits, bool anime)
{
    for (int m = 0; m < selecteurs.size() && m < droits.size(); ++m) selecteurs[m]->definirDroit(droits[m], anime);
    if (texteCombo(ui->cbRoleEmploye) == "Administrateur") selecteurs[M_EMPLOYES]->definirDroit(DROIT_COMPLET, anime);
}

// Seul l'administrateur règle les droits ; ceux de son propre compte ne se modifient pas
void Employe::activerSelecteurs()
{
    const FicheEmploye *c = auth.trouver(identifiantConnecte);
    const bool administrateur = c && c->role == "Administrateur" && auth.droit(*c, M_EMPLOYES) == DROIT_COMPLET;
    const bool soiMeme = !modeAjout && identifiantLigne(ligneAffichee) == identifiantConnecte;
    const bool roleAdmin = texteCombo(ui->cbRoleEmploye) == "Administrateur";
    for (int m = 0; m < selecteurs.size(); ++m)
        selecteurs[m]->setEnabled(administrateur && !soiMeme && !(roleAdmin && m == M_EMPLOYES));
    ui->lblSousTitreAccesEmploye->setText(soiMeme ? t("Vos propres droits ne peuvent pas être modifiés")
                                                  : t("Proposés selon le rôle, ajustables pour cet employé"));
}

// Connexion : les boutons autorisés du menu apparaissent un à un (fondu + glissement)
void Employe::animerMenu()
{
    int delai = 60;
    for (QPushButton *b : ui->barreLaterale->findChildren<QPushButton *>()) {
        if (b->property("module").toString().isEmpty() || !b->isVisible()) continue;
        QGraphicsOpacityEffect *effet = new QGraphicsOpacityEffect(b);
        effet->setOpacity(0.0);
        b->setGraphicsEffect(effet);
        QVariantAnimation *a = new QVariantAnimation(b);
        a->setDuration(300);
        a->setStartValue(0.0);
        a->setEndValue(1.0);
        a->setEasingCurve(QEasingCurve::OutCubic);
        const QPoint origine = b->pos();
        const int sens = b->layoutDirection() == Qt::RightToLeft ? 1 : -1;
        connect(a, &QVariantAnimation::valueChanged, b, [b, effet, origine, sens](const QVariant &v) {
            effet->setOpacity(v.toReal());
            b->move(origine + QPoint(int(sens * 24 * (1 - v.toReal())), 0));
        });
        connect(a, &QVariantAnimation::finished, b, [b, origine]() { b->setGraphicsEffect(nullptr); b->move(origine); });
        QSequentialAnimationGroup *groupe = new QSequentialAnimationGroup(b);
        groupe->addPause(delai);
        groupe->addAnimation(a);
        groupe->start(QAbstractAnimation::DeleteWhenStopped);
        delai += 40;
    }
}

// =============================================================================
// Interfaces des autres modules : ouvertes selon les droits du compte connecté
//  - Aucun : le bouton du menu est masqué (le module ne s'ouvre pas) ;
//  - Lecture : l'interface s'ouvre, badge « Lecture seule », boutons d'action désactivés ;
//  - Complet : l'interface s'ouvre avec toutes les actions.
// Le contenu (tableau d'exemple) sera remplacé par la vraie interface de chaque module.
// =============================================================================
void Employe::afficherModule(int module)
{
    if (droitConnecte(module) == DROIT_AUCUN) return;          // pas de droit : pas d'interface
    static const char *noms[] = {"Employés", "Missions", "Unités", "Véhicules", "Matériel", "Formation", "Tableau de bord"};
    // en-tête et carte du module
    const QString cle = Authentification::cleModule(module).toLower();
    const QPixmap tuile(QString(":/images/icones/tuile_%1_orange.png").arg(cle));
    ui->tuileEnteteModule->setPixmap(tuile);
    ui->tuileModule->setPixmap(tuile);
    ui->lblTitreModule->setText(t(noms[module]));
    ui->lblNomModule->setText(t("Interface %1").arg(t(noms[module])));
    ui->lblLectureSeuleModule->setVisible(true);

    // module non encore développé : un écran l'indique clairement (droit du compte rappelé)
    ui->tblModule->hide();
    for (QPushButton *b : {ui->btnAjouterModule, ui->btnModifierModule, ui->btnSupprimerModule}) b->hide();
    ui->lblLectureSeuleModule->setText(droitConnecte(module) == DROIT_COMPLET ? t("Accès complet") : t("Lecture seule"));
    ui->lblTexteModule->setText(t("Module non développé : cette interface sera ajoutée par l'équipe chargée du module."));
    ui->lblNonDeveloppeModule->setText(QString("<div align='center'><img src=':/images/icones/tuile_%3_orange.png' width='64' height='64'/><br/>"
                                               "<span style='font-size:15pt; font-weight:bold'>%1</span><br/>"
                                               "<span style='font-size:9.5pt; color:#7A8896'>%2</span></div>")
                                           .arg(t("Module non développé"),
                                                t("L'interface %1 n'est pas encore disponible dans cette version.").arg(t(noms[module])), cle));
    // boutons d'action : actifs seulement avec le droit « Complet » (appliquerDroits les règle)
    for (QPushButton *b : {ui->btnAjouterModule, ui->btnModifierModule, ui->btnSupprimerModule})
        b->setProperty("module", Authentification::cleModule(module));
    appliquerDroits();

    // le bouton du module est sélectionné dans le menu et la page s'ouvre
    for (QPushButton *b : ui->barreLaterale->findChildren<QPushButton *>())
        if (b->property("module").toString() == Authentification::cleModule(module) && !b->property("action").isValid())
            b->setChecked(true);
    // page du module dans SWCaserne (1 Missions … 5 Formation) ; tant que l'équipe n'y a pas mis son
    // interface (page vide), la page modèle « Module non développé » y est placée
    QWidget *page = ui->SWCaserne->widget(indexPageModule(module));
    if (page) {
        bool vide = true;
        for (QWidget *w : page->findChildren<QWidget *>(QString(), Qt::FindDirectChildrenOnly)) vide = vide && w == ui->PModule;
        if (vide && ui->PModule->parentWidget() != page) {
            ui->SWCaserne->removeWidget(ui->PModule);
            if (!page->layout()) new QVBoxLayout(page);
            page->layout()->addWidget(ui->PModule);
            ui->PModule->show();
        }
        ui->SWCaserne->setCurrentWidget(page);
    }
    emit tableauModifie();
}

// Index des pages de SWCaserne (guide d'intégration : une page par module)
int Employe::indexPageModule(int module)
{
    switch (module) {
    case M_MISSIONS: return 1;
    case M_UNITES: return 2;
    case M_VEHICULES: return 3;
    case M_MATERIEL: return 4;
    case M_FORMATION: return 5;
    default: return 0;
    }
}

// Applique les droits du compte connecté :
//  - boutons « ecriture » désactivés si le droit n'est pas Complet ;
//  - boutons du menu masqués si le droit est Aucun ;
//  - fiche en lecture seule, matrice visible pour l'administrateur uniquement.
void Employe::appliquerDroits()
{
    const FicheEmploye *c = auth.trouver(identifiantConnecte);
    if (!c) return;

    for (QPushButton *b : fenetre->findChildren<QPushButton *>()) {
        const QString cle = b->property("module").toString();
        if (cle.isEmpty()) continue;
        int module = -1;
        for (int m = 0; m < NB_MODULES; ++m) if (Authentification::cleModule(m) == cle) module = m;
        const Droit d = auth.droit(*c, module);
        if (b->property("action").toString() == "ecriture") b->setEnabled(d == DROIT_COMPLET);
        else b->setVisible(d != DROIT_AUCUN);
    }
    // un titre de section du menu (RESSOURCES…) disparaît s'il n'a plus aucun bouton
    for (QLabel *titre : ui->barreLaterale->findChildren<QLabel *>()) {
        if (titre->property("variante").toString() != "sectionNav") continue;
        const QString tx = titre->property("texteFrancais").isValid() ? titre->property("texteFrancais").toString() : titre->text();
        if (tx == "RESSOURCES")
            titre->setVisible(auth.droit(*c, M_EMPLOYES) || auth.droit(*c, M_MISSIONS) || auth.droit(*c, M_UNITES)
                              || auth.droit(*c, M_VEHICULES) || auth.droit(*c, M_MATERIEL));
        if (tx == "PILOTAGE") titre->setVisible(auth.droit(*c, M_FORMATION) != DROIT_AUCUN);
        if (tx == "SUIVI") titre->setVisible(auth.droit(*c, M_TABLEAU) != DROIT_AUCUN);
    }

    // Fiche employé : modifiable seulement avec le droit Complet ; le rôle est attribué par l'administrateur
    const bool complet = auth.droit(*c, M_EMPLOYES) == DROIT_COMPLET;
    const bool administrateur = c->role == "Administrateur";
    for (QWidget *w : std::initializer_list<QWidget *>{ui->txtNomEmploye, ui->txtPrenomEmploye, ui->cbGradeEmploye,
                                                        ui->cbFonctionEmploye, ui->cbStatutEmploye, ui->dateEntreeEmploye,
                                                        ui->txtEmailEmploye, ui->txtIdentifiantEmploye, ui->txtHabilitationsEmploye,
                                                        ui->spinReposEmploye})
        w->setEnabled(complet);
    ui->cbRoleEmploye->setEnabled(complet && administrateur);
    ui->btnAnnulerEmploye->setEnabled(complet);
    ui->lblLectureSeuleEmploye->setVisible(!complet);
    activerSelecteurs();
    if (!complet && (modeAjout || modeEdition)) { modeAjout = false; definirModeEdition(false); }

    // Utilisateur affiché en bas du menu
    ui->lbl76->setText(c->prenom.left(1) + ". " + c->nom);
    ui->lbl75->setText((c->prenom.left(1) + c->nom.left(1)).toUpper());
    ui->lbl77->setText(langueArabe ? traduireTexte(c->role) : c->role);
    genererPlanning();    // un agent ne voit que sa propre ligne du planning
}

void Employe::animerConnexion()
{
    // braises dans le fond (créées une seule fois)
    if (!fondBraises) fondBraises = new FondBraises(ui->PLogin);
    fondBraises->setGeometry(ui->PLogin->rect());
    fondBraises->show();                 // cachées pendant la session, elles reviennent à la déconnexion
    fondBraises->demarrer();
    fondBraises->lower();

    // textes de gauche puis carte de connexion : fondu + léger glissement vers le haut
    QList<QWidget *> elements = {ui->lbl56, ui->lbl57, ui->tuile1, ui->lbl50, ui->lbl51,
                                 ui->tuile2, ui->lbl52, ui->lbl53, ui->tuile3, ui->lbl54, ui->lbl55, ui->cadreConnexion};
    if (ui->PLogin->layout()) ui->PLogin->layout()->activate();
    int delai = 60;
    for (QWidget *w : elements) {
        QGraphicsOpacityEffect *effet = new QGraphicsOpacityEffect(w);
        effet->setOpacity(0.0);
        w->setGraphicsEffect(effet);
        QPropertyAnimation *fondu = new QPropertyAnimation(effet, "opacity");
        fondu->setDuration(480);
        fondu->setStartValue(0.0);
        fondu->setEndValue(1.0);
        fondu->setEasingCurve(QEasingCurve::OutCubic);
        // glissement vers le haut : la position d'arrivée est lue au démarrage du glissement,
        // quand la mise en page est terminée (la fenêtre vient d'être affichée)
        const int hauteur = w == ui->cadreConnexion ? 26 : 16;
        QVariantAnimation *glisse = new QVariantAnimation;
        glisse->setDuration(560);
        glisse->setStartValue(1.0);
        glisse->setEndValue(0.0);
        glisse->setEasingCurve(QEasingCurve::OutQuint);
        auto arrivee = std::make_shared<QPoint>(-100000, 0);
        connect(glisse, &QVariantAnimation::valueChanged, w, [w, arrivee, hauteur](const QVariant &v) {
            if (arrivee->x() == -100000) *arrivee = w->pos();
            w->move(*arrivee + QPoint(0, int(hauteur * v.toReal())));
        });
        QParallelAnimationGroup *ensemble = new QParallelAnimationGroup;
        ensemble->addAnimation(fondu);
        ensemble->addAnimation(glisse);
        QSequentialAnimationGroup *groupe = new QSequentialAnimationGroup(w);
        groupe->addPause(delai);
        groupe->addAnimation(ensemble);
        connect(groupe, &QAbstractAnimation::finished, w, [this, w]() {
            w->setGraphicsEffect(nullptr);
            if (ui->PLogin->layout()) ui->PLogin->layout()->invalidate();   // tout revient exactement à sa place
        });
        groupe->start(QAbstractAnimation::DeleteWhenStopped);
        delai += (w == ui->lbl57 || w == ui->lbl51 || w == ui->lbl53) ? 110 : 45;
    }

    // le logo luit doucement, en boucle (halo orange qui respire)
    if (!ui->imgLogoConnexion->property("halo").toBool()) {
        ui->imgLogoConnexion->setProperty("halo", true);
        new HaloPulsant(ui->imgLogoConnexion, QColor(255, 122, 77), true, 26, 2.2);
    }
}


void Employe::installerEffets()
{
    // carte verte, cercle photo : effet de survol
    new EffetSurvol(ui->cadreTempsServiceEmploye, 22, 4);
    new EffetSurvol(ui->btnPhotoEmploye, 24, 0);

    // point « En ligne » qui pulse doucement
    QVariantAnimation *pulsation = new QVariantAnimation(this);
    pulsation->setDuration(1600);
    pulsation->setKeyValueAt(0, 255);
    pulsation->setKeyValueAt(0.5, 70);
    pulsation->setKeyValueAt(1, 255);
    pulsation->setLoopCount(-1);
    // (opacité du point plutôt qu'une feuille de style recalculée 60 fois par seconde : plus léger)
    QGraphicsOpacityEffect *opacite = new QGraphicsOpacityEffect(ui->pointEnLigneEmploye);
    ui->pointEnLigneEmploye->setGraphicsEffect(opacite);
    connect(pulsation, &QVariantAnimation::valueChanged, opacite, [opacite](const QVariant &v) { opacite->setOpacity(v.toInt() / 255.0); });
    pulsation->start();
}

// Notification qui glisse depuis le bas de la fenêtre, puis repart toute seule
void Employe::afficherNotification(const QString &titre, const QString &texte, const QString &image, int duree)
{
    QFrame *toast = new QFrame(fenetre);
    toast->setProperty("variante", "toast");
    QHBoxLayout *h = new QHBoxLayout(toast);
    h->setContentsMargins(14, 12, 16, 12);
    h->setSpacing(12);
    QLabel *icone = new QLabel;
    icone->setPixmap(QPixmap(image.isEmpty() ? ":/images/icones/tuile_bell_rouge.png" : image)
                         .scaled(34, 34, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    icone->setFixedSize(34, 34);
    QVBoxLayout *v = new QVBoxLayout;
    v->setSpacing(2);
    QLabel *t = new QLabel(titre);
    t->setProperty("variante", "toastTitre");
    QLabel *d = new QLabel(texte);
    d->setProperty("variante", "toastTexte");
    d->setWordWrap(true);
    d->setTextInteractionFlags(Qt::TextSelectableByMouse);   // le code reçu peut être copié
    v->addWidget(t);
    v->addWidget(d);
    h->addWidget(icone, 0, Qt::AlignTop);
    h->addLayout(v, 1);
    toast->setFixedWidth(380);
    toast->adjustSize();

    // les notifications s'empilent au lieu de se recouvrir (une même notification n'est pas répétée)
    int decalage = 0;
    for (QFrame *autre : fenetre->findChildren<QFrame *>(QString(), Qt::FindDirectChildrenOnly)) {
        if (autre == toast || autre->property("variante").toString() != "toast" || !autre->isVisible()) continue;
        if (autre->property("message").toString() == titre + texte) { toast->deleteLater(); return; }
        decalage += autre->height() + 10;
    }
    toast->setProperty("message", titre + texte);

    const bool rtl = fenetre->layoutDirection() == Qt::RightToLeft;
    const QRect visible = zoneVisible(fenetre);   // coin de la partie visible de la fenêtre
    const int x = rtl ? visible.left() + 24 : visible.right() + 1 - toast->width() - 24;
    const int y = visible.bottom() + 1 - toast->height() - 24 - decalage;
    const int depart = rtl ? visible.left() - toast->width() : visible.right() + 1;
    toast->move(depart, y);
    toast->show();
    toast->raise();

    QPropertyAnimation *entree = new QPropertyAnimation(toast, "pos");
    entree->setDuration(420);
    entree->setEndValue(QPoint(x, y));
    entree->setEasingCurve(QEasingCurve::OutBack);
    QPropertyAnimation *sortie = new QPropertyAnimation(toast, "pos");
    sortie->setDuration(320);
    sortie->setEndValue(QPoint(depart, y));
    sortie->setEasingCurve(QEasingCurve::InCubic);
    QSequentialAnimationGroup *groupe = new QSequentialAnimationGroup(toast);
    groupe->addAnimation(entree);
    groupe->addPause(duree);
    groupe->addAnimation(sortie);
    connect(groupe, &QAbstractAnimation::finished, toast, &QFrame::deleteLater);
    groupe->start();
}

void Employe::notifications()
{
    // la cloche s'agite
    QWidget *cloche = ui->btnNotificationsEmploye;
    QVariantAnimation *agitation = new QVariantAnimation(cloche);
    agitation->setDuration(450);
    agitation->setStartValue(0.0);
    agitation->setEndValue(1.0);
    const QPoint origine = cloche->pos();
    connect(agitation, &QVariantAnimation::valueChanged, cloche, [cloche, origine](const QVariant &v) {
        const qreal t = v.toReal();
        cloche->move(origine + QPoint(int(5 * std::sin(t * 6 * M_PI) * (1 - t)), 0));
    });
    connect(agitation, &QVariantAnimation::finished, cloche, [cloche, origine]() { cloche->move(origine); });
    agitation->start(QAbstractAnimation::DeleteWhenStopped);

    afficherNotification(langueArabe ? QString::fromUtf8("تنبيهان") : QString::fromUtf8("2 alertes"),
                         langueArabe ? QString::fromUtf8("سامي العربي يقترب من 12 ساعة عمل · فترة واحدة بعدد غير كاف في جدول المناوبات.")
                                     : QString::fromUtf8("Sami Larbi approche des 12h de service · 1 créneau en sous-effectif dans le planning."));
}

// -----------------------------------------------------------------------------
// Animation d'entrée de la page (dans l'esprit de l'écran de connexion) :
// les panneaux apparaissent l'un après l'autre en fondu, les chiffres clés défilent
// et l'anneau de disponibilité se remplit.
// -----------------------------------------------------------------------------
void Employe::animerEntreePage()
{
    // Anneau de disponibilité : il se remplit
    QVariantAnimation *anneau = new QVariantAnimation(this);
    anneau->setDuration(1000);
    anneau->setStartValue(0.0);
    anneau->setEndValue(1.0);
    anneau->setEasingCurve(QEasingCurve::OutCubic);
    connect(anneau, &QVariantAnimation::valueChanged, this, [this](const QVariant &v) { animerAnneau(v.toReal()); });
    connect(anneau, &QVariantAnimation::finished, this, [this]() { animerAnneau(1.0); });
    anneau->start(QAbstractAnimation::DeleteWhenStopped);
}

void Employe::animerAnneau(qreal t)
{
    // mêmes parts que dans la feuille de style : 50 %, 27 %, 14 %, 9 %
    const qreal *bornes = bornesAnneau;      // parts calculées à partir de la liste des employés
    const char *couleurs[] = {"#1E9E63", "#E08E0B", "#9AA5B1", "#2F6FE0"};
    QString stops;
    qreal debut = 0;
    for (int i = 0; i < 4; ++i) {
        const qreal fin = bornes[i] * t;
        stops += QString(", stop:%1 %3, stop:%2 %3").arg(debut, 0, 'f', 4).arg(qMax(debut, fin - 0.0001), 0, 'f', 4).arg(couleurs[i]);
        debut = fin;
    }
    const QString vide = modeSombre ? "#26303B" : "#EDF0F4";
    if (t < 1.0) stops += QString(", stop:%1 %2, stop:1 %2").arg(qMin(1.0, debut + 0.0001), 0, 'f', 4).arg(vide);
    ui->anneauStatutEmploye->setStyleSheet(
        QString("QFrame#anneauStatutEmploye { background: qconicalgradient(cx:0.5, cy:0.5, angle:90%1); }").arg(stops));
}


// Photo de l'employé : l'image choisie est découpée en cercle et placée dans le bouton rond
// Photo découpée en cercle, avec en option une pastille orange « + » (changer la photo)
static QPixmap photoRonde(const QPixmap &source, int taille, qreal ratio, bool pastille)
{
    QPixmap rond(QSize(taille, taille) * ratio);
    rond.setDevicePixelRatio(ratio);
    rond.fill(Qt::transparent);
    QPainter p(&rond);
    p.setRenderHint(QPainter::Antialiasing);
    p.setRenderHint(QPainter::SmoothPixmapTransform);
    QPainterPath cercle;
    cercle.addEllipse(0, 0, taille, taille);
    p.save();
    p.setClipPath(cercle);
    QPixmap rempli = source.scaled(QSize(taille, taille) * ratio, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
    rempli.setDevicePixelRatio(ratio);
    p.drawPixmap(QPointF((taille - rempli.width() / ratio) / 2, (taille - rempli.height() / ratio) / 2), rempli);
    p.restore();
    if (pastille) {
        const qreal r = taille * 0.17;
        const QPointF c(taille - r - 1, taille - r - 1);
        p.setPen(QPen(Qt::white, 2));
        p.setBrush(QColor("#E4491F"));
        p.drawEllipse(c, r, r);
        p.setPen(QPen(Qt::white, 2, Qt::SolidLine, Qt::RoundCap));
        p.drawLine(c + QPointF(-r * 0.45, 0), c + QPointF(r * 0.45, 0));
        p.drawLine(c + QPointF(0, -r * 0.45), c + QPointF(0, r * 0.45));
    }
    return rond;
}

// Avatar par défaut : initiales sur une braise (dégradé du fond animé de l'application)
static QPixmap avatarInitiales(const QString &initiales, int variante, int taille)
{
    static const char *degrades[][3] = {{"#FF8A5B", "#E4491F", "#7A2410"},     // braise vive
                                        {"#E4491F", "#9E2E14", "#3A1C12"},     // braise rouge
                                        {"#3A1C12", "#151B24", "#0B1016"}};    // nuit de garde
    const int n = qAbs(variante) % 3;
    QPixmap image(taille * 3, taille * 3);
    image.fill(QColor(degrades[n][2]));
    QPainter p(&image);
    p.setRenderHint(QPainter::Antialiasing);
    QRadialGradient braise(image.width() * 0.3, image.height() * 0.25, image.width() * 0.95);
    braise.setColorAt(0, QColor(degrades[n][0]));
    braise.setColorAt(0.55, QColor(degrades[n][1]));
    braise.setColorAt(1, QColor(degrades[n][2]));
    p.fillRect(image.rect(), braise);
    p.setPen(n == 2 ? QColor("#FF8A5B") : QColor(Qt::white));
    QFont f("Segoe UI");
    f.setBold(true);
    f.setPixelSize(int(taille * 3 * 0.38));
    p.setFont(f);
    p.drawText(image.rect(), Qt::AlignCenter, initiales);
    return image;
}

static QString texteFrancais(QTableWidgetItem *it)
{
    if (!it) return QString();
    return it->data(Qt::UserRole + 30).isValid() ? it->data(Qt::UserRole + 30).toString() : it->text();
}


void Employe::preparerPhotos()
{
    QTableWidget *t = ui->tblEmploye;
    t->setIconSize(QSize(26, 26));
    for (int l = 0; l < t->rowCount(); ++l) {
        QTableWidgetItem *nom = t->item(l, 1);
        if (!nom) continue;
        const QString initiales = texteFrancais(t->item(l, 2)).left(1) + texteFrancais(nom).left(1);
        const int id = t->item(l, 0) ? t->item(l, 0)->text().toInt() : l;
        nom->setData(Qt::UserRole + 40, avatarInitiales(initiales.toUpper(), id - 1, 26));
        const QPixmap source = photos.value(identifiantLigne(l), nom->data(Qt::UserRole + 40).value<QPixmap>());
        nom->setIcon(QIcon(photoRonde(source, 26, fenetre->devicePixelRatioF(), false)));
    }
    if (t->rowCount() > 0) {
        t->selectRow(ligneAffichee);
        afficherPhoto(ligneAffichee);
    }
}

void Employe::afficherPhoto(int ligne)
{
    QTableWidgetItem *nom = ui->tblEmploye->item(ligne, 1);
    if (!nom) return;
    const QPixmap source = photos.value(identifiantLigne(ligne), nom->data(Qt::UserRole + 40).value<QPixmap>());
    ui->btnPhotoEmploye->setIcon(QIcon(photoRonde(source, 60, fenetre->devicePixelRatioF(), true)));
    ui->btnPhotoEmploye->setIconSize(QSize(60, 60));
}

// Choisir la photo de l'employé affiché (ou du nouvel employé) : elle apparaît dans le cercle et dans le tableau
void Employe::choisirPhoto()
{
    const QString chemin = QFileDialog::getOpenFileName(fenetre, QString::fromUtf8("Photo de l'employé"), QString(),
                                                        "Images (*.png *.jpg *.jpeg *.bmp)");
    if (chemin.isEmpty()) return;
    const QPixmap image(chemin);
    if (image.isNull()) return;
    if (modeAjout) {
        photoAjout = image;
        ui->btnPhotoEmploye->setIcon(QIcon(photoRonde(image, 60, fenetre->devicePixelRatioF(), true)));
    } else {
        photos.insert(identifiantLigne(ligneAffichee), image);
        preparerPhotos();
    }

    // petit « pop » du cercle pour confirmer (la photo grandit jusqu'à sa taille)
    QPropertyAnimation *pop = new QPropertyAnimation(ui->btnPhotoEmploye, "iconSize", this);
    pop->setDuration(420);
    pop->setStartValue(QSize(30, 30));
    pop->setEndValue(QSize(60, 60));
    pop->setEasingCurve(QEasingCurve::OutBack);
    pop->start(QAbstractAnimation::DeleteWhenStopped);
}

// Un clic sur une ligne du tableau affiche l'employé dans le formulaire (avec sa photo)
void Employe::afficherEmploye(int ligne, int)
{
    const FicheEmploye *f = auth.trouver(identifiantLigne(ligne));
    if (!f) return;
    if (modeAjout) definirModeAjout(false);
    ligneAffichee = ligne;
    ui->tblEmploye->selectRow(ligne);
    ui->txtNomEmploye->setText(f->nom);
    ui->txtPrenomEmploye->setText(f->prenom);
    choisirDansCombo(ui->cbGradeEmploye, f->grade);
    choisirDansCombo(ui->cbStatutEmploye, f->statut);
    choisirDansCombo(ui->cbRoleEmploye, f->role);
    choisirDansCombo(ui->cbFonctionEmploye, f->fonction);
    if (f->dateEntree.isValid()) ui->dateEntreeEmploye->setDate(f->dateEntree);
    ui->txtIdentifiantEmploye->setText(f->identifiant);
    ui->txtEmailEmploye->setText(f->email);
    ui->txtHabilitationsEmploye->setText(f->habilitations);
    ui->spinReposEmploye->setValue(f->tempsReposCumule);
    ui->lblReposServiceEmploye->setText(t("Repos cumulé : %1 h · alerte à 80 % de 12h").arg(f->tempsReposCumule));
    QVector<int> droits;
    for (int m = 0; m < NB_MODULES; ++m) droits.append(auth.droit(*f, m));
    afficherDroitsFiche(droits, true);
    definirModeEdition(false);
    activerSelecteurs();
    afficherPhoto(ligne);
}

// =============================================================================
// Sélecteur Complet / Lecture / Aucun : une pastille glisse sous le choix
// =============================================================================
SelecteurDroit::SelecteurDroit(QWidget *parent) : QWidget(parent)
{
    setMinimumSize(186, 26);
    setMaximumHeight(26);
    setCursor(Qt::PointingHandCursor);
    animation = new QVariantAnimation(this);
    animation->setDuration(320);
    animation->setEasingCurve(QEasingCurve::OutBack);
    connect(animation, &QVariantAnimation::valueChanged, this, [this](const QVariant &v) { position = v.toReal(); update(); });
}

void SelecteurDroit::definirDroit(int droit, bool anime)
{
    const int index = 2 - qBound(0, droit, 2);   // 0 Complet, 1 Lecture, 2 Aucun
    if (index == choix && !anime) return;
    choix = index;
    animation->stop();
    if (anime && isVisible()) {
        animation->setStartValue(position);
        animation->setEndValue(qreal(index));
        animation->start();
    } else { position = index; update(); }
}

void SelecteurDroit::mousePressEvent(QMouseEvent *e)
{
    if (!isEnabled()) return;
    const int index = qBound(0, int(e->position().x() * 3 / width()), 2);
    const int x = layoutDirection() == Qt::RightToLeft ? 2 - index : index;
    definirDroit(2 - x, true);
}

void SelecteurDroit::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    p.setOpacity(isEnabled() ? 1.0 : 0.5);
    const QRectF piste = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
    p.setPen(QPen(QColor(sombre ? "#2A3542" : "#E1E6EC"), 1));
    p.setBrush(QColor(sombre ? "#1B232C" : "#F4F6F9"));
    p.drawRoundedRect(piste, 13, 13);

    // pastille : orange (complet), encre (lecture), gris (aucun) — couleurs de l'interface
    const qreal largeur = piste.width() / 3;
    const bool rtl = layoutDirection() == Qt::RightToLeft;
    const qreal pos = rtl ? 2 - position : position;
    const QRectF pastille(piste.left() + pos * largeur + 2, piste.top() + 2, largeur - 4, piste.height() - 4);
    const QColor teintes[] = {QColor("#E4491F"), QColor(sombre ? "#46566A" : "#2B3742"), QColor(sombre ? "#4E5B69" : "#B8C1CB")};
    const qreal f = qBound(0.0, position, 2.0);
    const int a = qMin(1, int(f)), b = qMin(2, a + 1);
    const qreal r = f - a;
    QColor teinte;
    teinte.setRgbF(teintes[a].redF() * (1 - r) + teintes[b].redF() * r, teintes[a].greenF() * (1 - r) + teintes[b].greenF() * r,
                   teintes[a].blueF() * (1 - r) + teintes[b].blueF() * r);
    if (choix == 0) {   // complet : dégradé de braise
        QLinearGradient braise(pastille.topLeft(), pastille.bottomRight());
        braise.setColorAt(0, QColor("#FF7A4D"));
        braise.setColorAt(1, teinte);
        p.setBrush(braise);
    } else p.setBrush(teinte);
    p.setPen(Qt::NoPen);
    p.drawRoundedRect(pastille, 11, 11);

    static const char *textes[] = {"Complet", "Lecture", "Aucun"};
    QFont police = font();
    police.setPointSizeF(8.5);
    police.setBold(true);
    p.setFont(police);
    for (int i = 0; i < 3; ++i) {
        const int colonne = rtl ? 2 - i : i;
        const QRectF zone(piste.left() + colonne * largeur, piste.top(), largeur, piste.height());
        p.setPen(i == choix ? QColor(Qt::white) : QColor(sombre ? "#7F8C99" : "#8B99A6"));
        const QString texte = QString::fromUtf8(textes[i]);
        p.drawText(zone, Qt::AlignCenter, arabe ? traduireTexte(texte) : texte);
    }
}

// =============================================================================
// Noms des employés : couleurs des braises du fond, reflet qui défile lentement
// =============================================================================
void DelegueNomBraise::paint(QPainter *p, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QStyleOptionViewItem opt(option);
    initStyleOption(&opt, index);
    const QString texte = opt.text;
    opt.text.clear();
    const QWidget *vue = opt.widget;
    QStyle *style = vue ? vue->style() : QApplication::style();
    style->drawControl(QStyle::CE_ItemViewItem, &opt, p, vue);   // fond, sélection, avatar

    const QRect zone = style->subElementRect(QStyle::SE_ItemViewItemText, &opt, vue);
    QFont police = opt.font;
    police.setBold(gras);
    p->save();
    p->setFont(police);
    const QString affiche = QFontMetrics(police).elidedText(texte, Qt::ElideRight, zone.width());
    const qreal decalage = std::fmod(*phase + index.row() * 37.0, 240.0);
    QLinearGradient braise(zone.left() - decalage, 0, zone.left() - decalage + 240, 0);
    braise.setSpread(QGradient::RepeatSpread);
    braise.setColorAt(0.0, QColor("#C7341A"));
    braise.setColorAt(0.35, QColor("#E4491F"));
    braise.setColorAt(0.5, QColor("#FF8A5B"));      // reflet de la braise
    braise.setColorAt(0.65, QColor("#E4491F"));
    braise.setColorAt(1.0, QColor("#C7341A"));
    p->setPen(QPen(QBrush(braise), 1));
    p->drawText(zone, int(opt.displayAlignment) | Qt::AlignVCenter, affiche);
    p->restore();
}

// =============================================================================
// Message animé (ajout / suppression / modification)
// =============================================================================
MessageAnime::MessageAnime(QWidget *fenetre, Type type, const QString &titre, const QString &texte, bool sombre)
    : QWidget(fenetre), type(type), titre(titre), texte(texte), sombre(sombre)
{
    setAttribute(Qt::WA_NoSystemBackground);
    setGeometry(fenetre->rect());
    fenetre->installEventFilter(this);

    // étincelles (succès) ou débris (suppression)
    static const char *feu[] = {"#E4491F", "#F2A93B", "#1E9E63", "#FF8A5B", "#5FD39B", "#FFB08F"};
    static const char *gris[] = {"#D93636", "#F08080", "#9AA5B1", "#7A8896", "#B42A2A"};
    QRandomGenerator *g = QRandomGenerator::global();
    const int n = type == Succes ? 38 : 24;
    for (int i = 0; i < n; ++i) {
        Particule p;
        if (type == Succes) {
            const qreal angle = g->bounded(2 * M_PI), vitesse = 260 + g->bounded(260.0);
            p.vitesse = QPointF(std::cos(angle) * vitesse, std::sin(angle) * vitesse - 90);
            p.couleur = QColor(feu[i % 6]);
        } else {
            p.vitesse = QPointF(-260 + g->bounded(520.0), -120 - g->bounded(200.0));
            p.couleur = QColor(gris[i % 5]);
        }
        p.taille = 2.0 + g->bounded(3.5);
        particules.append(p);
    }

    chrono = new QVariantAnimation(this);
    chrono->setDuration(int(DUREE));
    chrono->setStartValue(0.0);
    chrono->setEndValue(DUREE);
    connect(chrono, &QVariantAnimation::valueChanged, this, [this](const QVariant &v) { temps = v.toReal(); update(); });
    connect(chrono, &QVariantAnimation::finished, this, &QWidget::deleteLater);
    chrono->start();
    show();
    raise();
}

qreal MessageAnime::phase(qreal t, qreal debut, qreal fin)
{
    return qBound(0.0, (t - debut) / (fin - debut), 1.0);
}

// =============================================================================
// Intro de connexion : le logo s'embrase sur toute la page
// =============================================================================
qreal IntroConnexion::phase(qreal t, qreal debut, qreal fin)
{
    return qBound(0.0, (t - debut) / (fin - debut), 1.0);
}

IntroConnexion::IntroConnexion(QWidget *fenetre, const QString &titre, const QString &bienvenue, const QString &detail,
                               std::function<void()> milieu, std::function<void()> fin)
    : QWidget(fenetre), titre(titre), bienvenue(bienvenue), detail(detail), milieu(milieu), fin(fin)
{
    setAttribute(Qt::WA_NoSystemBackground);
    setCursor(Qt::PointingHandCursor);
    setGeometry(fenetre->rect());
    fenetre->installEventFilter(this);

    // logo teinté en dégradé de feu : jaune à la base, orange, rouge braise au sommet
    const qreal ratio = fenetre->devicePixelRatioF();
    QImage image(":/images/logo.png");
    image = image.convertToFormat(QImage::Format_ARGB32_Premultiplied);
    {
        QPainter p(&image);
        p.setCompositionMode(QPainter::CompositionMode_SourceIn);
        QLinearGradient feu(0, image.height(), 0, 0);
        feu.setColorAt(0.0, QColor("#FFD36B"));
        feu.setColorAt(0.35, QColor("#FF8A2F"));
        feu.setColorAt(0.75, QColor("#E4491F"));
        feu.setColorAt(1.0, QColor("#B8261A"));
        p.fillRect(image.rect(), feu);
    }
    logo = QPixmap::fromImage(image);
    logo.setDevicePixelRatio(1.0);
    Q_UNUSED(ratio);

    QRandomGenerator *g = QRandomGenerator::global();
    for (int i = 0; i < 70; ++i) {
        braises.append(QPointF(g->bounded(1.0), g->bounded(1.0)));
        vitesses.append(0.04 + g->bounded(0.12));
    }

    chrono = new QVariantAnimation(this);
    chrono->setDuration(int(DUREE));
    chrono->setStartValue(0.0);
    chrono->setEndValue(DUREE);
    connect(chrono, &QVariantAnimation::valueChanged, this, [this](const QVariant &v) {
        precedent = temps;
        temps = v.toReal();
        const qreal dt = qBound(0.0, (temps - precedent) / 1000.0, 0.1);
        // braises du fond : elles montent, plus vite quand le logo s'embrase
        const qreal elan = 1.0 + 2.5 * phase(temps, 300, 1300);
        for (int i = 0; i < braises.size(); ++i) {
            braises[i].ry() -= vitesses[i] * dt * elan;
            if (braises[i].y() < -0.05) braises[i] = QPointF(QRandomGenerator::global()->bounded(1.0), 1.05);
        }
        // étincelles : vitesse, gravité inverse (elles montent), vie qui s'épuise
        for (Etincelle &e : etincelles) {
            e.position += e.vitesse * dt;
            e.vitesse.ry() -= 60 * dt;
            e.vie -= dt * 1.4;
        }
        etincelles.erase(std::remove_if(etincelles.begin(), etincelles.end(), [](const Etincelle &e) { return e.vie <= 0; }),
                         etincelles.end());
        if (!milieuFait && temps >= 380) { milieuFait = true; if (this->milieu) this->milieu(); }   // la page change sous l'intro
        if (!finFaite && temps >= SORTIE) { finFaite = true; if (this->fin) this->fin(); }          // la page s'anime en s'ouvrant
        update();
    });
    connect(chrono, &QVariantAnimation::finished, this, [this]() {
        if (!milieuFait && this->milieu) this->milieu();
        if (!finFaite && this->fin) this->fin();
        deleteLater();
    });
    chrono->start();
    show();
    raise();
}

bool IntroConnexion::eventFilter(QObject *o, QEvent *e)
{
    if (e->type() == QEvent::Resize) setGeometry(static_cast<QWidget *>(o)->rect());
    return false;
}

void IntroConnexion::mousePressEvent(QMouseEvent *)
{
    if (temps < SORTIE) chrono->setCurrentTime(int(SORTIE));     // un clic passe l'intro
}

void IntroConnexion::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    p.setRenderHint(QPainter::SmoothPixmapTransform);
    const QRect zone = zoneVisible(this);
    const qreal cote = qMin(zone.width(), zone.height()) * 0.24;      // taille du logo
    const QPointF centre(zone.center().x(), zone.top() + zone.height() * 0.40);
    const qreal entree = phase(temps, 0, 380);
    const qreal sortie = phase(temps, SORTIE, DUREE);
    const qreal contenu = 1.0 - phase(temps, SORTIE, SORTIE + 380);    // logo et textes s'effacent
    auto doux = [](qreal x) { return QEasingCurve(QEasingCurve::OutCubic).valueForProgress(x); };

    // 1. fond : nuit de braise (teinte du ciel de l'heure), ouvert à la fin par un cercle qui grandit
    const QColor ciel = CielHoraire::couleurCiel(QTime::currentTime().hour() + QTime::currentTime().minute() / 60.0);
    const QColor bord(int(9 + ciel.red() * 0.10), int(12 + ciel.green() * 0.10), int(17 + ciel.blue() * 0.14));
    // le dégradé du fond est dessiné une seule fois dans une image, puis simplement recopié (rapide)
    static QPixmap fondPret;
    if (fondPret.size() != size()) {
        fondPret = QPixmap(size());
        QPainter q(&fondPret);
        QRadialGradient fond(centre, qMax(width(), height()) * 0.75);
        fond.setColorAt(0.0, QColor(70, 26, 12));
        fond.setColorAt(0.45, QColor(28, 16, 14));
        fond.setColorAt(1.0, bord);
        q.fillRect(rect(), fond);
    }
    p.setOpacity(entree);
    if (sortie > 0) {
        const qreal rayon = std::hypot(width(), height()) * QEasingCurve(QEasingCurve::InOutCubic).valueForProgress(sortie);
        QPainterPath voile;
        voile.addRect(rect());
        voile.addEllipse(centre, rayon, rayon);                         // trou : la page apparaît dedans
        voile.setFillRule(Qt::OddEvenFill);
        p.save();
        p.setClipPath(voile);
        p.drawPixmap(0, 0, fondPret);
        p.restore();
    } else p.drawPixmap(0, 0, fondPret);
    if (sortie > 0) {                                                   // bord lumineux du cercle d'ouverture
        const qreal rayon = std::hypot(width(), height()) * QEasingCurve(QEasingCurve::InOutCubic).valueForProgress(sortie);
        p.setPen(QPen(QColor(255, 138, 91, int(200 * (1 - sortie))), 6));
        p.setBrush(Qt::NoBrush);
        p.drawEllipse(centre, rayon, rayon);
    }

    // 2. braises du fond
    p.setPen(Qt::NoPen);
    for (int i = 0; i < braises.size(); ++i) {
        const QPointF b(braises[i].x() * width(), braises[i].y() * height());
        if (sortie > 0 && QLineF(b, centre).length() < std::hypot(width(), height()) * sortie) continue;
        const qreal eclat = 0.45 + 0.55 * std::sin(temps / 180.0 + i * 1.7);
        p.setBrush(QColor(255, 120 + (i * 37) % 90, 40, int(150 * eclat)));
        const qreal r = 1.2 + (i % 4) * 0.7;
        p.drawEllipse(b, r, r);
    }

    p.setOpacity(contenu);
    p.save();
    const qreal echelle = 1.0 + 0.12 * phase(temps, SORTIE, SORTIE + 380);
    p.translate(centre);
    p.scale(echelle, echelle);
    p.translate(-centre);

    // 3. halo qui respire derrière le logo
    const qreal embrasement = doux(phase(temps, 250, 1300));
    const qreal souffle = 0.85 + 0.15 * std::sin(temps / 140.0);
    QRadialGradient halo(centre, cote * 1.3);
    halo.setColorAt(0.0, QColor(255, 140, 50, int(150 * embrasement * souffle)));
    halo.setColorAt(0.5, QColor(228, 73, 31, int(60 * embrasement * souffle)));
    halo.setColorAt(1.0, QColor(228, 73, 31, 0));
    p.setBrush(halo);
    p.drawEllipse(centre, cote * 1.3, cote * 1.3);

    // 4. anneau qui se trace autour du logo + anneau pointillé qui tourne
    const QRectF cadre(centre.x() - cote / 2, centre.y() - cote / 2, cote, cote);
    const qreal rayonAnneau = cote * 0.72;
    const qreal trace = doux(phase(temps, 900, 1800));
    if (trace > 0) {
        QConicalGradient degrade(centre, 90);
        degrade.setColorAt(0.0, QColor("#FFD36B"));
        degrade.setColorAt(0.5, QColor("#E4491F"));
        degrade.setColorAt(1.0, QColor("#FFD36B"));
        p.setBrush(Qt::NoBrush);
        p.setPen(QPen(QBrush(degrade), 3.5, Qt::SolidLine, Qt::RoundCap));
        p.drawArc(QRectF(centre.x() - rayonAnneau, centre.y() - rayonAnneau, 2 * rayonAnneau, 2 * rayonAnneau),
                  90 * 16, int(-360 * 16 * trace));
        p.save();
        p.translate(centre);
        p.rotate(temps * 0.04);
        QPen pointilles(QColor(255, 138, 91, int(120 * trace)), 1.4, Qt::DashLine);
        pointilles.setDashPattern({2, 6});
        p.setPen(pointilles);
        const qreal r2 = rayonAnneau * 1.14;
        p.drawEllipse(QPointF(0, 0), r2, r2);
        p.restore();
    }
    // onde de choc quand l'anneau se ferme
    const qreal onde = phase(temps, 1750, 2450);
    if (onde > 0 && onde < 1) {
        const qreal r = rayonAnneau * (1.0 + 1.4 * doux(onde));
        p.setBrush(Qt::NoBrush);
        p.setPen(QPen(QColor(255, 160, 90, int(170 * (1 - onde))), 2.5 * (1 - onde) + 0.5));
        p.drawEllipse(centre, r, r);
    }

    // 5. le logo s'embrase du bas vers le haut ; un front de flamme lumineux monte avec lui
    if (embrasement > 0) {
        const qreal hauteur = cote * embrasement;
        p.save();
        p.setClipRect(QRectF(cadre.left() - 4, cadre.bottom() - hauteur, cadre.width() + 8, hauteur + 2));
        p.drawPixmap(cadre, logo, logo.rect());
        p.restore();
        if (embrasement < 1) {
            const qreal y = cadre.bottom() - hauteur;
            QLinearGradient front(cadre.left(), y, cadre.right(), y);
            front.setColorAt(0.0, QColor(255, 230, 160, 0));
            front.setColorAt(0.5, QColor(255, 240, 190, 230));
            front.setColorAt(1.0, QColor(255, 230, 160, 0));
            p.setPen(Qt::NoPen);
            p.setBrush(front);
            p.drawRoundedRect(QRectF(cadre.left() + cote * 0.1, y - 2.5, cote * 0.8, 5), 2.5, 2.5);
            // des étincelles jaillissent du front
            QRandomGenerator *g = QRandomGenerator::global();
            for (int k = 0; k < 3; ++k) {
                Etincelle e;
                e.position = QPointF(cadre.left() + cote * (0.15 + g->bounded(0.7)), y);
                e.vitesse = QPointF(-50 + g->bounded(100.0), -60 - g->bounded(140.0));
                e.vie = 0.6 + g->bounded(0.5);
                e.taille = 1.2 + g->bounded(2.2);
                e.couleur = QColor(k == 0 ? "#FFE3A0" : k == 1 ? "#FFB347" : "#FF7A2F");
                const_cast<IntroConnexion *>(this)->etincelles.append(e);
            }
        }
    }
    p.setPen(Qt::NoPen);
    for (const Etincelle &e : etincelles) {
        QColor c = e.couleur;
        c.setAlphaF(qBound(0.0, e.vie, 1.0));
        p.setBrush(c);
        p.drawEllipse(e.position, e.taille, e.taille);
    }

    // 6. les circuits du logo s'allument l'un après l'autre (« Caserne Connectée »)
    static const QPointF noeuds[] = {{281 / 512.0, 121 / 512.0}, {352 / 512.0, 182 / 512.0}, {400 / 512.0, 247 / 512.0}};
    for (int i = 0; i < 3; ++i) {
        const qreal debut = 1250 + i * 160;
        const qreal allume = phase(temps, debut, debut + 260);
        if (allume <= 0) continue;
        const QPointF n(cadre.left() + noeuds[i].x() * cote, cadre.top() + noeuds[i].y() * cote);
        const qreal impulsion = phase(temps, debut, debut + 700);
        if (impulsion < 1) {
            p.setBrush(Qt::NoBrush);
            p.setPen(QPen(QColor(255, 255, 255, int(200 * (1 - impulsion))), 1.6));
            const qreal r = cote * (0.03 + 0.12 * impulsion);
            p.drawEllipse(n, r, r);
        }
        QRadialGradient lueur(n, cote * 0.07);
        lueur.setColorAt(0.0, QColor(255, 255, 255, int(255 * allume)));
        lueur.setColorAt(0.4, QColor(255, 230, 170, int(170 * allume * (0.8 + 0.2 * std::sin(temps / 90.0 + i)))));
        lueur.setColorAt(1.0, QColor(255, 200, 120, 0));
        p.setPen(Qt::NoPen);
        p.setBrush(lueur);
        p.drawEllipse(n, cote * 0.07, cote * 0.07);
    }

    // 7. le nom de l'application s'écrit lettre par lettre, puis le message de bienvenue
    QFont police = font();
    police.setPointSizeF(qMax(18.0, cote * 0.16));
    police.setBold(true);
    police.setLetterSpacing(QFont::AbsoluteSpacing, 1.5);
    p.setFont(police);
    const QFontMetricsF mesure(police);
    const qreal yTitre = centre.y() + rayonAnneau * 1.14 + cote * 0.32;
    if (titre.isRightToLeft()) {                                         // arabe : le titre apparaît d'un bloc
        const qreal a = phase(temps, 1500, 1900);
        p.setPen(QColor(255, 255, 255, int(255 * a)));
        p.drawText(QRectF(zone.left(), yTitre - mesure.ascent() + 12 * (1 - a), zone.width(), mesure.height()), Qt::AlignHCenter, titre);
    } else {
        qreal x = centre.x() - mesure.horizontalAdvance(titre) / 2;
        for (int i = 0; i < titre.size(); ++i) {
            const qreal a = doux(phase(temps, 1500 + i * 38, 1500 + i * 38 + 320));
            QColor c = QColor(255, 255, 255);
            if (a < 1) c = QColor(255, int(200 + 55 * a), int(120 + 135 * a));    // la lettre « refroidit » de l'orange au blanc
            c.setAlphaF(a);
            p.setPen(c);
            p.drawText(QPointF(x, yTitre + 14 * (1 - a)), QString(titre[i]));
            x += mesure.horizontalAdvance(titre[i]);
        }
    }
    QFont policeBienvenue = font();
    policeBienvenue.setPointSizeF(qMax(11.0, cote * 0.075));
    policeBienvenue.setBold(true);
    p.setFont(policeBienvenue);
    const qreal b = doux(phase(temps, 2050, 2400));
    p.setPen(QColor(255, 138, 91, int(255 * b)));
    const qreal yBienvenue = yTitre + mesure.descent() + 16 + 10 * (1 - b);
    p.drawText(QRectF(zone.left(), yBienvenue, zone.width(), 30), Qt::AlignHCenter | Qt::AlignTop, bienvenue);
    QFont policeDetail = font();
    policeDetail.setPointSizeF(9);
    p.setFont(policeDetail);
    p.setPen(QColor(201, 211, 220, int(220 * b)));
    p.drawText(QRectF(zone.left(), yBienvenue + 30, zone.width(), 22), Qt::AlignHCenter | Qt::AlignTop, detail);

    // 8. fine barre de chargement : ouverture de l'interface
    const qreal charge = phase(temps, 2100, SORTIE);
    if (charge > 0) {
        const QRectF piste(centre.x() - 110, yBienvenue + 64, 220, 3);
        p.setBrush(QColor(255, 255, 255, 40));
        p.drawRoundedRect(piste, 1.5, 1.5);
        QLinearGradient remplissage(piste.topLeft(), piste.topRight());
        remplissage.setColorAt(0.0, QColor("#FFD36B"));
        remplissage.setColorAt(1.0, QColor("#E4491F"));
        p.setBrush(remplissage);
        p.drawRoundedRect(QRectF(piste.left(), piste.top(), piste.width() * doux(charge), piste.height()), 1.5, 1.5);
    }
    p.restore();
}

// =============================================================================
// Carte des interventions (tableau de bord)
// =============================================================================
CarteInterventions::CarteInterventions(QWidget *parent) : QWidget(parent)
{
    setMinimumSize(200, 190);
    setMouseTracking(true);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    imagePlan = QPixmap(":/images/carte_interventions.png");

    // Lieux : position sur le plan (fraction de l'image) et position réelle (latitude, longitude)
    lieux = {
        {"INT-0419", QColor("#2F6FE0"), {0.074, 0.40}, 36.8478, 10.1702, 0},
        {"INT-0417", QColor("#D93636"), {0.878, 0.466}, 36.8536, 10.2112, 0},
        {QString::fromUtf8("Caserne Centrale"), QColor("#1E9E63"), {0.457, 0.735}, 36.8421, 10.1893, 1},
        {"S. Larbi · balise SOS", QColor("#D93636"), {0.835, 0.524}, 36.8529, 10.2096, 2},
    };
    // Trajets des unités (de la caserne vers l'intervention)
    trajets = {
        {"VSAV-03", QColor("#2F6FE0"),
         {{0.473, 0.696}, {0.548, 0.771}, {0.500, 0.829}, {0.468, 0.780}, {0.415, 0.753}, {0.319, 0.726},
          {0.285, 0.685}, {0.138, 0.469}, {0.080, 0.403}},
         {{36.8421, 10.1893}, {36.8410, 10.1850}, {36.8432, 10.1800}, {36.8455, 10.1760}, {36.8478, 10.1702}}, 7000},
        {"FPT-02", QColor("#E4491F"),
         {{0.548, 0.768}, {0.564, 0.685}, {0.681, 0.595}, {0.686, 0.527}, {0.750, 0.539}, {0.793, 0.572},
          {0.835, 0.524}},
         {{36.8421, 10.1893}, {36.8445, 10.1950}, {36.8470, 10.2010}, {36.8505, 10.2050}, {36.8529, 10.2096}}, 8000},
    };
    centrerSur(36.8475, 10.1900);

    animation = new QTimer(this);
    connect(animation, &QTimer::timeout, this, [this]() { temps += 50; if (fenetreActive(this) && !partieVisible(this).isEmpty()) update(); });
    animation->start(50);
}

QPointF CarteInterventions::versTuiles(double lat, double lon, int z)
{
    const double n = std::pow(2.0, z);
    const double x = (lon + 180.0) / 360.0 * n;
    const double r = lat * M_PI / 180.0;
    const double y = (1.0 - std::log(std::tan(r) + 1.0 / std::cos(r)) / M_PI) / 2.0 * n;
    return QPointF(x, y);
}

void CarteInterventions::centrerSur(double lat, double lon) { centre = versTuiles(lat, lon, zoom); update(); }

QPointF CarteInterventions::versEcranGeo(double lat, double lon) const
{
    const QPointF t = versTuiles(lat, lon, zoom);
    return QPointF(width() / 2.0 + (t.x() - centre.x()) * 256, height() / 2.0 + (t.y() - centre.y()) * 256);
}

// Le plan garde ses proportions : il remplit le cadre (les bords qui dépassent sont coupés)
QRectF CarteInterventions::zonePlan() const
{
    if (imagePlan.isNull()) return rect();
    const qreal echelle = qMax(width() / qreal(imagePlan.width()), height() / qreal(imagePlan.height()));
    const QSizeF taille(imagePlan.width() * echelle, imagePlan.height() * echelle);
    return QRectF(QPointF((width() - taille.width()) / 2, (height() - taille.height()) / 2), taille);
}

QPointF CarteInterventions::versEcran(const Lieu &l) const
{
    if (reelle) return versEcranGeo(l.lat, l.lon);
    const QRectF z = zonePlan();
    return QPointF(z.left() + l.plan.x() * z.width(), z.top() + l.plan.y() * z.height());
}

void CarteInterventions::definirReelle(bool r)
{
    reelle = r;
    erreurs = 0;
    if (reelle && !reseau) {
        reseau = new QNetworkAccessManager(this);
        QNetworkDiskCache *cache = new QNetworkDiskCache(reseau);         // tuiles gardées sur le disque
        cache->setCacheDirectory(QStandardPaths::writableLocation(QStandardPaths::CacheLocation) + "/tuiles");
        reseau->setCache(cache);
    }
    setCursor(reelle ? Qt::OpenHandCursor : Qt::ArrowCursor);
    update();
}

void CarteInterventions::localiserBalise()
{
    for (const Lieu &l : lieux)
        if (l.type == 2 && reelle) { zoom = qMax(zoom, 15); centrerSur(l.lat, l.lon); }
    debutRadar = temps;
    update();
}

void CarteInterventions::dessinerTuiles(QPainter &p)
{
    p.fillRect(rect(), QColor(sombre ? "#1B232C" : "#EEF1F4"));
    const int n = 1 << zoom;
    const int x0 = int(std::floor(centre.x() - width() / 512.0)), x1 = int(std::floor(centre.x() + width() / 512.0));
    const int y0 = int(std::floor(centre.y() - height() / 512.0)), y1 = int(std::floor(centre.y() + height() / 512.0));
    for (int tx = x0; tx <= x1; ++tx)
        for (int ty = y0; ty <= y1; ++ty) {
            if (ty < 0 || ty >= n) continue;
            const int vx = ((tx % n) + n) % n;
            const QString cle = QString("%1/%2/%3").arg(zoom).arg(vx).arg(ty);
            const QRectF cible(width() / 2.0 + (tx - centre.x()) * 256, height() / 2.0 + (ty - centre.y()) * 256, 256, 256);
            if (tuiles.contains(cle)) { p.drawPixmap(cible, tuiles[cle], tuiles[cle].rect()); continue; }
            p.setPen(QPen(QColor(sombre ? "#2A3542" : "#DCE2E8"), 1));
            p.setBrush(Qt::NoBrush);
            p.drawRect(cible);
            if (!demandes.contains(cle) && reseau && erreurs < 6) {
                demandes.insert(cle);
                QNetworkRequest requete(QUrl(QString("https://tile.openstreetmap.org/%1.png").arg(cle)));
                requete.setRawHeader("User-Agent", "CaserneConnectee/1.0 (projet academique ESPRIT)");
                requete.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::PreferCache);
                QNetworkReply *reponse = reseau->get(requete);
                connect(reponse, &QNetworkReply::finished, this, [this, reponse, cle]() {
                    QPixmap image;
                    if (reponse->error() == QNetworkReply::NoError && image.loadFromData(reponse->readAll())) {
                        tuiles.insert(cle, image);
                        erreurs = 0;
                    } else {
                        erreurs++;
                        demandes.remove(cle);
                    }
                    reponse->deleteLater();
                    update();
                });
            }
        }
    if (sombre) p.fillRect(rect(), QColor(10, 14, 20, 95));               // carte assombrie en mode sombre
}

// Boussole : un petit cercle qui pulse, puis s'agrandit et se transforme en boussole ;
// l'aiguille oscille avant de se stabiliser vers le nord. Au survol, elle grandit encore.
void CarteInterventions::dessinerBoussole(QPainter &p)
{
    const qreal t = temps - debutEntree;
    const qreal ouverture = QEasingCurve(QEasingCurve::OutBack).valueForProgress(qBound(0.0, (t - 900) / 650.0, 1.0));
    QPointF c(width() - 38, height() - (reelle ? 52 : 38));
    const bool survol = QLineF(c, souris).length() < 34;
    static qreal agrandi = 0;                                          // survol : grossit en douceur
    agrandi += ((survol ? 1.0 : 0.0) - agrandi) * 0.18;
    const qreal r = 6 + 16 * ouverture + 7 * agrandi;

    // halo + disque
    p.setPen(Qt::NoPen);
    if (ouverture < 1) {
        const qreal pouls = 0.5 + 0.5 * std::sin(temps / 160.0);
        p.setBrush(QColor(228, 73, 31, int(70 * pouls * (1 - ouverture))));
        p.drawEllipse(c, r + 6, r + 6);
    }
    QRadialGradient fond(c, r);
    fond.setColorAt(0.0, QColor(sombre ? "#222B36" : "#FFFFFF"));
    fond.setColorAt(1.0, QColor(sombre ? "#19212A" : "#F1F4F7"));
    p.setBrush(fond);
    p.setPen(QPen(QColor(sombre ? "#3A4654" : "#D5DBE1"), 1.2));
    p.drawEllipse(c, r, r);
    if (ouverture <= 0.05) {                                           // encore un petit cercle
        p.setBrush(QColor("#E4491F"));
        p.setPen(Qt::NoPen);
        p.drawEllipse(c, 2.5, 2.5);
        return;
    }
    p.save();
    p.setOpacity(qMin(1.0, ouverture));
    // graduations
    for (int i = 0; i < 16; ++i) {
        const qreal a = i * M_PI / 8;
        const qreal l = i % 4 == 0 ? 5 : 2.5;
        p.setPen(QPen(QColor(sombre ? "#7F8C99" : "#8B99A6"), i % 4 == 0 ? 1.4 : 0.8));
        p.drawLine(c + QPointF(std::sin(a), -std::cos(a)) * (r - 2), c + QPointF(std::sin(a), -std::cos(a)) * (r - 2 - l));
    }
    // aiguille : oscillation amortie vers le nord
    const qreal s2 = qMax(0.0, (t - 1100) / 1000.0);
    const qreal angle = 70 * std::exp(-2.2 * s2) * std::cos(6.0 * s2) + 3 * std::sin(temps / 900.0);
    p.translate(c);
    p.rotate(angle);
    const qreal L = r - 5;
    QPolygonF nord({QPointF(0, -L), QPointF(4, 0), QPointF(-4, 0)});
    QPolygonF sud({QPointF(0, L), QPointF(4, 0), QPointF(-4, 0)});
    p.setPen(Qt::NoPen);
    p.setBrush(QColor("#E4491F"));
    p.drawPolygon(nord);
    p.setBrush(QColor(sombre ? "#9AA5B1" : "#7A8896"));
    p.drawPolygon(sud);
    p.setBrush(Qt::white);
    p.drawEllipse(QPointF(0, 0), 2, 2);
    p.restore();
    // lettre N
    QFont police = font();
    police.setPointSizeF(6.5 + 1.5 * agrandi);
    police.setBold(true);
    p.setFont(police);
    p.setPen(QColor("#C7341A"));
    p.setOpacity(qMin(1.0, ouverture));
    p.drawText(QRectF(c.x() - 10, c.y() - r - 13, 20, 12), Qt::AlignCenter, "N");
    p.setOpacity(1.0);
}

QPointF CarteInterventions::pointSurTrajet(const QVector<QPointF> &points, qreal t) const
{
    QVector<QPointF> ecran;
    for (const QPointF &pt : points) {
        if (reelle) ecran << versEcranGeo(pt.x(), pt.y());
        else { const QRectF z = zonePlan(); ecran << QPointF(z.left() + pt.x() * z.width(), z.top() + pt.y() * z.height()); }
    }
    qreal total = 0;
    for (int i = 1; i < ecran.size(); ++i) total += QLineF(ecran[i - 1], ecran[i]).length();
    qreal reste = total * t;
    for (int i = 1; i < ecran.size(); ++i) {
        const qreal l = QLineF(ecran[i - 1], ecran[i]).length();
        if (reste <= l && l > 0) return ecran[i - 1] + (ecran[i] - ecran[i - 1]) * (reste / l);
        reste -= l;
    }
    return ecran.isEmpty() ? QPointF() : ecran.last();
}

// Épingle (intervention), pastille verte (caserne) ou balise SOS, avec son étiquette
void CarteInterventions::dessinerMarqueur(QPainter &p, const QPointF &pos, const Lieu &l, bool etiquette)
{
    p.setPen(Qt::NoPen);
    if (l.type == 0) {
        QPainterPath epingle;
        epingle.moveTo(pos);
        epingle.cubicTo(pos + QPointF(-4, -8), pos + QPointF(-11, -13), pos + QPointF(-11, -21));
        epingle.arcTo(QRectF(pos.x() - 11, pos.y() - 32, 22, 22), 180, -180);
        epingle.cubicTo(pos + QPointF(11, -13), pos + QPointF(4, -8), pos);
        p.setBrush(l.couleur);
        p.drawPath(epingle);
        p.setBrush(Qt::white);
        p.drawEllipse(pos + QPointF(0, -21), 4.5, 4.5);
    } else if (l.type == 1) {
        p.setBrush(l.couleur);
        p.drawRoundedRect(QRectF(pos.x() - 10, pos.y() - 10, 20, 20), 5, 5);
        p.setBrush(Qt::white);
        p.drawEllipse(pos, 3.5, 3.5);
    } else {
        p.setBrush(l.couleur);
        p.drawEllipse(pos, 6.5, 6.5);
        p.setBrush(Qt::white);
        p.drawEllipse(pos, 2.5, 2.5);
    }
    if (!etiquette) return;
    QFont police = font();
    police.setPointSizeF(7.5);
    police.setBold(true);
    p.setFont(police);
    const QFontMetricsF m(police);
    const QRectF boite(pos.x() + 12, pos.y() - (l.type == 0 ? 30 : 9), m.horizontalAdvance(l.nom) + 12, 18);
    p.setBrush(QColor(sombre ? "#19212A" : "#FFFFFF"));
    p.setPen(QPen(QColor(0, 0, 0, 30), 1));
    p.drawRoundedRect(boite, 9, 9);
    p.setPen(l.type == 1 ? QColor("#1E9E63") : l.couleur.darker(110));
    p.drawText(boite, Qt::AlignCenter, l.nom);
}

void CarteInterventions::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    p.setRenderHint(QPainter::SmoothPixmapTransform);
    QPainterPath coins;
    coins.addRoundedRect(QRectF(rect()), 10, 10);
    p.setClipPath(coins);

    // 1. fond : plan illustré ou tuiles OpenStreetMap
    if (reelle) dessinerTuiles(p);
    else {
        // plan mis à l'échelle une seule fois par taille (redessiner une grande image lissée 20 fois/s coûte cher)
        const QRectF zp = zonePlan();
        if (planEchelle.size() != zp.size().toSize()) planEchelle = imagePlan.scaled(zp.size().toSize(), Qt::IgnoreAspectRatio, Qt::SmoothTransformation);
        p.drawPixmap(zp.topLeft(), planEchelle);
        if (sombre) p.fillRect(rect(), QColor(10, 14, 20, 90));
    }

    // 2. trajets : en carte réelle, la ligne pointillée est tracée ; sur le plan elle est déjà dessinée
    for (const Trajet &tr : trajets) {
        if (reelle) {
            QPainterPath chemin;
            for (int i = 0; i < tr.geo.size(); ++i) {
                const QPointF e = versEcranGeo(tr.geo[i].x(), tr.geo[i].y());
                if (i == 0) chemin.moveTo(e); else chemin.lineTo(e);
            }
            QPen trait(tr.couleur, 3.5, Qt::DashLine, Qt::RoundCap, Qt::RoundJoin);
            trait.setDashOffset(-temps / 60.0);                              // les pointillés avancent
            p.setPen(trait);
            p.setBrush(Qt::NoBrush);
            p.drawPath(chemin);
        }
        // le véhicule roule le long de son trajet (aller, puis il recommence)
        const qreal t = std::fmod(temps, tr.periode) / tr.periode;
        const QPointF v = pointSurTrajet(reelle ? tr.geo : tr.plan, QEasingCurve(QEasingCurve::InOutSine).valueForProgress(t));
        QRadialGradient lueur(v, 14);
        QColor c = tr.couleur; c.setAlpha(120);
        lueur.setColorAt(0, c);
        c.setAlpha(0);
        lueur.setColorAt(1, c);
        p.setPen(Qt::NoPen);
        p.setBrush(lueur);
        p.drawEllipse(v, 14, 14);
        p.setBrush(Qt::white);
        p.drawEllipse(v, 5.5, 5.5);
        p.setBrush(tr.couleur);
        p.drawEllipse(v, 3.8, 3.8);
        if (reelle) {
            QFont police = font();
            police.setPointSizeF(7);
            police.setBold(true);
            p.setFont(police);
            p.setPen(tr.couleur.darker(115));
            p.drawText(v + QPointF(9, -7), tr.unite);
        }
    }

    // 3. points importants : halos qui pulsent, radar sur la balise SOS
    int rangLieu = 0;
    for (const Lieu &l : lieux) {
        // entrée : chaque point tombe du haut et rebondit (les uns après les autres)
        const qreal chute = QEasingCurve(QEasingCurve::OutBounce).valueForProgress(
            qBound(0.0, (temps - debutEntree - 150 * rangLieu++) / 700.0, 1.0));
        if (chute <= 0) continue;
        const QPointF pos = versEcran(l) - QPointF(0, 40 * (1 - chute));
        const QPointF centreHalo = l.type == 0 ? pos + QPointF(0, -21) : pos;
        p.setOpacity(qMin(1.0, chute * 1.5));
        if (l.type == 2) {
            for (int k = 0; k < 3; ++k) {                                    // ondes radar
                const qreal t = std::fmod(temps / 1600.0 + k / 3.0, 1.0);
                p.setBrush(Qt::NoBrush);
                p.setPen(QPen(QColor(217, 54, 54, int(200 * (1 - t))), 2));
                p.drawEllipse(centreHalo, 6 + 26 * t, 6 + 26 * t);
            }
        } else {
            const qreal t = std::fmod(temps / 1400.0 + (l.type == 1 ? 0.5 : 0.0), 1.0);
            QColor c = l.couleur;
            c.setAlpha(int(150 * (1 - t)));
            p.setPen(Qt::NoPen);
            p.setBrush(c);
            p.drawEllipse(centreHalo, 8 + 16 * t, 8 + 16 * t);
        }
        if (reelle) dessinerMarqueur(p, pos, l, true);                      // sur le plan, les épingles sont dessinées
        p.setOpacity(1.0);
    }

    // 4. « Localiser la balise » : grand radar qui balaie la zone pendant 3 secondes
    const qreal radar = (temps - debutRadar) / 3000.0;
    if (radar >= 0 && radar < 1) {
        for (const Lieu &l : lieux) {
            if (l.type != 2) continue;
            const QPointF pos = versEcran(l);
            const qreal r = 70;
            QConicalGradient balayage(pos, -temps * 0.25);
            balayage.setColorAt(0.0, QColor(217, 54, 54, int(150 * (1 - radar))));
            balayage.setColorAt(0.25, QColor(217, 54, 54, 0));
            balayage.setColorAt(1.0, QColor(217, 54, 54, 0));
            p.setPen(Qt::NoPen);
            p.setBrush(balayage);
            p.drawEllipse(pos, r, r);
            p.setBrush(Qt::NoBrush);
            p.setPen(QPen(QColor(217, 54, 54, int(220 * (1 - radar))), 2.2));
            p.drawEllipse(pos, r * (0.4 + 0.6 * std::fmod(radar * 3, 1.0)), r * (0.4 + 0.6 * std::fmod(radar * 3, 1.0)));
        }
    }

    // 5. boussole (coin inférieur droit)
    dessinerBoussole(p);

    // 6. mentions : source des tuiles, état de la connexion
    p.setClipping(false);
    QFont petite = font();
    petite.setPointSizeF(7);
    p.setFont(petite);
    if (reelle) {
        const QString source = QString::fromUtf8("© OpenStreetMap");
        const QRectF zone(width() - 104, height() - 18, 100, 15);
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(255, 255, 255, 200));
        p.drawRoundedRect(zone, 4, 4);
        p.setPen(QColor("#45505C"));
        p.drawText(zone, Qt::AlignCenter, source);
        if (erreurs >= 6 && tuiles.isEmpty()) {
            const QRectF bandeau(10, 46, width() - 20, 40);
            p.setPen(Qt::NoPen);
            p.setBrush(QColor(sombre ? "#2A1A16" : "#FDE9E1"));
            p.drawRoundedRect(bandeau, 8, 8);
            p.setPen(QColor("#C7341A"));
            p.drawText(bandeau, Qt::AlignCenter | Qt::TextWordWrap,
                       QString::fromUtf8("Carte réelle indisponible : pas de connexion Internet. Choisissez « Plan »."));
        }
    }
}

void CarteInterventions::mousePressEvent(QMouseEvent *e)
{
    if (!reelle) return;
    glisse = true;
    dernierePosition = e->position().toPoint();
    setCursor(Qt::ClosedHandCursor);
}

void CarteInterventions::mouseMoveEvent(QMouseEvent *e)
{
    const QPoint pos = e->position().toPoint();
    souris = e->position();
    if (glisse) {
        centre -= QPointF(pos - dernierePosition) / 256.0;
        dernierePosition = pos;
        update();
        return;
    }
    // info-bulle sur un point important
    for (const Lieu &l : lieux)
        if (QLineF(versEcran(l) + QPointF(0, l.type == 0 ? -21 : 0), pos).length() < 14) {
            QToolTip::showText(e->globalPosition().toPoint(), l.nom, this);
            return;
        }
}

void CarteInterventions::mouseReleaseEvent(QMouseEvent *)
{
    glisse = false;
    if (reelle) setCursor(Qt::OpenHandCursor);
}

void CarteInterventions::mouseDoubleClickEvent(QMouseEvent *)
{
    if (!reelle) return;
    zoom = 13;
    centrerSur(36.8475, 10.1900);
}

void CarteInterventions::wheelEvent(QWheelEvent *e)
{
    if (!reelle) return;
    const int nouveau = qBound(11, zoom + (e->angleDelta().y() > 0 ? 1 : -1), 18);
    if (nouveau == zoom) return;
    centre *= std::pow(2.0, nouveau - zoom);
    zoom = nouveau;
    update();
}

// =============================================================================
// Météo de l'en-tête (Open-Meteo, Tunis)
// =============================================================================
QList<MeteoEntete *> MeteoEntete::instances;
bool MeteoEntete::connue = false, MeteoEntete::jour = true;
double MeteoEntete::temperature = 0;
int MeteoEntete::code = 0;

MeteoEntete::MeteoEntete(QWidget *parent) : QWidget(parent)
{
    setFixedSize(sizeHint());
    instances << this;
    QTimer *animation = new QTimer(this);
    connect(animation, &QTimer::timeout, this, [this]() { phase += 0.1; if (isVisible() && fenetreActive(this) && !animationsLegeres()) update(); });
    animation->start(120);
    if (instances.size() == 1) {                     // une seule demande pour tous les en-têtes
        demander();
        QTimer *rafraichir = new QTimer(qApp);
        QObject::connect(rafraichir, &QTimer::timeout, qApp, &MeteoEntete::demander);
        rafraichir->start(15 * 60 * 1000);
    }
}

MeteoEntete::~MeteoEntete() { instances.removeAll(this); }

void MeteoEntete::demander()
{
    static QNetworkAccessManager *reseau = new QNetworkAccessManager(qApp);
    QNetworkRequest requete(QUrl("https://api.open-meteo.com/v1/forecast?latitude=36.85&longitude=10.19"
                                 "&current=temperature_2m,weather_code,is_day&timezone=auto"));
    requete.setRawHeader("User-Agent", "CaserneConnectee/1.0");
    QNetworkReply *reponse = reseau->get(requete);
    QObject::connect(reponse, &QNetworkReply::finished, qApp, [reponse]() {
        if (reponse->error() == QNetworkReply::NoError) {
            const QJsonObject actuel = QJsonDocument::fromJson(reponse->readAll()).object().value("current").toObject();
            if (actuel.contains("temperature_2m")) {
                temperature = actuel.value("temperature_2m").toDouble();
                code = actuel.value("weather_code").toInt();
                jour = actuel.value("is_day").toInt(1) == 1;
                connue = true;
            }
        }
        reponse->deleteLater();
        for (MeteoEntete *m : instances) { m->setToolTip(description()); m->update(); }
    });
}

QString MeteoEntete::description()
{
    if (!connue) return QString::fromUtf8("Météo indisponible (pas de connexion)");
    QString ciel = code == 0 ? (jour ? "Ciel dégagé" : "Nuit claire") : code <= 3 ? "Partiellement nuageux"
                 : code <= 48 ? "Brouillard" : code <= 67 ? "Pluie" : code <= 77 ? "Neige" : code <= 82 ? "Averses" : "Orage";
    return QString::fromUtf8("Tunis · %1 · %2 °C").arg(QString::fromUtf8(ciel.toUtf8())).arg(qRound(temperature));
}

void MeteoEntete::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const QPointF c(15, height() / 2.0);
    const bool sombre = qApp->palette().color(QPalette::Window).lightness() < 128;
    if (!connue) jour = QTime::currentTime().hour() >= 6 && QTime::currentTime().hour() < 19;   // sans données : soleil ou lune selon l'heure
    const bool nuages = connue && code >= 1, pluie = connue && ((code >= 51 && code <= 67) || (code >= 80 && code <= 82) || code >= 95);
    const bool astreVisible = !connue || code <= 3;
    // Icône nette : formes pleines aux couleurs vives, contour sombre fin pour ressortir sur le bandeau,
    // aucune rotation (une forme qui tourne paraît floue à cette petite taille).
    const QColor contour(14, 19, 26, 200);
    if (astreVisible) {
        const QPointF a = nuages ? QPointF(12, 13) : QPointF(17, 19);
        if (jour) {
            const qreal rayon = 1.0 + 0.8 * (0.5 + 0.5 * std::sin(phase * 2));      // les rayons « respirent »
            p.setPen(QPen(QColor("#FFC24A"), 2.2, Qt::SolidLine, Qt::RoundCap));
            for (int i = 0; i < 8; ++i) {
                const qreal ang = i * M_PI / 4;
                const QPointF d(std::cos(ang), std::sin(ang));
                p.drawLine(a + d * 8.8, a + d * (10.2 + rayon));
            }
            QRadialGradient soleil(a - QPointF(2, 2), 8);
            soleil.setColorAt(0, QColor("#FFF6C8"));
            soleil.setColorAt(0.5, QColor("#FFD54A"));
            soleil.setColorAt(1, QColor("#FFAA2B"));
            p.setPen(QPen(contour, 0.8));
            p.setBrush(soleil);
            p.drawEllipse(a, 6.8, 6.8);
        } else {
            QPainterPath lune;
            lune.addEllipse(a, 7.5, 7.5);
            QPainterPath ombre;
            ombre.addEllipse(a + QPointF(3.8, -2.8), 6.4, 6.4);
            p.setPen(QPen(contour, 0.8));
            p.setBrush(QColor("#FFF1B8"));
            p.drawPath(lune.subtracted(ombre));
        }
    }
    if (nuages) {                                   // nuage blanc, net, devant le soleil
        const QPointF n(nuages && astreVisible ? 19 : 17, 22);
        auto forme = [](const QPointF &c, qreal rx, qreal ry) { QPainterPath f; f.addEllipse(c, rx, ry); return f; };
        QPainterPath bas;
        bas.addRoundedRect(QRectF(n.x() - 12.5, n.y(), 23.5, 5.6), 2.8, 2.8);
        const QPainterPath nuage = forme(n + QPointF(-7, 0), 5.5, 5.2).united(forme(n + QPointF(-1, -4), 7, 7))
                                       .united(forme(n + QPointF(6, 0.5), 5, 4.8)).united(bas);   // une seule forme, sans traits internes
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(0, 0, 0, 70));                // petite ombre portée : le nuage se détache du soleil
        p.drawPath(nuage.translated(0.8, 1.2));
        QLinearGradient blanc(n + QPointF(0, -10), n + QPointF(0, 6));
        blanc.setColorAt(0, QColor("#FFFFFF"));
        blanc.setColorAt(1, QColor("#D5DEE8"));
        p.setBrush(blanc);
        p.drawPath(nuage);
    }
    if (pluie) {                                    // gouttes bleues qui tombent
        p.setPen(QPen(QColor("#5B9BFF"), 1.8, Qt::SolidLine, Qt::RoundCap));
        for (int i = 0; i < 3; ++i) {
            const qreal y = std::fmod(phase * 8 + i * 4, 8);
            p.drawLine(QPointF(10 + i * 6, 29 + y * 0.6), QPointF(9 + i * 6, 32 + y * 0.6));
        }
    }
    // température en petite police
    QFont police = font();
    police.setPointSizeF(9.5);
    police.setBold(true);
    p.setFont(police);
    p.setPen(QColor(sombre ? "#E6EBF0" : "#E6EBF0"));
    p.drawText(QRectF(36, 0, width() - 36, height()), Qt::AlignVCenter | Qt::AlignLeft,
               connue ? QString::fromUtf8("%1 °C").arg(qRound(temperature)) : QString::fromUtf8("— °C"));
}

// =============================================================================
// Fond qui suit l'heure
// =============================================================================
QColor CielHoraire::couleurCiel(qreal heure)
{
    struct Repere { qreal heure; QColor couleur; };
    static const Repere reperes[] = {
        {0, QColor("#1B2A4A")}, {5, QColor("#2C2A55")}, {6.5, QColor("#C9708A")}, {7.5, QColor("#FF9A6B")},
        {10, QColor("#FFD58A")}, {13, QColor("#FFE3A3")}, {16.5, QColor("#FFC27A")}, {18.5, QColor("#FF7A45")},
        {19.5, QColor("#B04A6A")}, {21, QColor("#2C2A55")}, {24, QColor("#1B2A4A")}};
    for (int i = 0; i + 1 < int(sizeof(reperes) / sizeof(reperes[0])); ++i)
        if (heure >= reperes[i].heure && heure <= reperes[i + 1].heure) {
            const qreal t = (heure - reperes[i].heure) / (reperes[i + 1].heure - reperes[i].heure);
            const QColor &a = reperes[i].couleur, &b = reperes[i + 1].couleur;
            return QColor(int(a.red() + (b.red() - a.red()) * t), int(a.green() + (b.green() - a.green()) * t),
                          int(a.blue() + (b.blue() - a.blue()) * t));
        }
    return reperes[0].couleur;
}

CielHoraire::CielHoraire(QWidget *page) : QWidget(page)
{
    setAttribute(Qt::WA_TransparentForMouseEvents);
    setAttribute(Qt::WA_NoSystemBackground);
    setGeometry(page->rect());
    page->installEventFilter(this);
    QRandomGenerator *g = QRandomGenerator::global();
    for (int i = 0; i < 46; ++i) etoiles.append(QPointF(g->bounded(1.0), g->bounded(0.45)));
    for (int i = 0; i < 4; ++i) nuages.append({g->bounded(1.0), 0.04 + g->bounded(0.22), 0.7 + g->bounded(0.6), 0.004 + g->bounded(0.006)});
    // animation continue : étoiles qui scintillent, nuages qui dérivent, étoile filante de temps en temps
    minuterie = new QTimer(this);
    connect(minuterie, &QTimer::timeout, this, [this]() {
        const qreal dt = minuterie->interval() / 1000.0;
        scintillement += dt;
        for (Nuage &n : nuages) { n.x += n.vitesse * dt; if (n.x > 1.25) n.x = -0.25; }
        prochaineFilante -= dt;
        if (prochaineFilante <= 0) {
            QRandomGenerator *g = QRandomGenerator::global();
            etoileFilante = QPointF(0.15 + g->bounded(0.6), 0.03 + g->bounded(0.15));
            debutFilante = scintillement;
            prochaineFilante = 6 + g->bounded(8.0);
        }
        // seule la bande du ciel (en haut de la page) est redessinée, et seulement si elle est visible ;
        // rythme lent (ciel calme), plus rapide pendant le passage d'une étoile filante
        const bool filante = scintillement - debutFilante < 1.0;
        minuterie->setInterval(filante ? 50 : 160);
        const QRect bande = QRect(0, 0, width(), qMin(height(), 520)).intersected(partieVisible(this));
        if (!bande.isEmpty() && fenetreActive(this)) update(QRegion(bande).subtracted(zonesCouvertes(this)));
    });
    minuterie->start(160);
    lower();
    show();
}

bool CielHoraire::eventFilter(QObject *o, QEvent *e)
{
    if (e->type() == QEvent::Resize) { setGeometry(static_cast<QWidget *>(o)->rect()); lower(); }
    return false;
}

void CielHoraire::changeEvent(QEvent *e)
{
    if (e->type() == QEvent::PaletteChange || e->type() == QEvent::StyleChange) update();   // thème changé
    QWidget::changeEvent(e);
}

void CielHoraire::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const QTime maintenant = QTime::currentTime();
    const qreal heure = maintenant.hour() + maintenant.minute() / 60.0;
    const bool sombre = qApp->palette().color(QPalette::Window).lightness() < 128;
    const QColor ciel = couleurCiel(heure);
    const int force = sombre ? 85 : 60;
    const qreal hauteurCiel = qMin<qreal>(height(), 520);

    // voile du ciel en haut de la page, qui s'efface vers le bas
    QLinearGradient voile(0, 0, 0, hauteurCiel);
    QColor haut = ciel; haut.setAlpha(force);
    QColor milieu = ciel; milieu.setAlpha(force / 3);
    QColor bas = ciel; bas.setAlpha(0);
    voile.setColorAt(0.0, haut);
    voile.setColorAt(0.45, milieu);
    voile.setColorAt(1.0, bas);
    p.fillRect(QRectF(0, 0, width(), hauteurCiel), voile);

    // soleil (6h-19h) ou lune (19h-6h) : il traverse la page de gauche à droite en suivant un arc
    const bool jour = heure >= 6 && heure < 19;
    const qreal course = jour ? (heure - 6) / 13.0 : std::fmod(heure - 19 + 24, 24) / 11.0;
    const qreal x = width() * (0.08 + 0.84 * course);
    const qreal y = 40 + 70 * (1 - std::sin(course * M_PI));
    const qreal r = jour ? 120 : 95;
    QRadialGradient astre(QPointF(x, y), r);
    if (jour) {
        astre.setColorAt(0.0, QColor(255, 236, 170, sombre ? 120 : 150));
        astre.setColorAt(0.25, QColor(255, 200, 110, sombre ? 60 : 70));
        astre.setColorAt(1.0, QColor(255, 180, 90, 0));
    } else {
        astre.setColorAt(0.0, QColor(225, 235, 255, sombre ? 110 : 90));
        astre.setColorAt(0.2, QColor(170, 195, 245, sombre ? 45 : 35));
        astre.setColorAt(1.0, QColor(150, 180, 240, 0));
    }
    p.setPen(Qt::NoPen);
    p.setBrush(astre);
    p.drawEllipse(QPointF(x, y), r, r);

    // rayons du soleil qui tournent très lentement autour de l'astre (le jour)
    if (jour) {
        p.save();
        p.translate(x, y);
        p.rotate(scintillement * 2.5);
        for (int i = 0; i < 10; ++i) {
            QPainterPath rayon;
            rayon.moveTo(0, 0);
            rayon.lineTo(QPointF(std::cos(-0.05) * 340, std::sin(-0.05) * 340));
            rayon.lineTo(QPointF(std::cos(0.05) * 340, std::sin(0.05) * 340));
            rayon.closeSubpath();
            QRadialGradient lumiere(QPointF(0, 0), 340);
            lumiere.setColorAt(0, QColor(255, 220, 140, sombre ? 26 : 34));
            lumiere.setColorAt(1, QColor(255, 220, 140, 0));
            p.setBrush(lumiere);
            p.drawPath(rayon);
            p.rotate(36);
        }
        p.restore();
    }

    // nuages qui dérivent lentement (plus visibles le jour, teintés par la couleur du ciel)
    for (const Nuage &n : nuages) {
        const QPointF c(n.x * width(), n.y * hauteurCiel);
        QColor teinte = jour ? QColor(255, 255, 255) : ciel.lighter(130);
        teinte.setAlpha(jour ? (sombre ? 22 : 70) : 18);
        p.setBrush(teinte);
        for (const QPointF &bulle : {QPointF(-40, 6), QPointF(-12, -8), QPointF(18, 0), QPointF(44, 8)})
            p.drawEllipse(c + bulle * n.echelle, 34 * n.echelle, 22 * n.echelle);
    }

    // étoiles qui scintillent la nuit (elles s'éteignent à l'aube)
    const qreal nuit = heure >= 21 || heure < 5 ? 1.0 : heure >= 19.5 && heure < 21 ? (heure - 19.5) / 1.5
                     : heure >= 5 && heure < 6.5 ? 1.0 - (heure - 5) / 1.5 : 0.0;
    if (nuit > 0) {
        for (int i = 0; i < etoiles.size(); ++i) {
            const qreal eclat = 0.35 + 0.65 * (0.5 + 0.5 * std::sin(scintillement * (0.7 + (i % 5) * 0.25) + i * 2.1));
            p.setBrush(QColor(sombre ? 235 : 120, sombre ? 240 : 140, 255, int((sombre ? 190 : 120) * eclat * nuit)));
            const qreal t = 0.7 + (i % 3) * 0.45;
            p.drawEllipse(QPointF(etoiles[i].x() * width(), etoiles[i].y() * hauteurCiel), t, t);
        }
    }
    // étoile filante : une traînée lumineuse traverse le ciel en 0,9 seconde
    const qreal f = (scintillement - debutFilante) / 0.9;
    if (nuit > 0.3 && f >= 0 && f <= 1) {
        const QPointF depart(etoileFilante.x() * width(), etoileFilante.y() * hauteurCiel);
        const QPointF tete = depart + QPointF(260, 110) * f;
        QLinearGradient trainee(tete, tete - QPointF(120, 50));
        trainee.setColorAt(0, QColor(255, 255, 255, int(230 * (1 - f) * nuit)));
        trainee.setColorAt(1, QColor(255, 255, 255, 0));
        p.setPen(QPen(QBrush(trainee), 2, Qt::SolidLine, Qt::RoundCap));
        p.drawLine(tete, tete - QPointF(120, 50));
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(255, 255, 255, int(255 * (1 - f))));
        p.drawEllipse(tete, 2, 2);
    }
}

bool MessageAnime::eventFilter(QObject *o, QEvent *e)
{
    if (e->type() == QEvent::Resize) setGeometry(static_cast<QWidget *>(o)->rect());
    return false;
}

void MessageAnime::mousePressEvent(QMouseEvent *)
{
    if (temps < DUREE - 380) chrono->setCurrentTime(int(DUREE - 380));   // un clic ferme le message
}

void MessageAnime::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const bool succes = type == Succes;
    const QColor accent(succes ? "#1E9E63" : "#D93636");
    const qreal sortie = 1.0 - phase(temps, DUREE - 380, DUREE);

    // voile sombre sur la fenêtre
    p.fillRect(rect(), QColor(8, 12, 17, int(150 * phase(temps, 0, 220) * sortie)));

    // la carte rebondit en apparaissant (et tremble un instant pour une suppression)
    const qreal rebond = QEasingCurve(QEasingCurve::OutBack).valueForProgress(phase(temps, 0, 480));
    const qreal echelle = (0.62 + 0.38 * rebond) * (0.94 + 0.06 * sortie);
    // centre de la partie de la fenêtre réellement visible à l'écran (fenêtre plus grande que
    // l'écran, ou page défilée) : le message est toujours au milieu de ce que l'on voit
    const QRect visible = zoneVisible(this);
    QPointF centre = QPointF(visible.center()) + QPointF(0, -14 * (1 - sortie));
    if (!succes) {
        const qreal s = phase(temps, 760, 1120);
        if (s > 0 && s < 1) centre += QPointF(7 * std::sin(s * 6 * M_PI) * (1 - s), 0);
    }
    const QRectF carte(-205, -128, 410, 256);
    const QPointF icone(0, -48);

    // étincelles qui jaillissent / débris qui tombent (dessinés derrière la carte)
    const qreal depart = succes ? 700 : 780;
    const qreal dt = (temps - depart) / 1000.0;
    if (dt > 0 && dt < 1.3) {
        const QPointF origine = centre + icone * echelle;
        const qreal gravite = succes ? 300 : 620;
        p.setPen(Qt::NoPen);
        for (const Particule &pa : particules) {
            const QPointF pos = origine + pa.vitesse * dt + QPointF(0, 0.5 * gravite * dt * dt);
            QColor c = pa.couleur;
            c.setAlphaF(qBound(0.0, 1.0 - dt / 1.3, 1.0) * sortie);
            p.setBrush(c);
            if (succes) p.drawEllipse(pos, pa.taille, pa.taille);
            else p.drawRect(QRectF(pos.x() - pa.taille, pos.y() - pa.taille / 2, pa.taille * 2, pa.taille));
        }
    }


    p.save();
    p.setOpacity(phase(temps, 0, 200) * sortie);
    p.translate(centre);
    p.scale(echelle, echelle);

    // ombre douce + carte
    p.setPen(Qt::NoPen);
    for (int i = 6; i >= 1; --i) {
        p.setBrush(QColor(0, 0, 0, 10));
        p.drawRoundedRect(carte.adjusted(-i * 2.5, -i * 2.5 + 10, i * 2.5, i * 2.5 + 10), 24 + i * 2, 24 + i * 2);
    }
    QPainterPath forme;
    forme.addRoundedRect(carte, 22, 22);
    p.setBrush(QColor(sombre ? "#19212A" : "#FFFFFF"));
    p.setPen(QPen(QColor(sombre ? "#2A3542" : "#E1E6EC"), 1));
    p.drawPath(forme);

    // liseré de feu (succès) ou rouge (suppression) en haut de la carte
    p.save();
    p.setClipPath(forme);
    QLinearGradient lisere(carte.left(), 0, carte.right(), 0);
    lisere.setColorAt(0, QColor(succes ? "#E4491F" : "#B42A2A"));
    lisere.setColorAt(0.5, QColor(succes ? "#F2A93B" : "#D93636"));
    lisere.setColorAt(1, QColor(succes ? "#1E9E63" : "#F08080"));
    p.fillRect(QRectF(carte.left(), carte.top(), carte.width(), 5), lisere);
    p.restore();

    // pastille de l'icône : elle grossit, puis son cercle se trace
    const qreal pop = QEasingCurve(QEasingCurve::OutBack).valueForProgress(phase(temps, 120, 460));
    p.setPen(Qt::NoPen);
    p.setBrush(QColor(succes ? (sombre ? "#14302A" : "#E6F5EE") : (sombre ? "#3A1C1C" : "#FCE9E9")));
    p.drawEllipse(icone, 40 * pop, 40 * pop);
    const qreal trace = QEasingCurve(QEasingCurve::InOutCubic).valueForProgress(phase(temps, 220, 720));
    if (trace > 0) {
        p.setPen(QPen(accent, 4.5, Qt::SolidLine, Qt::RoundCap));
        p.setBrush(Qt::NoBrush);
        p.drawArc(QRectF(icone - QPointF(40, 40), QSizeF(80, 80)), 90 * 16, int(-trace * 360 * 16));
    }

    if (succes) {
        // la coche se dessine d'un trait
        QPainterPath coche;
        coche.moveTo(icone + QPointF(-17, 1));
        coche.lineTo(icone + QPointF(-5, 13));
        coche.lineTo(icone + QPointF(18, -12));
        const qreal c = QEasingCurve(QEasingCurve::OutCubic).valueForProgress(phase(temps, 640, 960));
        if (c > 0) {
            const qreal largeur = 6, longueur = coche.length() / largeur;
            QPen stylo(accent, largeur, Qt::CustomDashLine, Qt::RoundCap, Qt::RoundJoin);
            stylo.setDashPattern({longueur, longueur});
            stylo.setDashOffset(longueur * (1 - c));
            p.setPen(stylo);
            p.drawPath(coche);
        }
    } else {
        // corbeille : elle apparaît, son couvercle se soulève puis se referme
        const qreal c = QEasingCurve(QEasingCurve::OutBack).valueForProgress(phase(temps, 560, 820));
        if (c > 0) {
            p.save();
            p.translate(icone);
            p.scale(c, c);
            p.setPen(QPen(accent, 3.4, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
            p.setBrush(Qt::NoBrush);
            QPainterPath corps;
            corps.moveTo(-11, -7);
            corps.lineTo(-9, 17);
            corps.lineTo(9, 17);
            corps.lineTo(11, -7);
            p.drawPath(corps);
            p.drawLine(QPointF(-4, -1), QPointF(-3.5, 11));
            p.drawLine(QPointF(4, -1), QPointF(3.5, 11));
            const qreal ouverture = std::sin(phase(temps, 820, 1250) * M_PI);   // 0 -> 1 -> 0
            p.translate(14, -11);
            p.rotate(-28 * ouverture);
            p.translate(-14, 0);
            p.drawLine(QPointF(-16, 0), QPointF(14, 0));
            p.drawLine(QPointF(-5, 0), QPointF(-4, -5));
            p.drawLine(QPointF(-4, -5), QPointF(4, -5));
            p.drawLine(QPointF(4, -5), QPointF(5, 0));
            p.restore();
        }
    }

    // textes : ils montent légèrement en apparaissant
    const qreal tx = QEasingCurve(QEasingCurve::OutCubic).valueForProgress(phase(temps, 380, 700));
    p.setOpacity(p.opacity() * tx);
    p.translate(0, 10 * (1 - tx));
    QFont f(font());
    f.setBold(true);
    f.setPointSizeF(14.5);
    p.setFont(f);
    p.setPen(QColor(sombre ? "#E6EBF0" : "#16202A"));
    p.drawText(QRectF(carte.left() + 20, 4, carte.width() - 40, 30), Qt::AlignCenter, titre);
    f.setBold(false);
    f.setPointSizeF(9.5);
    p.setFont(f);
    p.setPen(QColor(sombre ? "#9AA7B4" : "#5B6B7A"));
    p.drawText(QRectF(carte.left() + 28, 38, carte.width() - 56, 52), Qt::AlignHCenter | Qt::AlignTop | Qt::TextWordWrap, texte);

    // fine barre qui se vide : temps restant avant la fermeture
    const qreal reste = 1.0 - phase(temps, 900, DUREE - 380);
    p.setPen(Qt::NoPen);
    p.setBrush(QColor(sombre ? "#26303B" : "#EDF0F4"));
    p.drawRoundedRect(QRectF(-60, carte.bottom() - 22, 120, 4), 2, 2);
    p.setBrush(accent);
    p.drawRoundedRect(QRectF(-60, carte.bottom() - 22, 120 * reste, 4), 2, 2);
    p.restore();

}

// =============================================================================
//  FENÊTRE
// =============================================================================
CaserneConnectee::CaserneConnectee(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::CaserneConnectee)
{
    ui->setupUi(this);
    // Au démarrage : module Employé (page 0 de SWCaserne), page Login (page 0 de SWEmploye)
    ui->SWCaserne->setCurrentIndex(0);
    ui->SWEmploye->setCurrentIndex(0);
    ui->barreLaterale->hide();   // pas de menu tant qu'on n'est pas connecté

    styleClair = styleSheet();

    // Module Employé (page d'identification + gestion des employés) : caserneconnectee.h / caserneconnectee.cpp
    employe = new Employe(ui, this);
    // mot de passe réinitialisé : retour à la page d'identification
    connect(employe, &Employe::motDePasseReinitialise, this, &CaserneConnectee::on_btnRetourConnexion_clicked);
    // lignes ajoutées / supprimées : couleurs du thème réappliquées au tableau
    connect(employe, &Employe::tableauModifie, this, [this]() { appliquerCouleursTableau(ui->tblEmploye); });
    connect(employe, &Employe::planningModifie, this, [this]() { appliquerCouleursTableau(ui->tblPlanningEmploye); });
    connect(employe, &Employe::deconnexionDemandee, this, &CaserneConnectee::on_btnQuitter_clicked);
    connect(employe, &Employe::tableauDeBordModifie, this, [this]() {
        for (QTableWidget *t : {ui->tblMissionsDashboard, ui->tblEffectifDashboard, ui->tblAlertesDashboard}) appliquerCouleursTableau(t);
    });

    installerEffetsGlobaux();

    // ---- Zoom : boutons « − 100 % + » dans l'en-tête, à gauche du bouton du thème ----
    QSettings reglages("ESPRIT", "CaserneConnectee");
    zoom = reglages.value("affichage/zoom", 100).toInt();
    modeTheme = reglages.value("affichage/theme", 2).toInt();
    boutonsTheme << ui->btnThemeEmploye;
    boutonsLangue << ui->btnLangueEmploye;
    ajouterOutilsEntete(ui->btnThemeEmploye, false);            // en-tête Employés : − 100 % + avant le thème
    // en-tête du tableau de bord : les mêmes outils (zoom, thème, langue, notifications) avant l'horloge
    if (QWidget *horloge = ui->lblHeureTableau) ajouterOutilsEntete(horloge, true);
    // météo et bouton de la musique, juste avant l'horloge de chaque en-tête
    musique = reglages.value("affichage/musique", true).toBool();
    animationsLegeres() = reglages.value("affichage/animationsLegeres", false).toBool();
    for (QLabel *l : findChildren<QLabel *>())
        if (l->property("variante").toString() == "heure") ajouterMeteoMusique(l);
    mettreAJourBoutonsMusique();
    mettreAJourBoutonsAnimations();
    for (const QKeySequence &touches : {QKeySequence(QKeySequence::ZoomIn), QKeySequence("Ctrl+="), QKeySequence("Ctrl++")}) {
        QShortcut *raccourci = new QShortcut(touches, this);
        raccourci->setContext(Qt::ApplicationShortcut);
        connect(raccourci, &QShortcut::activated, this, [this]() { changerZoom(zoom + 10); });
    }
    QShortcut *dezoom = new QShortcut(QKeySequence(QKeySequence::ZoomOut), this);
    dezoom->setContext(Qt::ApplicationShortcut);
    connect(dezoom, &QShortcut::activated, this, [this]() { changerZoom(zoom - 10); });
    QShortcut *normal = new QShortcut(QKeySequence("Ctrl+0"), this);
    normal->setContext(Qt::ApplicationShortcut);
    connect(normal, &QShortcut::activated, this, [this]() { changerZoom(100); });

    // ---- Thème au démarrage : clair, sombre ou selon l'horaire ----
    if (modeTheme == 1 || (modeTheme == 2 && sombreSelonHoraire())) appliquerTheme(true, false);
    mettreAJourBoutonTheme();

    // ---- Relance après un changement de zoom : la session continue ----
    const QStringList arguments = QCoreApplication::arguments();
    const int i = arguments.indexOf("--reprise");
    if (i >= 0 && i + 1 < arguments.size()) {
        const QString jeton = arguments[i + 1];
        QTimer::singleShot(0, this, [this, jeton]() { reprendreApresZoom(jeton); });
    } else {
        // ---- Lancement de l'application : le logo s'embrase sur toute la fenêtre, avec un son ----
        QTimer::singleShot(150, this, [this]() {
            jouerSonIntro();
            new IntroConnexion(this, QString::fromUtf8("Caserne Connectée"), QString::fromUtf8("Protection civile · Console de garde"),
                               QString::fromUtf8("Caserne Centrale — Tunis Nord"), {}, [this]() { employe->animerConnexion(); });
            // la musique douce commence quand le son de l'intro est terminé
            QTimer::singleShot(3500, this, [this]() { if (musique) jouerMusique(true); });
        });
    }

    // Date et heure de l'en-tête, mises à jour chaque seconde
    horloge = new QTimer(this);
    connect(horloge, &QTimer::timeout, this, &CaserneConnectee::mettreAJourHorloge);
    horloge->start(1000);
    mettreAJourHorloge();
}

CaserneConnectee::~CaserneConnectee()
{
    delete ui;
}

// =============================================================================
// Page d'identification (identifiant + mot de passe)
// =============================================================================
void CaserneConnectee::on_btnConnexion_clicked()
{
    if (!employe->connecter()) {                  // identifiant vérifié par le module Employé
        employe->animerResultatConnexion(false);  // refusé : croix rouge, éclats qui retombent
        return;
    }
    // Accepté : coche verte et étincelles sur la carte, puis l'intro du logo sur toute la fenêtre ;
    // sous l'intro, la page d'accueil des modules se prépare et ses carreaux arrivent en cascade.
    employe->animerResultatConnexion(true);
    ui->btnConnexion->setEnabled(false);
    QTimer::singleShot(900, this, [this]() {
        ui->btnConnexion->setEnabled(true);
        employe->jouerIntroConnexion(
            [this]() {
                employe->appliquerDroits();       // boutons et menu selon les droits du compte
                employe->quitterPageConnexion();
                employe->afficherAccueilModules(false);
            },
            [this]() { employe->animerAccueilModules(); });
    });
}

// =============================================================================
// Menu (barre latérale) : Employés et déconnexion
// =============================================================================
// Slots créés avec Qt Designer (clic droit sur le bouton -> Aller au slot... -> clicked()).
// Chaque module s'ouvre selon le droit du compte connecté (Aucun : le bouton est masqué).
void CaserneConnectee::on_btnMTableauDeBord_clicked() { employe->afficherTableauDeBord(); }          // SWEmploye page 4
void CaserneConnectee::on_btnMEmploye_clicked()
{
    ui->SWCaserne->setCurrentIndex(0);
    ui->SWEmploye->setCurrentIndex(3);            // page 3 : CRUD et métiers du module Employé
    employe->animerEntreePage();
}
void CaserneConnectee::on_btnMMission_clicked()       { employe->afficherModule(M_MISSIONS); }   // SWCaserne page 1
void CaserneConnectee::on_btnMUnite_clicked()         { employe->afficherModule(M_UNITES); }     // SWCaserne page 2
void CaserneConnectee::on_btnMVehicule_clicked()      { employe->afficherModule(M_VEHICULES); }  // SWCaserne page 3
void CaserneConnectee::on_btnMMateriel_clicked()      { employe->afficherModule(M_MATERIEL); }   // SWCaserne page 4
void CaserneConnectee::on_btnMFormation_clicked()     { employe->afficherModule(M_FORMATION); }  // SWCaserne page 5

void CaserneConnectee::on_btnQuitter_clicked()
{
    employe->deconnecter();
    ui->SWCaserne->setCurrentIndex(0);
    ui->SWEmploye->setCurrentIndex(0);            // retour à la page Login
    ui->barreLaterale->hide();
    employe->animerConnexion();
}

// =============================================================================
// Mot de passe oublié (page 2 de SWEmploye)
// =============================================================================
void CaserneConnectee::on_btnMotDePasseOublie_clicked()
{
    transitionDouce([this]() {
        employe->preparerMotDePasseOublie();
        ui->SWEmploye->setCurrentIndex(2);        // Login -> Mot de passe oublié
    });
}

void CaserneConnectee::on_btnRetourConnexion_clicked()
{
    transitionDouce([this]() {
        ui->SWEmploye->setCurrentIndex(0);        // Mot de passe oublié -> Login
        employe->animerConnexion();
    });
}

QString traduireTexte(const QString &francais);   // défini plus bas (traduction en arabe)

// -----------------------------------------------------------------------------
// Apparition des panneaux l'un après l'autre : un voile de la couleur du fond
// recouvre chaque panneau puis s'efface (rendu propre même sur les tableaux).
// -----------------------------------------------------------------------------
void CaserneConnectee::animerPanneaux(QWidget *contenu, const QList<QWidget *> &panneaux)
{
    if (contenu->layout()) contenu->layout()->activate();
    const QColor fond(modeSombre ? "#0F141A" : "#EDF1F5");
    int delai = 0;
    for (QWidget *p : panneaux) {
        VoileFondu *voile = new VoileFondu(contenu, fond, delai, 300);
        voile->setGeometry(QRect(p->mapTo(contenu, QPoint(0, 0)), p->size()).adjusted(-3, -3, 3, 3));
        voile->show();
        voile->raise();
        delai += 50;
    }
}

// =============================================================================
// Thème « caserne » animé, appliqué à toute l'application
// =============================================================================

// Liseré de feu sous chaque en-tête de page : un dégradé orange / ambre / rouge qui défile
class BandeFeu : public QWidget
{
public:
    explicit BandeFeu(QWidget *entete) : QWidget(entete)
    {
        setAttribute(Qt::WA_TransparentForMouseEvents);
        entete->installEventFilter(this);
        placer();
        minuterie = new QTimer(this);
        connect(minuterie, &QTimer::timeout, this, [this]() { decalage += 3.3; if (isVisible() && fenetreActive(this) && !animationsLegeres()) update(); });
        minuterie->start(50);
    }
protected:
    bool eventFilter(QObject *, QEvent *e) override
    {
        if (e->type() == QEvent::Resize || e->type() == QEvent::Show) placer();
        return false;
    }
    void paintEvent(QPaintEvent *) override
    {
        if (!isVisible()) return;
        QPainter p(this);
        QLinearGradient feu(-decalage, 0, -decalage + 420, 0);
        feu.setSpread(QGradient::RepeatSpread);
        feu.setColorAt(0.0, QColor("#E4491F"));
        feu.setColorAt(0.35, QColor("#F2A93B"));
        feu.setColorAt(0.6, QColor("#D93636"));
        feu.setColorAt(1.0, QColor("#E4491F"));
        p.fillRect(rect(), feu);
    }
private:
    void placer()
    {
        QWidget *e = parentWidget();
        setGeometry(0, e->height() - 3, e->width(), 3);
        raise();
    }
    QTimer *minuterie;
    qreal decalage = 0;
};

// Sirène : un halo rouge qui pulse autour des cadres d'alerte (balise d'urgence...)
static void pulsationSirene(QWidget *cadre)
{
    new HaloPulsant(cadre, QColor(217, 54, 54), false, 16, 1.4);     // halo rouge qui pulse autour du bandeau
}

// Logo de la barre latérale : la flamme « respire » et vacille légèrement
static void flammeVivante(QLabel *logo)
{
    new HaloPulsant(logo, QColor(255, 106, 61, 150), true, 10, 3.0, true);
}

void CaserneConnectee::installerEffetsGlobaux()
{
    // Barre latérale : icônes claires (orange pour le module ouvert), braises qui montent, flamme vivante
    const QList<QPair<QPushButton *, QString>> boutons = {
        {ui->btnMTableauDeBord, "tableau"}, {ui->btnMEmploye, "user"}, {ui->btnMMission, "missions"}, {ui->btnMUnite, "unites"},
        {ui->btnMVehicule, "vehicules"}, {ui->btnMMateriel, "materiel"}, {ui->btnMFormation, "formation"}};
    for (const auto &b : boutons) {
        QIcon icone;
        icone.addFile(QString(":/images/icones/navclair_%1.png").arg(b.second), QSize(), QIcon::Normal, QIcon::Off);
        icone.addFile(QString(":/images/icones/navorange_%1.png").arg(b.second), QSize(), QIcon::Normal, QIcon::On);
        b.first->setIcon(icone);
    }
    ui->btnThemeEmploye->setIcon(QIcon(":/images/icones/moon_clair.png"));            // bandeau sombre : icônes claires
    ui->btnNotificationsEmploye->setIcon(QIcon(":/images/icones/bell_clair.png"));
    FondBraises *braises = new FondBraises(ui->barreLaterale, 10, 0.5);
    braises->setProperty("secondaire", true);
    braises->demarrer();
    braises->lower();
    flammeVivante(ui->imgLogoBarre);

    // Toutes les pages : liseré de feu sous l'en-tête, sirène sur les alertes,
    // cartes de chiffres clés et boutons principaux qui se soulèvent au survol
    for (QFrame *f : findChildren<QFrame *>()) {
        const QString v = f->property("variante").toString();
        if (v == "entete") {
            new BandeFeu(f);
            // (pas d'étincelles dans le bandeau : elles obligeaient à redessiner tous ses boutons)
        }
        else if (v == "alerte" && !qobject_cast<QLabel *>(f)) pulsationSirene(f);
        else if (v == "kpi" && !f->graphicsEffect()) new EffetSurvol(f);
    }
    for (QPushButton *b : findChildren<QPushButton *>())
        if (b->property("variante").toString() == "principal" && !b->graphicsEffect()) new EffetSurvol(b, 18, 3);

    // Braises dans le fond de chaque page des modules ; le ciel (soleil le jour, étoiles la nuit)
    // reste seulement sur la page d'identification
    for (QWidget *contenu : findChildren<QWidget *>())
        if (contenu->property("variante").toString() == "contenuDefilant") {
            bool dejaBraises = false;                     // (FondBraises n'a pas Q_OBJECT : on le reconnaît à sa propriété)
            for (QObject *enfant : contenu->children()) dejaBraises = dejaBraises || enfant->property("fondBraises").toBool();
            if (!dejaBraises) new FondBraises(contenu, 14, 0.5);
            for (QObject *enfant : contenu->children()) if (enfant->property("fondBraises").toBool()) enfant->setProperty("secondaire", true);
        }
    new CielHoraire(ui->SWEmploye->widget(0));     // page d'identification

    // Changement de page (menu, gestion <-> métiers avancés) : la nouvelle page apparaît en douceur
    for (QStackedWidget *pile : findChildren<QStackedWidget *>())
        if (pile->objectName().startsWith("SW"))      // piles de navigation seulement (pas Plan / Carte réelle)
        connect(pile, &QStackedWidget::currentChanged, this, [this]() {
            QTimer::singleShot(0, this, &CaserneConnectee::animerPageVisible);
        });
}

// Panneaux de la page affichée qui apparaissent l'un après l'autre + chiffres clés qui défilent
void CaserneConnectee::animerPageVisible()
{
    static const QSet<QString> types = {"kpi", "panneau", "alerte", "bienvenue", "resultat"};
    for (QWidget *contenu : findChildren<QWidget *>()) {
        if (contenu->property("variante").toString() != "contenuDefilant" || !contenu->isVisible()) continue;
        QList<QWidget *> panneaux;
        for (QFrame *f : contenu->findChildren<QFrame *>()) {
            if (!f->isVisible() || qobject_cast<QLabel *>(f) || !types.contains(f->property("variante").toString())) continue;
            bool imbrique = false;                                  // un panneau dans un panneau : animé avec son parent
            for (QWidget *p = f->parentWidget(); p && p != contenu; p = p->parentWidget())
                if (types.contains(p->property("variante").toString())) imbrique = true;
            if (!imbrique) panneaux << f;
        }
        animerPanneaux(contenu, panneaux);

        static const QRegularExpression nombre("^(\\d+)(.*)$");
        for (QLabel *l : contenu->findChildren<QLabel *>()) {
            if (l->property("variante").toString() != "kpiValeur") continue;
            if (!l->property("valeurCible").isValid()) l->setProperty("valeurCible", l->text());   // valeur de Qt Designer
            const auto m = nombre.match(l->property("valeurCible").toString());
            if (!m.hasMatch()) continue;
            const QString suite = m.captured(2);
            QVariantAnimation *compteur = new QVariantAnimation(l);
            compteur->setDuration(900);
            compteur->setStartValue(0);
            compteur->setEndValue(m.captured(1).toInt());
            compteur->setEasingCurve(QEasingCurve::OutCubic);
            connect(compteur, &QVariantAnimation::valueChanged, l, [l, suite](const QVariant &v) {
                l->setText(QString::number(v.toInt()) + suite);
            });
            compteur->start(QAbstractAnimation::DeleteWhenStopped);
        }
    }
}

// Fondu enchaîné : une photo de l'écran actuel s'efface au-dessus du nouvel écran
void CaserneConnectee::transitionDouce(const std::function<void()> &changement)
{
    QLabel *photo = new QLabel(this);
    photo->setPixmap(grab());
    photo->setGeometry(rect());
    photo->show();
    photo->raise();
    changement();
    photo->raise();
    QGraphicsOpacityEffect *effet = new QGraphicsOpacityEffect(photo);
    photo->setGraphicsEffect(effet);
    QPropertyAnimation *fondu = new QPropertyAnimation(effet, "opacity", photo);
    fondu->setDuration(420);
    fondu->setStartValue(1.0);
    fondu->setEndValue(0.0);
    fondu->setEasingCurve(QEasingCurve::InOutQuad);
    connect(fondu, &QPropertyAnimation::finished, photo, &QLabel::deleteLater);
    fondu->start();
}

// -----------------------------------------------------------------------------
// Date et heure de l'en-tête
// -----------------------------------------------------------------------------
void CaserneConnectee::mettreAJourHorloge()
{
    // toutes les horloges de l'application (une dans l'en-tête de chaque page)
    const QDateTime maintenant = QDateTime::currentDateTime();
    QLocale langue = langueArabe ? QLocale(QLocale::Arabic, QLocale::Tunisia) : QLocale(QLocale::French, QLocale::France);
    QString date = langue.toString(maintenant.date(), "dddd d MMMM yyyy");
    if (!date.isEmpty()) date[0] = date[0].toUpper();
    const QString heure = maintenant.toString("HH:mm:ss");
    // mode selon l'horaire : bascule automatique à 7h et à 19h
    if (modeTheme == 2 && sombreSelonHoraire() != modeSombre) appliquerTheme(sombreSelonHoraire(), true);
    for (QLabel *l : findChildren<QLabel *>()) {
        const QString v = l->property("variante").toString();
        if (v == "heure") l->setText(heure);
        else if (v == "date") l->setText(date);
    }
}

// -----------------------------------------------------------------------------
// Mode sombre / clair : la feuille de style de Qt Designer est conservée, seules ses
// couleurs claires sont remplacées par leurs équivalents sombres (les couleurs de la
// charte — orange, vert, ambre, rouge, bleu — ne changent pas).
// -----------------------------------------------------------------------------
static const QHash<QString, QString> &couleursSombres()
{
    static const QHash<QString, QString> table = {
        {"#EDF1F5", "#0F141A"}, {"#FAFBFC", "#121921"}, {"#F4F6F9", "#1E2731"}, {"#F7F9FB", "#141B23"},
        {"#F8FAFC", "#1B232C"}, {"#F3F5F8", "#232D38"}, {"#EEF1F5", "#232D38"}, {"#EDF0F4", "#26303B"},
        {"#E9EDF2", "#2A3542"}, {"#EEF1F4", "#26303B"}, {"#EFF2F6", "#26303B"}, {"#E1E6EC", "#2A3542"},
        {"#DCE1E8", "#334050"}, {"#DCE2EA", "#2A3542"}, {"#C5CDD6", "#46566A"}, {"#CFD6DE", "#3A4757"},
        {"#E5EAF0", "#2A3542"}, {"#16202A", "#E6EBF0"}, {"#2B3742", "#D5DCE3"}, {"#45505C", "#B8C2CC"},
        {"#5B6B7A", "#9AA7B4"}, {"#6B7A88", "#8F9CA9"}, {"#7A8896", "#8794A1"}, {"#8B99A6", "#7F8C99"},
        {"#B8C1CB", "#4E5B69"}, {"#FDE9E1", "#3A2219"}, {"#FFF8F5", "#2A1D17"}, {"#FFF3EE", "#2E1E17"},
        {"#F5B49B", "#7A3E28"}, {"#E6F5EE", "#14302A"}, {"#F3FBF7", "#132620"}, {"#1E7A4F", "#5FD39B"},
        {"#FCE9E9", "#3A1C1C"}, {"#FCEDED", "#3A1C1C"}, {"#F3C4C4", "#6B2B2B"}, {"#B42A2A", "#F08080"},
        {"#E3ECFB", "#1A2A45"}, {"#FDEDED", "#3A1C1C"}, {"#F1D9CF", "#3A2A24"}, {"#FEFEFE", "#19212A"}, {"#FFF8F4", "#1E1A19"}, {"#E8E1DC", "#2A3542"}, {"#F2C9B8", "#5A3628"}, {"#F2B8B8", "#6B2B2B"}, {"#FFFFFF", "#19212A"},
        {"#FFF5F0", "#2E1F18"}, {"#EBD8CF", "#4A3026"},   // survol des lignes de tableau : fond sombre, le texte blanc reste lisible
    };
    return table;
}

QString CaserneConnectee::versionSombre(const QString &style) const
{
    QString resultat = style;
    resultat.replace(QRegularExpression("background:\\s*white"), "background: #19212A");
    resultat.replace("motif_points.png", "motif_points_sombre.png");
    static const QRegularExpression hexa("#[0-9A-Fa-f]{6}\\b");
    QString sortie;
    int debut = 0;
    auto it = hexa.globalMatch(resultat);
    while (it.hasNext()) {
        auto m = it.next();
        sortie += resultat.mid(debut, m.capturedStart() - debut);
        const QString c = m.captured().toUpper();
        sortie += (c == "#FFFFFF") ? m.captured() : couleursSombres().value(c, m.captured());   // le texte blanc reste blanc
        debut = m.capturedEnd();
    }
    sortie += resultat.mid(debut);
    return sortie;
}

// Les cases colorées des tableaux (statuts, J / N / R du planning) suivent le thème
void CaserneConnectee::appliquerCouleursTableau(QTableWidget *table)
{
    const int FOND = Qt::UserRole + 20, TEXTE = Qt::UserRole + 21;
    for (int l = 0; l < table->rowCount(); ++l)
        for (int c = 0; c < table->columnCount(); ++c) {
            QTableWidgetItem *case_ = table->item(l, c);
            if (!case_) continue;
            if (!case_->data(FOND).isValid()) {   // mémorise les couleurs d'origine (Qt Designer)
                case_->setData(FOND, case_->background().style() != Qt::NoBrush ? case_->background().color().name() : QString());
                case_->setData(TEXTE, case_->foreground().style() != Qt::NoBrush ? case_->foreground().color().name() : QString());
            }
            const QString fond = case_->data(FOND).toString(), texte = case_->data(TEXTE).toString();
            if (!fond.isEmpty())
                case_->setBackground(QColor(modeSombre ? couleursSombres().value(fond.toUpper(), fond) : fond));
            if (!texte.isEmpty())
                case_->setForeground(QColor(modeSombre ? couleursSombres().value(texte.toUpper(), texte) : texte));
        }
}

// Bouton du thème : clair -> sombre -> selon l'horaire -> clair…
void CaserneConnectee::on_btnThemeEmploye_clicked()
{
    modeTheme = (modeTheme + 1) % 3;
    QSettings("ESPRIT", "CaserneConnectee").setValue("affichage/theme", modeTheme);
    const bool sombre = modeTheme == 1 || (modeTheme == 2 && sombreSelonHoraire());
    if (sombre != modeSombre) appliquerTheme(sombre, true);
    mettreAJourBoutonTheme();
    static const char *titres[] = {"Mode clair", "Mode sombre", "Mode selon l'horaire"};
    static const char *textes[] = {"L'affichage reste clair.", "L'affichage reste sombre.",
                                   "Sombre de 19h à 7h (garde de nuit), clair de 7h à 19h (garde de jour)."};
    employe->notifier(langueArabe ? traduireTexte(QString::fromUtf8(titres[modeTheme])) : QString::fromUtf8(titres[modeTheme]),
                      langueArabe ? traduireTexte(QString::fromUtf8(textes[modeTheme])) : QString::fromUtf8(textes[modeTheme]));
}

// Sombre pendant la garde de nuit (19h-7h), clair pendant la garde de jour (7h-19h)
bool CaserneConnectee::sombreSelonHoraire()
{
    const int heure = QTime::currentTime().hour();
    return heure >= 19 || heure < 7;
}

// Icône du bouton : lune (passer en sombre), soleil (passer à l'horaire), horloge (passer en clair)
void CaserneConnectee::mettreAJourBoutonTheme()
{
    QIcon icone;
    if (modeTheme == 0) icone = QIcon(":/images/icones/moon_clair.png");
    else if (modeTheme == 1) icone = QIcon(":/images/icones/sun_clair.png");
    else {
        // horloge dessinée : moitié jour (orange) / moitié nuit (bleu)
        const qreal ratio = devicePixelRatioF();
        QPixmap image(QSize(36, 36) * ratio);
        image.setDevicePixelRatio(ratio);
        image.fill(Qt::transparent);
        QPainter p(&image);
        p.setRenderHint(QPainter::Antialiasing);
        const QRectF cadran(4, 4, 28, 28);
        p.setPen(Qt::NoPen);
        p.setBrush(QColor("#F2A93B"));
        p.drawPie(cadran, 90 * 16, 180 * 16);
        p.setBrush(QColor("#2F6FE0"));
        p.drawPie(cadran, 270 * 16, 180 * 16);
        p.setPen(QPen(Qt::white, 2.6, Qt::SolidLine, Qt::RoundCap));
        p.drawLine(QPointF(18, 18), QPointF(18, 9.5));
        p.drawLine(QPointF(18, 18), QPointF(24, 21));
        p.end();
        icone = QIcon(image);
    }
    static const char *infobulles[] = {"Mode clair (cliquer : mode sombre)", "Mode sombre (cliquer : mode selon l'horaire)",
                                       "Mode selon l'horaire : sombre de 19h à 7h (cliquer : mode clair)"};
    for (QPushButton *b : boutonsTheme) {
        b->setIcon(icone);
        b->setProperty("infobulleFrancais", QString::fromUtf8(infobulles[modeTheme]));
        b->setToolTip(langueArabe ? traduireTexte(QString::fromUtf8(infobulles[modeTheme])) : QString::fromUtf8(infobulles[modeTheme]));
    }
}

void CaserneConnectee::appliquerTheme(bool sombre, bool anime)
{
    auto changement = [this, sombre]() {
        modeSombre = sombre;
        setStyleSheet(modeSombre ? versionSombre(styleClair) : styleClair);

        // Palette des fenêtres surgissantes (menus, listes) assortie au thème
        QPalette palette;
        const QColor fond(modeSombre ? "#19212A" : "#FFFFFF"), texte(modeSombre ? "#E6EBF0" : "#16202A");
        palette.setColor(QPalette::Window, QColor(modeSombre ? "#0F141A" : "#EDF1F5"));
        palette.setColor(QPalette::WindowText, texte);
        palette.setColor(QPalette::Base, fond);
        palette.setColor(QPalette::AlternateBase, QColor(modeSombre ? "#1B232C" : "#F8FAFC"));
        palette.setColor(QPalette::Text, texte);
        palette.setColor(QPalette::Button, fond);
        palette.setColor(QPalette::ButtonText, texte);
        palette.setColor(QPalette::Highlight, QColor("#E4491F"));
        palette.setColor(QPalette::HighlightedText, Qt::white);
        palette.setColor(QPalette::PlaceholderText, QColor(modeSombre ? "#7F8C99" : "#8B99A6"));
        qApp->setPalette(palette);

        mettreAJourBoutonTheme();
        appliquerCouleursTableau(ui->tblEmploye);
        appliquerCouleursTableau(ui->tblPlanningEmploye);
        for (QTableWidget *t : {ui->tblMissionsDashboard, ui->tblEffectifDashboard, ui->tblAlertesDashboard}) appliquerCouleursTableau(t);
        employe->definirModeSombre(modeSombre);
    };
    if (anime) transitionDouce(changement);
    else changement();
}

// -----------------------------------------------------------------------------
// Zoom : enregistré, puis l'application se relance avec le nouveau facteur (QT_SCALE_FACTOR,
// lu dans main()). Si un compte est connecté, un jeton à usage unique lui rend sa session.
// -----------------------------------------------------------------------------
// Outils d'en-tête : « − 100 % + » puis, pour un nouvel en-tête, thème / langue / notifications
// (mêmes actions que l'en-tête Employés). Ils sont insérés juste avant le widget « avant ».
void CaserneConnectee::ajouterOutilsEntete(QWidget *avant, bool avecThemeLangue)
{
    QBoxLayout *rangee = nullptr;
    int position = -1;
    for (QBoxLayout *l : findChildren<QBoxLayout *>()) {
        for (int i = 0; i < l->count(); ++i) {
            QLayoutItem *element = l->itemAt(i);
            bool trouve = element->widget() == avant;
            if (!trouve && element->layout())                     // widget placé dans une sous-mise en page
                for (int j = 0; j < element->layout()->count(); ++j)
                    if (element->layout()->itemAt(j)->widget() == avant) trouve = true;
            if (trouve) { rangee = l; position = i; break; }
        }
        if (rangee) break;
    }
    if (!rangee) return;
    auto bouton = [this](const QString &texte, const QString &infobulle) {
        QPushButton *b = new QPushButton(texte);
        b->setProperty("variante", "iconeEntete");
        b->setCursor(Qt::PointingHandCursor);
        b->setToolTip(infobulle);
        b->setFocusPolicy(Qt::NoFocus);
        return b;
    };
    QList<QPushButton *> outils;
    QPushButton *moins = bouton(QString::fromUtf8("−"), QString::fromUtf8("Dézoomer (Ctrl −)"));
    QPushButton *valeur = bouton(QString("%1 %").arg(zoom), QString::fromUtf8("Taille normale (Ctrl 0)"));
    valeur->setStyleSheet("min-width: 56px; max-width: 56px; font-size: 9pt;");
    QPushButton *plus = bouton("+", QString::fromUtf8("Zoomer (Ctrl +)"));
    connect(moins, &QPushButton::clicked, this, [this]() { changerZoom(zoom - 10); });
    connect(plus, &QPushButton::clicked, this, [this]() { changerZoom(zoom + 10); });
    connect(valeur, &QPushButton::clicked, this, [this]() { changerZoom(100); });
    boutonsZoomValeur << valeur;
    outils << moins << valeur << plus;
    if (avecThemeLangue) {
        QPushButton *theme = bouton(QString(), ui->btnThemeEmploye->toolTip());
        theme->setIconSize(ui->btnThemeEmploye->iconSize());
        theme->setIcon(ui->btnThemeEmploye->icon());
        connect(theme, &QPushButton::clicked, this, &CaserneConnectee::on_btnThemeEmploye_clicked);
        QPushButton *langue = bouton(ui->btnLangueEmploye->text(), ui->btnLangueEmploye->toolTip());
        connect(langue, &QPushButton::clicked, this, &CaserneConnectee::on_btnLangueEmploye_clicked);
        QPushButton *cloche = bouton(QString(), ui->btnNotificationsEmploye->toolTip());
        cloche->setIconSize(ui->btnNotificationsEmploye->iconSize());
        cloche->setIcon(QIcon(":/images/icones/bell_clair.png"));
        connect(cloche, &QPushButton::clicked, ui->btnNotificationsEmploye, &QPushButton::click);
        boutonsTheme << theme;
        boutonsLangue << langue;
        outils << theme << langue << cloche;
    }
    for (int i = outils.size() - 1; i >= 0; --i) rangee->insertWidget(position, outils[i]);
}

void CaserneConnectee::ajouterMeteoMusique(QWidget *horloge)
{
    for (QBoxLayout *l : findChildren<QBoxLayout *>())
        for (int i = 0; i < l->count(); ++i) {
            QLayoutItem *element = l->itemAt(i);
            bool trouve = element->widget() == horloge;
            if (!trouve && element->layout())
                for (int j = 0; j < element->layout()->count(); ++j)
                    if (element->layout()->itemAt(j)->widget() == horloge) trouve = true;
            if (!trouve) continue;
            QPushButton *note = new QPushButton;
            note->setProperty("variante", "iconeEntete");
            note->setCursor(Qt::PointingHandCursor);
            note->setFocusPolicy(Qt::NoFocus);
            note->setIconSize(QSize(18, 18));
            connect(note, &QPushButton::clicked, this, &CaserneConnectee::basculerMusique);
            boutonsMusique << note;
            QPushButton *eclair = new QPushButton;              // ⚡ animations complètes / légères
            eclair->setProperty("variante", "iconeEntete");
            eclair->setCursor(Qt::PointingHandCursor);
            eclair->setFocusPolicy(Qt::NoFocus);
            eclair->setIconSize(QSize(18, 18));
            connect(eclair, &QPushButton::clicked, this, &CaserneConnectee::basculerAnimations);
            boutonsAnimations << eclair;
            l->insertWidget(i, new MeteoEntete);
            l->insertWidget(i, note);
            l->insertWidget(i, eclair);
            return;
        }
}

// Bouton ♪ : note de musique (barrée quand la musique est coupée)
void CaserneConnectee::mettreAJourBoutonsMusique()
{
    const qreal ratio = devicePixelRatioF();
    QPixmap image(QSize(36, 36) * ratio);
    image.setDevicePixelRatio(ratio);
    image.fill(Qt::transparent);
    QPainter p(&image);
    p.setRenderHint(QPainter::Antialiasing);
    const QColor couleur(musique ? "#FF8A5B" : "#9AA5B1");
    p.setPen(QPen(couleur, 2.6, Qt::SolidLine, Qt::RoundCap));
    p.drawLine(QPointF(14, 25), QPointF(14, 8));
    p.drawLine(QPointF(25, 22), QPointF(25, 6));
    p.setPen(QPen(couleur, 4, Qt::SolidLine, Qt::RoundCap));
    p.drawLine(QPointF(14, 8), QPointF(25, 6));
    p.setPen(Qt::NoPen);
    p.setBrush(couleur);
    p.drawEllipse(QPointF(10.5, 26), 4, 3.2);
    p.drawEllipse(QPointF(21.5, 23), 4, 3.2);
    if (!musique) {
        p.setPen(QPen(QColor("#D93636"), 2.6, Qt::SolidLine, Qt::RoundCap));
        p.drawLine(QPointF(6, 30), QPointF(30, 6));
    }
    p.end();
    for (QPushButton *b : boutonsMusique) {
        b->setIcon(QIcon(image));
        const QString fr = musique ? QString::fromUtf8("Couper la musique") : QString::fromUtf8("Mettre la musique douce");
        b->setProperty("infobulleFrancais", fr);
        b->setToolTip(langueArabe ? traduireTexte(fr) : fr);
    }
}

// Bouton ⚡ : éclair orange = animations complètes ; éclair gris = animations légères (plus rapide)
void CaserneConnectee::mettreAJourBoutonsAnimations()
{
    QPixmap image(36, 36);
    image.fill(Qt::transparent);
    QPainter p(&image);
    p.setRenderHint(QPainter::Antialiasing);
    const QColor couleur(animationsLegeres() ? "#9AA5B1" : "#FFB347");
    QPolygonF eclair({QPointF(20, 4), QPointF(9, 20), QPointF(17, 20), QPointF(14, 32), QPointF(27, 14), QPointF(19, 14), QPointF(22, 4)});
    p.setPen(Qt::NoPen);
    p.setBrush(couleur);
    p.drawPolygon(eclair);
    p.end();
    for (QPushButton *b : boutonsAnimations) {
        b->setIcon(QIcon(image));
        const QString fr = animationsLegeres() ? QString::fromUtf8("Animations légères (cliquer : animations complètes)")
                                               : QString::fromUtf8("Animations complètes (cliquer : animations légères, plus rapide)");
        b->setProperty("infobulleFrancais", fr);
        b->setToolTip(langueArabe ? traduireTexte(fr) : fr);
    }
}

void CaserneConnectee::basculerAnimations()
{
    animationsLegeres() = !animationsLegeres();
    QSettings("ESPRIT", "CaserneConnectee").setValue("affichage/animationsLegeres", animationsLegeres());
    mettreAJourBoutonsAnimations();
    employe->notifier(animationsLegeres() ? QString::fromUtf8("Animations légères") : QString::fromUtf8("Animations complètes"),
                      animationsLegeres() ? QString::fromUtf8("Les décors animés des modules sont arrêtés : l'application est plus rapide.")
                                          : QString::fromUtf8("Braises, liseré de feu et reflets sont de retour."));
}

void CaserneConnectee::basculerMusique()
{
    musique = !musique;
    QSettings("ESPRIT", "CaserneConnectee").setValue("affichage/musique", musique);
    jouerMusique(musique);
    mettreAJourBoutonsMusique();
}

void CaserneConnectee::changerZoom(int nouveau)
{
    nouveau = qBound(50, nouveau, 150);
    if (nouveau == zoom) return;
    QSettings reglages("ESPRIT", "CaserneConnectee");
    reglages.setValue("affichage/zoom", nouveau);
    QStringList arguments;
    if (!employe->compteConnecte().isEmpty()) {
        const QString jeton = QString::number(QRandomGenerator::system()->generate64(), 16);
        reglages.setValue("session/jeton", jeton);
        reglages.setValue("session/identifiant", employe->compteConnecte());
        reglages.setValue("session/expiration", QDateTime::currentDateTime().addSecs(20));
        reglages.setValue("session/arabe", langueArabe);
        arguments << "--reprise" << jeton;
    }
    reglages.sync();
    for (QPushButton *b : boutonsZoomValeur) b->setText(QString("%1 %").arg(nouveau));
    // La nouvelle fenêtre (au nouveau zoom) est lancée AVANT de fermer celle-ci, depuis le dossier
    // de l'application ; si le lancement échoue, on ne ferme rien et on prévient.
    qint64 pid = 0;
    const bool lancee = QProcess::startDetached(QCoreApplication::applicationFilePath(), arguments,
                                                QCoreApplication::applicationDirPath(), &pid);
    if (!lancee) {
        reglages.setValue("affichage/zoom", zoom);
        reglages.remove("session");
        for (QPushButton *b : boutonsZoomValeur) b->setText(QString("%1 %").arg(zoom));
        employe->notifier("Zoom", QString::fromUtf8("Impossible de relancer l'application au nouveau zoom."));
        return;
    }
    hide();                                       // la nouvelle fenêtre prend le relais
    QTimer::singleShot(300, qApp, &QCoreApplication::quit);
}

void CaserneConnectee::reprendreApresZoom(const QString &jeton)
{
    QSettings reglages("ESPRIT", "CaserneConnectee");
    const bool valide = !jeton.isEmpty() && reglages.value("session/jeton").toString() == jeton
                        && reglages.value("session/expiration").toDateTime() >= QDateTime::currentDateTime();
    const QString identifiant = reglages.value("session/identifiant").toString();
    const bool arabe = reglages.value("session/arabe").toBool();
    reglages.remove("session");                   // jeton à usage unique
    raise();                                      // fenêtre relancée par le zoom : au premier plan
    activateWindow();
    if (!valide || !employe->reprendreSession(identifiant)) return;

    employe->appliquerDroits();
    employe->quitterPageConnexion();
    employe->afficherAccueilModules(true);         // retour sur la page des modules
    if (arabe && !langueArabe) on_btnLangueEmploye_clicked();
    if (musique) jouerMusique(true);
    employe->notifier(langueArabe || arabe ? traduireTexte("Zoom") : QString("Zoom"),
                      QString("%1 %").arg(zoom));
}

// -----------------------------------------------------------------------------
// Langue : français / arabe (lecture de droite à gauche). Les textes d'origine sont
// ceux de Qt Designer ; on traduit ceux qui figurent dans le dictionnaire ci-dessous.
// Pour traduire un autre module, il suffit d'ajouter ses textes au dictionnaire.
// -----------------------------------------------------------------------------
static const QHash<QString, QString> &dictionnaireArabe()
{
    static const QHash<QString, QString> d = [] {
        const char *paires[][2] = {
            // Barre latérale
            {"Caserne Connectée", "الثكنة المتصلة"}, {"CONSOLE DE GARDE", "لوحة المناوبة"}, {"SUIVI", "المتابعة"},
            {"Tableau de bord", "لوحة القيادة"}, {"RESSOURCES", "الموارد"}, {"Employés", "الموظفون"},
            {"Missions", "المهام"}, {"Unités", "الوحدات"}, {"Véhicules", "المركبات"}, {"Matériel", "المعدات"},
            {"PILOTAGE", "القيادة"}, {"Formation", "التكوين"}, {"Garde en cours · Équipe B", "المناوبة الحالية · الفريق ب"},
            {"Relève à 19:00", "التبديل على الساعة 19:00"}, {"Administrateur", "مسؤول"}, {"Se déconnecter", "تسجيل الخروج"},
            // En-tête
            {"Gestion des employés", "إدارة الموظفين"},
            {"Effectif de la caserne et comptes de connexion", "أعوان الثكنة وحسابات الدخول"},
            {"Mode sombre / clair", "الوضع الداكن / الفاتح"}, {"Changer de langue (français / arabe)", "تغيير اللغة (الفرنسية / العربية)"},
            {"Notifications", "الإشعارات"}, {"Métiers avancés", "الوظائف المتقدمة"}, {"En ligne", "متصل"},
            // Chiffres clés
            {"Effectif total", "العدد الجملي"}, {"dont 18 opérationnels", "منهم 18 عونا ميدانيا"}, {"Disponibles", "المتاحون"},
            {"50 % de l'effectif", "50 % من الأعوان"}, {"En intervention", "في تدخل"}, {"sur 4 unités", "على 4 وحدات"},
            {"Comptes bloqués", "الحسابات المقفلة"}, {"après 5 essais échoués", "بعد 5 محاولات فاشلة"},
            // Formulaire
            {"Cliquez pour ajouter la photo de l'employé", "انقر لإضافة صورة الموظف"},
            {"Ajouter / modifier un employé", "إضافة / تعديل موظف"}, {"Ajouter / modifier\nun employé", "إضافة / تعديل\nموظف"},
            {"Cliquez sur le cercle pour ajouter une photo", "انقر على الدائرة لإضافة صورة"},
            {"Nom", "اللقب"}, {"Prénom", "الاسم"}, {"Grade", "الرتبة"}, {"Fonction", "الوظيفة"}, {"Statut", "الحالة"},
            {"Entrée en service", "تاريخ المباشرة"}, {"E-mail", "البريد الإلكتروني"}, {"Identifiant", "المعرّف"},
            {"Rôle", "الدور"}, {"Habilitations", "المؤهلات"}, {"MOT DE PASSE DU COMPTE", "كلمة مرور الحساب"},
            {"Mot de passe", "كلمة المرور"}, {"Confirmer", "تأكيد"}, {"Retaper le mot de passe", "أعد كتابة كلمة المرور"},
            {"Pour la sécurité, le mot de passe n'est jamais affiché dans la fiche.", "للأمان، لا تظهر كلمة المرور أبدا في البطاقة."},
            {"MÉTIER · TEMPS DE SERVICE", "وظيفة · مدة العمل"}, {"9h30 de service restantes", "تبقى 9 س 30 د من العمل"},
            {"Temps de service : 2h30 / 12h", "مدة العمل: 2 س 30 د / 12 س"},
            {"Repos cumulé : 9 h · alerte à 80 % de 12h", "الراحة المتراكمة: 9 س · تنبيه عند 80 % من 12 س"},
            {"Ajouter", "إضافة"}, {"Modifier", "تعديل"}, {"Supprimer", "حذف"}, {"Annuler", "إلغاء"},
            {"Disponible", "متاح"}, {"En repos", "في راحة"}, {"En congé", "في عطلة"}, {"Agent", "عون"},
            {"Chef de garde", "رئيس المناوبة"}, {"Pompier opérationnel", "عون إطفاء ميداني"}, {"Chauffeur", "سائق"},
            {"Standardiste", "عون استقبال المكالمات"}, {"Agent administratif", "عون إداري"},
            {"Capitaine", "نقيب"}, {"Lieutenant", "ملازم"}, {"Adjudant-chef", "وكيل أول"}, {"Sergent-chef", "رقيب أول"},
            {"Sergent", "رقيب"}, {"Caporal", "عريف"}, {"Sapeur", "عون"},
            // Liste
            {"Liste des employés", "قائمة الموظفين"}, {"22 employés · Caserne Centrale", "22 موظفا · الثكنة المركزية"},
            {"Rechercher un employé par nom, grade ou compétence…", "ابحث عن موظف بالاسم أو الرتبة أو الكفاءة…"},
            {"Rechercher", "بحث"}, {"Trier par :", "ترتيب حسب:"}, {"Trier", "ترتيب"}, {"Exporter PDF", "تصدير PDF"},
            {"Ancienneté", "الأقدمية"}, {"Service / 12h", "العمل / 12 س"}, {"ID", "المعرف"},
            // Statistiques
            {"Statistiques — employés", "إحصائيات الموظفين"}, {"Disponibilité des employés", "توفر الموظفين"},
            {"<span style=\"font-size:17pt; font-weight:bold\">50 %</span><br/><span style=\"font-size:8pt; font-weight:normal; color:#7A8896\">disponibles</span>",
             "<span style=\"font-size:17pt; font-weight:bold\">50 %</span><br/><span style=\"font-size:8pt; font-weight:normal; color:#7A8896\">متاحون</span>"},
            {"Effectif par fonction", "العدد حسب الوظيفة"},
            // Planning
            {"Planning des gardes", "جدول المناوبات"},
            {"Roulement des agents sur la période : effectif minimum par créneau et repos réglementaire respectés",
             "تداول الأعوان خلال الفترة مع احترام الحد الأدنى لكل فترة والراحة القانونية"},
            {"DÉBUT", "البداية"}, {"DURÉE", "المدة"}, {"EFFECTIF MIN. / CRÉNEAU", "الحد الأدنى / فترة"},
            {"7 jours", "7 أيام"}, {"14 jours", "14 يوما"}, {"30 jours", "30 يوما"},
            {"Générer le planning", "إنشاء الجدول"}, {"Gardes", "المناوبات"},
            {"Télécharger PDF", "تنزيل PDF"},
            {"Bonjour, %1", "صباح الخير، %1"}, {"Bonsoir, %1", "مساء الخير، %1"},
            {"Choisissez le module dont vous avez besoin.", "اختر الوحدة التي تحتاجها."}, {"Retour aux modules", "العودة إلى الوحدات"},
            {"Vue d'ensemble de la garde : alertes, carte des interventions, effectif.", "نظرة عامة على المناوبة: التنبيهات، خريطة التدخلات، الأعوان."},
            {"Personnel, comptes, droits d'accès et planning des gardes.", "الأعوان، الحسابات، الصلاحيات وجدول المناوبات."},
            {"Appels reçus, interventions en cours et clôtures.", "المكالمات الواردة، التدخلات الجارية والإغلاق."},
            {"Équipes d'intervention et affectations.", "فرق التدخل والتعيينات."},
            {"Flotte, disponibilité et localisation des engins.", "الأسطول، التوفر وتحديد مواقع المركبات."},
            {"Équipements, stocks et dates de péremption.", "المعدات، المخزون وتواريخ الصلاحية."},
            {"Sessions, habilitations et recyclages.", "الدورات، المؤهلات والرسكلة."},
            {"Liste exportée en Excel", "تم تصدير القائمة إلى Excel"}, {"Excel enregistré", "تم حفظ ملف Excel"},
            {"Planning téléchargé en Excel", "تم تنزيل الجدول بصيغة Excel"}, {"Enregistrer dans un classeur Excel (.xlsx)", "حفظ في ملف Excel (.xlsx)"},
            {"Le fichier Excel n'a pas pu être enregistré.", "تعذر حفظ ملف Excel."},
            {"Couper la musique", "إيقاف الموسيقى"}, {"Mettre la musique douce", "تشغيل الموسيقى الهادئة"},
            {"Pompiers disponibles", "الأعوان المتاحون"}, {"Missions actives", "المهام النشطة"}, {"Unités disponibles", "الوحدات المتاحة"},
            {"Véhicules en service", "المركبات في الخدمة"}, {"Temps de réponse", "زمن الاستجابة"}, {"Missions en cours", "المهام الجارية"},
            {"Carte des interventions", "خريطة التدخلات"}, {"Effectif de garde", "أعوان المناوبة"}, {"À traiter aujourd'hui", "للمعالجة اليوم"},
            {"Interventions de la semaine", "تدخلات الأسبوع"}, {"Localiser la balise", "تحديد موقع المنارة"}, {"Plan", "المخطط"},
            {"Carte réelle", "خريطة حقيقية"}, {"Agent", "عون"}, {"Fonction", "الوظيفة"}, {"Statut", "الحالة"}, {"Alerte", "تنبيه"},
            {"Adresse", "العنوان"}, {"Gravité", "الخطورة"}, {"Type", "النوع"}, {"N°", "رقم"}, {"En ligne", "متصل"},
            {"sur %1 · équipe B", "من %1 · الفريق ب"}, {"Balise localisée", "تم تحديد المنارة"},
            {"Alerte pompier au sol — balise d'urgence déclenchée", "تنبيه: عون على الأرض — تم تشغيل منارة الطوارئ"},
            {"Faites glisser la carte, molette pour zoomer, double-clic pour recentrer.", "اسحب الخريطة، العجلة للتكبير، نقرة مزدوجة لإعادة التوسيط."},
            {"Caserne Centrale — Tunis Nord", "الثكنة المركزية — تونس الشمالية"},
            {"Tableau de bord", "لوحة القيادة"}, {"Ce compte n'a accès à aucun module.", "هذا الحساب لا يملك الوصول إلى أي وحدة."},
            {"Bienvenue, %1", "مرحبا، %1"}, {"%1 · accès vérifié", "%1 · تم التحقق من الوصول"},
            {"Dézoomer (Ctrl −)", "تصغير (Ctrl −)"}, {"Zoomer (Ctrl +)", "تكبير (Ctrl +)"}, {"Taille normale (Ctrl 0)", "الحجم العادي (Ctrl 0)"},
            {"Zoom", "التكبير"}, {"Mode clair", "الوضع الفاتح"}, {"Mode sombre", "الوضع الداكن"}, {"Mode selon l'horaire", "الوضع حسب التوقيت"},
            {"L'affichage reste clair.", "يبقى العرض فاتحا."}, {"L'affichage reste sombre.", "يبقى العرض داكنا."},
            {"Sombre de 19h à 7h (garde de nuit), clair de 7h à 19h (garde de jour).", "داكن من 19 س إلى 7 س (مناوبة الليل)، فاتح من 7 س إلى 19 س (مناوبة النهار)."},
            {"Mode clair (cliquer : mode sombre)", "الوضع الفاتح (انقر: الوضع الداكن)"},
            {"Mode sombre (cliquer : mode selon l'horaire)", "الوضع الداكن (انقر: الوضع حسب التوقيت)"},
            {"Mode selon l'horaire : sombre de 19h à 7h (cliquer : mode clair)", "الوضع حسب التوقيت: داكن من 19 س إلى 7 س (انقر: الوضع الفاتح)"},
            {"MOT DE PASSE DU COMPTE", "كلمة مرور الحساب"}, {"MODIFIER LE MOT DE PASSE", "تغيير كلمة المرور"},
            {"Mot de passe", "كلمة المرور"}, {"Vérification", "التحقق"}, {"Laisser vide pour le garder", "اتركه فارغا للإبقاء عليه"},
            {"Obligatoire : l'employé se connectera avec ce mot de passe. Il est haché avant l'enregistrement et n'est jamais affiché.",
             "إجباري: سيدخل الموظف بكلمة المرور هذه. تُشفَّر قبل الحفظ ولا تظهر أبدا."},
            {"Facultatif : laisser vide pour garder le mot de passe actuel. Il est haché avant l'enregistrement et n'est jamais affiché.",
             "اختياري: اتركه فارغا للإبقاء على كلمة المرور الحالية. تُشفَّر قبل الحفظ ولا تظهر أبدا."}, {"Génération…", "جار الإنشاء…"},
            {"Enregistrer le planning affiché dans un fichier PDF", "حفظ الجدول المعروض في ملف PDF"},
            {"Télécharger le planning des gardes", "تنزيل جدول المناوبات"},
            {"Planning téléchargé en PDF", "تم تنزيل الجدول بصيغة PDF"}, {"Planning généré", "تم إنشاء الجدول"},
            {"Le planning est vide.", "الجدول فارغ."}, {"Jour", "نهار"}, {"Nuit", "ليل"},
            {"Opérateur du standard", "عون الاستقبال الهاتفي"},
            {"Du %1 au %2 · %3 créneaux de 12h · effectif minimum %4 (dont 1 chef de garde et 1 conducteur)",
             "من %1 إلى %2 · %3 فترة من 12 س · حد أدنى %4 (منهم رئيس مناوبة وسائق)"},
            {" · votre planning personnel", " · جدولك الشخصي"},
            {"· effectif complet sur tous les créneaux", "· العدد مكتمل في كل الفترات"},
            {"· créneaux incomplets : %1", "· فترات غير مكتملة: %1"}, {"%1 en sous-effectif", "%1 بعدد غير كاف"},
            {"%1 sans chef de garde", "%1 بدون رئيس مناوبة"}, {"%1 sans conducteur", "%1 بدون سائق"},
            {"Créneau incomplet : %1 agent(s) de garde", "فترة غير مكتملة: %1 عون في المناوبة"},
            {"NOUVEAU MOT DE PASSE", "كلمة مرور جديدة"}, {"Nouveau", "الجديدة"},
            {"Majuscule, minuscule, chiffre et symbole rendent le mot de passe plus sûr. Il est haché avant l'enregistrement et n'est jamais affiché dans la fiche.",
             "الحروف الكبيرة والصغيرة والأرقام والرموز تجعل كلمة المرور أكثر أمانا. تُشفَّر قبل الحفظ ولا تظهر أبدا في البطاقة."},
            {"8 caractères minimum", "8 أحرف على الأقل"},
            {"Gestion des droits d'accès", "إدارة صلاحيات الوصول"},
            {"Métier avancé : chaque rôle n'a accès qu'aux actions autorisées (matrice rôle × module)",
             "وظيفة متقدمة: لكل دور الوصول إلى العمليات المسموح بها فقط (مصفوفة الدور × الوحدة)"},
            {"Module", "الوحدة"}, {"Poste", "الوظيفة"}, {"Rôle attribué", "الدور المسند"},
            {"Attribués automatiquement selon le poste : poste → rôle → droits sur chaque module",
             "تُسند آليا حسب الوظيفة: الوظيفة ← الدور ← الصلاحيات على كل وحدة"},
            {"APERÇU : SE CONNECTER AVEC LE POSTE", "معاينة: الدخول بوظيفة"},
            {"<b>Complet</b> = ajouter, modifier, supprimer · <b>Lecture</b> = consultation · <b>Aucun</b> = module masqué. Le rôle d'un employé change dès que son poste change.",
             "<b>كامل</b> = إضافة وتعديل وحذف · <b>قراءة</b> = اطلاع · <b>لا شيء</b> = وحدة مخفية. يتغير دور الموظف بمجرد تغيّر وظيفته."},
            {"Attribué automatiquement selon le poste", "يُسند آليا حسب الوظيفة"},
            {"Complet", "كامل"}, {"Lecture", "قراءة"}, {"Aucun", "لا شيء"},
            {"APERÇU : SE CONNECTER EN TANT QUE", "معاينة: الدخول بصفة"},
            {"Choisissez un droit dans chaque case : <b>Complet</b> = ajouter, modifier, supprimer ; <b>Lecture</b> = consultation seulement ; <b>Aucun</b> = module masqué.",
             "اختر صلاحية في كل خانة: <b>كامل</b> = إضافة وتعديل وحذف؛ <b>قراءة</b> = اطلاع فقط؛ <b>لا شيء</b> = وحدة مخفية."},
            {"Utilisateurs du module : Administrateur (complet) · Chef de garde (consultation) · tout employé (connexion).",
             "مستخدمو الوحدة: المسؤول (كامل) · رئيس المناوبة (اطلاع) · كل موظف (دخول)."},
            {"Accès refusé : le rôle « Agent » n'a aucun droit sur le module Employés. Les actions et les données sont masquées.",
             "وصول مرفوض: دور «عون» لا يملك أي صلاحية على وحدة الموظفين. العمليات والبيانات مخفية."},
            {"Afficher / masquer", "إظهار / إخفاء"},
            // Connexion, mot de passe oublié
            {"Mot de passe oublié ?", "نسيت كلمة المرور؟"}, {"Mot de passe oublié", "نسيت كلمة المرور"},
            {"Saisissez l'adresse e-mail de votre compte : vous recevrez un code à 6 chiffres valable 15 minutes.",
             "أدخل البريد الإلكتروني لحسابك: ستتلقى رمزا من 6 أرقام صالحا لمدة 15 دقيقة."},
            {"ADRESSE E-MAIL", "البريد الإلكتروني"}, {"Envoyer le code", "إرسال الرمز"},
            {"CODE REÇU PAR E-MAIL (6 CHIFFRES)", "الرمز المستلم عبر البريد (6 أرقام)"},
            {"CONFIRMER LE MOT DE PASSE", "تأكيد كلمة المرور"},
            {"Valider le nouveau mot de passe", "تأكيد كلمة المرور الجديدة"}, {"Renvoyer un code", "إعادة إرسال الرمز"},
            {"← Retour à la connexion", "→ العودة إلى تسجيل الدخول"},
            {"Code à usage unique · valable 15 minutes", "رمز يُستعمل مرة واحدة · صالح لمدة 15 دقيقة"},
            {"Saisissez votre identifiant et votre mot de passe.", "أدخل المعرّف وكلمة المرور."},
            {"Identifiant inconnu.", "معرّف غير معروف."},
            {"Mot de passe incorrect : %1 essais restants avant le blocage du compte.", "كلمة مرور خاطئة: تبقى %1 محاولات قبل قفل الحساب."},
            {"Mot de passe incorrect : dernier essai avant le blocage du compte.", "كلمة مرور خاطئة: آخر محاولة قبل قفل الحساب."},
            {"Compte bloqué après 5 essais échoués. Cliquez sur « Mot de passe oublié ? » pour le débloquer.",
             "تم قفل الحساب بعد 5 محاولات فاشلة. انقر على «نسيت كلمة المرور؟» لفتحه."},
            {"Compte bloqué", "حساب مقفل"},
            {"Trop d'essais échoués : ce compte est bloqué jusqu'à la réinitialisation du mot de passe.",
             "محاولات فاشلة كثيرة: هذا الحساب مقفل إلى حين إعادة تعيين كلمة المرور."},
            {"Votre rôle « %1 » n'a aucun droit sur le module Employés.", "دورك «%1» لا يملك أي صلاحية على وحدة الموظفين."},
            {"Accès refusé", "وصول مرفوض"},
            {"Saisissez une adresse e-mail valide.", "أدخل بريدا إلكترونيا صحيحا."},
            {"Aucun compte n'est associé à cette adresse e-mail.", "لا يوجد حساب مرتبط بهذا البريد الإلكتروني."},
            {"E-mail envoyé (simulation)", "تم إرسال البريد (محاكاة)"},
            {"À %1 — votre code : %2 (valable 15 minutes, usage unique)", "إلى %1 — رمزك: %2 (صالح 15 دقيقة، لمرة واحدة)"},
            {"Un code à 6 chiffres a été envoyé à %1. Saisissez-le puis choisissez un nouveau mot de passe.",
             "تم إرسال رمز من 6 أرقام إلى %1. أدخله ثم اختر كلمة مرور جديدة."},
            {"Nouveau code envoyé : l'ancien n'est plus valable.", "تم إرسال رمز جديد: الرمز القديم لم يعد صالحا."},
            {"Code valable encore %1", "الرمز صالح لمدة %1"},
            {"Code expiré : cliquez sur « Renvoyer un code ».", "انتهت صلاحية الرمز: انقر على «إعادة إرسال الرمز»."},
            {"Code annulé : cliquez sur « Renvoyer un code ».", "تم إلغاء الرمز: انقر على «إعادة إرسال الرمز»."},
            {"Le code contient 6 chiffres.", "يتكون الرمز من 6 أرقام."},
            {"Code incorrect. Vérifiez le code reçu par e-mail.", "رمز خاطئ. تحقق من الرمز المستلم عبر البريد."},
            {"Ce code a expiré (15 minutes) : demandez un nouveau code.", "انتهت صلاحية هذا الرمز (15 دقيقة): اطلب رمزا جديدا."},
            {"Ce code n'est plus valable (déjà utilisé ou trop d'essais) : demandez un nouveau code.",
             "هذا الرمز لم يعد صالحا (مستعمل أو محاولات كثيرة): اطلب رمزا جديدا."},
            {"Mot de passe réinitialisé : vous pouvez vous connecter.", "تمت إعادة تعيين كلمة المرور: يمكنك تسجيل الدخول."},
            {"Mot de passe modifié", "تم تغيير كلمة المرور"},
            {"Votre compte est débloqué. Connectez-vous avec votre nouveau mot de passe.", "تم فتح حسابك. سجّل الدخول بكلمة المرور الجديدة."},
            {"Le mot de passe doit contenir au moins 8 caractères.", "يجب أن تحتوي كلمة المرور على 8 أحرف على الأقل."},
            {"Le mot de passe doit contenir au moins une lettre et un chiffre.", "يجب أن تحتوي كلمة المرور على حرف ورقم على الأقل."},
            {"Les mots de passe ne correspondent pas.", "كلمتا المرور غير متطابقتين."},
            // Gestion des employés : ajout, modification, suppression
            {"Lecture seule", "قراءة فقط"}, {"Enregistrer", "حفظ"}, {"Valider l'ajout", "تأكيد الإضافة"}, {"Nouveau", "جديد"},
            {"%1 employés · Caserne Centrale", "%1 موظفا · الثكنة المركزية"},
            {"Nouvel employé", "موظف جديد"},
            {"Remplissez la fiche et choisissez un mot de passe, puis cliquez sur « Valider l'ajout ».",
             "املأ البطاقة واختر كلمة مرور ثم انقر على «تأكيد الإضافة»."},
            {"Fiche incomplète", "بطاقة غير مكتملة"}, {"Le nom est obligatoire.", "اللقب إجباري."}, {"Le prénom est obligatoire.", "الاسم إجباري."},
            {"L'adresse e-mail n'est pas valide.", "البريد الإلكتروني غير صحيح."},
            {"L'identifiant doit contenir 3 à 30 caractères (lettres minuscules, chiffres, point).",
             "يجب أن يحتوي المعرّف على 3 إلى 30 حرفا (حروف صغيرة، أرقام، نقطة)."},
            {"Cet identifiant est déjà utilisé par un autre compte.", "هذا المعرّف مستعمل من حساب آخر."},
            {"Cette adresse e-mail est déjà utilisée par un autre compte.", "هذا البريد مستعمل من حساب آخر."},
            {"Ajout impossible", "تعذّرت الإضافة"}, {"Cet identifiant ou cette adresse e-mail est déjà utilisé.", "المعرّف أو البريد مستعمل مسبقا."},
            {"Employé ajouté avec succès", "تمت إضافة الموظف بنجاح"}, {"%1 %2 · compte « %3 » créé", "%1 %2 · تم إنشاء الحساب «%3»"},
            {"Employé modifié avec succès", "تم تعديل الموظف بنجاح"}, {"%1 %2 · fiche enregistrée", "%1 %2 · تم حفظ البطاقة"},
            {" · mot de passe changé", " · تم تغيير كلمة المرور"}, {" · compte débloqué", " · تم فتح الحساب"},
            {"Modification refusée", "تعديل مرفوض"}, {"Vous ne pouvez pas changer le rôle de votre propre compte.", "لا يمكنك تغيير دور حسابك."},
            {"La caserne doit garder au moins un administrateur.", "يجب أن تحتفظ الثكنة بمسؤول واحد على الأقل."},
            {"Suppression refusée", "حذف مرفوض"},
            {"Impossible de supprimer le compte avec lequel vous êtes connecté.", "لا يمكن حذف الحساب الذي سجّلت به الدخول."},
            {"Supprimer un employé", "حذف موظف"},
            {"Supprimer %1 et son compte « %2 » ? Cette action est définitive.", "حذف %1 وحسابه «%2»؟ هذا الإجراء نهائي."},
            {"Employé supprimé", "تم حذف الموظف"}, {"%1 et son compte « %2 » ont été supprimés", "تم حذف %1 وحسابه «%2»"},
            {"Droits mis à jour", "تم تحديث الصلاحيات"},            // Tri, recherche, export PDF, statistiques
            {"Liste triée", "تم ترتيب القائمة"}, {"Employés triés %1.", "تم ترتيب الموظفين %1."},
            {"par nom (A → Z)", "حسب اللقب (أ ← ي)"}, {"par nom (Z → A)", "حسب اللقب (ي ← أ)"},
            {"par grade (du plus haut au plus bas)", "حسب الرتبة (من الأعلى إلى الأدنى)"},
            {"par grade (du plus bas au plus haut)", "حسب الرتبة (من الأدنى إلى الأعلى)"},
            {"par ancienneté (les plus anciens d'abord)", "حسب الأقدمية (الأقدم أولا)"},
            {"par ancienneté (les plus récents d'abord)", "حسب الأقدمية (الأحدث أولا)"},
            {"dans l'ordre d'ajout", "حسب ترتيب الإضافة"},
            {"Aucun résultat", "لا توجد نتائج"}, {"Aucun employé ne correspond à « %1 ».", "لا يوجد موظف يطابق «%1»."},
            {"%1 employé(s) trouvé(s) sur %2", "%1 موظف(ين) من أصل %2"},
            {"Export impossible", "تعذّر التصدير"}, {"La liste affichée est vide.", "القائمة المعروضة فارغة."},
            {"Exporter la liste des employés", "تصدير قائمة الموظفين"},
            {"Le fichier PDF n'a pas pu être enregistré.", "تعذّر حفظ ملف PDF."},
            {"Liste exportée en PDF", "تم تصدير القائمة إلى PDF"}, {"%1 employé(s) · %2", "%1 موظف(ين) · %2"},
            {"PDF enregistré", "تم حفظ ملف PDF"},
            {"dont %1 opérationnels", "منهم %1 عونا ميدانيا"}, {"%1 % de l'effectif", "%1 % من الأعوان"},
            {"disponibles", "متاحون"}, {"Repos cumulé", "الراحة المتراكمة"},
            {"Repos cumulé : %1 h · alerte à 80 % de 12h", "الراحة المتراكمة: %1 س · تنبيه عند 80 % من 12 س"},
            {"DROITS D'ACCÈS AUX MODULES", "صلاحيات الوصول إلى الوحدات"},
            {"Proposés selon le rôle, ajustables pour cet employé", "مقترحة حسب الدور وقابلة للتعديل لهذا الموظف"},
            {"Vos propres droits ne peuvent pas être modifiés", "لا يمكن تعديل صلاحياتك الخاصة"},
            {"Accès complet", "وصول كامل"}, {"Module non développé", "وحدة غير مطورة"},
            {"Module non développé : cette interface sera ajoutée par l'équipe chargée du module.", "وحدة غير مطورة: ستضيف هذه الواجهة الفرقةُ المكلفة بالوحدة."},
            {"L'interface %1 n'est pas encore disponible dans cette version.", "واجهة %1 غير متوفرة بعد في هذه النسخة."}, {"Interface %1", "واجهة %1"},
            {"« %1 » autorisé pour votre compte : l'action sera reliée par l'équipe du module.", "«%1» مسموح لحسابك: سيتم ربط العملية من فريق الوحدة."},
            {"Interface du module développée par l'équipe : les actions s'activent selon les droits du compte connecté.",
             "واجهة الوحدة يطورها الفريق: تُفعَّل العمليات حسب صلاحيات الحساب المتصل."},
            {"Caserne Centrale — Tunis Nord", "الثكنة المركزية — تونس الشمالية"},
            {"ce module est intégré par l'équipe dans l'application complète.", "هذه الوحدة يدمجها الفريق في التطبيق الكامل."},
            {"Ce compte n'a pas accès à l'interface Employés.", "هذا الحساب لا يملك الوصول إلى واجهة الموظفين."},
            {"· 1 créneau en sous-effectif", "· فترة واحدة بعدد غير كاف"},
            {"Du 03/10/2026 au 09/10/2026 · 14 créneaux de 12h · effectif minimum 4 (dont 1 chef de garde et 1 conducteur)",
             "من 03/10/2026 إلى 09/10/2026 · 14 فترة من 12 س · حد أدنى 4 (منهم رئيس مناوبة وسائق)"},
        };
        QHash<QString, QString> h;
        for (auto &p : paires) h.insert(QString::fromUtf8(p[0]), QString::fromUtf8(p[1]));
        return h;
    }();
    return d;
}

// Traduit un texte en gardant ses espaces de tête et sa pastille « ● » éventuelle
QString traduireTexte(const QString &francais)
{
    static const QRegularExpression forme("^(\\s*(?:●\\s*)?)(.*?)(\\s*)$", QRegularExpression::DotMatchesEverythingOption);
    auto m = forme.match(francais);
    const QString coeur = m.captured(2);
    auto it = dictionnaireArabe().constFind(coeur);
    if (it == dictionnaireArabe().constEnd()) {
        // en-têtes du planning : « sam 03\nJour » -> jour traduit
        static const QHash<QString, QString> jours = {
            {"sam", "السبت"}, {"dim", "الأحد"}, {"lun", "الإثنين"}, {"mar", "الثلاثاء"},
            {"mer", "الأربعاء"}, {"jeu", "الخميس"}, {"ven", "الجمعة"}};
        static const QRegularExpression annees("^(\\d+) ans?$");   // « 14 ans » -> « 14 سنة »
        auto a = annees.match(coeur);
        if (a.hasMatch()) return m.captured(1) + a.captured(1) + QString::fromUtf8(" سنة") + m.captured(3);
        static const QRegularExpression creneau("^(\\w{3}) (\\d{2})\\n(Jour|Nuit)$");
        auto c = creneau.match(coeur);
        if (c.hasMatch() && jours.contains(c.captured(1)))
            return jours.value(c.captured(1)) + " " + c.captured(2) + "\n"
                 + (c.captured(3) == "Jour" ? QString::fromUtf8("نهار") : QString::fromUtf8("ليل"));
        return francais;
    }
    return m.captured(1) + it.value() + m.captured(3);
}

void CaserneConnectee::traduireInterface()
{
    const char *FR = "texteFrancais";
    auto texte = [&](QObject *o, const QString &actuel) {
        if (!o->property(FR).isValid()) o->setProperty(FR, actuel);
        const QString fr = o->property(FR).toString();
        return langueArabe ? traduireTexte(fr) : fr;
    };
    for (QLabel *l : findChildren<QLabel *>())
        if (!l->text().isEmpty() && l->property("variante").toString() != "heure" && l->property("variante").toString() != "date"
            && l != ui->lblForceMotDePasseEmploye
            && l != ui->lblCorrespondanceEmploye && l != ui->lbl75 && l != ui->lbl76 && l != ui->lbl77
            && l->property("variante").toString() != "kpiValeur" && !l->property("dynamique").toBool())
            l->setText(texte(l, l->text()));
    for (QPushButton *b : findChildren<QPushButton *>()) {
        if (!b->text().isEmpty() && !boutonsLangue.contains(b) && !boutonsZoomValeur.contains(b)) b->setText(texte(b, b->text()));
        if (!b->toolTip().isEmpty()) {
            const char *TIP = "infobulleFrancais";
            if (!b->property(TIP).isValid()) b->setProperty(TIP, b->toolTip());
            b->setToolTip(langueArabe ? traduireTexte(b->property(TIP).toString()) : b->property(TIP).toString());
        }
    }
    for (QLineEdit *e : findChildren<QLineEdit *>()) {
        if (e->placeholderText().isEmpty()) continue;
        const char *PH = "indiceFrancais";
        if (!e->property(PH).isValid()) e->setProperty(PH, e->placeholderText());
        e->setPlaceholderText(langueArabe ? traduireTexte(e->property(PH).toString()) : e->property(PH).toString());
    }
    for (QComboBox *c : findChildren<QComboBox *>())
        for (int i = 0; i < c->count(); ++i) {
            if (!c->itemData(i, Qt::UserRole + 30).isValid()) c->setItemData(i, c->itemText(i), Qt::UserRole + 30);
            const QString fr = c->itemData(i, Qt::UserRole + 30).toString();
            c->setItemText(i, langueArabe ? traduireTexte(fr) : fr);
        }
    for (QTableWidget *t : findChildren<QTableWidget *>()) {
        auto traiter = [&](QTableWidgetItem *it) {
            if (!it) return;
            if (!it->data(Qt::UserRole + 30).isValid()) it->setData(Qt::UserRole + 30, it->text());
            const QString fr = it->data(Qt::UserRole + 30).toString();
            it->setText(langueArabe ? traduireTexte(fr) : fr);
        };
        for (int c = 0; c < t->columnCount(); ++c) traiter(t->horizontalHeaderItem(c));
        for (int l = 0; l < t->rowCount(); ++l)
            for (int c = 0; c < t->columnCount(); ++c) traiter(t->item(l, c));
    }
}

void CaserneConnectee::on_btnLangueEmploye_clicked()
{
    transitionDouce([this]() {
        langueArabe = !langueArabe;
        setLayoutDirection(langueArabe ? Qt::RightToLeft : Qt::LeftToRight);
        for (QPushButton *b : boutonsLangue) b->setText(langueArabe ? "Fr" : QString::fromUtf8("ع"));
        traduireInterface();
        employe->definirLangueArabe(langueArabe);
        mettreAJourHorloge();
    });
}

// =============================================================================
//  LANCEMENT
// =============================================================================
// Pour intégrer le module dans l'application de l'équipe, ajouter dans le .pro :
//     DEFINES += MODULE_EMPLOYE_INTEGRE
// (le main() de l'application complète est alors utilisé à la place de celui-ci).
#ifndef MODULE_EMPLOYE_INTEGRE
int main(int argc, char *argv[])
{
    // Page « zoomée » : l'interface est dessinée pour un écran 1366 x 768 à 100 %. Quand Windows
    // agrandit l'affichage (125 %, 150 %…), Qt agrandit aussi toute la fenêtre et elle déborde.
    // On garde donc la taille réelle des pixels et des polices (comme à 100 %).
    qputenv("QT_ENABLE_HIGHDPI_SCALING", "0");
    qputenv("QT_FONT_DPI", "96");
    // Zoom choisi dans l'en-tête (− / +) : facteur appliqué à toute l'interface
    const int zoom = QSettings("ESPRIT", "CaserneConnectee").value("affichage/zoom", 100).toInt();
    if (zoom != 100) qputenv("QT_SCALE_FACTOR", QByteArray::number(qBound(50, zoom, 150) / 100.0, 'f', 2));
    QApplication a(argc, argv);
    a.setOrganizationName("ESPRIT");             // dossier des données : comptes et droits (fichier JSON)
    a.setApplicationName("CaserneConnectee");
    a.setStyle("Fusion");   // même apparence des widgets sur tous les PC

    // Palette claire imposée : si Windows est en mode sombre, les listes déroulantes et le
    // calendrier restent lisibles (le mode sombre de l'application se règle dans l'en-tête).
    QPalette palette;
    palette.setColor(QPalette::Window, QColor("#EDF1F5"));
    palette.setColor(QPalette::WindowText, QColor("#16202A"));
    palette.setColor(QPalette::Base, Qt::white);
    palette.setColor(QPalette::AlternateBase, QColor("#F8FAFC"));
    palette.setColor(QPalette::Text, QColor("#16202A"));
    palette.setColor(QPalette::Button, Qt::white);
    palette.setColor(QPalette::ButtonText, QColor("#16202A"));
    palette.setColor(QPalette::Highlight, QColor("#E4491F"));
    palette.setColor(QPalette::HighlightedText, Qt::white);
    palette.setColor(QPalette::ToolTipBase, Qt::white);
    palette.setColor(QPalette::ToolTipText, QColor("#16202A"));
    palette.setColor(QPalette::PlaceholderText, QColor("#8B99A6"));
    a.setPalette(palette);
    CaserneConnectee w;
    w.showMaximized();   // l'application s'ouvre en plein écran
    return a.exec();
}
#endif // MODULE_EMPLOYE_INTEGRE

// =============================================================================
// Son de l'intro (images/intro.wav : souffle de flamme, allumage, carillon des circuits)
//  - Windows : PlaySound (bibliothèque winmm, fournie avec Windows) ;
//  - autres systèmes : QSoundEffect si Qt Multimedia est installé, sinon pas de son.
// Placé à la fin du fichier : les macros de <windows.h> ne touchent pas le reste du code.
// =============================================================================
#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <mmsystem.h>
#elif defined(AVEC_SON_QT)
#include <QSoundEffect>
#endif

void jouerSonIntro()
{
#ifdef Q_OS_WIN
    static QByteArray son;                         // le son doit rester en mémoire pendant la lecture
    if (son.isEmpty()) {
        QFile fichier(":/images/intro.wav");
        if (fichier.open(QIODevice::ReadOnly)) son = fichier.readAll();
    }
    if (!son.isEmpty())
        PlaySoundW(reinterpret_cast<LPCWSTR>(son.constData()), nullptr, SND_MEMORY | SND_ASYNC | SND_NODEFAULT);
#elif defined(AVEC_SON_QT)
    QSoundEffect *effet = new QSoundEffect(qApp);
    effet->setSource(QUrl("qrc:/images/intro.wav"));
    effet->setVolume(0.8);
    QObject::connect(effet, &QSoundEffect::playingChanged, effet, [effet]() { if (!effet->isPlaying()) effet->deleteLater(); });
    effet->play();
#endif
}

// Musique douce en boucle (images/musique.wav : nappes et cloches calmes, créées pour le projet)
void jouerMusique(bool marche)
{
#ifdef Q_OS_WIN
    static QByteArray morceau;
    if (marche && morceau.isEmpty()) {
        QFile fichier(":/images/musique.wav");
        if (fichier.open(QIODevice::ReadOnly)) morceau = fichier.readAll();
    }
    if (marche && !morceau.isEmpty())
        PlaySoundW(reinterpret_cast<LPCWSTR>(morceau.constData()), nullptr, SND_MEMORY | SND_ASYNC | SND_LOOP | SND_NODEFAULT);
    else
        PlaySoundW(nullptr, nullptr, 0);
#elif defined(AVEC_SON_QT)
    static QSoundEffect *boucle = nullptr;
    if (!boucle) {
        boucle = new QSoundEffect(qApp);
        boucle->setSource(QUrl("qrc:/images/musique.wav"));
        boucle->setLoopCount(QSoundEffect::Infinite);
        boucle->setVolume(0.5);
    }
    if (marche) boucle->play(); else boucle->stop();
#else
    Q_UNUSED(marche);
#endif
}
