# =============================================================================
#  Caserne Connectée — MODULE EMPLOYÉ + PAGE D'IDENTIFICATION (projet autonome)
#  Qt 6 Widgets, C++17
#
#  Structure conforme au Guide d'intégration GUI (une seule UI, un QStackedWidget principal) :
#  caserneconnectee.h   : toutes les classes (CaserneConnectee = fenêtre principale, Employe, effets)
#  caserneconnectee.cpp : tout le code du module + slots de navigation on_<objet>_clicked()
#  caserneconnectee.ui  : SWCaserne (une page par module) ; page 0 = SWEmploye
#                         (0 Login, 1 Menu, 2 Mot de passe oublié, 3 CRUD, 4 Tableau de bord)
# =============================================================================
QT       += core gui widgets network concurrent   # network : QPasswordDigestor ; concurrent : PDF en arrière-plan
CONFIG   += c++17
# Toujours compilé en mode Release (optimisé) : en Debug, Qt et les animations sont plusieurs fois
# plus lents. Pour déboguer pas à pas, mettre les deux lignes suivantes en commentaire (#).
CONFIG   -= debug debug_and_release
CONFIG   += release
TARGET   = CaserneConnectee
TEMPLATE = app

SOURCES += caserneconnectee.cpp

HEADERS += caserneconnectee.h

FORMS += \
    caserneconnectee.ui

RESOURCES += ressources.qrc

RC_ICONS = images/logo.ico

# Son de l'intro : API Windows (winmm, toujours présente) ; ailleurs Qt Multimedia s'il est installé
win32: LIBS += -lwinmm
!win32:qtHaveModule(multimedia) { QT += multimedia
    DEFINES += AVEC_SON_QT }
