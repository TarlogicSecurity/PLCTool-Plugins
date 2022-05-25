#-------------------------------------------------
#
# Project created by QtCreator 2020-03-10T11:14:49
#
#-------------------------------------------------

QT       += core gui widgets

isEmpty(PREFIX) {
  PREFIX=/usr/local
}

target.path=$$PREFIX/lib/plctool

TARGET = BlinkAttack
TEMPLATE = lib

SOURCES += BlinkAttack.cpp \
    BlinkAttackFactory.cpp \
    BlinkAttackPluginEntryPoint.cpp

HEADERS +=	BlinkAttack.h \
    BlinkAttackFactory.h

unix: LIBS += -ldl

INSTALLS += target
