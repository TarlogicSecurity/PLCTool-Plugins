#-------------------------------------------------
#
# Project created by QtCreator 2020-03-10T11:14:49
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

isEmpty(PREFIX) {
  PREFIX=/usr/local
}

PLCTOOL_HEADERS_INSTALL = $$PREFIX/include/PLCTool

INCLUDEPATH += $$PLCTOOL_HEADERS_INSTALL

target.path=$$PREFIX/plctool/plugins

TARGET = BlinkAttackPlugin
TEMPLATE = lib

SOURCES += BlinkAttack/BlinkAttack.cpp \
    BlinkAttack/BlinkAttackFactory.cpp \
    BlinkAttack/BlinkAttackPluginEntryPoint.cpp

HEADERS +=	BlinkAttack/BlinkAttack.h \
    BlinkAttack/BlinkAttackFactory.h

unix: LIBS += -ldl

INSTALLS += target
