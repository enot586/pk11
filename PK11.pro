
TARGET = pk11
TEMPLATE = app

QT -= gui
QT += core network

CONFIG += c++11 console thread
CONFIG -= app_bundle
CONFIG += no_keywords

INCLUDEPATH += "/usr/include/PCSC"
INCLUDEPATH += "/usr/include/nss"
INCLUDEPATH += "/usr/include/nspr"

LIBS += -ljcPKCS11-2 -lnss3 -lnspr4
LIBS += -L/lib64/


SOURCES += \
        main.cpp

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
