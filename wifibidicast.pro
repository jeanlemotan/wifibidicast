TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += c++11

LIBS += -lpcap

SOURCES += main.cpp \
    radiotap.c

include(deployment.pri)
qtcAddDeployment()

HEADERS += \
    ieee80211_radiotap.h \
    radiotap.h

