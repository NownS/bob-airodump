TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap -lnet -lpthread
SOURCES += \
    airodump.cpp \
    mac.cpp

HEADERS += \
    airodump.h \
    mac.h
