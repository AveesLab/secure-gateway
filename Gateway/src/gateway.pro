CONFIG += c++11

INCLUDEPATH += ../../src-gen-gateway/
SOURCES += SecurityGatewayStubImpl.cpp \
    ../../src-gen-gateway/v1/automotive/SecurityGatewaySomeIPDeployment.cpp \
    ../../src-gen-gateway/v1/automotive/SecurityGatewaySomeIPProxy.cpp \
    ../../src-gen-gateway/v1/automotive/SecurityGatewaySomeIPStubAdapter.cpp \


# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

win32:CONFIG(release, debug|release): LIBS += -L/usr/local/lib/release/ -lCommonAPI
else:win32:CONFIG(debug, debug|release): LIBS += -L/usr/local/lib/debug/ -lCommonAPI
else:unix: LIBS += -L/usr/local/lib/ -lCommonAPI

INCLUDEPATH += /usr/local/include/CommonAPI-3.2
DEPENDPATH += /usr/local/include/CommonAPI-3.2

win32:CONFIG(release, debug|release): LIBS += -L/usr/local/lib/release/ -lCommonAPI-SomeIP
else:win32:CONFIG(debug, debug|release): LIBS += -L/usr/local/lib/debug/ -lCommonAPI-SomeIP
else:unix: LIBS += -L/usr/local/lib/ -lCommonAPI-SomeIP

INCLUDEPATH += /usr/local/include/CommonAPI-3.2
DEPENDPATH += /usr/local/include/CommonAPI-3.2

win32:CONFIG(release, debug|release): LIBS += -L/usr/local/lib/release/ -lvsomeip3
else:win32:CONFIG(debug, debug|release): LIBS += -L/usr/local/lib/debug/ -lvsomeip3
else:unix: LIBS += -L/usr/local/lib/ -lvsomeip3

INCLUDEPATH += /usr/local/include
DEPENDPATH += /usr/local/include

HEADERS += \
    ../../src-gen-gateway/v1/automotive/SecurityGateway.hpp \
    ../../src-gen-gateway/v1/automotive/SecurityGatewayProxy.hpp \
    ../../src-gen-gateway/v1/automotive/SecurityGatewayProxyBase.hpp \
    ../../src-gen-gateway/v1/automotive/SecurityGatewaySomeIPDeployment.hpp \
    ../../src-gen-gateway/v1/automotive/SecurityGatewaySomeIPProxy.hpp \
    ../../src-gen-gateway/v1/automotive/SecurityGatewaySomeIPStubAdapter.hpp \
    ../../src-gen-gateway/v1/automotive/SecurityGatewayStub.hpp \
    ../../src-gen-gateway/v1/automotive/SecurityGatewayStubDefault.hpp \
    SecurityGatewayStubImpl.hpp \
