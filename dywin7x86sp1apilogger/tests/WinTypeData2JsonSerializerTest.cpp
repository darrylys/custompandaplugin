/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   WinTypeData2JsonSerializerTest.cpp
 * Author: darryl
 *
 * Created on November 17, 2018, 11:58 AM
 */

#include <stdlib.h>
#include <iostream>

#include "TestInterface.h"
#include "WinTypeData2JsonSerializer.h"
#include "IWinApis.h"

namespace Tests {
	namespace WinTypeData2JsonSerializerTest {
using namespace WinApiLib;
using namespace WinApiLib::Json;

#define CURRDIR "../res"
#define TESTSUITENAME "WinTypeData2JsonSerializerTest"
#define DATATYPECSV "/alltypes.csv"
#define ABSDCSV CURRDIR DATATYPECSV

class TestEnv : public IEnv {
public:
    
    /**
     * Creates an environment with supplied backing buffer.
     * Write operation is NOP.
     * Read operation will be performed on this buffer.
     * @param buffer
     */
    TestEnv(const uint8_t * buffer)
    : data(buffer)
    {
    
    }
    ~TestEnv(){}
    int readEnv(uint64_t addr, uint8_t * buf, int len, void * extra) {
        int datalen = sizeof (data) / sizeof (data[0]);
        uint32_t iAddr = (uint32_t) (addr);
        for (int i = 0; i < len; ++i) {
            *(buf + i) = data[(iAddr + i)];
        }

        return IEnv::S_OK;
    }
    int writeEnv(uint64_t addr, uint8_t * buf, int len, void * extra) {
    }
    
private:
    const uint8_t * data;
};
class Holder {
public:
    Holder(IEnv& env, const char * fname) {
        mWinTypes = createWinTypes(env, fname);
        mSerializer = createWinType2JsonSerializer(*mWinTypes);
    }
    
    ~Holder() {
        releaseSerializer(mSerializer);
        releaseWinTypes(mWinTypes);
    }
    
    IWinTypes& getWinTypes() {
        return *(this->mWinTypes);
    }
    
    ISerializer<ObjData>& getSerializer() {
        return *(this->mSerializer);
    }
    
    
private:
    IWinTypes* mWinTypes;
    ISerializer<ObjData> * mSerializer;
    
};

void testInt32WinTypeExpectSuccessJson() {
    
    const char * METHOD_NAME = "testInt32WinTypeExpectSuccessJson";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x0
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    param.addr = 0;
    param.varName = "paramInt32";
    param.typeData = winTypes.findData("int32");
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"0x53525150\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testInt32FromHostWinTypeExpectSuccessJson() {
    
    const char * METHOD_NAME = "testInt32FromHostWinTypeExpectSuccessJson";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x0
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    uint32_t dataInHost = 0xab10ff78;
    
    param.addr = 0;
    param.varName = "paramInt32";
    param.dataInHostSize = sizeof(dataInHost);
    param.pDataInHost = (uint8_t*)(&dataInHost);
    
    param.typeData = winTypes.findData("int32");
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"0xab10ff78\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testInt32PtrRedirectionExpectSuccess() {
    const char * METHOD_NAME = "testInt32PtrRedirectionExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
       /* 0000 */ 0x04, 0x00, 0x00, 0x00,
       /* 0004 */ 0x08, 0x00, 0x00, 0x00,
       /* 0008 */ 0x0c, 0x00, 0x00, 0x00,
       /* 000c */ 0x10, 0x00, 0x00, 0x00,
       /* 0010 */ 0x50, 0x51, 0x52, 0x53,
       /* 0014 */ 0x00, 0x00, 0x00, 0x00
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    param.addr = 0;
    param.varName = "paramInt32";
    param.typeData = winTypes.findData("int32****");
    param.varType = "int32****";
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"0x53525150\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testInt32PtrFirstRedirectionFromHostExpectSuccess() {
    const char * METHOD_NAME = "testInt32PtrFirstRedirectionFromHostExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
       /* 0000 */ 0x04, 0x00, 0x00, 0x00,
       /* 0004 */ 0x08, 0x00, 0x00, 0x00,
       /* 0008 */ 0x0c, 0x00, 0x00, 0x00,
       /* 000c */ 0x10, 0x00, 0x00, 0x00,
       /* 0010 */ 0x50, 0x51, 0x52, 0x53,
       /* 0014 */ 0x00, 0x00, 0x00, 0x00
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    uint32_t dataInHost = buffer[0];
    
    param.addr = 0xffff;
    param.varName = "paramInt32";
    param.typeData = winTypes.findData("int32****");
    param.varType = "int32****";
    param.dataInHostSize = sizeof(dataInHost);
    param.pDataInHost = (uint8_t*)(&dataInHost);
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"0x53525150\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testUSHORTWinTypeExpectSuccess() {
    const char * METHOD_NAME = "testUSHORTWinTypeExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x0
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    param.addr = 0;
    param.varName = "paramUSHORT";
    param.typeData = winTypes.findData("USHORT");
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"0x5150\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testUSHORTFromHostWinTypeExpectSuccess() {
    const char * METHOD_NAME = "testUSHORTFromHostWinTypeExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x0
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    uint16_t dataInHost = 0x15ab;
    
    param.addr = 0;
    param.varName = "paramUSHORT";
    param.typeData = winTypes.findData("USHORT");
    param.dataInHostSize = sizeof(dataInHost);
    param.pDataInHost = (uint8_t*)(&dataInHost);
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"0x15ab\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testU64WinTypeExpectSuccess() {
    const char * METHOD_NAME = "testU64WinTypeExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x0
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    param.addr = 0;
    param.varName = "paramU64";
    param.typeData = winTypes.findData("uint64");
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"0x5756555453525150\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testU64FromHostWinTypeExpectSuccess() {
    const char * METHOD_NAME = "testU64FromHostWinTypeExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x0
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    uint64_t dataInHost = 0xabcdef0011223344LL;
    
    param.addr = 0;
    param.varName = "paramU64";
    param.typeData = winTypes.findData("uint64");
    param.dataInHostSize = sizeof(dataInHost);
    param.pDataInHost = (uint8_t*)(&dataInHost);
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"0xabcdef0011223344\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testU64PtrRedirectionWinTypeExpectSuccess() {
    const char * METHOD_NAME = "testU64PtrRedirectionWinTypeExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
       /* 0000 */ 0x04, 0x00, 0x00, 0x00,
       /* 0004 */ 0x08, 0x00, 0x00, 0x00,
       /* 0008 */ 0x0c, 0x00, 0x00, 0x00,
       /* 000c */ 0x10, 0x00, 0x00, 0x00,
       /* 0010 */ 0x40, 0x41, 0x42, 0x43,
       /* 0014 */ 0x44, 0x45, 0x46, 0x47
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    param.addr = 0;
    param.varName = "paramInt64";
    param.typeData = winTypes.findData("uint64****");
    param.varType = "uint64****";
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"0x4746454443424140\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testU64FromHostPtrRedirectionWinTypeExpectSuccess() {
    const char * METHOD_NAME = "testU64FromHostPtrRedirectionWinTypeExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
       /* 0000 */ 0x04, 0x00, 0x00, 0x00,
       /* 0004 */ 0x08, 0x00, 0x00, 0x00,
       /* 0008 */ 0x0c, 0x00, 0x00, 0x00,
       /* 000c */ 0x10, 0x00, 0x00, 0x00,
       /* 0010 */ 0x14, 0x00, 0x00, 0x00,
       /* 0014 */ 0x44, 0x45, 0x46, 0x47,
       /* 0018 */ 0x5a, 0x5b, 0x5c, 0x5d
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    uint32_t dataInHost = 0x8;
    
    param.addr = 0;
    param.varName = "paramInt64";
    param.typeData = winTypes.findData("uint64****");
    param.varType = "uint64****";
    param.dataInHostSize = sizeof(dataInHost);
    param.pDataInHost = (uint8_t*)(&dataInHost);
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"0x5d5c5b5a47464544\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testBinary10BytesWinTypeExpectSuccess() {
    const char * METHOD_NAME = "testBinary10BytesWinTypeExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x0
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    param.addr = 0;
    param.varName = "paramU64";
    param.typeData = winTypes.findData("BINARY10");
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"\\x50\\x51\\x52\\x53\\x54\\x55\\x56\\x57\\x58\\x59\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testBinary10FromHostBytesWinTypeExpectSuccess() {
    const char * METHOD_NAME = "testBinary10FromHostBytesWinTypeExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x0
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    const uint8_t dataInHost[] = {
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0
    };
    
    param.addr = 0;
    param.varName = "paramU64";
    param.typeData = winTypes.findData("BINARY10");
    param.dataInHostSize = sizeof(dataInHost);
    param.pDataInHost = dataInHost;
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testStringWinTypeSuccess() {
    const char * METHOD_NAME = "testStringWinTypeSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x0
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    param.addr = 0;
    param.varName = "paramU64";
    param.typeData = winTypes.findData("STR");
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"PQRSTUVWXYZ\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testStringFromHostWinTypeSuccess() {
    const char * METHOD_NAME = "testStringFromHostWinTypeSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x0
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    const uint8_t dataInHost[] = {
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 0
    };
    
    param.addr = 0;
    param.varName = "paramU64";
    param.typeData = winTypes.findData("STR");
    param.dataInHostSize = sizeof(dataInHost);
    param.pDataInHost = dataInHost;
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"abcdefgh\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testStringPtrRedirectionExpectSuccess() {
    const char * METHOD_NAME = "testStringPtrRedirectionExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
       /* 0000 */ 0x04, 0x00, 0x00, 0x00,
       /* 0004 */ 0x08, 0x00, 0x00, 0x00,
       /* 0008 */ 0x0c, 0x00, 0x00, 0x00,
       /* 000c */ 0x10, 0x00, 0x00, 0x00,
       /* 0010 */ 0x40, 0x41, 0x42, 0x43,
       /* 0014 */ 0x44, 0x45, 0x46, 0x47,
       /* 0018 */ 0x48, 0x49, 0x00, 0x00
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    param.addr = 0;
    param.varName = "paramInt64";
    param.typeData = winTypes.findData("STR****");
    param.varType = "STR****";
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"@ABCDEFGHI\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testWStringWinTypeSuccess() {
    const char * METHOD_NAME = "testStringWinTypeSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint16_t buffer[] = {
        0x50, 0x51, 0x52, 0x53, 0x0
    };
    
    TestEnv env((uint8_t*)buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    param.addr = 0;
    param.varName = "paramU64";
    param.typeData = winTypes.findData("WSTR");
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"\\u0050\\u0051\\u0052\\u0053\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testWStringFromHostWinTypeSuccess() {
    const char * METHOD_NAME = "testWStringFromHostWinTypeSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint16_t buffer[] = {
        0x50, 0x51, 0x52, 0x53, 0x0
    };
    
    TestEnv env((uint8_t*)buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    const uint16_t dataInHost[] = {
        0x6061, 0x6263, 0x6465, 0x0
    };
    
    param.addr = 0;
    param.varName = "paramU64";
    param.typeData = winTypes.findData("WSTR");
    param.dataInHostSize = sizeof(dataInHost);
    param.pDataInHost = (uint8_t*)(dataInHost);
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"\\u6061\\u6263\\u6465\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testWStringPtrRedirectionExpectSuccess() {
    const char * METHOD_NAME = "testWStringPtrRedirectionExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
       /* 0000 */ 0x04, 0x00, 0x00, 0x00,
       /* 0004 */ 0x08, 0x00, 0x00, 0x00,
       /* 0008 */ 0x0c, 0x00, 0x00, 0x00,
       /* 000c */ 0x10, 0x00, 0x00, 0x00,
       /* 0010 */ 0x40, 0x41, 0x42, 0x43,
       /* 0014 */ 0x44, 0x45, 0x46, 0x47,
       /* 0018 */ 0x48, 0x49, 0x00, 0x00
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    param.addr = 0;
    param.varName = "paramInt64";
    param.typeData = winTypes.findData("WSTR****");
    param.varType = "WSTR****";
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = "\"\\u4140\\u4342\\u4544\\u4746\\u4948\"";
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testUnicodeStringExpectSuccess() {
    const char * METHOD_NAME = "testUnicodeStringExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
       /* 0000 */ 0x06, 0x00, 0x08, 0x00,
       /* 0004 */ 0x08, 0x00, 0x00, 0x00,
       /* 0008 */ 0x40, 0x41, 0x42, 0x43,
       /* 000c */ 0x44, 0x45, 0x46, 0x47,
       /* 0010 */ 0x48, 0x49, 0x00, 0x00
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    param.addr = 0;
    param.varName = "paramInt64";
    param.typeData = winTypes.findData("UNICODE_STRING");
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = 
            "{"
                "\"Buffer\":\"\\u4140\\u4342\\u4544\\u4746\\u4948\","
                "\"Length\":\"0x6\","
                "\"MaximumLength\":\"0x8\""
            "}";
    
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testUnicodeStringFromHostExpectSuccess() {
    const char * METHOD_NAME = "testUnicodeStringFromHostExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    const uint8_t buffer[] = {
       /* 0000 */ 0x06, 0x00, 0x08, 0x00,
       /* 0004 */ 0x08, 0x00, 0x00, 0x00,
       /* 0008 */ 0x40, 0x41, 0x42, 0x43,
       /* 000c */ 0x44, 0x45, 0x46, 0x47,
       /* 0010 */ 0x48, 0x49, 0x00, 0x00
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    const uint8_t dataInHost[] = {
       /* 0000 */ 0x07, 0x00, 0x08, 0x00,
       /* 0004 */ 0x08, 0x00, 0x00, 0x00,
       /* 0008 */ 0x50, 0x51, 0x52, 0x53,
       /* 000c */ 0x54, 0x55, 0x56, 0x57,
       /* 0010 */ 0x58, 0x59, 0x00, 0x00
    };
    
    param.addr = 0;
    param.varName = "paramInt64";
    param.typeData = winTypes.findData("UNICODE_STRING");
    param.dataInHostSize = sizeof(dataInHost);
    param.pDataInHost = dataInHost;
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    // ONLY the immediate contents of UNICODE_STRING (Buffer, Length, and the address of STR in guest) in host memory
    // the actual content of STR is still read from guest memory!
    const char * expected = 
            "{"
                "\"Buffer\":\"\\u4140\\u4342\\u4544\\u4746\\u4948\","
                "\"Length\":\"0x7\","
                "\"MaximumLength\":\"0x8\""
            "}";
    
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testUnicodeStringPtrRedirectionExpectSuccess() {
    const char * METHOD_NAME = "testUnicodeStringPtrRedirectionExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    // in reality, there's no address 0 anyway
    const uint8_t buffer[] = {
       /* 0000 */ 0x00, 0x00, 0x00, 0x00,
       /* 0004 */ 0x06, 0x00, 0x08, 0x00,
       /* 0008 */ 0x0c, 0x00, 0x00, 0x00,
       /* 000c */ 0x40, 0x41, 0x42, 0x43,
       /* 0010 */ 0x44, 0x45, 0x46, 0x47,
       /* 0014 */ 0x48, 0x49, 0x00, 0x00,
       /* 0018 */ 0x04, 0x00, 0x00, 0x00
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    param.addr = 0x18;
    param.varName = "paramInt64";
    param.typeData = winTypes.findData("UNICODE_STRING*");
    param.varType = "UNICODE_STRING*";
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = 
            "{"
                "\"Buffer\":\"\\u4140\\u4342\\u4544\\u4746\\u4948\","
                "\"Length\":\"0x6\","
                "\"MaximumLength\":\"0x8\""
            "}";
    
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testObjectAttributesExpectSuccess() {
    const char * METHOD_NAME = "testObjectAttributesExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    /*
     * #typedef struct _OBJECT_ATTRIBUTES {
        # 0000    ULONG           Length;
        # 0004   HANDLE          RootDirectory;
        # 0008   PUNICODE_STRING ObjectName;
        # 000c   ULONG           Attributes;
        # 0010   PVOID           SecurityDescriptor;
        # 0014   PVOID           SecurityQualityOfService;
        #} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
     */
    const uint8_t buffer[] = {
        // OBJECT_ATTRIBUTES
       /* 0000 */ 0x18, 0x00, 0x00, 0x00,
       /* 0004 */ 0x00, 0x00, 0x00, 0x00,
       /* 0008 */ 0x18, 0x00, 0x00, 0x00,
       /* 000c */ 0x10, 0x11, 0x12, 0x00,
       /* 0010 */ 0x21, 0x22, 0x23, 0x24,
       /* 0014 */ 0x00, 0x25, 0x26, 0x27,
       
       // UNICODE_STRING
       /* 0018 */ 0x06, 0x00, 0x08, 0x00,
       /* 001c */ 0x20, 0x00, 0x00, 0x00,
       /* 0020 */ 0x41, 0x42, 0x43, 0x44,
       /* 0024 */ 0x45, 0x46, 0x00, 0x00
       
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    param.addr = 0;
    param.varName = "paramInt64";
    param.typeData = winTypes.findData("OBJECT_ATTRIBUTES");
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = 
    "{"
        "\"Attributes\":\"0x121110\","
        "\"Length\":\"0x18\","
        "\"ObjectName\":"
            "{"
                "\"Buffer\":\"\\u4241\\u4443\\u4645\","
                "\"Length\":\"0x6\","
                "\"MaximumLength\":\"0x8\""
            "},"
        "\"RootDirectory\":\"0x0\","
        "\"SecurityDescriptor\":\"0x24232221\","
        "\"SecurityQualityOfService\":\"0x27262500\""
    "}";
    
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}
void testObjectAttributesFromHostExpectSuccess() {
    const char * METHOD_NAME = "testObjectAttributesFromHostExpectSuccess";
    std::cout << "Method: " << METHOD_NAME << " runs" << std::endl;
    
    ObjData param;
    
    /*
     * #typedef struct _OBJECT_ATTRIBUTES {
        # 0000    ULONG           Length;
        # 0004   HANDLE          RootDirectory;
        # 0008   PUNICODE_STRING ObjectName;
        # 000c   ULONG           Attributes;
        # 0010   PVOID           SecurityDescriptor;
        # 0014   PVOID           SecurityQualityOfService;
        #} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
     */
    const uint8_t buffer[] = {
        // OBJECT_ATTRIBUTES
       /* 0000 */ 0x18, 0x00, 0x00, 0x00,
       /* 0004 */ 0x00, 0x00, 0x00, 0x00,
       /* 0008 */ 0x18, 0x00, 0x00, 0x00,
       /* 000c */ 0x10, 0x11, 0x12, 0x00,
       /* 0010 */ 0x21, 0x22, 0x23, 0x24,
       /* 0014 */ 0x00, 0x25, 0x26, 0x27,
       
       // UNICODE_STRING
       /* 0018 */ 0x06, 0x00, 0x08, 0x00,
       /* 001c */ 0x20, 0x00, 0x00, 0x00,
       /* 0020 */ 0x41, 0x42, 0x43, 0x44,
       /* 0024 */ 0x45, 0x46, 0x00, 0x00
       
    };
    
    TestEnv env(buffer);
    Holder holder(env, ABSDCSV);
    
    IWinTypes& winTypes = holder.getWinTypes();
    ISerializer<ObjData>& serializer = holder.getSerializer();
    
    std::cout << "Method: " << METHOD_NAME << " Obtains winTypes and serializer" << std::endl;
    
    /*
     * #typedef struct _OBJECT_ATTRIBUTES {
        # 0000    ULONG           Length;
        # 0004   HANDLE          RootDirectory;
        # 0008   PUNICODE_STRING ObjectName;
        # 000c   ULONG           Attributes;
        # 0010   PVOID           SecurityDescriptor;
        # 0014   PVOID           SecurityQualityOfService;
        #} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
     */
    const uint8_t dataInHost[] = {
         // OBJECT_ATTRIBUTES
       /* 0000 */ 0x24, 0x00, 0x00, 0x00,
       /* 0004 */ 0xff, 0xaf, 0x00, 0x00,
       /* 0008 */ 0x18, 0x00, 0x00, 0x00,
       /* 000c */ 0x20, 0x21, 0x22, 0x00,
       /* 0010 */ 0x31, 0x32, 0x33, 0x34,
       /* 0014 */ 0x00, 0x35, 0x36, 0x37,
       
       // UNICODE_STRING
       /* 0018 */ 0x07, 0x00, 0x09, 0x00,
       /* 001c */ 0x20, 0x00, 0x00, 0x00,
       /* 0020 */ 0x61, 0x62, 0x63, 0x64,
       /* 0024 */ 0x65, 0x66, 0x00, 0x00
    };
    
    param.addr = 0;
    param.varName = "paramInt64";
    param.typeData = winTypes.findData("OBJECT_ATTRIBUTES");
    param.dataInHostSize = sizeof(dataInHost);
    param.pDataInHost = dataInHost;
    
    if (param.typeData == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect typeData NOT NULL " << ", observed NULL" << std::endl;
        return;
    }
    
    std::string observed(serializer.serialize(param, NULL));
    const char * expected = 
    "{"
        "\"Attributes\":\"0x222120\","
        "\"Length\":\"0x24\","
        "\"ObjectName\":"
            "{"
                "\"Buffer\":\"\\u4241\\u4443\\u4645\","
                "\"Length\":\"0x6\","
                "\"MaximumLength\":\"0x8\""
            "},"
        "\"RootDirectory\":\"0xafff\","
        "\"SecurityDescriptor\":\"0x34333231\","
        "\"SecurityQualityOfService\":\"0x37363500\""
    "}";
    
    if (observed != expected) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect json " << expected << ", observed " << observed << std::endl;
        return;
    }   
}

#define T(X) RUNFUNC(X,TESTSUITENAME)

void runTest_WinTypeData2JsonSerializerTest() {
    std::cout << "%SUITE_STARTING% "TESTSUITENAME << std::endl;
    std::cout << "%SUITE_STARTED%" << std::endl;

    T(testInt32WinTypeExpectSuccessJson                  );
    T(testInt32FromHostWinTypeExpectSuccessJson          );
    T(testInt32PtrRedirectionExpectSuccess               );
    T(testInt32PtrFirstRedirectionFromHostExpectSuccess  );
    T(testUSHORTWinTypeExpectSuccess                     );
    T(testUSHORTFromHostWinTypeExpectSuccess             );
    T(testU64WinTypeExpectSuccess                        );
    T(testU64FromHostWinTypeExpectSuccess                );
    T(testU64PtrRedirectionWinTypeExpectSuccess          );
    T(testU64FromHostPtrRedirectionWinTypeExpectSuccess  );
    T(testBinary10BytesWinTypeExpectSuccess              );
    T(testBinary10FromHostBytesWinTypeExpectSuccess      );
    T(testStringWinTypeSuccess                           );
    T(testStringFromHostWinTypeSuccess                   );
    T(testStringPtrRedirectionExpectSuccess              );
    T(testWStringWinTypeSuccess                          );
    T(testWStringFromHostWinTypeSuccess                  );
    T(testWStringPtrRedirectionExpectSuccess             );
    T(testUnicodeStringExpectSuccess                     );
    T(testUnicodeStringFromHostExpectSuccess             );
    T(testUnicodeStringPtrRedirectionExpectSuccess       );
    T(testObjectAttributesExpectSuccess                  );
    T(testObjectAttributesFromHostExpectSuccess          );
    
    std::cout << "%SUITE_FINISHED% time=0" << std::endl;
}
		
	}
}

void runTest_WinTypeData2JsonSerializerTest() {
	Tests::WinTypeData2JsonSerializerTest::runTest_WinTypeData2JsonSerializerTest();
}
