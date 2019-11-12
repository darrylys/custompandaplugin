/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "LiteralMetaData.h"
#include "LiteralData.h"

namespace WinApiLib {
    
    // literal meta data
    /**
     * Constructs a metadata for literal types, which is just a byte array in memory, without any internal features
     * like struct or string. Integers and Pointers are included in this metadata.
     * @param env
     * @param name, the data type name
     * @param size, size in bytes
     * @param isSigned, is the byte array signed / unsigned. For byte arrays, always unsigned
     */
    LiteralMetaData::LiteralMetaData(IEnv &env, const char* name, int size, bool isSigned) 
    :CommonMetaData(env, name), mSize(size), mIsSigned(isSigned), mImpl(new LiteralData(*this))
    {
    }

    LiteralMetaData::~LiteralMetaData() {
        delete this->mImpl;
    }
    
    int LiteralMetaData::getSize() {
        return this->mSize;
    }

    bool LiteralMetaData::isSigned() {
        return this->mIsSigned;
    }

    DATA_TYPE_CATEGORY LiteralMetaData::getCategory() {
        return LITERAL;
    }
    
    IWinTypeData& LiteralMetaData::read() {
        return *(this->mImpl);
    }

}