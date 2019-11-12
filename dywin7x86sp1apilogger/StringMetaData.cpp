/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "StringMetaData.h"
#include "StringData.h"

namespace WinApiLib {

    StringMetaData::StringMetaData(IEnv &env, const char * name, int charSize)
    : CommonMetaData(env, name), 
            mCharSize(charSize), 
            mIsZeroTerminated(true),
            mLengthOffset(-1), 
            mLengthOffsetSize(-1), 
            mZImpl(new ZeroTerminatedString(*this)), 
            mBImpl(new LengthSpecifiedString(*this)) 
    {

    }

    StringMetaData::StringMetaData(IEnv &env, const char * name, int charSize, int offset, int offsetSize)
    : CommonMetaData(env, name), 
            mCharSize(charSize), 
            mIsZeroTerminated(false),
            mLengthOffset(offset), 
            mLengthOffsetSize(offsetSize),
            mZImpl(new ZeroTerminatedString(*this)), 
            mBImpl(new LengthSpecifiedString(*this)) 
    {

    }

    StringMetaData::~StringMetaData() {
        delete this->mZImpl;
        delete this->mBImpl;
    }
    
    int StringMetaData::getCharSize() {
        return this->mCharSize;
    }

    bool StringMetaData::is0Terminated() {
        return this->mIsZeroTerminated;
    }

    /**
     * Obtains the length offset. If string is zero terminated, this is ignored.
     * Only useful if string is not zero terminated. This is the offset of the
     * length data from the current pointer. Useful for BSTR strings.
     * @return 
     */
    int StringMetaData::getLengthOffset() {
        return this->mLengthOffset;
    }

    int StringMetaData::getLengthOffsetSize() {
        return this->mLengthOffsetSize;
    }

    DATA_TYPE_CATEGORY StringMetaData::getCategory() {
        return STRING;
    }

    IWinTypeData& StringMetaData::read() {
        if (this->mIsZeroTerminated) {
            return *(this->mZImpl);
        } else {
            return *(this->mBImpl);
        }
    }
}

