/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   StringMetaData.h
 * Author: darryl
 *
 * Created on November 3, 2018, 2:47 PM
 */

#ifndef STRINGMETADATA_H
#define STRINGMETADATA_H

#include "CommonMetaData.h"

#include <string>

namespace WinApiLib {
    class StringMetaData : public CommonMetaData {
    public:
        
        /**
         * Constructor for Zero-Terminated strings, the most common string type in Windows.
         * @param env
         * @param name, string data type name
         * @param charSize, size of char in string. ASCII type is 1, wide-char for Windows is 2.
         */
        StringMetaData(IEnv &env, const char * name, int charSize);
        
        /**
         * Constructor for Length-Specified strings. Useful for BSTR strings
         * @param env
         * @param name, string data type name
         * @param charSize, size of char in string. ASCII type is 1, wide-char for Windows is 2.
         * @param offset, offset of length data in memory before the address of first character in string
         * @param offsetSize, size of length data in memory
         */
        StringMetaData(IEnv &env, const char * name, int charSize, int offset, int offsetSize);
        
        
        ~StringMetaData();
        
        
        int getCharSize();
        
        /**
         * Checks whether string is zero-terminated
         * @return true if string is zero-terminated, false otherwise
         */
        bool is0Terminated();
        
        /**
         * Obtains the length offset. If string is zero terminated, this is ignored.
         * Only useful if string is not zero terminated. This is the offset of the
         * length data from the current pointer. Useful for BSTR strings.
         * @return 
         */
        int getLengthOffset();
        
        int getLengthOffsetSize();
        
        
        DATA_TYPE_CATEGORY getCategory();
        
        
        IWinTypeData& read();
        
    private:
        int mCharSize;
        bool mIsZeroTerminated;
        int mLengthOffset;
        int mLengthOffsetSize;
        IWinTypeData * mZImpl;
        IWinTypeData * mBImpl;
        
    };
}

#endif /* STRINGMETADATA_H */

