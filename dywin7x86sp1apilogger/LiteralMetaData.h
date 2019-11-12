/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   LiteralMetaData.h
 * Author: darryl
 *
 * Created on November 3, 2018, 2:37 PM
 */

#ifndef LITERALMETADATA_H
#define LITERALMETADATA_H

#include "CommonMetaData.h"

#include <string>

namespace WinApiLib {
    class LiteralMetaData : public CommonMetaData {
    public:
        LiteralMetaData(IEnv &env, const char * name, int size, bool isSigned);
        ~LiteralMetaData();
        
        int getSize();
        bool isSigned();
        DATA_TYPE_CATEGORY getCategory();
        IWinTypeData& read();
        
    private:
        int mSize;
        bool mIsSigned;
        IWinTypeData *mImpl;
    };
}

#endif /* LITERALMETADATA_H */

