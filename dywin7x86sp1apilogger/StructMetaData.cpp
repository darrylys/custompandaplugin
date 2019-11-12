/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "StructMetaData.h"
#include "StructData.h"

namespace WinApiLib {

    StructMetaData::StructMetaData(IEnv &env, const char * name, int size)    
    : CommonMetaData(env, name), mSize(size), mImpl(new StructData(*this)) 
    {

    }

    StructMetaData::~StructMetaData() {
        delete this->mImpl;
    }

    int StructMetaData::getSize() {
        return this->mSize;
    }

    const std::vector<STRUCT_ENTRY>& StructMetaData::getEntries() {
        return this->mEntries;
    }

    void StructMetaData::addEntry(const STRUCT_ENTRY& entry) {
        this->mEntries.push_back(entry);
    }

    DATA_TYPE_CATEGORY StructMetaData::getCategory() {
        return STRUCT;
    }

    IWinTypeData& StructMetaData::read() {
        return *(this->mImpl);
    }

}
