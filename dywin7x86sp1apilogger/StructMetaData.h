/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   StructMetaData.h
 * Author: darryl
 *
 * Created on November 3, 2018, 2:51 PM
 */

#ifndef STRUCTMETADATA_H
#define STRUCTMETADATA_H

#include "CommonMetaData.h"

#include <vector>
#include <string>

namespace WinApiLib {

    /**
     * Represents metadata about the struct member.
     */
    typedef struct _STRUCT_ENTRY {
        
        // offset of this member from address of the beginning of struct in memory
        int offset;
        
        // name of the data type
        std::string dataType;
        
        // name of the variable of the data type
        std::string name;
    } STRUCT_ENTRY, *PSTRUCT_ENTRY;

    class StructMetaData : public CommonMetaData {
    public:

        StructMetaData(IEnv &env, const char * name, int size);
        ~StructMetaData();
        int getSize();
        const std::vector<STRUCT_ENTRY>& getEntries();
        void addEntry(const STRUCT_ENTRY& entry);
        DATA_TYPE_CATEGORY getCategory();
        IWinTypeData& read();

    private:
        int mSize;
        std::vector<STRUCT_ENTRY> mEntries;
        IWinTypeData * mImpl;
        
    };

}

#endif /* STRUCTMETADATA_H */

