/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   IWinTypeMetaData.h
 * Author: darryl
 *
 * Created on November 3, 2018, 2:41 PM
 */

#ifndef IWINTYPEMETADATA_H
#define IWINTYPEMETADATA_H

#include "IWinTypes.h"

namespace WinApiLib {
    enum DATA_TYPE_CATEGORY {
        LITERAL,
        STRING,
        STRUCT
    };
    
    class IWinTypeData;
    
    /**
     * Interface to represent metadata information about a data type such as name, size, etc.
     * If struct, it may contain information about its members.
     */
    class IWinTypeMetaData {
    public:
        IWinTypeMetaData() {}
        virtual ~IWinTypeMetaData() {}

        virtual const char * getName() = 0;

        /**
         * @return LITERAL / STRING or STRUCT
         */
        virtual DATA_TYPE_CATEGORY getCategory() = 0;
        
        /**
         * Returns a reference to an object to read the actual data from memory buffer in guest / host based on this metadata.
         * @return IWinTypeData&
         */
        virtual IWinTypeData& read() = 0;
        
        /**
         * reads the data at address addr
         * 
         * @param addr
         * @return pointer to the data, 
         * This must be freed manually, using the supplied delete method in IWinTypes.h
         */
//        virtual IWinTypeData* read(uint64_t addr) = 0;

    };
}

#endif /* IWINTYPEMETADATA_H */

