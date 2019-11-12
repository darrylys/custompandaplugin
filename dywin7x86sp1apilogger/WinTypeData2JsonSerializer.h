/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   JsonSerializer.h
 * Author: darryl
 *
 * Created on November 10, 2018, 11:33 AM
 */

#ifndef WINTYPEDATA2JSONSERIALIZER_H
#define WINTYPEDATA2JSONSERIALIZER_H

#include "IWinTypes.h"
#include "IWinTypeMetaData.h"
#include "ISerializer.h"

#include <stdint.h>
#include <string>

namespace WinApiLib {
    
    namespace Json {
        
        class ObjData {
            
        public:
            /**
             * Set initialization of variables here 
             */
            ObjData() 
            : addr(0)
            , pDataInHost(NULL)
            , dataInHostSize(0)
            , typeData(NULL)
            , varName("")
            , varType("")
            {
            }
            
            /**
             * Address of the data in guest (optional).
             */
            uint64_t addr;
            
            /**
             * pointer to array of bytes of the data in Host (optional, takes precedence)
             * This is useful if somehow the data in guest is already destroyed, but the
             * data itself is copied in host memory.
             */
            const uint8_t * pDataInHost;
            
            /**
             * size of the data pointed by pDataInHost
             */
            int dataInHostSize;
            
            /**
             * Type of the data
             */
            IWinTypeData * typeData;
            
            /**
             * Variable name of the data
             */
            std::string varName;
            
            /**
             * Type of the variable.
             * This is optional, because, it should've been covered in typeData
             * normally. But, usually when dealing with pointers,
             * the pointer type is not put in csv, but uses the default entry,
             * as such, the type name in typeData will be '*' (the default), instead
             * of the real name (uint32_t***, for example)
             * 
             * If varType is not empty, this will be preferred. Otherwise, uses the name
             * in typeData.
             */
            std::string varType;
        };
        
        /**
         * Delete returned object with releaseSerializer method in ISerializer.h
         * @return NULL if creation unsuccessful.
         */
        ISerializer<ObjData> *createWinType2JsonSerializer(IWinTypes& dbWinTypes);
    }
}

#endif /* WINTYPEDATA2JSONSERIALIZER_H */

