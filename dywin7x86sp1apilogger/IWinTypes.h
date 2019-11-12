/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   IWinTypes.h
 * Author: darryl
 *
 * Created on November 3, 2018, 2:44 PM
 */

#ifndef IWINTYPES_H
#define IWINTYPES_H

#include "IEnv.h"
#include "IWinTypeMetaData.h"

namespace WinApiLib {
    
    class IWinTypeData {
        
    public:
        IWinTypeData(){}
        virtual ~IWinTypeData(){}
        
        /**
         * reads byte array from addr (guest) to outBuf with buffer size outBufLen. Actual length 
         * is given at out variable actualLen
         * 
         * @param cpu
         * @param addr
         * @param outBuf
         * @param outBufLen, if 0, required length is given in out variable actualLen
         * @param actualLen
         * @param nBytesRead Optional size of bytes of data to be read in runtime.
         *        Useful of the size of bytes to be read is only determined at runtime
         *        such as PWSTR in UNICODE_STRING which is not guaranteed to end with zeros.
         * @return 
         */
        virtual bool getBytes(void * cpu, uint64_t addr, uint8_t outBuf[], 
                int outBufLen, int &actualLen, int nBytesRead = 0) = 0;
        
        /**
         * Reads byte array from host pointed to by pDataInHost. This is useful if the object in guest memory
         * has been destroyed but it has been copied to host memory, so, to read from host for this object
         * instead of guest
         * 
         * @param cpu
         * @param pDataInHost
         * @param outBuf
         * @param outBufLen, if 0, required length is given in out variable actualLen
         * @param actualLen
         * @param nBytesRead Optional size of bytes of data to be read in runtime.
         *        Useful of the size of bytes to be read is only determined at runtime
         *        such as PWSTR in UNICODE_STRING which is not guaranteed to end with zeros.
         * @return 
         */
        virtual bool getBytesFromHost(void * cpu, const uint8_t * pDataInHost, uint8_t outBuf[],
                int outBufLen, int &actualLen, int nBytesRead = 0) = 0;
        
//        virtual const char * getJsonForm(void * cpu) = 0;
        virtual IWinTypeMetaData& getMetaData() = 0;
        
    };
    
    class IWinTypes {
    public:
        IWinTypes(){}
        virtual ~IWinTypes(){}

        // init method should be removed, move it to impl method
//        virtual void init() = 0;
        
        /**
         * Finds the metadata of specified name.
         * @param dataTypeName
         * @return pointer to metadata. Don't free this pointer.
         */
        virtual IWinTypeMetaData * findMetadata(const char * dataTypeName) = 0;
        
        /**
         * Finds the default metadata. 
         * @return 
         */
        virtual int getPointerSize() = 0;
        
        /**
         * Obtains the data object for pointer types
         * @return 
         */
        virtual IWinTypeData * getPointer() = 0;
        
        /**
         * finds the data type with name dataTypeName. If not found, automatically
         * gets the default type (*). If fails, then returns NULL
         * 
         * @param dataTypeName
         * @return pointer to the data. Don't release the pointer because it is
         * a singleton!
         */
        virtual IWinTypeData * findData(const char * dataTypeName) = 0;
        
        /**
         * finds the data type with name dataTypeName. If not found, returns NULL
         * @param dataTypeName
         * @return 
         */
        virtual IWinTypeData * findDataDefaultNull(const char * dataTypeName) = 0;
        
        /**
         * Finds the data type with name "*"
         * @return 
         */
        virtual IWinTypeData * getDefault() = 0;
        
    };

    IWinTypes * createWinTypes(IEnv &env, const char * data_types_file_name);
    void releaseWinTypes(IWinTypes * obj);
    void releaseWinTypeData(IWinTypeData * obj);

}

#endif /* IWINTYPES_H */

