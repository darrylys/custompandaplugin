/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   IWinApis.h
 * Author: darryl
 *
 * Created on November 4, 2018, 11:14 PM
 */

#ifndef IWINAPIS_H
#define IWINAPIS_H

#include <stdint.h>

#include "IEnv.h"
#include <vector>
#include <string>

namespace WinApiLib {
    
    enum FUNC_PARAM_DIRECTION {
        IN = 1, OUT = 2, INOUT = 3
    };
    
    typedef struct _FUNC_PARAM_DESC {
        
        const char * name;
        const char * type;
        FUNC_PARAM_DIRECTION usage;
        
    } FUNC_PARAM_DESC, *PFUNC_PARAM_DESC;
    
    typedef struct _FUNC_DESC {
        
        const char * dllName;
        const char * fnName;
        uint32_t fnRva;
        uint16_t fnOrd;
        const char * fnReturnType;
        const char * fnCallConvention;
        std::vector<FUNC_PARAM_DESC> fnParam;
        
    } FUNC_DESC, *PFUNC_DESC;
    
    class IWinApis {
    public:
        IWinApis(){}
        virtual ~IWinApis(){}
        
        // should be removed. Just make this object stateless.
        // findFunc should be given imageName as well!
        
        //virtual bool setImageBaseAddr(uint64_t baseDllVa, const char * imageName) = 0;
        /**
         * Finds the API function based on the csv file.
         * 
         * @param dllName
         * @param baseDllVa Virtual Address of the dll in memory
         * @param currentVa Current Virtual Address of the currently running instruction
         * @param out fnDesc
         * @return true if success, false otherwise
         */
        virtual bool findFunc(const char * dllName, uint64_t baseDllVa, 
                uint64_t currentVa, FUNC_DESC &fnDesc) = 0;
        
    };
    
    IWinApis * createWinApiParser(IEnv &env, const char * fileName);
    void releaseWinApiParser(IWinApis * obj);
    
}


#endif /* IWINAPIS_H */

