/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   EnvAwareMetaData.h
 * Author: darryl
 *
 * Created on November 4, 2018, 4:53 PM
 */

#ifndef ENVAWAREMETADATA_H
#define ENVAWAREMETADATA_H

#include "IWinTypes.h"
#include "IWinTypeMetaData.h"
#include "IEnv.h"
#include <string>

namespace WinApiLib {
    
    class CommonMetaData : public IWinTypeMetaData {
    public:
        CommonMetaData(IEnv &env, const char * name);
        virtual ~CommonMetaData();
        const char * getName();
        IEnv& getEnv();
        
    private:
        IEnv &mEnv;
        std::string mName;
    };
    
}

#endif /* ENVAWAREMETADATA_H */

