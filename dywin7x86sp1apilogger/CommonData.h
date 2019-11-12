/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   CommonData.h
 * Author: darryl
 *
 * Created on November 10, 2018, 12:46 PM
 */

#ifndef COMMONDATA_H
#define COMMONDATA_H

#include "IWinTypes.h"
#include "IWinTypeMetaData.h"
#include <stdint.h>

namespace WinApiLib {
    
    class CommonData : public IWinTypeData {
    public:
        virtual ~CommonData();
        IWinTypeMetaData& getMetaData();
        
    protected:
        CommonData(IWinTypeMetaData& metadata);
        
    private:
        IWinTypeMetaData &mMetadata;
        
    };
    
}

#endif /* COMMONDATA_H */

