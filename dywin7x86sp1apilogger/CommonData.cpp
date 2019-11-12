/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "CommonData.h"

namespace WinApiLib {

    CommonData::CommonData(IWinTypeMetaData& metadata) 
    : mMetadata(metadata)
    {
    }
    
    CommonData::~CommonData() {
        
    }
    
    IWinTypeMetaData& CommonData::getMetaData() {
        return this->mMetadata;
    }
    

}
