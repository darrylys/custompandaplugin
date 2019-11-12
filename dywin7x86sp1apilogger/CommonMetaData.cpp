/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "CommonMetaData.h"

namespace WinApiLib {
    
    CommonMetaData::CommonMetaData(IEnv& env, const char* name) 
    :mEnv(env), mName(name)
    {
        
    }
    
    CommonMetaData::~CommonMetaData() {
        
    }
    
    IEnv& CommonMetaData::getEnv() {
        return this->mEnv;
    }

    const char * CommonMetaData::getName() {
        return this->mName.c_str();
    }
}