/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ISerializer.h
 * Author: darryl
 *
 * Created on November 10, 2018, 11:04 AM
 */

#ifndef ISERIALIZER_H
#define ISERIALIZER_H

#include <string>

namespace WinApiLib {
    template <class T>
    class ISerializer {
    public:
        ISerializer() {}
        virtual ~ISerializer() {}
        virtual std::string serialize(T& param, void * cpu) = 0;
    };
    
    // for templates, the definitions should be placed in the header file.
    template <class T>
    void releaseSerializer(ISerializer<T> *serializer) {
        delete serializer;
    }
}

#endif /* ISERIALIZER_H */

