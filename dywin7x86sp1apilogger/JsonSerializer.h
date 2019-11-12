/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   JsonSerializer.h
 * Author: darryl
 *
 * Created on November 10, 2018, 2:00 PM
 */

#ifndef JSONSERIALIZER_H
#define JSONSERIALIZER_H

#include <stdint.h>
#include <string>
#include <map>
#include <vector>

namespace WinApiLib {
    
    namespace Json {
        
        // for C++, enum names are automatic global.
        // so, STRING defined here will conflict with STRING from other enum, somehow.
        // The enum names should also prefixed by the enum name!
        // The enum::name is MSVC extension which does not exist in GCC.
        enum JSON_TYPE {
            JSON_TYPE_INTEGER,
            JSON_TYPE_FLOAT,
            JSON_TYPE_STRING,
            JSON_TYPE_WSTRING,
            JSON_TYPE_COLLECTION,
            JSON_TYPE_OBJECT,
            JSON_TYPE_BINARY
        };
        
        class IJsonObj {
        public:
            IJsonObj() {}
            virtual ~IJsonObj() {}
            
            // don't add const on functions that return values, not references!
            virtual JSON_TYPE getCategory() = 0;
            virtual std::string toJson() = 0;
            
        };
        
        /**
         * prints plain unsigned integer
         */
        class JsonInt : public IJsonObj {
        public:
            JsonInt(uint64_t val);
            ~JsonInt();
            
            JSON_TYPE getCategory();
            virtual std::string toJson();
            
        protected:
            uint64_t getVal();
            
        private:
            uint64_t mVal;
            
        };
        
        class JsonIntHex : public JsonInt {
        public:
            JsonIntHex(uint64_t val);
            ~JsonIntHex();
            
            std::string toJson();
        };
        
        class JsonFloat : public IJsonObj {
        public:
            JsonFloat(double val);
            ~JsonFloat();
            
            JSON_TYPE getCategory();
            std::string toJson();
            
        private:
            double mVal;
            
        };
        
        /**
         * Json object that adds a string to json object, as is.
         * Useful if there's already an existing json representation of an object and adding that to another
         * IJsonObj object, since this project does not have Json parser.
         */
        class JsonLiteralObj : public IJsonObj {
        public:
            JsonLiteralObj(const char * str);
            ~JsonLiteralObj();
            
            JSON_TYPE getCategory();
            std::string toJson();
            
        private:
            std::string mStr;
        };
        
        class JsonString : public IJsonObj {
        public:
            JsonString(const char * str);
            ~JsonString();
            
            JSON_TYPE getCategory();
            std::string toJson();
            
        private:
            std::string mStr;
            
        };
        
        class JsonWstring : public IJsonObj {
        public:
            JsonWstring(const uint16_t * wstr);
            ~JsonWstring();
            
            JSON_TYPE getCategory();
            std::string toJson();
            
        private:
            std::vector<uint16_t> mBuf;
            
        };
        
        class JsonBinary : public IJsonObj {
        public:
            JsonBinary(const uint8_t * bin, int length);
            ~JsonBinary();
            
            JSON_TYPE getCategory();
            std::string toJson();
            
        private:
            std::vector<uint8_t> mBuf;
            
        };
        
        class JsonArray : public IJsonObj {
        public:
            JsonArray();
            ~JsonArray();
            
            JSON_TYPE getCategory();
            std::string toJson();
            
            /**
             * this class does not in any way manage the reference. It must be
             * deallocated manually outside
             * @param obj
             */
            void addObj(IJsonObj* obj);
            
            /**
             * Clears the content of array, 
             * does not deallocate the contents. 
             */
            void clearArray();
            
        private:
            std::vector<IJsonObj*> mArray;
            
        };
        
        class JsonStruct : public IJsonObj {
        public:
            JsonStruct();
            ~JsonStruct();
            
            JSON_TYPE getCategory();
            std::string toJson();
            
            /**
             * this class does not in any way manage the reference. It must be
             * deallocated manually outside
             * @param key
             * @param val
             */
            void setValue(const char * key, IJsonObj * val);
            
            /**
             * this class does not in any way manage the reference. It must be
             * deallocated manually outside
             */
            void clearObj();
            
        private:
            std::map<std::string, IJsonObj*> mMap;
            typedef std::map<std::string, IJsonObj*>::iterator MapIt;
            
        };
        
    }
    
}

#endif /* JSONSERIALIZER_H */

