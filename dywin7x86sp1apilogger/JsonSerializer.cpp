/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "JsonSerializer.h"

#include <sstream>
#include <iomanip>

#include <cstdlib>
#include <cstdio>

namespace WinApiLibJson = WinApiLib::Json;

using namespace WinApiLibJson;

JsonInt::JsonInt(uint64_t val) 
: mVal(val)
{
    
}

JsonInt::~JsonInt() {
    
}

JSON_TYPE JsonInt::getCategory() {
    return JSON_TYPE_INTEGER;
}

/**
 * @return string representation of int, as unsigned int.
 */
std::string JsonInt::toJson() {
    char buf[32];
    snprintf(buf, 31, "%lu", this->mVal);
    std::string sbuf(buf);
    return sbuf;
}

uint64_t JsonInt::getVal() {
    return this->mVal;
}

JsonIntHex::JsonIntHex(uint64_t val) 
: JsonInt(val)
{

}

JsonIntHex::~JsonIntHex() {
    
}

/**
 * @return string representation of int, in unsigned hex, sample: 0xabcde
 */
std::string JsonIntHex::toJson() {
    char buf[32];
    snprintf(buf, 31, "\"0x%lx\"", this->getVal());
    std::string sbuf(buf);
    return sbuf;
}


JsonFloat::JsonFloat(double val) 
: mVal(val)
{

}

JsonFloat::~JsonFloat() {
    
}

JSON_TYPE JsonFloat::getCategory() {
    return JSON_TYPE_FLOAT;
}

/**
 * @return string representation of a float
 */
std::string JsonFloat::toJson() {
    char buf[32];
    snprintf(buf, 31, "%lf", this->mVal);
    std::string sbuf(buf);
    return sbuf;
}

JsonString::JsonString(const char* str) 
: mStr(str)
{

}

JsonString::~JsonString() {
    
}

JSON_TYPE JsonString::getCategory() {
    return JSON_TYPE_STRING;
}

/**
 * @return string representation of input ASCII string. For Json usage, this only handles ASCII string.
 * All non-printable characters and doublequote are changed to hex representation (\xXX). Doublequote is also 
 * changed to \xXX to allow enclosing entire string with doublequotes.
 * printable characters are in range 0x20 to 0x7e.
 */
std::string JsonString::toJson() {
    std::stringstream ss;
    
    ss << "\"";
    std::string::size_type strLen = this->mStr.length();
    for (std::string::size_type i = 0; i < strLen; ++i) {
        
        // to handle very weird characters (gt 0x7f), in char, this will be negative number
        // converted to int, this results to 0xffff...ff, so, mask it with 0xff to obtain
        // only last byte and zero-in the others, then convert to int.
        int ch = (int)(this->mStr[i] & 0xff);
        if (ch >= 0x20 && ch <= 0x7e && ch != '"') { // printable ascii characters except doublequote
            ss << (char)ch;
        } else { // non-printable ascii and doublequotes are represented by their hex code
            ss << "\\x" << std::hex << std::setfill('0') << std::setw(2) << (int)ch;
        }
    }
    ss << "\"";
//    ss << "\"" << this->mStr << "\"";
    return ss.str();
}


JsonLiteralObj::JsonLiteralObj(const char* str) 
: mStr(str)
{
    
}

JsonLiteralObj::~JsonLiteralObj() {
    
}

JSON_TYPE JsonLiteralObj::getCategory() {
    return JSON_TYPE_STRING;
}

std::string JsonLiteralObj::toJson() {
    return mStr;
}


JsonWstring::JsonWstring(const uint16_t* wstr) {
    this->mBuf.clear();
    for (int i=0; wstr[i]; ++i) {
        this->mBuf.push_back(wstr[i]);
    }
}

JsonWstring::~JsonWstring() {
    
}

JSON_TYPE JsonWstring::getCategory() {
    return JSON_TYPE_WSTRING;
}

/**
 * @return string representation of input wide-char string. Only 2-byte char string is accepted.
 * There's no formatting whatsoever. 2-byte char is treated as signed 16bit integer and is transformed to \uXXXX in json
 * one-byte char is transformed to \x00XX.
 */
std::string JsonWstring::toJson() {
    int size = this->mBuf.size();
    std::stringstream ss;
    ss << "\"";
    for (int i=0; i<size; ++i) {
        ss << "\\u" << std::hex << std::setfill('0') << std::setw(4) << this->mBuf[i]; 
    }
    ss << "\"";
    return ss.str();
}

JsonBinary::JsonBinary(const uint8_t* bin, int length) {
    this->mBuf.clear();
    for (int i=0; i<length; ++i) {
        this->mBuf.push_back(bin[i]);
    }
}

JsonBinary::~JsonBinary() {
    
}

JSON_TYPE JsonBinary::getCategory() {
    return JSON_TYPE_BINARY;
}

/**
 * @return string representation of byte array in json. Format is "\xXX\xXX\xXX..."
 */
std::string JsonBinary::toJson() {
    int size = this->mBuf.size();
    std::stringstream ss;
    ss << "\"";
    for (int i=0; i<size; ++i) {
        // must be converted to uint32_t first
        // because in stringstream, C++ interprets uint8_t as char, it seems
        // and converts it to ascii representation.
        ss << "\\x" << std::hex << std::setfill('0') << 
                std::setw(2) << ((uint32_t)this->mBuf[i]); 
    }
    ss << "\"";
    return ss.str();
}

JsonArray::JsonArray() {
    this->mArray.clear();
}

JsonArray::~JsonArray() {
    
}

JSON_TYPE JsonArray::getCategory() {
    return JSON_TYPE_COLLECTION;
}

void JsonArray::addObj(IJsonObj* obj) {
    this->mArray.push_back(obj);
}

/**
 * This function does not delete the objects that are pointed to by the pointers inside mArray.
 * Those things must be manually deleted by the caller!
 */
void JsonArray::clearArray() {
    this->mArray.clear();
}

/**
 * @return json array representation of the objects inside mArray
 * Empty array is []
 */
std::string JsonArray::toJson() {
    int size = this->mArray.size();
    std::stringstream ss;
    
    ss << "[";
    if (size > 0) {
        ss << this->mArray[0]->toJson();
        for (int i=1; i<size; ++i) {
            ss << "," << this->mArray[i]->toJson();
        }
    }
    ss << "]";
    
    return ss.str();
}

/**
 * Clear does not delete the objects that are pointed to by the pointers inside mArray.
 * Those things must be manually deleted by the caller!
 */
JsonStruct::JsonStruct() {
    this->mMap.clear();
}

JsonStruct::~JsonStruct() {
    
}

JSON_TYPE JsonStruct::getCategory() {
    return JSON_TYPE_OBJECT;
}

void JsonStruct::setValue(const char* key, IJsonObj* val) {
    std::string sKey(key);
    this->mMap[sKey] = val;
}

/**
 * This function does not delete the objects that are pointed to by the pointers inside mArray.
 * Those things must be manually deleted by the caller!
 */
void JsonStruct::clearObj() {
    this->mMap.clear();
}

/**
 * Returns json representation of map object. 
 * The ordering of map entries is lexicographic, based on
 * default C++ STL map ordering implementation
 * 
 * NULL is represented as null, no quotes
 *
 * @return json representation of map object.
 * empty map is {}
 */
std::string JsonStruct::toJson() {
    
    std::stringstream ss;
    ss << "{";
    int i=0;
    int size = this->mMap.size();
    for (MapIt it = this->mMap.begin(); it != this->mMap.end(); ++it) {
        if (it->second != NULL) {
            ss << "\"" << it->first << "\":" << it->second->toJson();
        } else {
            ss << "\"" << it->first << "\":null";
        }
        // make sure there's no trailing comma for the last element.
        if (i < size-1) {
            ss << ",";
        }
        i++;
    }
    ss << "}";
    return ss.str();
}
