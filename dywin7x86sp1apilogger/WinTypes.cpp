/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "IWinTypes.h"
#include "IWinTypeMetaData.h"
#include "StringMetaData.h"
#include "LiteralMetaData.h"
#include "StructMetaData.h"

#include "CsvReader.h"
#include "IEnv.h"

#include <assert.h>

#include <string>
#include <fstream>
#include <vector>
#include <map>

#include <cstdlib>

namespace WinApiLib {
    
#define STAR ("*")
    class WinTypesImpl : public IWinTypes {
    public:

        WinTypesImpl(IEnv &env, const char * dt_file_name)
        : m_data_types_file_name(dt_file_name), mEnv(env), isInitialized(false) {

        }

        ~WinTypesImpl() {
            for (mWinTypeMetadataIt it = this->mWinTypeMetadata.begin(); 
                    it != this->mWinTypeMetadata.end();
                    ++it) {
                delete it->second;
            }
        }
        
        bool init() {
            if (!isInitialized) {
                isInitialized = this->_read_data_types_file();
            }
            return isInitialized;
        }
        
        IWinTypeMetaData * findMetadata(const char * dataTypeName) {
            mWinTypeMetadataIt it = this->mWinTypeMetadata.find(dataTypeName);
            if (it == this->mWinTypeMetadata.end()) {
                return NULL;
            }
            return it->second;
        }
        
        IWinTypeData* getPointer() {
            return getDefault();
        }
        
        int getPointerSize() {
            
            // assume default entry (*) as a pointer type
            IWinTypeMetaData * ptrmetadata = findMetadata(STAR);
            LiteralMetaData * pl = reinterpret_cast<LiteralMetaData*>(ptrmetadata); 
            return pl->getSize();
            
        }
        
        IWinTypeData * findDataDefaultNull(const char * dataTypeName) {
            IWinTypeMetaData * meta = this->findMetadata(dataTypeName);
            if (meta == NULL) {
                return NULL;
            } else {
                return &(meta->read());
            }
        }
        
        IWinTypeData * getDefault() {
            return findDataDefaultNull(STAR);
        }
        
        IWinTypeData * findData(const char * dataTypeName) {
            IWinTypeData * val = findDataDefaultNull(dataTypeName);
            if (val == NULL) {
                return getDefault();
            } else {
                return val;
            }
        }

    private:
        std::string m_data_types_file_name;
        std::map<std::string, IWinTypeMetaData*> mWinTypeMetadata;
        typedef std::map<std::string, IWinTypeMetaData*>::iterator mWinTypeMetadataIt;
        IEnv &mEnv;
        bool isInitialized;
        
        /**
            This function reads given types-csv file.
            
            types-csv recognized 3 possible types, literal, string, and struct.
            Do not have trailing spaces between commas, at the beginning or the end.

            common format:
            <data type name>,<type: literal|string|struct>,[from here on, dependent on the type]

            if type is empty, literal is assumed

            literal types format:
            <data type name>,<literal/empty string>,<size in bytes>,<(s)igned|(u)nsigned>
            uint32_t,,4,u       // data type name = uint32_t, size = 4 bytes, unsigned
            int32_t,,4,s        //
            uint8_t,,1,u        //
            *,,4,u              // Default handling, if no other types matched

            string types format:
            <data type name>,<string>,<char size>,<z|b,<size offset>>

            This plugin handled 2 kinds of strings, the standard Zero-Terminated C-style strings, or 
            e.g. layout: 'a', 'b', 'c', 'd', '\0'
                 pointer: ^
            a string with specified length in specified offset from the pointer to the beginning of string
            e.g. layout: 5, 'a', 'b', 'c', 'd', 'e'
                 pointer:    ^

            The former is commonly seen with data type LPSTR, LPWSTR, etc...
            The latter is known as BSTR strings. BSTR strings may or may not ended with zero.

            <char size> is the size in bytes of one char. For ANSI strings, char size is 1 bytes. For Windows UNICODE (UTF-16LE), it's 2 bytes.

            STR,string,1,z      // a zero terminated string 
            WSTR,string,2,z     // a zero terminated wide-string
            BSTR,string,1,b,1   // a string with length specified in 1 byte before the pointer of first character
            BWSTR,string,2,b,1  // a wide-string with length specified in 1 byte before the pointer of first character

            struct types format: (# is for comments)
            <data type name>,<struct>,<size in bytes>[,<offset>,<data type name[*]*>,<var name>]*
            #typedef struct tagPOINT1 {
            #  000 LONG x;
            #  004 LONG y;
            #} POINT, *PPOINT;
            POINT,struct,8,0,LONG,x,4,LONG,y    
            // a struct named POINT, 
            //      8 bytes size total, 
            //      with members: 
            //          x, data type = LONG, 0 bytes offset from beginning of struct, 
            //          y, data type = LONG, 4 bytes offset from beginning of struct


            #typedef struct _UNICODE_STRING {
            #    USHORT Length;
            #    USHORT MaximumLength;
            #    PWSTR  Buffer;
            #} UNICODE_STRING, *PUNICODE_STRING;
            UNICODE_STRING,struct,8,0,USHORT,Length,2,USHORT,MaximumLength,4,WSTR*,Buffer
            // a struct named UNICODE_STRING
            //      8 bytes size total
            //      with members:
            //          Length, type USHORT, 0 bytes offset from beginning of struct
            //          MaximumLength, type USHORT, 2 bytes offset from beginning of struct
            //          Buffer, type WSTR* (a pointer to WSTR type), 4 bytes offset from beginning of struct
            
            @return true if read success, false otherwise
        */
        bool _read_data_types_file() {

            std::ifstream dtf(this->m_data_types_file_name.c_str());
            if (dtf.good()) {

                std::string line;
                while (std::getline(dtf, line)) {

                    if (line.empty()) {
                        continue;
                    }

                    if (line[0] == '#') {
                        // skip comments
                        continue;
                    }

                    std::vector<std::string> cells;
                    csvreader::parse_csv(line.c_str(), cells);

                    int i = 0;
                    std::string &name = cells[i++];
                    std::string &categ = cells[i++];
                    
                    IWinTypeMetaData * pMetadata = NULL;
                    
                    // continue parsing based on categ and so on
                    if (categ == "string") {
                        int charSize = atoi(cells[i++].c_str());
                        std::string &stringType = cells[i++];
                        
                        if (stringType == "z") {
                            pMetadata = new StringMetaData(this->mEnv, name.c_str(), charSize);
                        } else if (stringType == "b") {
                            int lengthOffset = atoi(cells[i++].c_str());
                            pMetadata = new StringMetaData(this->mEnv, name.c_str(), charSize, 
                                    lengthOffset, lengthOffset);
                        } else {
                            // unknown config
                            continue;
                        }
                        
                    } else if (categ == "struct") {
//                        std::string &nameAlias = cells[i++];
//                        std::string &namePAlias = cells[i++];
                        int structSize = atoi(cells[i++].c_str());
                        
                        StructMetaData * structMetadata = new StructMetaData(
                                this->mEnv, name.c_str(), structSize);
                        
                        int cellLen = cells.size();
                        for (; i < cellLen ;i += 3) {
                            int offset = atoi(cells[i].c_str());
                            std::string &entryType = cells[i+1];
                            std::string &entryName = cells[i+2];
                            
                            STRUCT_ENTRY entry;
                            entry.dataType = entryType;
                            entry.name = entryName;
                            entry.offset = offset;
                            
                            structMetadata->addEntry(entry);
                        }
                        
                        pMetadata = structMetadata;
                        
                    } else if (categ == "" || categ == "literal" || categ == "primitive") {
                        int size = atoi(cells[i++].c_str());
                        std::string &signCfg = cells[i++];
                        
                        if (signCfg == "s") {
                            pMetadata = new LiteralMetaData(this->mEnv, 
                                    name.c_str(), size, true);
                        } else {
                            // default unsigned
                            pMetadata = new LiteralMetaData(this->mEnv, 
                                    name.c_str(), size, false);
                        }
                        
                    } else {
                        // crashed unknown category
                        assert(false);
                        continue;
                    }
                    
                    if (pMetadata) {
                        const mWinTypeMetadataIt it = this->mWinTypeMetadata.find(name);
                        if (it == this->mWinTypeMetadata.end()) {
                            mWinTypeMetadata[name] = pMetadata;
                        } else {
                            // overwrite is forbidden
                            delete pMetadata;
                        }
                    }

                }

            } else {
                return false;
            }

            return true;
        }


    };

    IWinTypes * createWinTypes(IEnv &env, const char * file_name) {
        WinTypesImpl * w = new WinTypesImpl(env, file_name);
        bool isInitialized = w->init();
        if (!isInitialized) {
            releaseWinTypes(w);
            return NULL;
        } else {
            return w;
        }
    }

    void releaseWinTypes(IWinTypes * obj) {
        delete obj;
    }
    
    void releaseWinTypeData(IWinTypeData * obj) {
//        delete obj;
        // current impl, the object is actually singleton. Don't delete them!
        // let the owner (IWinTypes) deletes them in destructor
    }
    
}
