/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "WinTypeData2JsonSerializer.h"
#include "JsonSerializer.h"
#include "LiteralMetaData.h"
#include "LiteralData.h"
#include "StringMetaData.h"
#include "StringData.h"
#include "StructMetaData.h"
#include "StructData.h"

#include <assert.h>
#include <vector>
#include <map>
#include <string>
#include <cstring>
#include <iostream>

namespace WinApiLib {

    namespace Json {

        /**
         * To allow safe release of dynamically created IJsonObj implementations,
         * this class is used to delete all created IJsonObj upon destroy when this variable
         * goes out of scope
         */
        class JsonObjPtrList {
        public:
            JsonObjPtrList() {
            }
            // must make sure no double deletes!
            // Ans: Since all objects are only inserted once, double delete should not have been possible
            ~JsonObjPtrList() { 
                int size = jsonObjList.size();
                for (int i = 0; i < size; ++i) {
                    delete jsonObjList[i];
                }
            }
            std::vector<IJsonObj*> jsonObjList;
        };

        class WinTypeData2JsonSerializer : public ISerializer<ObjData> {
        public:
            WinTypeData2JsonSerializer(IWinTypes& dbWinTypes)
            : mWinTypes(dbWinTypes) {
            }
            virtual ~WinTypeData2JsonSerializer() {
            }
            virtual std::string serialize(ObjData& param, void * cpu) {
                JsonObjPtrList ptrList;
                return this->serializeProxy(param, cpu, ptrList.jsonObjList);
            }
        private:
            IWinTypes& mWinTypes;
            
            /**
             * A wrapper function to call actual implementation. This should be combined with serialize function above!
             *
             * @param root, description of object to be represented as json
             * @param cpu, extra data (any) to pass. This object will be passed to mWinTypes, which is passed to IEnv implementation. For PANDA / QEMU, this can be used to pass CPUState objects.
             * @param jsonObjList, the vector containing the address of dynamically created IJsonObj-s.
             * All objects added to this list will automatically be deleted after this function returns.
             * @return json string representation of object described in root parameter.
             */
            std::string serializeProxy(ObjData& root, void * cpu,
                    std::vector<IJsonObj*> &jsonObjList) {
                
                IJsonObj* pJson = this->convert2Json(root, cpu, jsonObjList);
                if (pJson != NULL) {
                    return pJson->toJson();
                } else {
                    return "null";
                }
                
            }

            /**
             * Finds the last pointer that points to the object.
             * 
             * This is useful if given data in root object is pointer to pointer to ... to pointer (i.e. int**** a);
             * @param typeName
             * @param firstPtrAddr
             * @param cpu, passed to mWinTypes, CPUState in PANDA
             * @param root, in-out.
             * @return the value of the last pointer that actually points to the object in guest memory.
             */
            uint64_t drillDownPtrRedirections(const char * typeName, 
                    uint64_t firstPtrAddr, void * cpu, 
                    ObjData &root) const {
                
                //int ptrSize = this->mWinTypes.getPointerSize();
                int nameLen = strlen(typeName);
                int nPtrRedir = 0;
                
                // simple way to find out the number of redirections is to find the number of
                // asterisks (*) at the end of type.
                // e.g. int****, means 4 redirections.
                for (int i = nameLen - 1; i >= 0; --i) {
                    if (typeName[i] == '*') {
                        nPtrRedir++;
                    } else {
                        break;
                    }
                }
                
                // allows for first address is saved in Host memory. This is useful if the memory no longer exist in guest
                // for example, on return address of API calls, the contents of the parameters might have been lost / destroyed in guest
                // unless they're copied to host beforehand. Since C allows for parameters to be in-out, it can be useful to
                // print parameters upon API return as well!
                if (root.pDataInHost != NULL) {
                    uint64_t tmp = 0;
                    uint8_t * pTmp = reinterpret_cast<uint8_t*>(&tmp);
                    int ptrSize;
                    if (root.dataInHostSize == 0) {
                        ptrSize = this->mWinTypes.getPointerSize();
                    } else {
                        ptrSize = root.dataInHostSize;
                    }
                    for (int i=0; i<ptrSize; ++i) {
                        *(pTmp+i) = *(root.pDataInHost+i);
                    }
                    
                    firstPtrAddr = tmp;
                    nPtrRedir--; // pDataInHost is the content of the data 
                                 // pointed by firstPtrAddr, so, minus one redirection
                    
                    // only first pointer is saved in host.
                    // finds the rest of the objects in guest memory.
                    // If the parameter is in-out, the actual object should still exist in guest, 
                    // although the pointers pointing to it
                    // in parameter has been invalidated for some reason.
                    root.pDataInHost = NULL;
                    root.dataInHostSize = 0;
                }
                
                uint64_t currPtrAddr = firstPtrAddr;
                uint64_t nextPtrAddr = 0;

                for (int i = 0; i < nPtrRedir; ++i) {
                    IWinTypeData* pPtrDataObj = this->mWinTypes.getPointer();

                    int actualLen;
                    bool res = pPtrDataObj->getBytes(cpu, currPtrAddr,
                            reinterpret_cast<uint8_t*> (&nextPtrAddr), sizeof (nextPtrAddr), actualLen);

                    if (!res) {
                        return 0;
                    }

                    currPtrAddr = nextPtrAddr;
                    nextPtrAddr = 0;
                }

                return currPtrAddr;
            }
            
            /**
             * converts object specified in root as IJsonObj.
             * 
             * @param root, description of object
             * @param cpu, PANDA CPUState, or extradata supplied to mWinTypes
             * @param jsonObjList, @see serialize and serializeProxy
             */
            IJsonObj * convert2Json(ObjData &root, void * cpu,
                    std::vector<IJsonObj*> &jsonObjList) {
                
                IWinTypeData * pData = root.typeData;
                uint64_t startAddr = root.addr;
                std::string& varName = root.varName;
                std::string& varType = root.varType;
                
                const char * typeName;
                if (varType == "") {
                    typeName = pData->getMetaData().getName();
                } else {
                    typeName = varType.c_str();
                }
                const char * pchVarName = varName.c_str();
                
                // check if Array
                // only support 1 dimension array
                int varNameLen = varName.length();
                int arrLen = 1;
                // for now, just assume length = 1
                if (varNameLen >= 3 && pchVarName[varNameLen - 2] == '[' && 
                        pchVarName[varNameLen - 1] == ']') { // if ends with []
                    // means Array!
                    
                    // TODO: must find length!
                    arrLen = 1;
                }
                
                // TODO: For array implementation, it has not been tested in any way, except for arrLen = 1.
                uint64_t addr = startAddr;
                for (int i = 0; i < arrLen; ++i) {
                    
                    int namelen = strlen(typeName);
                    uint64_t objAddr;
                    
                    // if typeName describes a pointer.
                    if (typeName[namelen - 1] == '*') {
                        // a pointer type
                        objAddr = this->drillDownPtrRedirections(typeName, addr, cpu, root);
                        if (objAddr == 0) {
                            return NULL;
                        }
                        
                        // must update the data now! change the data type and find new one!
                        // remove the asterisks (redirections) from typeName
                        int lenNoStar = namelen;
                        for (int i=namelen-1; i>=0; --i) {
                            if (typeName[i] == '*') {
                                lenNoStar--;
                            } else {
                                break;
                            }
                        }
                        std::string tmp = typeName;
                        
                        // realType is typeName without asterisks, redirections
                        std::string realType = tmp.substr(0, lenNoStar);
                        
                        // when trying to use references (IWinTypeData&), 
                        // the data is not updated. Probably some weird C++ stuff.
                        pData = this->mWinTypes.findData(realType.c_str());
                        
                    } else {
                        objAddr = addr;
                    }

                    
                    // If pointer redirections, must be updated now!
                    IWinTypeMetaData& metadata = pData->getMetaData();
                    DATA_TYPE_CATEGORY category = metadata.getCategory();
                    switch (category) {
                        case LITERAL:
                        {
                            return this->literal2json(*pData, objAddr, 
                                    root.pDataInHost, root.dataInHostSize, 
                                    cpu, jsonObjList);
                        }
                            break;

                        case STRING:
                        {
                            return this->string2json(*pData, objAddr, 
                                    root.pDataInHost, root.dataInHostSize, 
                                    cpu, jsonObjList);
                        }
                            break;

                        case STRUCT:
                        {
                            // create IJsonObj
                            JsonStruct * pJson = new JsonStruct();
                            
                            // add IJsonObj to vector
                            jsonObjList.push_back(pJson);
                            
                            StructMetaData& structMeta = reinterpret_cast<StructMetaData&> (metadata);
                            const std::vector<STRUCT_ENTRY>& entryList = structMeta.getEntries();
                            int entryLen = entryList.size();
                            
                            // loop for each member of struct
                            for (int i=0; i<entryLen; ++i) {
                                const STRUCT_ENTRY& entry = entryList[i];
                                
                                IWinTypeData* entryType = 
                                        this->mWinTypes.findData(entry.dataType.c_str());
                                
                                // for entries like UNICODE_STRING which PWSTR has no
                                // guarantee of last zero, just grab max 512 chars.
                                
                                ObjData entryObjData;
                                
                                // find the data in host, if required
                                if (root.pDataInHost != NULL) {
                                    entryObjData.addr = objAddr + entry.offset;
                                    entryObjData.pDataInHost = root.pDataInHost + entry.offset;
                                    entryObjData.dataInHostSize = 0; // use default pointer size
                                    
                                } else { // find it in guest memory (pDataInHost is NULL)
                                    entryObjData.addr = objAddr + entry.offset;
                                    entryObjData.pDataInHost = NULL; // don't use data in host
                                    entryObjData.dataInHostSize = 0; // use default pointer size
                                }
                                
                                entryObjData.typeData = entryType;
                                entryObjData.varName = entry.name;
                                entryObjData.varType = entry.dataType;
                                
                                // call this function for each member
                                IJsonObj* pEntryJson = this->convert2Json(entryObjData, cpu, jsonObjList);
                                
                                // add to parent IJsonObj
                                pJson->setValue(entry.name.c_str(), pEntryJson);
                                
                                // don't add pEntryJson to vector because it has been
                                // added previously.
                                
                            }
                            
                            return pJson;
                            
                        }
                            break;

                        default:
                            assert(false);
                            break;
                    }
                    
                    // update addr to next element in array
                }
                
                return NULL;
            }

            /**
             * Converts data to string json object. Depending on the char size, it can be
             * Json string or Json Wstring.
             * 
             * @param data
             * @param addr
             * @param pDataInHost
             * @param dataInHostSize
             * @param cpu
             * @param jsonObjList
             * @return 
             */
            IJsonObj * string2json(IWinTypeData& data, uint64_t addr, 
                    const uint8_t* pDataInHost, int dataInHostSize, void * cpu,
                    std::vector<IJsonObj*> &jsonObjList) {

                IWinTypeMetaData& metadata = data.getMetaData();
                StringMetaData& strMeta = reinterpret_cast<StringMetaData&> (metadata);
//                const char * typeName = metadata.getName();
                int charSize = strMeta.getCharSize();
                
                // clamp down size to 512 characters
                std::vector<uint8_t> vBuf(512 * charSize);
                int actualLen = 0;
                
                if (pDataInHost != NULL) {
                    bool res = data.getBytesFromHost(cpu, pDataInHost, &vBuf[0], 512, actualLen);
                    if (!res) {
                        return NULL;
                    }
                    
                } else {
                    bool res = data.getBytes(cpu, addr, &vBuf[0], 512, actualLen);
                    if (!res) {
                        return NULL;
                    }
                }

                vBuf.push_back(0); // add null characte because why not
                if (charSize == 2) {
                    vBuf.push_back(0); // if charSize == 2 (wide), add one more
                }

                IJsonObj * pJson;
                if (charSize == 1) {
                    pJson = new JsonString((char*) (&vBuf[0]));
                } else {
                    pJson = new JsonWstring((uint16_t*) (&vBuf[0]));
                }

                jsonObjList.push_back(pJson);

                return pJson;
            }

            /**
             * Converts a literal object at address addr.
             * This assumes no pointer redirections and no arrays
             *
             * If size of data is <= 8 bytes, uses JsonIntHex. The data is interpreted as a 64-bit unsigned int (0x67452301)
             * else, use JsonBinary (\x01\x23\x45\x67). The data is interpreted as a binary array.
             * 
             * @param data
             * @param addr
             * @param pDataInHost, the content of the data pointed by addr in host memory (set NULL if not used)
             * @param dataInHostSize
             * @param cpu
             * @param jsonObjList
             * @return 
             */
            IJsonObj * literal2json(IWinTypeData& data, uint64_t addr, 
                    const uint8_t* pDataInHost, int dataInHostSize, void * cpu,
                    std::vector<IJsonObj*> &jsonObjList) {

                LiteralMetaData& metadata = reinterpret_cast<LiteralMetaData&> (
                        data.getMetaData());
                int size = metadata.getSize();
                int actualLen;
                std::vector<uint8_t> vBuf(size);

                if (pDataInHost != NULL) {
                    bool res = data.getBytesFromHost(cpu, pDataInHost, &vBuf[0], size, actualLen);
                    if (!res) {
                        return NULL;
                    }
                } else {
                    bool res = data.getBytes(cpu, addr, &vBuf[0], size, actualLen);
                    if (!res) {
                        return NULL;
                    }
                }

                IJsonObj * pJson;
                if (actualLen <= 8) {
                    uint64_t sv = 0;
                    uint8_t *buf = reinterpret_cast<uint8_t*>(&sv);
                    
                    for (int i=0; i<actualLen; ++i) {
                        *(buf + i) = vBuf[i];
                    }
                    
//                    uint64_t smpl = *(reinterpret_cast<uint64_t*> (&vBuf[0]));
//                    smpl = smpl & (1LL << (actualLen*8));
                    pJson = new JsonIntHex(sv);
                    jsonObjList.push_back(pJson);

                } else {
                    pJson = new JsonBinary(&vBuf[0], actualLen);
                    jsonObjList.push_back(pJson);

                }

                return pJson;
            }

        };

        ISerializer<ObjData> *createWinType2JsonSerializer(IWinTypes& d) {
            return new WinTypeData2JsonSerializer(d);
        }
    }

//    template class ISerializer<Json::ObjData>;
}
