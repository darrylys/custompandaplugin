/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "IWinApis.h"

#include "CsvReader.h"
#include "IEnv.h"
#include "utils.h"

#include <string>
#include <fstream>
#include <vector>
#include <map>
#include <iostream>

#include <cstdlib>
#include <locale>
#include <algorithm>

namespace WinApiLib {
    
    /**
     * Representation of function parameter.
     */
    typedef struct _WINPE_EXPORT_FN_PAR {
        
        std::string name;               // name of variable. No reference(&), pointer(*), or array ([]) are allowed. Array is not yet implemented.
        std::string type;               // May contain (*) to represent pointers. References are usually implemented as pointers behind the scenes.
        FUNC_PARAM_DIRECTION usage;     // IN/OUT/INOUT
        
    } WINPE_EXPORT_FN_PAR, *PWINPE_EXPORT_FN_PAR;
    
    /**
     * Representation of an export entry in dll
     */
    typedef struct _WINPE_EXPORT_FN {
        
        std::string fnName;                         // Exported API name
        uint32_t fnRva;                             // Exported API RVA
        uint16_t fnOrd;                             // Exported API Ordinal
        std::string fnReturnType;                   
        std::string fnCallConvention;               // Call convention. Only STDCALL and PASCAL are supported. Windows API uses STDCALL (WINAPI)
        std::vector<WINPE_EXPORT_FN_PAR> fnParam;   // Parameters of the API. Empty if no parameters.
        
    } WINPE_EXPORT_FN, *PWINPE_EXPORT_FN;
    
    // representation of PE image in memory
    class WinPE {
    public:
        WinPE() 
        : mImgName("")
//        , mBaseAddr(0)
        {
            
        }
        
        WinPE(const char * imgName) 
        : mImgName(imgName)
//        , mBaseAddr(baseAddr)
        {
            
        }
        
        ~WinPE() {
            
        }
        
        // to make this completely conversation-stateless, so, the objects can be shared
        // no base address should be kept here. It should be supplied for every call.
//        uint64_t getBaseAddr() const {
//            return this->mBaseAddr;
//        }
//        
//        void setBaseAddr(uint64_t addr) {
//            this->mBaseAddr = addr;
//        }
        
        const char * getImgName() const {
            return this->mImgName.c_str();
        }
        
        void setImgName(const char * str) {
            this->mImgName = str;
        }
        
        void addExportFn(const WINPE_EXPORT_FN &exportFn) {
            int idx = this->mExportFnList.size();
            this->mExportFnList.push_back(exportFn);
            this->mExportFnIdxByFnName[exportFn.fnName] = idx;
            this->mExportFnIdxByFnRva[exportFn.fnRva] = idx;
        }
        
        void clearExportFn() {
            this->mExportFnIdxByFnName.clear();
            this->mExportFnList.clear();
            this->mExportFnIdxByFnRva.clear();
        }
        
        const WINPE_EXPORT_FN* findFn(const char * fnName) {
            std::string strFnName(fnName);
            ExportFnIdxByFnNameIt it = this->mExportFnIdxByFnName.find(strFnName);
            if (it != this->mExportFnIdxByFnName.end()) {
                return &(this->mExportFnList[it->second]);
            } else {
                return NULL;
            }
        }
        
        const WINPE_EXPORT_FN* findFn(uint64_t baseAddr, uint64_t addrVa) {
            if (addrVa <= baseAddr) {
                return NULL;
            }
            
            uint32_t rva = (uint32_t)(addrVa - baseAddr);
            ExportFnIdxByFnRvaIt it = this->mExportFnIdxByFnRva.find(rva);
            if (it != this->mExportFnIdxByFnRva.end()) {
                return &(this->mExportFnList[it->second]);
            } else {
                return NULL;
            }
        }
        
    private:
        // name of dll
        std::string mImgName;
//        uint64_t mBaseAddr;
        std::vector<WINPE_EXPORT_FN> mExportFnList;
        std::map<std::string, int> mExportFnIdxByFnName;
        std::map<uint32_t, int> mExportFnIdxByFnRva;
        
        typedef std::map<std::string, int>::const_iterator ExportFnIdxByFnNameIt;
        typedef std::map<uint32_t, int>::const_iterator ExportFnIdxByFnRvaIt;
        
    };
    
    class WinApisLibImpl : public IWinApis {
    public:
        WinApisLibImpl(IEnv &env, const char * fileName) 
        : mEnv(env), mFileName(fileName), isInitialized(false)
        {
            
        }
        
        ~WinApisLibImpl() {
            
        }
        
        bool init() {
            if (!isInitialized) {
                isInitialized = this->_loadFnDb();
            }
            return isInitialized;
        }
        
        /**
         * Checks whether Virtual Address given in currentVa is the Virtual Address of a registered API call.
         * Does not support Dlls exporting two or more API with same name (if any)
         * Name is searched as is, if API name is mangled, it must be registered in csv file as is.
         * 
         * @param pzDllName, name of dll to search
         * @param baseDllVa, Virtual Address of the base address of dll
         * @param currentVa, contents of EIP
         * @param fnDesc, output object.
         * @return true if function is found, false otherwise
         */
        bool findFunc(const char * pzDllName, uint64_t baseDllVa, 
                uint64_t currentVa, FUNC_DESC &fnDesc) {
            
//            const ImageAddrMapIt it = this->mImageAddrMap.find(baseDllVa);
//            if (it == this->mImageAddrMap.end()) {
//                return false;
//            }
//            const std::string& dllName = it->second;
            
            const std::string dllNameRw(pzDllName);
            std::string dllNameLc = dllNameRw;
            std::transform(dllNameLc.begin(), dllNameLc.end(), dllNameLc.begin(), ::tolower);
            
            // Dll name is not found in registration, therefore API is not found
            const WinPEMapIt peit = this->mWinPEMap.find(dllNameLc);
            if (peit == this->mWinPEMap.end()) {
                return false;
            }
            
            WinPE& winpe = peit->second;
            
            // find the function in registered PE file.
            const WINPE_EXPORT_FN * fnExp = winpe.findFn(baseDllVa, currentVa);
            if (fnExp == NULL) {
                return false;
            }
            
            // Since this WinApisLibImpl is kept in memory at all times, 
            // fnDesc may contain only pointers to strings,
            // instead of copied string from this object
            fnDesc.dllName = winpe.getImgName();
            fnDesc.fnCallConvention = fnExp->fnCallConvention.c_str();
            fnDesc.fnName = fnExp->fnName.c_str();
            fnDesc.fnOrd = fnExp->fnOrd;
            fnDesc.fnReturnType = fnExp->fnReturnType.c_str();
            fnDesc.fnRva = fnExp->fnRva;
            
            int fnParSz = fnExp->fnParam.size();
            for (int i=0; i<fnParSz; ++i) {
                FUNC_PARAM_DESC fnParDesc;
                
                const WINPE_EXPORT_FN_PAR& fnExpPar = fnExp->fnParam[i];
                fnParDesc.name = fnExpPar.name.c_str();
                fnParDesc.type = fnExpPar.type.c_str();
                fnParDesc.usage = fnExpPar.usage;
                
                fnDesc.fnParam.push_back(fnParDesc);
            }
            
            return true;
        }
        
//        bool setImageBaseAddr(uint64_t baseDllVa, const char * imageName) {
//            std::string key(imageName);
//            WinPEMapIt it = this->mWinPEMap.find(key);
//            if (it != this->mWinPEMap.end()) {
//                WinPE &pe = it->second;
//                pe.setBaseAddr(baseDllVa);
//                this->mImageAddrMap[baseDllVa] = imageName;
//                
//                return true;
//            }
//            return false;
//        }
        
    private:
        IEnv &mEnv;
        std::string mFileName;
//        std::map<uint64_t, std::string> mImageAddrMap;
        std::map<std::string, WinPE> mWinPEMap;
        
//        typedef std::map<uint64_t, std::string>::iterator ImageAddrMapIt;
        typedef std::map<std::string, WinPE>::iterator WinPEMapIt;
        
        bool isInitialized;
        
        /** 
         * load apifndb.csv here
         * Format each line: <dllName>,<rva(hex)>,<ord(dec)>,<return type>,<call convention>,<API name>[,<in|out|inout>,<param type[\*]*>,<param name>]*
         * Sample input: ADVAPI32.dll,0x114b3,1638,LONG,WINAPI,RegSetValueExA,in,HKEY,hKey,in,STR*,lpValueName,in,DWORD,Reserved,in,DWORD,dwType,in,BYTE*,lpData,in,DWORD,cbData
         * 
         * @return true if success, false otherwise
         */
        bool _loadFnDb() {
            
            std::ifstream dtf(this->mFileName.c_str());
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
                    int cellLen = cells.size(); // number of tokens
                    
                    int i = 0;
                    const std::string& dllNameRw = cells[i++];
                    
                    // dllName is case insensitive in windows.
                    // convert dllName to lowercase
                    std::string dllNameLc = dllNameRw;
                    std::transform(dllNameLc.begin(), dllNameLc.end(), dllNameLc.begin(), ::tolower);
                    
                    // forcing initialization of WinPE object of dllNameLc in mWinPEMap
                    WinPE& winPe = this->mWinPEMap[dllNameLc];
                    
                    winPe.setImgName(dllNameLc.c_str());
                    
                    const std::string& xiFnRva = cells[i++]; // maybe hex, maybe int
                    uint32_t fnRva = utils::str2uint(xiFnRva.c_str());
                    
                    const std::string& xiFnOrd = cells[i++]; // maybe hex, maybe int
                    uint32_t fnOrd = utils::str2uint(xiFnOrd.c_str());
                    
                    const std::string& fnRetType = cells[i++];
                    const std::string& fnCallConv = cells[i++];
                    const std::string& fnName = cells[i++];
                    
                    WINPE_EXPORT_FN fn;
                    fn.fnCallConvention = fnCallConv;
                    fn.fnName = fnName;
                    fn.fnOrd = (uint16_t) (fnOrd & 0xFFFF);
                    fn.fnRva = fnRva;
                    fn.fnReturnType = fnRetType;
                    
                    for (; i<cellLen; i+=3) {
                        const std::string& parMode = cells[i];
                        const std::string& parType = cells[i+1];
                        const std::string& parName = cells[i+2];
                        
                        WINPE_EXPORT_FN_PAR fnPar;
                        fnPar.name = parName;
                        fnPar.type = parType;
                        
                        if (parMode == "in") {
                            fnPar.usage = IN;
                        } else if (parMode == "out") {
                            fnPar.usage = OUT;
                        } else {
                            fnPar.usage = INOUT;
                        }
                        
                        fn.fnParam.push_back(fnPar);
                    }
                    
                    winPe.addExportFn(fn);
                }
            } else {
                return false;
            }
            return true;
            
        }
    };
    
    /**
     * creates WinApiParser
     * @param env, the implementation of IEnv interface
     * @param fileName, the file name of function csv, db-fn.csv
     */
    IWinApis * createWinApiParser(IEnv &env, const char * fileName) {
        WinApisLibImpl * ptr = new WinApisLibImpl(env, fileName);
        bool isInit = ptr->init();
        if (isInit) {
            return ptr;
        } else {
            releaseWinApiParser(ptr);
            return NULL;
        }
    }
    
    void releaseWinApiParser(IWinApis * obj) {
        delete obj;
    }
    
}
