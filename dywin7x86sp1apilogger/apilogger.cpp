/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "panda/plugin.h"                                    
#include "panda/plugin_plugin.h"                             
#include "panda/common.h"                                    
#include "panda/rr/rr_log.h"                                 
#include "osi/osi_types.h"                                   
#include "osi/osi_ext.h"                                     

#include "IWinApis.h"
#include "IWinTypes.h"
#include "IEnv.h"
#include "WinTypeData2JsonSerializer.h"
#include "JsonSerializer.h"

#include "winhelper.h"
#include "apihelper.h"
#include "apilogger.h"
#include "dbgdefs.h"

#include <map>
#include <string>
#include <vector>
#include <cstdio> 

extern FILE * gDebugFile;

WinApiLib::IWinApis * gPtrWinApis;
WinApiLib::IWinTypes * gPtrWinTypes;
WinApiLib::ISerializer<WinApiLib::Json::ObjData> * gPtrJsonSerializer;

/**
 * PANDA implementation for environment object. Reads and writes are simply forwarded
 * to panda_virtual_memory_read/write functions.
 */
class QemuEnv : public WinApiLib::IEnv {
public:
    QemuEnv() {
        
    }
    
    ~QemuEnv() {
        
    }
    
    int readEnv(uint64_t addr, uint8_t * buf, int len, void * extra) {
        
        CPUState * env = (CPUState*) extra;
        if (-1 == panda_virtual_memory_read(env, (target_ulong)addr, buf, len)) {
            return WinApiLib::IEnv::E_ERR;
            
        } else {
            return WinApiLib::IEnv::S_OK;
            
        }
    }
    
    int writeEnv(uint64_t addr, uint8_t * buf, int len, void * extra) {
        
        CPUState * env = (CPUState*) extra;
        if (-1 == panda_virtual_memory_write(env, (target_ulong)addr, buf, len)) {
            return WinApiLib::IEnv::E_ERR;
            
        } else {
            return WinApiLib::IEnv::S_OK;
            
        }
        
    }
    
};

QemuEnv gEnv;

typedef struct _RETURN_POINT {                                                                                     
    // outer vector: list of parameters, param_data[i] = i-th param, and so on                                     
    // inner vector is the contents of the parameter specified in index i.                                         
    std::vector < std::vector < uint8_t> > param_data;
    WinApiLib::FUNC_DESC fnDesc;
} RETURN_POINT;
                                                                                                                   
typedef struct _PARAM_FUNC_RET {                                                                                   
    // maps ( return_address (VA) ==> RETURN_POINT )                                                               
    std::map < target_ulong, RETURN_POINT > retn_param_map;                                                        
} PARAM_FUNC_RET;                                                                                                  
typedef std::map < target_ulong, RETURN_POINT >::iterator retn_param_map_it;                                       
                                                                                                                   
// maps ( TID => PARAM_FUNC_RET )                                                                        
std::map < target_ulong, PARAM_FUNC_RET > api_func_param_map;                          
typedef std::map < target_ulong, PARAM_FUNC_RET >::iterator api_func_param_map_it;

typedef struct _PARAMDATA {
    std::string name;
    std::string json;
} PARAMDATA;

template < class T >
class Holder {
public:
    Holder() {
        
    }
    
    ~Holder() {
        int sz = mVec.size();
        for (int i=0; i<sz; ++i) {
            delete mVec[i];
        }
    }
    
    void add(T* obj) {
        this->mVec.push_back(obj);
    }
    
private:
    std::vector<T*> mVec;
    
};

bool apilogger_init(const char * typesCsvSource, const char * fnApiCsvSource) {
    
#ifdef _DEBUG
    printf(">> apilogger_init(types=%s, api=%s)\n", typesCsvSource, fnApiCsvSource);
#endif
    
    gPtrWinTypes = WinApiLib::createWinTypes(gEnv, typesCsvSource);
    if (!gPtrWinTypes) {
        return false;
    }
    
#ifdef _DEBUG
    printf(" - createWinApiParser\n");
#endif
    
    gPtrWinApis = WinApiLib::createWinApiParser(gEnv, fnApiCsvSource);
    if (!gPtrWinApis) {
        return false;
    }
    
#ifdef _DEBUG
    printf(" - createWinType2JsonSerializer\n");
#endif
    
    gPtrJsonSerializer = WinApiLib::Json::createWinType2JsonSerializer(*gPtrWinTypes);
    if (!gPtrJsonSerializer) {
        return false;
    }
    
#ifdef _DEBUG
    printf("<< apilogger_init(types=%s, api=%s)\n", typesCsvSource, fnApiCsvSource);
#endif
    
    return true;
}

/**
 * Converts to json format
 * 
 * @param cpu
 * @param pc
 * @param apiName
 * @param dllName
 * @param dllBaseVa
 * @param param
 * @param isReturn
 * @return 
 */
std::string convert2Json(CPUState * cpu, target_ulong pc, const char * apiName, 
        const char * dllName, target_ulong dllBaseVa, const std::vector<PARAMDATA>&param, bool isReturn) {
    
    WinApiLib::Json::JsonStruct obj;
    
    WinApiLib::Json::JsonString jsonApiName(apiName);
    obj.setValue("api_name", &jsonApiName);
    
    WinApiLib::Json::JsonString jsonDllName(dllName);
    obj.setValue("dll_name", &jsonDllName);
    
    WinApiLib::Json::JsonIntHex jsonDllBaseVa((uint64_t)dllBaseVa);
    obj.setValue("dll_base_va", &jsonDllBaseVa);
    
    const char * strTraceLocation = "entry";
    if (isReturn) {
        strTraceLocation = "exit";
    }
    WinApiLib::Json::JsonString jsonTraceLocation(strTraceLocation);
    obj.setValue("trace_location", &jsonTraceLocation);
    
    target_ulong asid = panda_current_asid(cpu);
    WinApiLib::Json::JsonIntHex jsonAsid((uint64_t)asid);
    obj.setValue("asid", &jsonAsid);
    
    WinApiLib::Json::JsonIntHex jsonPC((uint64_t)pc);
    obj.setValue("pc", &jsonPC);
    
    RR_prog_point pp = rr_prog_point();
    WinApiLib::Json::JsonInt jsonPP(pp.guest_instr_count);
    obj.setValue("instrcnt", &jsonPP);
    
    target_ulong tid = panda::win::get_tid(cpu);
    WinApiLib::Json::JsonInt jsonTid((uint64_t)tid);
    obj.setValue("thread_id", &jsonTid);
    
    target_ulong pid = panda::win::get_pid(cpu);
    WinApiLib::Json::JsonInt jsonPid((uint64_t)pid);
    obj.setValue("process_id", &jsonPid);

#if defined(TARGET_I386)    
    CPUArchState * cpuarch = reinterpret_cast<CPUArchState*>(cpu->env_ptr);
    target_ulong retval = cpuarch->regs[R_EAX];
    WinApiLib::Json::JsonIntHex jsonRet((uint64_t)retval);
    if (isReturn) {
        obj.setValue("return", &jsonRet);
    }
#endif
    
    WinApiLib::Json::JsonStruct jsonParamObj;
    
    Holder<WinApiLib::Json::IJsonObj> holder;
    int paramSize = param.size();
    for (int i=0; i<paramSize; ++i) {
        const PARAMDATA &pd = param[i];
        
        WinApiLib::Json::IJsonObj* tmp = new WinApiLib::Json::JsonLiteralObj(pd.json.c_str());
        holder.add(tmp);
        
        jsonParamObj.setValue(pd.name.c_str(), tmp);
    }
    
    obj.setValue("parameters", &jsonParamObj);
    
    return obj.toJson();
}

const char * apilogger_find_func(CPUState * cpu, const char * dllName, 
        target_ulong pc, target_ulong dllBaseAddr) {
    
    WinApiLib::FUNC_DESC fnDesc;
    bool fnExists = gPtrWinApis->findFunc(dllName, dllBaseAddr, pc, fnDesc);
    if (fnExists) {
        return fnDesc.fnName;
    }
    
    return NULL;
}

void clearFuncDesc(WinApiLib::FUNC_DESC& fnDesc) {
    fnDesc.dllName = NULL;
    fnDesc.fnCallConvention = NULL;
    fnDesc.fnName = NULL;
    fnDesc.fnOrd = 0;
    fnDesc.fnParam.clear();
    fnDesc.fnReturnType = NULL;
    fnDesc.fnRva = 0;
}

bool apilogger_log_call(CPUState * cpu, target_ulong pc, const char * dllName, 
        target_ulong dllBaseAddr, const char * funcName, std::string& out) {
    
#if defined(TARGET_I386)                                                            
    CPUArchState * arch = reinterpret_cast<CPUArchState*> (cpu->env_ptr);           
    RR_prog_point pp = rr_prog_point();                                             
//    target_ulong asid = panda_current_asid(cpu);                                    
    target_ulong fs_tid = panda::win::get_tid(cpu);                                             
    target_ulong esp = arch->regs[R_ESP];                                           
    target_ulong ret_addr;                                                          
    panda_virtual_memory_read(cpu, esp, (uint8_t*) (&ret_addr), sizeof (ret_addr)); 
            
    /*const char * dllName, uint64_t baseDllVa, 
                uint64_t currentVa, FUNC_DESC &fnDesc*/
    // same fnDesc must be transported to return call!
    WinApiLib::FUNC_DESC fnDesc;
    bool findFnRes = gPtrWinApis->findFunc(dllName, dllBaseAddr, pc, fnDesc);
    if (!findFnRes) {
#ifdef _DEBUG
        fprintf(gDebugFile, " - [ERROR] pp: %lu PC: 0x%08lx, Unable to find func %s in dll %s at base addr 0x%08lx\n",
                pp.guest_instr_count, (uint64_t)pc, funcName, dllName, (uint64_t)dllBaseAddr);
#endif
        out = "";
        return false;
    }               
                                                                                    
    PARAM_FUNC_RET &fr = api_func_param_map[fs_tid];          
    RETURN_POINT &rp = fr.retn_param_map[ret_addr];                                 
    rp.param_data.clear();      
    clearFuncDesc(rp.fnDesc);
    
    
    // loop the parameters here
    
    /* sample API func:
     * extern HOOKDEF(int32_t, WINAPI, MessageBoxExW,
    __in_opt HWND hWnd,
    __in_opt PWSTR lpText,
    __in_opt PWSTR lpCaption,
    __in UINT uType,
    __in DWORD wLanguageId
);
     */
    
    
    int inc, start, end;
    target_ulong offset = 0;  
    
    std::string strCallConv(fnDesc.fnCallConvention);
    if (strCallConv == "PASCAL") {
        // args are pushed to stack L to R
        // This is commonly seen in Delphi / pascal compiled.
        // Windows API don't use this, supposedly.
        inc = -1;
        start = fnDesc.fnParam.size()-1;
        end = -1;
        
    } else {
        // args are pushed to stack R to L.
        // This is common Windows API arg passing mode which is __stdcall
        inc = 1;
        start = 0;
        end = fnDesc.fnParam.size();
        
    }
    
    std::vector<PARAMDATA> vParamData;
    
    for (int i=start; i != end; i += inc) {
        
        WinApiLib::FUNC_PARAM_DESC &desc = fnDesc.fnParam[i];
        WinApiLib::IWinTypeData* typeData = gPtrWinTypes->findData(desc.type);
        if (typeData == NULL) {
#ifdef _DEBUG
            fprintf(gDebugFile, " - [WARN] unable to find type %s\n", desc.type);
#endif
            return false;
        }
        
        target_ulong paramStackAddr = get_func_param_addr(cpu, offset);
        if (paramStackAddr == 0) {
#ifdef _DEBUG
            fprintf(gDebugFile, " - [WARN] unable to get address of parameter %s\n", desc.name);
#endif
            return false;
        }
        
        /*bool getBytes(void * cpu, uint64_t addr, uint8_t outBuf[], 
                int outBufLen, int &actualLen, int nBytesRead = 0)
         */
        int actualLen;
        // if outBuf NULL, actualLen is filled with the data length
        typeData->getBytes(cpu, (uint64_t)paramStackAddr, NULL, 0, actualLen);
        
        std::vector < uint8_t > data(actualLen+10); // sentinel buffer
        bool readReqRes;
        readReqRes = typeData->getBytes(cpu, (uint64_t)paramStackAddr, (uint8_t*)(&data[0]), 
                data.size(), actualLen);
        
        if (!readReqRes) {
#ifdef _DEBUG
            fprintf(gDebugFile, " - [ERROR] unable to read address 0x%08lx\n", (uint64_t)paramStackAddr);
#endif
            return false;
        }
        
        WinApiLib::Json::ObjData objData;
        objData.addr = paramStackAddr;
        objData.typeData = typeData;
        objData.varName = desc.name;
        objData.varType = desc.type;
        std::string jsonRep = gPtrJsonSerializer->serialize(objData, cpu);
        
        PARAMDATA tmp;
        tmp.name = desc.name;
        tmp.json = jsonRep;
        vParamData.push_back(tmp);
        
        rp.param_data.push_back(data);
        
        int ptrSize = sizeof(target_ulong);
        
        // offset += ceil(actualLen/ptrSize)*ptrSize;
        offset += ((actualLen / ptrSize) + (actualLen % ptrSize > 0))*ptrSize;
        
    }
    
    rp.fnDesc = fnDesc;
     
    std::string jsonStr = convert2Json(cpu, pc, funcName, dllName, dllBaseAddr, 
            vParamData, false);
    out = jsonStr;
    
    return true;
    
    //on_cb_xMessageBoxExW193_enter (cpu, pc, hWnd, lpText, lpCaption, uType, wLanguageId);
    
#endif
    
    return false;
}

/*
 #if defined(TARGET_I386)                                                     
//  CPUArchState * arch = reinterpret_cast<CPUArchState*> (cpu->env_ptr);    
//    RR_prog_point pp = rr_prog_point();                                      
//    target_ulong asid = panda_current_asid(cpu);                             
//    target_ulong fs_tid = get_tid(cpu);                                      
//    target_ulong retval = arch->regs[R_EAX];                                 
                                                                             
//    fprintf(outFile, "<<\t%lu\t0x%lx\t%ld\t0x%lx\t%s!%s\t0x%lx\n",
//            (uint64_t) pp.guest_instr_count,                                 
//            (uint64_t) asid, (uint64_t) fs_tid, (uint64_t) pc,               
//            "", "xNtCreateFile0", (uint64_t) retval);              
                                                                             

#endif
 */
bool apilogger_log_return(CPUState * cpu, target_ulong pc, const char * dllName, 
        target_ulong dllBaseAddr, const char * funcName, std::string& out) {
    
#if defined(TARGET_I386)
    
    //RR_prog_point pp = rr_prog_point();
    
    target_ulong fs_tid = panda::win::get_tid(cpu);                                      
    PARAM_FUNC_RET &fr = api_func_param_map[fs_tid];   
    RETURN_POINT &rp = fr.retn_param_map[pc];      
    
    // this is error, of f*cking course. The pc is the return address in main module
    // not the starting address of function. Of course findFunc will ALWAYS fail!
//    WinApiLib::FUNC_DESC fnDesc;
//    bool findFnRes = gPtrWinApis->findFunc(dllName, dllBaseAddr, pc, fnDesc);
//    if (!findFnRes) {
//#ifdef _DEBUG
//        fprintf(gDebugFile, " - [ERROR] pp: %lu PC: 0x%08lx, Unable to find func %s in dll %s at base addr 0x%08lx\n",
//                pp.guest_instr_count, (uint64_t)pc, funcName, dllName, (uint64_t)dllBaseAddr);
//#endif
//        out = "";
//        return false;
//    }
    
    WinApiLib::FUNC_DESC &fnDesc = rp.fnDesc;
    
    int inc, start, end;
    //target_ulong offset = 0;  
    
    std::string strCallConv(fnDesc.fnCallConvention);
    if (strCallConv == "PASCAL") {
        // args are pushed to stack L to R
        // This is commonly seen in Delphi / pascal compiled.
        // Windows API don't use this, supposedly.
        inc = -1;
        start = fnDesc.fnParam.size()-1;
        end = -1;
        
    } else {
        // args are pushed to stack R to L.
        // This is common Windows API arg passing mode which is __stdcall
        inc = 1;
        start = 0;
        end = fnDesc.fnParam.size();
        
    }
    
    std::vector<PARAMDATA> vParamData;
    
    for (int i=start; i != end; i += inc) {
        
        WinApiLib::FUNC_PARAM_DESC &desc = fnDesc.fnParam[i];
        WinApiLib::IWinTypeData* typeData = gPtrWinTypes->findData(desc.type);
        if (typeData == NULL) {
#ifdef _DEBUG
            fprintf(gDebugFile, " - [WARN] unable to find type %s\n", desc.type);
#endif
            return false;
        }
        
        std::vector < uint8_t > &data = rp.param_data[i];
        
        WinApiLib::Json::ObjData objData;
        objData.typeData = typeData;
        objData.varName = desc.name;
        objData.varType = desc.type;
        objData.pDataInHost = &data[0];
        objData.dataInHostSize = data.size();
        
        std::string jsonForm = gPtrJsonSerializer->serialize(objData, cpu);
        PARAMDATA paramData;
        paramData.name = desc.name;
        paramData.json = jsonForm;
        vParamData.push_back(paramData);
        
    }
    
    std::string jsonStr = convert2Json(cpu, pc, funcName, dllName, dllBaseAddr, 
            vParamData, true);
    out = jsonStr;
    
    return true;
    
    //on_cb_xNtCreateFile0_return (cpu, pc, FileHandle, DesiredAccess, ObjectAttributes, 
    //IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, 
    //CreateOptions, EaBuffer, EaLength);
    
#endif
    
    return false;
    
}

void apilogger_close() {
    
    WinApiLib::releaseSerializer(gPtrJsonSerializer);
    WinApiLib::releaseWinApiParser(gPtrWinApis);
    WinApiLib::releaseWinTypes(gPtrWinTypes);
    
}

