#include "Windows_7_x86_prototypes_fixed_for_panda.txt.trc.h.dump.h"
#include "string"

bool replace(std::string& str, const std::string& from, const std::string& to) {
    size_t start_pos = str.find(from);
    if(start_pos == std::string::npos)
        return false;
    str.replace(start_pos, from.length(), to);
    return true;
}

void replaceAll(std::string& str, const std::string& from, const std::string& to) {
    if(from.empty())
        return;
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
}


#define MAX_FILENAME 512
uint32_t guest_wstrncpy(CPUState *cpu, uint16_t *buf, size_t maxlen, target_ulong guest_addr) {
    buf[0] = 0;
    unsigned i = 0;
    for (i=0; i<maxlen; i++) {
        panda_virtual_memory_rw(cpu, guest_addr + 2 * i, (uint8_t *)&buf[i], sizeof(buf[0]), 0);
        if (buf[i] == 0) {
            break;
        }
    }
    buf[maxlen - 1] = 0;
    return i;
}

void dump_PWSTR(CPUState *cpu, uint32_t param) {
    uint16_t chBuf[MAX_FILENAME];
    memset(chBuf, 0, sizeof(chBuf));
    uint32_t d = guest_wstrncpy(cpu, chBuf, MAX_FILENAME, param);
    std::string strBuf;
    char tmp[10];
    for (int i=0; i < d; ++i) {
        sprintf(tmp, "\\u%04x", chBuf[i]);
        strBuf += tmp;
    }
    //std::string strBuf(chBuf);
    //replaceAll(strBuf, "\\", "\\\\");
    //replaceAll(strBuf, "\"", "\\\"");
    //replaceAll(strBuf, "\'", "\\\'");
    fprintf(outFile, "\"%s\"", strBuf.c_str());
}

void dump_uint32_t(CPUState *cpu, uint32_t param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}
void dump_int32_t(CPUState *cpu, int32_t param) {
    fprintf(outFile, "\"%ld\"", (long) param);
}
void dump_uint64_t(CPUState *cpu, uint64_t param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}
void dump_int64_t(CPUState *cpu, int64_t param) {
    fprintf(outFile, "\"%ld\"", (long) param);
}
void dump_uint16_t(CPUState *cpu, uint16_t param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}
void dump_int16_t(CPUState *cpu, int16_t param) {
    fprintf(outFile, "\"%ld\"", (long) param);
}
void dump_uint8_t(CPUState *cpu, uint8_t param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}
void dump_int8_t(CPUState *cpu, int8_t param) {
    fprintf(outFile, "\"%ld\"", (long) param);
}
void dump_NTSTATUS(CPUState *cpu, NTSTATUS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PVOID(CPUState *cpu, PVOID param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_HANDLE(CPUState *cpu, HANDLE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PHANDLE(CPUState *cpu, uint32_t param) {
HANDLE tmpv;
uint32_t pr = panda_virtual_memory_rw(cpu, param, (uint8_t *)(&tmpv), sizeof(tmpv), 0);
if (pr == -1) {
    fprintf(outFile, "\"*ERR*: Cannot read param\"");
    return;
}
	dump_HANDLE(cpu, tmpv);
}

void dump_BYTE(CPUState *cpu, BYTE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_UNICODE_STRING(CPUState *cpu, UNICODE_STRING &param) {
    fprintf(outFile, "{\n");
    fprintf(outFile, "\"Length\" : ");dump_uint16_t(cpu, param.Length);fprintf(outFile, ",\n");
    fprintf(outFile, "\"MaximumLength\" : ");dump_uint16_t(cpu, param.MaximumLength);fprintf(outFile, ",\n");
    fprintf(outFile, "\"Buffer\" : ");dump_PWSTR(cpu, param.Buffer);fprintf(outFile, "\n");
	fprintf(outFile, "}\n");
}

void dump_PUNICODE_STRING(CPUState *cpu, uint32_t param) {
    if (param == 0) { fprintf(outFile, "\"NULL\""); return; }
    UNICODE_STRING tmpv;
    uint32_t pr = panda_virtual_memory_rw(cpu, param, (uint8_t *)(&tmpv), sizeof(tmpv), 0);
    if (pr == -1) {
        fprintf(outFile, "\"*ERR*: Cannot read param\"");
        return;
    }
    dump_UNICODE_STRING(cpu, tmpv);
}

void dump_OBJECT_ATTRIBUTES(CPUState *cpu, OBJECT_ATTRIBUTES &param) {
    fprintf(outFile, "{\n");
    fprintf(outFile, "\"Length\" : ");dump_uint32_t(cpu, param.Length);fprintf(outFile, ",\n");
    fprintf(outFile, "\"RootDirectory\" : ");dump_HANDLE(cpu, param.RootDirectory);fprintf(outFile, ",\n");
    fprintf(outFile, "\"ObjectName\" : ");dump_PUNICODE_STRING(cpu, param.ObjectName);fprintf(outFile, ",\n");
    fprintf(outFile, "\"Attributes\" : ");dump_uint32_t(cpu, param.Attributes);fprintf(outFile, ",\n");
    fprintf(outFile, "\"SecurityDescriptor\" : ");dump_PVOID(cpu, param.SecurityDescriptor);fprintf(outFile, ",\n");
    fprintf(outFile, "\"SecurityQualityOfService\" : ");dump_PVOID(cpu, param.SecurityQualityOfService);fprintf(outFile, "\n");
	fprintf(outFile, "}\n");
}

void dump_POBJECT_ATTRIBUTES(CPUState *cpu, uint32_t param) {
    if (param == 0) { fprintf(outFile, "\"NULL\""); return; }
    OBJECT_ATTRIBUTES tmpv;
    uint32_t pr = panda_virtual_memory_rw(cpu, param, (uint8_t *)(&tmpv), sizeof(tmpv), 0);
    if (pr == -1) {
        fprintf(outFile, "\"*ERR*: Cannot read param\"");
        return;
    }
    dump_OBJECT_ATTRIBUTES(cpu, tmpv);
}

void dump_ALPC_MESSAGE_INFORMATION_CLASS(CPUState *cpu, ALPC_MESSAGE_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PLUID(CPUState *cpu, PLUID param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PTOKEN_SOURCE(CPUState *cpu, PTOKEN_SOURCE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_LONG(CPUState *cpu, LONG param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PLONG(CPUState *cpu, uint32_t param) {
LONG tmpv;
uint32_t pr = panda_virtual_memory_rw(cpu, param, (uint8_t *)(&tmpv), sizeof(tmpv), 0);
if (pr == -1) {
    fprintf(outFile, "\"*ERR*: Cannot read param\"");
    return;
}
	dump_LONG(cpu, tmpv);
}

void dump_TRANSACTIONMANAGER_INFORMATION_CLASS(CPUState *cpu, TRANSACTIONMANAGER_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_ACCESS_MASK(CPUState *cpu, ACCESS_MASK param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_RTL_ATOM(CPUState *cpu, RTL_ATOM param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PBOOT_ENTRY(CPUState *cpu, PBOOT_ENTRY param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_KAFFINITY(CPUState *cpu, KAFFINITY param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PSECURITY_DESCRIPTOR(CPUState *cpu, PSECURITY_DESCRIPTOR param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_SEMAPHORE_INFORMATION_CLASS(CPUState *cpu, SEMAPHORE_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_BOOLEAN(CPUState *cpu, BOOLEAN param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_ALPC_HANDLE(CPUState *cpu, ALPC_HANDLE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_LCID(CPUState *cpu, LCID param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PALPC_MESSAGE_ATTRIBUTES(CPUState *cpu, PALPC_MESSAGE_ATTRIBUTES param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_TRANSACTION_INFORMATION_CLASS(CPUState *cpu, TRANSACTION_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PKEY_VALUE_ENTRY(CPUState *cpu, PKEY_VALUE_ENTRY param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_POWER_ACTION(CPUState *cpu, POWER_ACTION param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PIO_STATUS_BLOCK(CPUState *cpu, PIO_STATUS_BLOCK param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PFILE_IO_COMPLETION_INFORMATION(CPUState *cpu, PFILE_IO_COMPLETION_INFORMATION param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_JOBOBJECTINFOCLASS(CPUState *cpu, JOBOBJECTINFOCLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PFILE_SEGMENT_ELEMENT(CPUState *cpu, PFILE_SEGMENT_ELEMENT param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_IO_SESSION_STATE(CPUState *cpu, IO_SESSION_STATE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_LARGE_INTEGER(CPUState *cpu, LARGE_INTEGER &param) {
    fprintf(outFile, "{\n");
    fprintf(outFile, "\"QuadPart\" : ");dump_int64_t(cpu, param.QuadPart);fprintf(outFile, "\n");
	fprintf(outFile, "}\n");
}

void dump_PLARGE_INTEGER(CPUState *cpu, uint32_t param) {
    if (param == 0) { fprintf(outFile, "\"NULL\""); return; }
    LARGE_INTEGER tmpv;
    uint32_t pr = panda_virtual_memory_rw(cpu, param, (uint8_t *)(&tmpv), sizeof(tmpv), 0);
    if (pr == -1) {
        fprintf(outFile, "\"*ERR*: Cannot read param\"");
        return;
    }
    dump_LARGE_INTEGER(cpu, tmpv);
}

void dump_PCRM_PROTOCOL_ID(CPUState *cpu, PCRM_PROTOCOL_ID param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_MEMORY_INFORMATION_CLASS(CPUState *cpu, MEMORY_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_TOKEN_TYPE(CPUState *cpu, TOKEN_TYPE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_WORKERFACTORYINFOCLASS(CPUState *cpu, WORKERFACTORYINFOCLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PCHAR(CPUState *cpu, PCHAR param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PBOOT_OPTIONS(CPUState *cpu, PBOOT_OPTIONS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_SYSDBG_COMMAND(CPUState *cpu, SYSDBG_COMMAND param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_RTL_USER_PROCESS_PARAMETERS(CPUState *cpu, RTL_USER_PROCESS_PARAMETERS &param) {
    fprintf(outFile, "{\n");
    fprintf(outFile, "\"ImagePathName\" : ");dump_UNICODE_STRING(cpu, param.ImagePathName);fprintf(outFile, ",\n");
    fprintf(outFile, "\"CommandLine\" : ");dump_UNICODE_STRING(cpu, param.CommandLine);fprintf(outFile, "\n");
	fprintf(outFile, "}\n");
}

void dump_PRTL_USER_PROCESS_PARAMETERS(CPUState *cpu, uint32_t param) {
    if (param == 0) { fprintf(outFile, "\"NULL\""); return; }
    RTL_USER_PROCESS_PARAMETERS tmpv;
    uint32_t pr = panda_virtual_memory_rw(cpu, param, (uint8_t *)(&tmpv), sizeof(tmpv), 0);
    if (pr == -1) {
        fprintf(outFile, "\"*ERR*: Cannot read param\"");
        return;
    }
    dump_RTL_USER_PROCESS_PARAMETERS(cpu, tmpv);
}

void dump_SECTION_INFORMATION_CLASS(CPUState *cpu, SECTION_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_FS_INFORMATION_CLASS(CPUState *cpu, FS_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_TIMER_INFORMATION_CLASS(CPUState *cpu, TIMER_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PSECURITY_QUALITY_OF_SERVICE(CPUState *cpu, PSECURITY_QUALITY_OF_SERVICE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PTIMER_APC_ROUTINE(CPUState *cpu, PTIMER_APC_ROUTINE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_ULONG_PTR(CPUState *cpu, ULONG_PTR param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PDBGUI_WAIT_STATE_CHANGE(CPUState *cpu, PDBGUI_WAIT_STATE_CHANGE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_WIN32_PROTECTION_MASK(CPUState *cpu, WIN32_PROTECTION_MASK param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_APPHELPCOMMAND(CPUState *cpu, APPHELPCOMMAND param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PTOKEN_OWNER(CPUState *cpu, PTOKEN_OWNER param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_LANGID(CPUState *cpu, LANGID param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PROCESSINFOCLASS(CPUState *cpu, PROCESSINFOCLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_POBJECT_TYPE_LIST(CPUState *cpu, POBJECT_TYPE_LIST param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_SECURITY_INFORMATION(CPUState *cpu, SECURITY_INFORMATION param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_NOTIFICATION_MASK(CPUState *cpu, NOTIFICATION_MASK param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_ATOM_INFORMATION_CLASS(CPUState *cpu, ATOM_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PTRANSACTION_NOTIFICATION(CPUState *cpu, PTRANSACTION_NOTIFICATION param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_FILE_INFORMATION_CLASS(CPUState *cpu, FILE_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PFILE_NETWORK_OPEN_INFORMATION(CPUState *cpu, PFILE_NETWORK_OPEN_INFORMATION param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PSID(CPUState *cpu, PSID param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PCLIENT_ID(CPUState *cpu, PCLIENT_ID param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_KPROFILE_SOURCE(CPUState *cpu, KPROFILE_SOURCE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PALPC_PORT_ATTRIBUTES(CPUState *cpu, PALPC_PORT_ATTRIBUTES param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PTOKEN_PRIVILEGES(CPUState *cpu, PTOKEN_PRIVILEGES param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_IO_COMPLETION_INFORMATION_CLASS(CPUState *cpu, IO_COMPLETION_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_RESOURCEMANAGER_INFORMATION_CLASS(CPUState *cpu, RESOURCEMANAGER_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PEXECUTION_STATE(CPUState *cpu, PEXECUTION_STATE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_LPGUID(CPUState *cpu, LPGUID param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_KEY_SET_INFORMATION_CLASS(CPUState *cpu, KEY_SET_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PBOOLEAN(CPUState *cpu, PBOOLEAN param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_DEVICE_POWER_STATE(CPUState *cpu, DEVICE_POWER_STATE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PEXCEPTION_RECORD(CPUState *cpu, PEXCEPTION_RECORD param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PPROCESS_CREATE_INFO(CPUState *cpu, PPROCESS_CREATE_INFO param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PRTL_ATOM(CPUState *cpu, PRTL_ATOM param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PORT_INFORMATION_CLASS(CPUState *cpu, PORT_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_TIMER_TYPE(CPUState *cpu, TIMER_TYPE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PTOKEN_USER(CPUState *cpu, PTOKEN_USER param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PGENERIC_MAPPING(CPUState *cpu, PGENERIC_MAPPING param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_THREADINFOCLASS(CPUState *cpu, THREADINFOCLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_SECTION_INHERIT(CPUState *cpu, SECTION_INHERIT param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_SYSTEM_INFORMATION_CLASS(CPUState *cpu, SYSTEM_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_MEMORY_RESERVE_TYPE(CPUState *cpu, MEMORY_RESERVE_TYPE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_TIMER_SET_INFORMATION_CLASS(CPUState *cpu, TIMER_SET_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_KEY_VALUE_INFORMATION_CLASS(CPUState *cpu, KEY_VALUE_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_ALPC_PORT_INFORMATION_CLASS(CPUState *cpu, ALPC_PORT_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PPORT_MESSAGE(CPUState *cpu, PPORT_MESSAGE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PCONTEXT(CPUState *cpu, PCONTEXT param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PKTMOBJECT_CURSOR(CPUState *cpu, PKTMOBJECT_CURSOR param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_ULARGE_INTEGER(CPUState *cpu, ULARGE_INTEGER &param) {
    fprintf(outFile, "{\n");
    fprintf(outFile, "\"QuadPart\" : ");dump_uint64_t(cpu, param.QuadPart);fprintf(outFile, "\n");
	fprintf(outFile, "}\n");
}

void dump_PULARGE_INTEGER(CPUState *cpu, uint32_t param) {
    if (param == 0) { fprintf(outFile, "\"NULL\""); return; }
    ULARGE_INTEGER tmpv;
    uint32_t pr = panda_virtual_memory_rw(cpu, param, (uint8_t *)(&tmpv), sizeof(tmpv), 0);
    if (pr == -1) {
        fprintf(outFile, "\"*ERR*: Cannot read param\"");
        return;
    }
    dump_ULARGE_INTEGER(cpu, tmpv);
}

void dump_KEY_INFORMATION_CLASS(CPUState *cpu, KEY_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PPLUGPLAY_EVENT_BLOCK(CPUState *cpu, PPLUGPLAY_EVENT_BLOCK param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_ENLISTMENT_INFORMATION_CLASS(CPUState *cpu, ENLISTMENT_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PLUGPLAY_CONTROL_CLASS(CPUState *cpu, PLUGPLAY_CONTROL_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_ULONG(CPUState *cpu, ULONG param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PULONG(CPUState *cpu, uint32_t param) {
ULONG tmpv;
uint32_t pr = panda_virtual_memory_rw(cpu, param, (uint8_t *)(&tmpv), sizeof(tmpv), 0);
if (pr == -1) {
    fprintf(outFile, "\"*ERR*: Cannot read param\"");
    return;
}
	dump_ULONG(cpu, tmpv);
}

void dump_EXECUTION_STATE(CPUState *cpu, EXECUTION_STATE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_SHUTDOWN_ACTION(CPUState *cpu, SHUTDOWN_ACTION param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PSIZE_T(CPUState *cpu, PSIZE_T param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PUSHORT(CPUState *cpu, PUSHORT param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_VDMSERVICECLASS(CPUState *cpu, VDMSERVICECLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PPROCESS_ATTRIBUTE_LIST(CPUState *cpu, PPROCESS_ATTRIBUTE_LIST param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PALPC_HANDLE(CPUState *cpu, PALPC_HANDLE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PLCID(CPUState *cpu, PLCID param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PTOKEN_PRIMARY_GROUP(CPUState *cpu, PTOKEN_PRIMARY_GROUP param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_EVENT_INFORMATION_CLASS(CPUState *cpu, EVENT_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PULONG_PTR(CPUState *cpu, PULONG_PTR param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PJOB_SET_ARRAY(CPUState *cpu, PJOB_SET_ARRAY param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_AUDIT_EVENT_TYPE(CPUState *cpu, AUDIT_EVENT_TYPE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PPS_APC_ROUTINE(CPUState *cpu, PPS_APC_ROUTINE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_OBJECT_INFORMATION_CLASS(CPUState *cpu, OBJECT_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PEFI_DRIVER_ENTRY(CPUState *cpu, PEFI_DRIVER_ENTRY param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PACCESS_MASK(CPUState *cpu, PACCESS_MASK param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PPRIVILEGE_SET(CPUState *cpu, PPRIVILEGE_SET param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PNTSTATUS(CPUState *cpu, PNTSTATUS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_KTMOBJECT_TYPE(CPUState *cpu, KTMOBJECT_TYPE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_SYSTEM_POWER_STATE(CPUState *cpu, SYSTEM_POWER_STATE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PPS_ATTRIBUTE_LIST(CPUState *cpu, PPS_ATTRIBUTE_LIST param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PALPC_SECURITY_ATTR(CPUState *cpu, PALPC_SECURITY_ATTR param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PPORT_VIEW(CPUState *cpu, PPORT_VIEW param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PFILE_PATH(CPUState *cpu, PFILE_PATH param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PIO_APC_ROUTINE(CPUState *cpu, PIO_APC_ROUTINE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PALPC_DATA_VIEW_ATTR(CPUState *cpu, PALPC_DATA_VIEW_ATTR param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_WAIT_TYPE(CPUState *cpu, WAIT_TYPE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PTOKEN_DEFAULT_DACL(CPUState *cpu, PTOKEN_DEFAULT_DACL param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PINITIAL_TEB(CPUState *cpu, PINITIAL_TEB param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PFILE_BASIC_INFORMATION(CPUState *cpu, PFILE_BASIC_INFORMATION param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PALPC_CONTEXT_ATTR(CPUState *cpu, PALPC_CONTEXT_ATTR param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_DEBUGOBJECTINFOCLASS(CPUState *cpu, DEBUGOBJECTINFOCLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_TOKEN_INFORMATION_CLASS(CPUState *cpu, TOKEN_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PREMOTE_PORT_VIEW(CPUState *cpu, PREMOTE_PORT_VIEW param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_EVENT_TYPE(CPUState *cpu, EVENT_TYPE param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PTOKEN_GROUPS(CPUState *cpu, PTOKEN_GROUPS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_SIZE_T(CPUState *cpu, SIZE_T param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_POWER_INFORMATION_LEVEL(CPUState *cpu, POWER_INFORMATION_LEVEL param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_MUTANT_INFORMATION_CLASS(CPUState *cpu, MUTANT_INFORMATION_CLASS param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

void dump_PGROUP_AFFINITY(CPUState *cpu, PGROUP_AFFINITY param) {
    fprintf(outFile, "\"0x%lx\"", (unsigned long) param);
}

