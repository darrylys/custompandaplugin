#ifndef WINSTRUCT_H
#define WINSTRUCT_H

#include <stdint.h>

typedef uint32_t NTSTATUS;
typedef uint32_t HANDLE;

const NTSTATUS NTSTATUS_SUCCESS = 0;
const HANDLE CURRENT_PROCESS = ~0;

typedef struct _LARGE_INTEGER {
  int64_t QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _ULARGE_INTEGER {
  uint64_t QuadPart;
} ULARGE_INTEGER, *PULARGE_INTEGER;

typedef struct _UNICODE_STRING {
	
	// size of buffer in bytes, not including null terminating char, if any
    uint16_t Length;
	
	// maximum size of buffer, in bytes
    uint16_t MaximumLength;
	
	// address of buffer, may or may not end with zero character
    uint32_t Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    uint32_t           Length;
	
	// HANDLE type
    uint32_t          RootDirectory;
	
	// PUNICODE_STRING type
    uint32_t 		ObjectName;
	
    uint32_t           Attributes;
	
	// PVOID
    uint32_t           SecurityDescriptor;
	
	// PVOID
    uint32_t           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#endif