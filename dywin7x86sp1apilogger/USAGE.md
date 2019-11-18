Plugin: dywin7x86sp1apilogger
=============================

Summary
-------

This plugin logs API calls that are performed by the analyzed process. The APIs to be logged must be configured manually. This plugin is only available for Windows 7 x86 SP1. Neither output directory nor name is configurable.

DLLs used for the API configuration
SHA1                                     dlls
453d4c3bf4a489433b593420a37bbffb7749875a advapi32.dll
f47f8ff22dcebaf427051f37de9151220a12d517 dnsapi.dll
9c1bcf751682ab4d36c8cd252a954828fb935f54 kernel32.dll
7b823c4b0382189a3dc1506ea316e0ec2746666c kernelbase.dll
9d936eaa33418b995dd2b1b80dada9be4315d766 msvcrt.dll
8bc9247909b17f497d74433e2476d40811394d96 mswsock.dll
ec4fa2e62be62a7bd1a67157ba46d1b022837575 ntdll.dll
1ba58d221a2c95178ae479affc29585b3a37bd01 shell32.dll
eb0eb8069e408fa87de74dcbbbd0714777cd5eb9 urlmon.dll
2b7fd5ff48bd4cb70192503c43adbb1ef5cb5b2a user32.dll
eb0d5584b9ecf5949f5c6daa25e098f0e37db042 wininet.dll
a3d338a38c2b92f95129814973f59446668402a8 ws2_32.dll
78d41b4450c8422b9028c524572fca28fd9e59a5 wsock32.dll

This plugin uses 2 csv sources, the function source and types source, in csv format.

types-csv format:
types-csv recognized 3 possible types, literal, string, and struct.
Do not have trailing spaces between commas, at the beginning or the end.

common format:
`<data type name>,<type: literal|string|struct>,[from here on, dependent on the type]`

if type is empty, literal is assumed

literal types format:
`<data type name>,<literal/empty string>,<size in bytes>,<(s)igned|(u)nsigned>`
`uint32_t,,4,u       // data type name = uint32_t, size = 4 bytes, unsigned`
`int32_t,,4,s        //`
`uint8_t,,1,u        //`
`*,,4,u              // Default handling, if no other types matched`

string types format:
`<data type name>,<string>,<char size>,<z|b,<size offset>>`

This plugin handled 2 kinds of strings, the standard Zero-Terminated C-style strings, or 
e.g. layout: 'a', 'b', 'c', 'd', '\0'
     pointer: ^
a string with specified length in specified offset from the pointer to the beginning of string
e.g. layout: 5, 'a', 'b', 'c', 'd', 'e'
     pointer:    ^

The former is commonly seen with data type LPSTR, LPWSTR, etc...
The latter is known as BSTR strings. BSTR strings may or may not ended with zero.

`<char size>` is the size in bytes of one char. For ANSI strings, char size is 1 bytes. For Windows UNICODE (UTF-16LE), it's 2 bytes.

`STR,string,1,z      // a zero terminated string` 
`WSTR,string,2,z     // a zero terminated wide-string`
`BSTR,string,1,b,1   // a string with length specified in 1 byte before the pointer of first character`
`BWSTR,string,2,b,1  // a wide-string with length specified in 1 byte before the pointer of first character`

struct types format: (# is for comments)
`<data type name>,<struct>,<size in bytes>[,<offset>,<data type name[*]*>,<var name>]*`
`#typedef struct tagPOINT1 {`
`#  /*0*/LONG x;`
`#  /*4*/LONG y;`
`#} POINT, *PPOINT;`
`POINT,struct,8,0,LONG,x,4,LONG,y    `
`// a struct named POINT, `
`//      8 bytes size total, `
`//      with members: `
`//          x, data type = LONG, 0 bytes offset from beginning of struct, `
`//          y, data type = LONG, 4 bytes offset from beginning of struct`


`#typedef struct _UNICODE_STRING {`
`#    USHORT Length;`
`#    USHORT MaximumLength;`
`#    PWSTR  Buffer;`
`#} UNICODE_STRING, *PUNICODE_STRING;`
`UNICODE_STRING,struct,8,0,USHORT,Length,2,USHORT,MaximumLength,4,WSTR*,Buffer`
`// a struct named UNICODE_STRING`
`//      8 bytes size total`
`//      with members:`
`//          Length, type USHORT, 0 bytes offset from beginning of struct`
`//          MaximumLength, type USHORT, 2 bytes offset from beginning of struct`
`//          Buffer, type WSTR* (a pointer to WSTR type), 4 bytes offset from beginning of struct`


function-csv format:
This function only has one common format for all:
`<dll name>,<RVA(hex)>,<ord(dec)>,<return type>,<calling convention>,<API name>[,<in|out|inout>,<data type name[*]*>,<parameter name>]*`

`LONG WINAPI RegSetValueExA(`
`    __in        HKEY hKey,`
`    __in_opt    PCHAR lpValueName, // this is a pointer to an ascii string, which is STR* based on types-csv.`
`    __reserved  DWORD Reserved,`
`    __in        DWORD dwType,`
`    __in       BYTE *lpData,`
`    __in        DWORD cbData`
`);`
`ADVAPI32.dll,0x114b3,1638,LONG,WINAPI,RegSetValueExA,in,HKEY,hKey,in,STR*,lpValueName,in,DWORD,Reserved,in,DWORD,dwType,in,BYTE*,lpData,in,DWORD,cbData`

Information about RVA and ord must match with the actual DLL used for PANDA recording. Otherwise, the plugin won't work!
Use PEView.exe to find out the RVA and ord of functions, or pefile python library for scripting. See scripts/export_extractor.py for sample code to extract exported API information from dll binaries.


Dependencies
------------

This plugin does not depend on any other panda plugins such as osi, wintrospection, win7x86intro or others.
Due to some assert calls in wintrospection, it fails when the register for base address cannot be read. 
Instead of returning error, it simply ends qemu right there via assert. Bad programming practice.
This modification exists in future PANDAs, not exist (assuming the PANDA has not been updated since March 3rd, 2018).
This is tested in PANDA downloaded at July 21th 2018.
This modification is here to stay. Latest PANDA still has this modification.


Arguments
---------

*`asid`				: the asid of the monitored process in hex string. Does not need to append `0x` string
*`apicsv`			: absolute path of the API prototype csv configuration (function-csv) file
*`typecsv`			: absolute path of the types database (types-csv) referred to by the API prototype config file
*`log_api_call`		: boolean, if `true`, the apis are logged. If `false`, the apis are not logged. `false` option is useful if this plugin is used for other plugin as an API database, and the API logging capability is not needed.


APIs and Callbacks
------------------

This plugin has no callbacks


This plugin provides the following API:

	reads API_INFO from csv file.
	int get_api_info(CPUState* cpu, target_ulong pc, API_INFO* api_info)


Building
----------

modify config.panda, add dywin7x86sp1apilogger at the end
go to folder panda/build and run make.

cpp sources under `tests/` folder is only used for unit testing. To execute tests, simply run `make` in tests folder.
		`cd tests/`
		'make'
		
an executable named `testexec` will be created. Execute it and text `TEST_FAILED` should be found if any tests failed.

Unit testing is done under a different set of Makefiles and does not depend on PANDA/QEMU. Make sure tests can be built and executed
without accessing any of PANDA/QEMU files.


Example
-------

	./i386-softmmu/qemu-system-i386 \
		-m 2G \
		-monitor stdio \
		-replay yyyy \
		-os windows-32-7 \
		-panda 'dywin7x86sp1apilogger:asid=166dc000,apicsv=/home/.../panda/plugins/dywin7x86sp1apilogger/res/db-fn.csv,typecsv=/home/.../panda/plugins/dywin7x86sp1apilogger/res/db-types.csv,log_api_call=true'

file locations must must be an absolute path from root

output has 2 files,
dywin7x86sp1apilogger-debug.log
dywin7x86sp1apilogger-apis.log, json format


Limitations
-----------

    1.  The callback is rather slow because it needs to trace every beginning of basic block, checking whether a jump to one of the addresses listed in API call database has been performed.
    2.  The api does not handle correctly when the API returned struct object. This is due to the fact that how struct returning mechanism is implemented is compiler dependent and is impossible to determine from panda.
    3.  Does not handle floating points correctly, either as parameter or as returned value. Floating points are one of those compiler dependent implementations.
    4.  Only handles __cdecl, __stdcall, __pascal calling conventions. Primarily, windows uses __stdcall for windows API and __cdecl for functions that require elipsis such as printf and the like
    5.  Not handling C++ class objects as parameter. Either pass by value or reference
    6.  C structs are aligned by 4 bytes. It cannot handle structs that are packed using custom #pragma pack. See http://www.catb.org/esr/structure-packing/ for more details
    7.  Does not expand the return value like what done in parameters.
    8.  Does not correctly handle 64-bit sized return values. They are supposed to be in EDX:EAX pair register but, it is still calling convention and compiler dependent. Return values are obtained from EAX register only.
    9.  This plugin only supports Windows 7 x86 SP1 with the specified dlls.
    10. This plugin is not capable of searching the API guest virtual address (VA) automatically. As such, the relative VA (RVA) of the API addresses must be regenerated for each Windows OS. This process can be done once for every Windows installation.
    
    
