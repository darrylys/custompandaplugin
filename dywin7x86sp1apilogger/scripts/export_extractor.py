import os
import re
import sys
import pefile

def dump_exports(dllpath, filename):
    pe =  pefile.PE(dllpath)
    with open(("./exports/%s.exports" % filename).lower(), 'w') as f:
        
        f.write("%s\n" % (pe.DIRECTORY_ENTRY_EXPORT.name.decode('ascii')))
        
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            
            # forwarder is not useful because we're going to breakpoint on real library, not forwarded anyway
            # if exported name not exist, probably ordinal only, this one is removed because it rarely happened in malware analysis
            if exp.forwarder is None and exp.name:
                name = exp.name.decode('ascii')
                #forwarder = exp.forwarder.decode('ascii')
                #f.write ("%s %s %s %s\n" % (hex(exp.address), name, exp.ordinal, forwarder))
                f.write ("%s %s %s\n" % (hex(exp.address)[2:], name, exp.ordinal))
                

def main():
    folder_name = "./bin";
    for file in os.listdir(folder_name):
        proto_file_name = os.path.join(folder_name, file)
        dump_exports(proto_file_name, file)
    

if __name__ == '__main__':
    main()
