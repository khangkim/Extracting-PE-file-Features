import pefile 
import math
import argparse
import array
import os
import threading
import traceback
import hashlib
import csv

def calculate_md5(file_path):
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def get_resources(pe):
    """Extract resources :
    [entropy, size]"""
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)
                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources
        
def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0]*256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x*math.log(p_x, 2)

    return entropy


def extract(file_name):
    res = []
    try:
        pe = pefile.PE(file_name)
    except:
        return 0
    
    #Name
    res.append(os.path.basename(file_name))

    #MD5 
    res.append(calculate_md5(file_name))

    #Dos header
    res.append(pe.DOS_HEADER.e_magic)
    res.append(0)
    res.append(pe.DOS_HEADER.e_cblp)
    res.append(pe.DOS_HEADER.e_cp)
    res.append(pe.DOS_HEADER.e_crlc)
    res.append(pe.DOS_HEADER.e_cparhdr)
    res.append(pe.DOS_HEADER.e_minalloc)
    res.append(pe.DOS_HEADER.e_maxalloc)
    res.append(pe.DOS_HEADER.e_ss)
    res.append(pe.DOS_HEADER.e_sp)
    res.append(pe.DOS_HEADER.e_csum)
    res.append(pe.DOS_HEADER.e_ip)
    res.append(pe.DOS_HEADER.e_cs)
    res.append(pe.DOS_HEADER.e_lfarlc)
    res.append(pe.DOS_HEADER.e_ovno)
    res.append(pe.DOS_HEADER.e_oemid)
    res.append(pe.DOS_HEADER.e_oeminfo)
    res.append(pe.DOS_HEADER.e_lfanew)
    
    
    #NT header
    res.append(pe.NT_HEADERS.Signature)

    #File header
    res.append(pe.FILE_HEADER.Machine)
    res.append(pe.FILE_HEADER.NumberOfSections)
    res.append(pe.FILE_HEADER.TimeDateStamp)
    res.append(pe.FILE_HEADER.PointerToSymbolTable)
    res.append(pe.FILE_HEADER.NumberOfSymbols)
    res.append(pe.FILE_HEADER.SizeOfOptionalHeader)
    res.append(pe.FILE_HEADER.Characteristics)

    #Optional header 
    res.append(pe.OPTIONAL_HEADER.Magic)
    res.append(pe.OPTIONAL_HEADER.MajorLinkerVersion)
    res.append(pe.OPTIONAL_HEADER.MinorLinkerVersion)
    res.append(pe.OPTIONAL_HEADER.SizeOfCode)
    res.append(pe.OPTIONAL_HEADER.SizeOfInitializedData)
    res.append(pe.OPTIONAL_HEADER.SizeOfUninitializedData)
    res.append(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    res.append(pe.OPTIONAL_HEADER.BaseOfCode)
    try:
        res.append(pe.OPTIONAL_HEADER.BaseOfData)
    except AttributeError:
        res.append(0)
    res.append(pe.OPTIONAL_HEADER.ImageBase)
    res.append(pe.OPTIONAL_HEADER.SectionAlignment)
    res.append(pe.OPTIONAL_HEADER.FileAlignment)
    res.append(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
    res.append(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
    res.append(pe.OPTIONAL_HEADER.MajorImageVersion)
    res.append(pe.OPTIONAL_HEADER.MinorImageVersion)
    res.append(pe.OPTIONAL_HEADER.MajorSubsystemVersion)
    res.append(pe.OPTIONAL_HEADER.MinorSubsystemVersion)
    res.append(pe.OPTIONAL_HEADER.Reserved1)
    res.append(pe.OPTIONAL_HEADER.SizeOfImage)
    res.append(pe.OPTIONAL_HEADER.SizeOfHeaders)
    res.append(pe.OPTIONAL_HEADER.CheckSum)
    res.append(pe.OPTIONAL_HEADER.Subsystem)
    res.append(pe.OPTIONAL_HEADER.DllCharacteristics)
    res.append(pe.OPTIONAL_HEADER.SizeOfStackReserve)
    res.append(pe.OPTIONAL_HEADER.SizeOfStackCommit)
    res.append(pe.OPTIONAL_HEADER.SizeOfHeapReserve)
    res.append(pe.OPTIONAL_HEADER.SizeOfHeapCommit)
    res.append(pe.OPTIONAL_HEADER.LoaderFlags)
    res.append(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)

    #Sections
    res.append(len(pe.sections))

    entropy = list(map(lambda x:x.get_entropy(), pe.sections))
    res.append(sum(entropy)/float(len(entropy)))
    res.append(min(entropy))
    res.append(max(entropy))
    
    characteristics = list(map(lambda x:x.Characteristics, pe.sections))
    res.append(sum(characteristics)/float(len(characteristics)))
    res.append(min(characteristics))
    res.append(max(characteristics))

    raw_sizes = list(map(lambda x:x.SizeOfRawData, pe.sections))
    res.append(sum(raw_sizes)/float(len(raw_sizes)))
    res.append(min(raw_sizes))
    res.append(max(raw_sizes))

    virtual_sizes = list(map(lambda x:x.Misc_VirtualSize, pe.sections))
    res.append(sum(virtual_sizes)/float(len(virtual_sizes)))
    res.append(min(virtual_sizes))
    res.append( max(virtual_sizes))

    #Imports
    try:
        res.append(len(pe.DIRECTORY_ENTRY_IMPORT))
        imports = list(sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], []))
        res.append(len(imports))
        res.append(len(list(filter(lambda x:x.name is None, imports))))
    except AttributeError:
        res.append(0)
        res.append(0)
        res.append(0)

    #Exports
    try:
        res.append(len(pe.DIRECTORY_ENTRY_EXPORT.symbols))
    except AttributeError:
        # No export
        res.append(0)

    #Resources
    resources= get_resources(pe)
    res.append(len(resources))
    if len(resources)> 0:
        entropy = list(map(lambda x:x[0], resources))
        res.append( sum(entropy)/float(len(entropy)))
        res.append( min(entropy))
        res.append(max(entropy))
        sizes = list(map(lambda x:x[1], resources))
        res.append( sum(sizes)/float(len(sizes)))
        res.append( min(sizes))
        res.append(max(sizes))
    else:
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)

    # Load configuration size
    res.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']].Size)
        
    # Version information size
    try:
        res.append(pe.VS_VERSIONINFO[0].Length)
    except: 
        res.append(0)

    return res

def write_to_file(content,path):
    features = []
    features.append(content)
    with file_lock:
        with open(path, "a") as file:
            writer = csv.writer(file)
            writer.writerow(features)

def thread_task(file_paths,dest_path,bov):
    try:
        while file_paths:
            with file_paths_lock:
                path = file_paths.pop(0)
            data = extract(path)
            if data != 0 :
                data_str = ','.join(map(str, data))
                data_str = data_str + "," + bov
                write_to_file(data_str,dest_path)
    except:
        traceback.print_exc()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='You need add some argument')
    parser.add_argument('-s', type=str, required=True, help='The dataset folder path')
    parser.add_argument('-d', type=str, required=True, help='The result folder path')
    parser.add_argument('-bov', type=str, required=True, help='0 math with benign, 1 math with virus')

    args = parser.parse_args()
    
    path = args.s
    dest_path = args.d + "/static.csv"
    bov = args.bov
    file_paths = []

    for item in os.listdir(path):
        item_path = os.path.join(path, item)
        if os.path.isfile(item_path):
            if item.endswith(".exe") | item.endswith(".EXE") :
                file_paths.append(item_path)
    
    features = [ ("Name,MD5,e_magic,e_cblp,e_cp,e_crlc,e_cparhdr,e_minalloc,e_maxalloc,e_ss,e_sp,e_csum,"
                "e_ip,e_cs,e_lfarlc,e_ovno,e_oemid,e_oeminfo,e_lfanew,Signature,Machine,NumberOfSections,"
                "TimeDateStamp,PointerToSymbolTable,NumberOfSymbols,SizeOfOptionalHeader,Characteristics,"
                "Magic,MajorLinkerVersion,MinorLinkerVersion,SizeOfCode,SizeOfInitializedData,"
                "SizeOfUninitializedData,AddressOfEntryPoint,BaseOfCode,BaseOfData,ImageBase,"
                "SectionAlignment,FileAlignment,MajorOperatingSystemVersion,MinorOperatingSystemVersion,"
                "MajorImageVersion,MinorImageVersion,MajorSubsystemVersion,MinorSubsystemVersion,Reserved1,"
                "SizeOfImage,SizeOfHeaders,CheckSum,Subsystem,DllCharacteristics,SizeOfStackReserve,"
                "SizeOfStackCommit,SizeOfHeapReserve,SizeOfHeapCommit,LoaderFlags,NumberOfRvaAndSizes,"
                "SectionsNb,SectionsMeanEntropy,SectionsMinEntropy,SectionsMaxEntropy,CharacteristicsMean,"
                "CharacteristicsMin,CharacteristicsMax,SectionsMeanRawsize,SectionsMinRawsize,SectionMaxRawsize,"
                "SectionsMeanVirtualsize,SectionsMinVirtualsize,SectionMaxVirtualsize,ImportsNbDLL,ImportsNb,"
                "ImportsNbOrdinal,ExportNb,ResourcesNb,ResourcesMeanEntropy,ResourcesMinEntropy,ResourcesMaxEntropy,"
                "ResourcesMeanSize,ResourcesMinSize,ResourcesMaxSize,LoadConfigurationSize,VersionInformationSize,BenignOrVirus")]
    
    with open(dest_path, "wb") as file:
        writer = csv.writer(file)
        writer.writerow(features)
       
    
    file_lock = threading.Lock()
    file_paths_lock = threading.Lock()

    threads = []
    for i in range(10):
        thread = threading.Thread(target=thread_task, args=(file_paths,dest_path,bov,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()






        
    
    





