import os,sys,time,struct

ComplexStrings = ["Variable of type ","Pointer to ","Function returning ","Array of "]
BaseStrings =["NULL","VOID","CHAR","SHORT","INT","LONG","FLOAT","DOUBLE","STRUCT","UNION","ENUM","MOE","BYTE","WORD","UINT","DWORD"]


def IsNull(Str):
    LenStr = len(Str)
    ret = True
    for i in range(0,LenStr):
        if Str[i]!="\x00":
            ret = False
            break
    return ret

def IsValidCoffStorageClass(StCls):
    if StCls == 0xFF:
        return True
    if StCls >= 0 and StCls <= 18:
        return True
    if StCls >= 100 and StCls <= 105:
        return True
    if StCls == 107:
        return True
    return False

def GetCoffStorageClass(StCls):
    if StCls == 0xFF:
        return "IMAGE_SYM_CLASS_END_OF_FUNCTION"
    Cls0 = ["IMAGE_SYM_CLASS_NULL","IMAGE_SYM_CLASS_AUTOMATIC","IMAGE_SYM_CLASS_EXTERNAL","IMAGE_SYM_CLASS_STATIC","IMAGE_SYM_CLASS_REGISTER","IMAGE_SYM_CLASS_EXTERNAL_DEF","IMAGE_SYM_CLASS_LABEL","IMAGE_SYM_CLASS_UNDEFINED_LABEL","IMAGE_SYM_CLASS_MEMBER_OF_STRUCT","IMAGE_SYM_CLASS_ARGUMENT","IMAGE_SYM_CLASS_STRUCT_TAG","IMAGE_SYM_CLASS_MEMBER_OF_UNION","IMAGE_SYM_CLASS_UNION_TAG","IMAGE_SYM_CLASS_TYPE_DEFINITION","IMAGE_SYM_CLASS_UNDEFINED_STATIC","IMAGE_SYM_CLASS_ENUM_TAG","IMAGE_SYM_CLASS_MEMBER_OF_ENUM","IMAGE_SYM_CLASS_REGISTER_PARAM","IMAGE_SYM_CLASS_BIT_FIELD"]
    if StCls >= 0 and StCls <= 18:
        return Cls0[StCls]
    Cls1 = ["IMAGE_SYM_CLASS_BLOCK","IMAGE_SYM_CLASS_FUNCTION","IMAGE_SYM_CLASS_END_OF_STRUCT","IMAGE_SYM_CLASS_FILE","IMAGE_SYM_CLASS_SECTION","IMAGE_SYM_CLASS_WEAK_EXTERNAL"]
    if StCls >= 100 and StCls <= 105:
        return Cls1[StCls-100]
    if StCls == 107:
        return "IMAGE_SYM_CLASS_CLR_TOKEN"
    return "UNKNOWN"


def GetCoffStringTableOffset(PointerToSymbolTable,NumberOfSymbols):
    return PointerToSymbolTable + (NumberOfSymbols*0x12)

def GetCoffStringTableSize(Content,PointerToSymbolTable,NumberOfSymbols):
    StringTableOffset = PointerToSymbolTable + (NumberOfSymbols*0x12)
    X = Content[StringTableOffset:StringTableOffset+4]
    return struct.unpack("L",X)[0]

def GetCoffStringFromStringTable(StringTable,Offset):
    X = StringTable[0:4]
    X_i = struct.unpack("L",X)[0]
    if Offset >= X_i or Offset <= 3:
        return ""
    else:
        NewStr = ""
        i = Offset
        while i < X_i:
            CCC = StringTable[i]
            if CCC != "\x00":
                NewStr += CCC
            else:
                break
            i = i + 1
        return NewStr
    return ""




def ParseCoff(Content,PtrToSymbolTable,NumberOfSymbols,StringTable):
    i = 0
    Runner = PtrToSymbolTable
    if Runner >= len(Content):
        print "Boundary error while reading COFF Symbol table"
        return
    while i < NumberOfSymbols:
        SymTable = Content[Runner:Runner+0x12]
        i = i + 1
        Runner += 0x12
        #-----------------
        gUndefinedSym = False
        gAbsoluteSym = False
        gDebugSym = False
        gFunc = False
        gNonFunc = False
        #-----------------
        Name = SymTable[0:8]
        if IsNull(Name[0:4])==True:
            #Long Name ==> Read from "string" table
            NameOffset = struct.unpack("L",Name[4:8])[0]
            #pass
            print "Name: " + GetCoffStringFromStringTable(StringTable,NameOffset)
        else:
            #Short Name
            print "Name: " + Name.rstrip("\x00")
        #-----------------
        Value = SymTable[8:12]
        iValue = struct.unpack("L",Value)[0]
        print "Value: " + str(hex(iValue))
        #-----------------
        #N.B. Section Numbers are One-based
        SectionNumber = struct.unpack("H",SymTable[12:14])[0]
        #Check for SectionNumber Special values
        if SectionNumber == 0:
            gUndefinedSym = True
        elif SectionNumber == 0xFFFF:
            gAbsoluteSym = True
        elif SectionNumber == 0xFFFE:
            gDebugSym = True
        print "Section Number: " + str(hex(SectionNumber))
        #------------------
        Type = SymTable[14:16]
        iType = struct.unpack("H",Type)[0]
        BaseType = struct.unpack("B",Type[0])[0]
        ComplexType = struct.unpack("B",Type[1])[0]
        Descr = ""
        if ComplexType >= 0 and ComplexType <= 3:
            Descr += ComplexStrings[ComplexType]
        else:
            Descr += "Unknown of "
        if BaseType >=0 and BaseType <=15:
            Descr += BaseStrings[BaseType]
        else:
            Descr += "Unknown Type"
        print "Type: " + Descr + " (" + str(hex(iType)) + ")"
        #-------------------
        StorageClass = struct.unpack("B",SymTable[16])[0]
        print "Storage Class: " + GetCoffStorageClass(StorageClass)
        #-------------------
        NumberOfAuxSymbols = struct.unpack("B",SymTable[17])[0]
        print "Number of Auxillary symbols: " + str(NumberOfAuxSymbols)
        i += NumberOfAuxSymbols
        SzAux = NumberOfAuxSymbols * 0x12
        AuxData = Content[Runner:Runner+SzAux]
        Runner += SzAux
        #-------------------
        print "----------------------------"
        #-------------------
        



NumArgs = len(sys.argv)
if NumArgs != 2:
    print "Usage: CoffParser.py input.obj"
    sys.exit(-1)

inF = sys.argv[1]

fIn = open(inF,"rb")
fCon = fIn.read()

#------------------_IMAGE_FILE_HEADER-----------
ImageFileHeader = fCon[0:0x14]
Machine = (struct.unpack("H",ImageFileHeader[0:2]))[0]
print "Machine: " + str(hex(Machine))
NumberOfSections = (struct.unpack("H",ImageFileHeader[2:4]))[0]
print "Number Of Sections: " + str(hex(NumberOfSections))
TimeDateStamp = (struct.unpack("L",ImageFileHeader[4:8]))[0]
print "TimeDateStamp: " + str(hex(TimeDateStamp))
PointerToSymbolTable = (struct.unpack("L",ImageFileHeader[8:0xC]))[0]
print "PointerToSymbolsTable: " + str(hex(PointerToSymbolTable))
NumberOfSymbols = (struct.unpack("L",ImageFileHeader[0xC:0x10]))[0]
print "NumberOfSymbols: " + str(hex(NumberOfSymbols))
SizeOfOptionalHeader = (struct.unpack("H",ImageFileHeader[0x10:0x12]))[0]
if SizeOfOptionalHeader != 0:
    print "SizeOfOptionalHeader: " + str(hex(SizeOfOptionalHeader))
Characteristics = (struct.unpack("H",ImageFileHeader[0x12:0x14]))[0]
if Characteristics != 0:
    print "Characteristics: " + str(hex(Characteristics))

print "\r\n\r\n"
#--------------------------------


PtrSymTable = PointerToSymbolTable
NumSym = NumberOfSymbols

#-------------------------------

StringTableOffset = GetCoffStringTableOffset(PtrSymTable,NumSym)
StringsSize = GetCoffStringTableSize(fCon,PtrSymTable,NumSym)

StringTable = fCon[StringTableOffset:StringTableOffset+StringsSize]


ParseCoff(fCon,PtrSymTable,NumSym,StringTable)


fIn.close()


