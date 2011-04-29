/*
 *          Copyright Pedro Rodrigues 2011.
 * Distributed under the Boost Software License, Version 1.0.
 *    (See accompanying file LICENSE_1_0.txt or copy at
 *          http://www.boost.org/LICENSE_1_0.txt)
 */
/**
 * Utilities to manipulate the Portable Executable format.
 * 
 * Portable Executable is the format used in Windows executable files (.exe).
 * This library is based on the Microsoft Portable Executable and Common Object
 * File Format Specification, Revision 8.2 - September 21, 2010
 */
module portexec;

import std.algorithm;
import std.conv;
import std.exception;
import std.file;
import std.stream;
import std.traits;
import std.zlib;


/**
 * A PortableExecutable object includes all the necessary data structures and
 * methods to parse, manipulate and output a Portable Execute file.
 */
class PortableExecutable
{
    immutable PE_SIGNATURE= "PE\0\0";
    
    PeMagicNumber peMagicNumber;
    
    MsDosHeader msDosHeader;
    ubyte[] msDosStub;
    CoffFileHeader coffFileHeader;
    
    //TODO: only one type of header is in use for a given file. Find a more space-efficient solution
    OptionalHeaderPe32 optionalHeaderPe32;
    OptionalHeaderPe32Plus optionalHeaderPe32Plus;
    
    DataDirectory[] dataDirectories;
    SectionHeaderEntry[] sectionHeaderEntries;
    
    ubyte[][] sections;
    
    
    this() {}
    
    
    this(string filename)
    {
        scope File file = new File(filename);
        read(file);
    }
    
    
    this(Stream input)
    {
        enforce(input.seekable, "The input stream should be seekable");
        read(input);
    }
    
    
    private void read(Stream input)
    in
    {
        assert(input.seekable);
    }
    body 
    {
        readInput(input, msDosHeader);
        enforce(msDosHeader.signature == MsDosHeader.SIGNATURE, "Invalid Portable Executable file");
        
        input.position(msDosHeader.newHeaderOffset);
        enforce(input.readString(PE_SIGNATURE.length) == PE_SIGNATURE, "Invalid Portable Executable file");
        
        readInput(input, coffFileHeader);
        
        readInput(input, peMagicNumber);
        input.seekCur(-to!(int)(PeMagicNumber.sizeof));
        
        readOptionalHeader(input);
        readDataDirectories(input);
        readSectionTable(input);
    }
    
    
    private void readOptionalHeader(Stream input)
    in
    {
        assert(input.seekable);
        // Magic number must have been read
    }
    body
    {
        switch (peMagicNumber)
        {
            case PeMagicNumber.PE32:
                readInput(input, optionalHeaderPe32);
                //op = optionalHeaderPe32;
                break;
            case PeMagicNumber.PE32PLUS:
                readInput(input, optionalHeaderPe32Plus);
                break;
            default:
                throw new Exception("Invalid Portable Executable file");
        }
    }
    
    
    private void readDataDirectories(Stream input)
    in
    {
        assert(input.seekable);
        // Optional Header must have been read
    }
    body
    {
        immutable uint numberOfRvaAndSizes = getOptionalHeaderField!("numberOfRvaAndSizes");
        
        dataDirectories = new DataDirectory[numberOfRvaAndSizes];
        
        foreach (ref dataDirectory; dataDirectories)
        {
            readInput(input, dataDirectory);
        }
    }
    
    
    private void readSectionTable(Stream input)
    in
    {
        assert(input.seekable);
        // COFF Header must have been read
    }
    body
    {
        immutable uint tablePosition = msDosHeader.newHeaderOffset + PE_SIGNATURE.length +
            CoffFileHeader.sizeof + coffFileHeader.sizeOfOptionalHeader;
        
        input.position(tablePosition);
        sectionHeaderEntries = new SectionHeaderEntry[coffFileHeader.numberOfSections];
        
        foreach (ref sectionHeaderEntry; sectionHeaderEntries)
        {
            readInput(input, sectionHeaderEntry);
        }
    }
    
    
    bool isPe32()
    {
        return peMagicNumber == PeMagicNumber.PE32;
    }
    
    
    auto getOptionalHeaderField(string name)()
    {
        return isPe32 ? __traits(getMember, this.optionalHeaderPe32, name) :
            __traits(getMember, this.optionalHeaderPe32Plus, name);
    }
    
    
    void setOptionalHeaderField(string name, Type)(Type value)
    {
        if (isPe32)
        {
            __traits(getMember, this.optionalHeaderPe32, name) = cast(typeof(__traits(getMember, this.optionalHeaderPe32, name)))value;
        }
        else
        {
            __traits(getMember, this.optionalHeaderPe32Plus, name) = cast(typeof(__traits(getMember, this.optionalHeaderPe32Plus, name)))value;
        }
    }
}


pure uint alignedSize(const uint size, const uint alignment)
{
    return size + (alignment - (size % alignment));
}


struct MsDosHeader
{
    immutable SIGNATURE= "MZ";
    
    char[2] signature;
    ubyte[58] data;
    uint newHeaderOffset;
}


struct CoffFileHeader
{
    MachineType machine;
    ushort numberOfSections;
    uint timeDateStamp;
    uint pointerToSymbolTable;
    uint numberOfSymbols;
    ushort sizeOfOptionalHeader;
    ushort characteristics;
}


enum MachineType : ushort
{
    UNKNOWN = 0x0,
    AM33 = 0x1d3,
    AMD64 = 0x8664,
    ARM = 0x1c0,
    ARMV7 = 0x1c4,
    EBC = 0xebc,
    I386 = 0x14c,
    IA64 = 0x200,
    M32R = 0x9041,
    MIPS16 = 0x266,
    MIPSFPU = 0x366,
    MIPSFPU16 = 0x466,
    POWERPC = 0x1f0,
    POWERPCFP = 0x1f1,
    R4000 = 0x166,
    SH3 = 0x1a2,
    SH3DSP = 0x1a3,
    SH4 = 0x1a6,
    SH5 = 0x1a8,
    THUMB = 0x1c2,
    WCEMIPSV2 = 0x169
}


enum CharacteristicsFlags : ushort
{
    RELOCS_STRIPPED = 0x0001,
    EXECUTABLE_IMAGE = 0x0002,
    LINE_NUMS_STRIPPED = 0x0004,
    LOCAL_SYMS_STRIPPED = 0x0008,
    AGGRESSIVE_WS_TRIM = 0x0010,
    LARGE_ADDRESS_AWARE = 0x0020,
    BYTES_REVERSED_LO = 0x0080, // Flag deprecated. Should always be zero
    SIZE_32BIT_MACHINE = 0x0100,
    DEBUG_STRIPPED = 0x0200,
    REMOVABLE_RUN_FROM_SWAP = 0x0400,
    SYSTEM = 0x1000,
    DLL = 0x2000,
    UP_SYSTEM_ONLY = 0x4000,
    BYTES_REVERSED_HI = 0x8000,
}


struct OptionalHeaderPe32
{
    PeMagicNumber magic;
    ubyte majorLinkerVersion;
    ubyte minorLinkerVersion;
    uint sizeOfCode;
    uint sizeOfInitializedData;
    uint sizeOfUninitializedData;
    uint addressOfEntryPoint;
    uint baseOfCode;
    
    uint baseOfData;    
    uint imageBase;
    
    uint sectionAlignment;
    uint fileAlignment;
    ushort majorOperatingSystemVersion;
    ushort minorOperatingSystemVersion;
    ushort majorImageVersion;
    ushort minorImageVersion;
    ushort majorSubsystemVersion;
    ushort minorSubsystemVersion;
    uint win32VersionValue;
    uint sizeOfImage;
    uint sizeOfHeaders;
    uint checkSum;
    ushort subsystem; //TODO
    ushort dllCharacteristics; //TODO
    
    uint sizeOfStackReserve;
    uint sizeOfStackCommit;
    uint sizeOfHeapReserve;
    uint sizeOfHeapCommit;
    
    uint loaderFlags;
    uint numberOfRvaAndSizes;
}


struct OptionalHeaderPe32Plus
{
    PeMagicNumber magic;
    ubyte majorLinkerVersion;
    ubyte minorLinkerVersion;
    uint sizeOfCode;
    uint sizeOfInitializedData;
    uint sizeOfUninitializedData;
    uint addressOfEntryPoint;
    uint baseOfCode;
    
    ulong imageBase;
    
    uint sectionAlignment;
    uint fileAlignment;
    ushort majorOperatingSystemVersion;
    ushort minorOperatingSystemVersion;
    ushort majorImageVersion;
    ushort minorImageVersion;
    ushort majorSubsystemVersion;
    ushort minorSubsystemVersion;
    uint win32VersionValue;
    uint sizeOfImage;
    uint sizeOfHeaders;
    uint checkSum;
    ushort subsystem;
    ushort dllCharacteristics;
    
    ulong sizeOfStackReserve;
    ulong sizeOfStackCommit;
    ulong sizeOfHeapReserve;
    ulong sizeOfHeapCommit;
    
    uint loaderFlags;
    uint numberOfRvaAndSizes;
}


enum PeMagicNumber : ushort
{
    PE32 = 0x10b,
    PE32PLUS = 0x20b
}


struct DataDirectory
{
    uint virtualAddress;
    uint size;
}


struct SectionHeaderEntry
{
    char[8] name;
    uint virtualSize;
    uint virtualAddress;
    uint sizeOfRawData;
    uint pointerToRawData;
    uint pointerToRelocations;
    uint pointerToLinenumbers;
    ushort numberOfRelocations;
    ushort numberOfLinenumbers;
    uint characteristics; //TODO
}


void readInput(Type)(InputStream input, ref Type x)
    if (is (Type == struct))
{
    foreach (i, field; x.tupleof)
    {
        readInput(input, x.tupleof[i]);
    }
}


void readInput(Type)(InputStream input, ref Type x)
    if (is (Type == enum))
{
    input.read(cast(OriginalType!(Type))x);
}


void readInput(Type)(InputStream input, ref Type x)
    if (is (Type : char[]))
{
    input.readExact(cast(void*)x.ptr, typeof(x[0]).sizeof * x.length);
}


void readInput(Type)(InputStream input, ref Type x)
    if (isIntegral!(Type) || is(Type : ubyte[]))
{
    input.read(x);
}


unittest
{
    immutable ubyte[] compressedPeFile = [
        120, 218, 243, 141, 98, 32, 27, 236, 96, 24, 56, 16, 224, 202, 192, 144,
        210, 198, 200, 144, 234, 178, 195, 23, 38, 246, 129, 65, 137, 129, 155,
        137, 139, 129, 129, 9, 73, 161, 0, 20, 51, 48, 56, 48, 194, 248, 64, 121,
        86, 168, 34, 24, 205, 160, 192, 0, 215, 199, 196, 224, 208, 8, 211, 4,
        163, 48, 249, 40, 204, 1, 3, 122, 37, 169, 21, 37, 64, 154, 25, 201, 111,
        40, 254, 135, 120, 45, 1, 151, 126, 227, 3, 135, 25, 70, 193, 200, 5, 0,
        129, 214, 11, 175];
    const ubyte[] peFile = cast(ubyte[]) uncompress(cast(void[])compressedPeFile);
    scope auto istream = new TArrayStream!(ubyte[])(peFile.dup);
    scope auto pe = new PortableExecutable(istream);
    
    assert(pe.msDosHeader.newHeaderOffset == 184);
}
