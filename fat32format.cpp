// Fat32 formatter version 1.05
// (c) Tom Thornhill 2007,2008,2009
// This software is covered by the GPL. 
// By using this tool, you agree to absolve Ridgecrop of an liabilities for lost data.
// Please backup any data you value before using this tool.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <winioctl.h>  // From the Win32 SDK \Mstools\Include, or Visual Studio.Net

typedef unsigned char BYTE; 
typedef unsigned short WORD;
//typedef unsigned int DWORD;

#pragma pack(push, 1)
typedef struct tagFAT_BOOTSECTOR32
{
    // Common fields.
    BYTE sJmpBoot[3];
    BYTE sOEMName[8];
    WORD wBytsPerSec;
    BYTE bSecPerClus;
    WORD wRsvdSecCnt;
    BYTE bNumFATs;
    WORD wRootEntCnt;
    WORD wTotSec16; // if zero, use dTotSec32 instead
    BYTE bMedia;
    WORD wFATSz16;
    WORD wSecPerTrk;
    WORD wNumHeads;
    DWORD dHiddSec;
    DWORD dTotSec32;
    // Fat 32/16 only
    DWORD dFATSz32;
    WORD wExtFlags;
    WORD wFSVer;
    DWORD dRootClus;
    WORD wFSInfo;
    WORD wBkBootSec;
    BYTE Reserved[12];
    BYTE bDrvNum;
    BYTE Reserved1;
    BYTE bBootSig; // == 0x29 if next three fields are ok
    DWORD dBS_VolID;
    BYTE sVolLab[11];
    BYTE sBS_FilSysType[8];

} FAT_BOOTSECTOR32;

typedef struct {
    DWORD dLeadSig;         // 0x41615252
    BYTE sReserved1[480];   // zeros
    DWORD dStrucSig;        // 0x61417272
    DWORD dFree_Count;      // 0xFFFFFFFF
    DWORD dNxt_Free;        // 0xFFFFFFFF
    BYTE sReserved2[12];    // zeros
    DWORD dTrailSig;     // 0xAA550000
} FAT_FSINFO;


#pragma pack(pop)


// This is just so it will build with old versions of Visual Studio. Yeah, I know...
#ifndef IOCTL_DISK_GET_PARTITION_INFO_EX
	#define IOCTL_DISK_GET_PARTITION_INFO_EX    CTL_CODE(IOCTL_DISK_BASE, 0x0012, METHOD_BUFFERED, FILE_ANY_ACCESS)

	typedef struct _PARTITION_INFORMATION_MBR {
		BYTE  PartitionType;
		BOOLEAN BootIndicator;
		BOOLEAN RecognizedPartition;
		DWORD HiddenSectors;
	} PARTITION_INFORMATION_MBR, *PPARTITION_INFORMATION_MBR;

	typedef struct _PARTITION_INFORMATION_GPT {
		GUID PartitionType;                 // Partition type. See table 16-3.
		GUID PartitionId;                   // Unique GUID for this partition.
		DWORD64 Attributes;                 // See table 16-4.
		WCHAR Name [36];                    // Partition Name in Unicode.
	} PARTITION_INFORMATION_GPT, *PPARTITION_INFORMATION_GPT;


	typedef enum _PARTITION_STYLE {
		PARTITION_STYLE_MBR,
		PARTITION_STYLE_GPT,
		PARTITION_STYLE_RAW
	} PARTITION_STYLE;

	typedef struct _PARTITION_INFORMATION_EX {
		PARTITION_STYLE PartitionStyle;
		LARGE_INTEGER StartingOffset;
		LARGE_INTEGER PartitionLength;
		DWORD PartitionNumber;
		BOOLEAN RewritePartition;
		union {
			PARTITION_INFORMATION_MBR Mbr;
			PARTITION_INFORMATION_GPT Gpt;
		} DUMMYUNIONNAME;
	} PARTITION_INFORMATION_EX, *PPARTITION_INFORMATION_EX;
#endif

#ifndef FSCTL_ALLOW_EXTENDED_DASD_IO
 #define FSCTL_ALLOW_EXTENDED_DASD_IO 0x00090083
#endif

/*
28.2  CALCULATING THE VOLUME SERIAL NUMBER

For example, say a disk was formatted on 26 Dec 95 at 9:55 PM and 41.94
seconds.  DOS takes the date and time just before it writes it to the
disk.

Low order word is calculated:               Volume Serial Number is:
    Month & Day         12/26   0c1ah
    Sec & Hundrenths    41:94   295eh               3578:1d02
                                -----
                                3578h

High order word is calculated:
    Hours & Minutes     21:55   1537h
    Year                1995    07cbh
                                -----
                                1d02h
*/
DWORD get_volume_id ( )
{
    SYSTEMTIME s;
    DWORD d;
    WORD lo,hi,tmp;

    GetLocalTime( &s );

    lo = s.wDay + ( s.wMonth << 8 );
    tmp = (s.wMilliseconds/10) + (s.wSecond << 8 );
    lo += tmp;

    hi = s.wMinute + ( s.wHour << 8 );
    hi += s.wYear;
   
    d = lo + (hi << 16);
    return(d);
}


typedef struct 
    {
    int sectors_per_cluster;        // can be zero for default or 1,2,4,8,16,32 or 64
    }
format_params;

void die ( char * error )
{
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    DWORD dw = GetLastError(); 

	if ( dw )
		{
		FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | 
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dw,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR) &lpMsgBuf,
			0, NULL );

		// Display the error message and exit the process

		fprintf ( stderr, "%s\nGetLastError()=%d: %s\n", error, dw, lpMsgBuf );	
		}
	else
		{
		fprintf ( stderr, "%s\n", error );	
		}

    LocalFree(lpMsgBuf);
 
	exit(dw);

}

/*
This is the Microsoft calculation from FATGEN
    
    DWORD RootDirSectors = 0;
    DWORD TmpVal1, TmpVal2, FATSz;

    TmpVal1 = DskSize - ( ReservedSecCnt + RootDirSectors);
    TmpVal2 = (256 * SecPerClus) + NumFATs;
    TmpVal2 = TmpVal2 / 2;
    FATSz = (TmpVal1 + (TmpVal2 - 1)) / TmpVal2;

    return( FatSz );
*/



DWORD get_fat_size_sectors ( DWORD DskSize, DWORD ReservedSecCnt, DWORD SecPerClus, DWORD NumFATs, DWORD BytesPerSect )
{
    ULONGLONG   Numerator, Denominator;
    ULONGLONG   FatElementSize = 4;
    ULONGLONG   FatSz;

    // This is based on 
    // http://hjem.get2net.dk/rune_moeller_barnkob/filesystems/fat.html
    // I've made the obvious changes for FAT32
    Numerator = FatElementSize * ( DskSize - ReservedSecCnt );
    Denominator = ( SecPerClus * BytesPerSect ) + ( FatElementSize * NumFATs );
    FatSz = Numerator / Denominator;
    // round up
    FatSz += 1;

    return( (DWORD) FatSz );
}

void seek_to_sect( HANDLE hDevice, DWORD Sector, DWORD BytesPerSect )
{
	LONGLONG Offset;
	LONG HiOffset;
    
    Offset = Sector * BytesPerSect ;
    HiOffset = (LONG) (Offset>>32);
    SetFilePointer ( hDevice, (LONG) Offset , &HiOffset , FILE_BEGIN );
}

void write_sect ( HANDLE hDevice, DWORD Sector, DWORD BytesPerSector, void *Data, DWORD NumSects )
{
	DWORD dwWritten;
    BOOL ret;

    seek_to_sect ( hDevice, Sector, BytesPerSector );
    ret=WriteFile ( hDevice, Data, NumSects*BytesPerSector, &dwWritten, NULL );

    if ( !ret )
        die ( "Failed to write" );
}

void zero_sectors ( HANDLE hDevice, DWORD Sector, DWORD BytesPerSect, DWORD NumSects, DISK_GEOMETRY* pdgDrive  )
{
    BYTE *pZeroSect;
    DWORD BurstSize;
    DWORD WriteSize;
    BOOL ret;
	DWORD dwWritten;
    LARGE_INTEGER Start, End, Ticks, Frequency;
    double fTime;
    double fBytesTotal;
    LONGLONG qBytesTotal=NumSects*BytesPerSect;

    //BurstSize = pdgDrive->SectorsPerTrack * pdgDrive->TracksPerCylinder;
    BurstSize = 128; // 64K
    //BurstSize = 8; // 4k
    //BurstSize = 1; // one sector

    pZeroSect = (BYTE*) VirtualAlloc( NULL, BytesPerSect*BurstSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );


    seek_to_sect( hDevice, Sector, BytesPerSect  );

    QueryPerformanceFrequency( &Frequency );
    QueryPerformanceCounter( &Start );
    while ( NumSects )
    {
        if ( NumSects > BurstSize )
            WriteSize = BurstSize;
        else 
            WriteSize = NumSects;

        ret=WriteFile ( hDevice, pZeroSect, WriteSize*BytesPerSect, &dwWritten, NULL );   
        if ( !ret )
            die ( "Failed to write" );  
        
        NumSects -= WriteSize;
    }

    QueryPerformanceCounter( &End );
    Ticks.QuadPart = End.QuadPart - Start.QuadPart;
    fTime = (double) ( Ticks.QuadPart ) / Frequency.QuadPart;
    

    fBytesTotal = (double) qBytesTotal;
    printf ( "Wrote %I64d bytes in %.2f seconds, %.2f Megabytes/sec\n", qBytesTotal, fTime, fBytesTotal/(fTime*1024.0*1024.0) );

}

BYTE get_spc ( DWORD ClusterSizeKB, DWORD BytesPerSect )
{
    DWORD spc = ( ClusterSizeKB * 1024 ) / BytesPerSect;
    return( (BYTE) spc );
}

BYTE get_sectors_per_cluster ( LONGLONG DiskSizeBytes, DWORD BytesPerSect )
{
    BYTE ret = 0x01; // 1 sector per cluster
    LONGLONG DiskSizeMB = DiskSizeBytes / ( 1024*1024 );

    // 512 MB to 8,191 MB 4 KB
    if ( DiskSizeMB > 512 )
        ret = get_spc( 4, BytesPerSect );  // ret = 0x8;
        
    // 8,192 MB to 16,383 MB 8 KB 
    if ( DiskSizeMB > 8192 )
        ret = get_spc( 8, BytesPerSect ); // ret = 0x10;

    // 16,384 MB to 32,767 MB 16 KB 
    if ( DiskSizeMB > 16384 )
        ret = get_spc( 16, BytesPerSect ); // ret = 0x20;

    // Larger than 32,768 MB 32 KB
    if ( DiskSizeMB > 32768 )
        ret = get_spc( 32, BytesPerSect );  // ret = 0x40;
    
    return( ret );

}


int format_volume ( char vol, format_params* params )
{
    // First open the device
    char DriveDevicePath[]="\\\\.\\Z:"; // for CreateFile
    DWORD i;
    HANDLE hDevice;
    int cbRet;
    BOOL bRet;
    DISK_GEOMETRY         dgDrive;
    PARTITION_INFORMATION  piDrive;
	PARTITION_INFORMATION_EX xpiDrive;
	BOOL bGPTMode = FALSE;
    SET_PARTITION_INFORMATION spiDrive;
    // Recommended values
    DWORD ReservedSectCount = 32;
    DWORD NumFATs = 2;
    DWORD BackupBootSect = 6;
    DWORD VolumeId=0; // calculated before format
    
    // // Calculated later
    DWORD FatSize=0; 
    DWORD BytesPerSect=0;
    DWORD SectorsPerCluster=0;
    DWORD TotalSectors=0;
    DWORD SystemAreaSize=0;
    DWORD UserAreaSize=0;
    ULONGLONG qTotalSectors=0;

    // structures to be written to the disk
    FAT_BOOTSECTOR32 *pFAT32BootSect;
    FAT_FSINFO *pFAT32FsInfo;
    
    DWORD *pFirstSectOfFat;
    
    BYTE VolId[12] = "NO NAME    ";

    // Debug temp vars
    ULONGLONG FatNeeded, ClusterCount;
    char c;

    DriveDevicePath[4] = vol;
    
    VolumeId = get_volume_id( );

    printf ( "Warning ALL data on drive '%c' will be lost irretrievably, are you sure\n(y/n) :", vol );
    c=getchar();
    if ( toupper(c) != 'Y' )
    {
        exit(1);
    }
    


    // open the drive
    hDevice = CreateFile (
        DriveDevicePath,  
        GENERIC_READ | GENERIC_WRITE,
        0 ,
        NULL, 
        OPEN_EXISTING, 
        FILE_FLAG_NO_BUFFERING,
        NULL);

    if ( hDevice ==  INVALID_HANDLE_VALUE )
        die( "Failed to open device - close any files before formatting and make sure you have Admin rights when using fat32format\n Are you SURE you're formatting the RIGHT DRIVE!!!" );
 
	bRet= DeviceIoControl(
	  (HANDLE) hDevice,              // handle to device
	  FSCTL_ALLOW_EXTENDED_DASD_IO,  // dwIoControlCode
	  NULL,                          // lpInBuffer
	  0,                             // nInBufferSize
	  NULL,                          // lpOutBuffer
	  0,                             // nOutBufferSize
	  &cbRet,				         // number of bytes returned
	  NULL                           // OVERLAPPED structure
	);

	if ( !bRet )
        printf ( "Failed to allow extended DASD on device" );
	else
		printf ( "FSCTL_ALLOW_EXTENDED_DASD_IO OK\n" ); 

    // lock it
    bRet = DeviceIoControl( hDevice, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL );

    if ( !bRet )
        die( "Failed to lock device" );


    // work out drive params
    bRet = DeviceIoControl ( hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY    ,
        NULL, 0, &dgDrive, sizeof(dgDrive),
        &cbRet, NULL);

    if ( !bRet )
        die( "Failed to get device geometry" );

    bRet = DeviceIoControl ( hDevice, 
        IOCTL_DISK_GET_PARTITION_INFO,
        NULL, 0, &piDrive, sizeof(piDrive),
        &cbRet, NULL);

	if ( !bRet )
    {
		printf ( "IOCTL_DISK_GET_PARTITION_INFO failed, trying IOCTL_DISK_GET_PARTITION_INFO_EX\n" );
		bRet = DeviceIoControl ( hDevice, 
			IOCTL_DISK_GET_PARTITION_INFO_EX,
			NULL, 0, &xpiDrive, sizeof(xpiDrive),
			&cbRet, NULL);
  
			
		if (!bRet)
			die( "Failed to get partition info (both regular and _ex)" );

		memset ( &piDrive, 0, sizeof(piDrive) );
		piDrive.StartingOffset.QuadPart = xpiDrive.StartingOffset.QuadPart;
		piDrive.PartitionLength.QuadPart = xpiDrive.PartitionLength.QuadPart;
		piDrive.HiddenSectors = (DWORD) (xpiDrive.StartingOffset.QuadPart / dgDrive.BytesPerSector);
		

		bGPTMode = ( xpiDrive.PartitionStyle == PARTITION_STYLE_MBR ) ? 0 : 1;
		printf ( "IOCTL_DISK_GET_PARTITION_INFO_EX ok, GPTMode=%d\n", bGPTMode );

	}

    // Only support hard disks at the moment 
    //if ( dgDrive.BytesPerSector != 512 )
    //{
    //    die ( "This version of fat32format only supports hard disks with 512 bytes per sector.\n" );
    //}
    BytesPerSect = dgDrive.BytesPerSector;

    // Checks on Disk Size
    qTotalSectors = piDrive.PartitionLength.QuadPart/dgDrive.BytesPerSector;
    // low end limit - 65536 sectors
    if ( qTotalSectors < 65536 )
    {
        // I suspect that most FAT32 implementations would mount this volume just fine, but the
        // spec says that we shouldn't do this, so we won't
        die ( "This drive is too small for FAT32 - there must be at least 64K clusters\n" );
    }

    if ( qTotalSectors >= 0xffffffff )
    {
        // This is a more fundamental limitation on FAT32 - the total sector count in the root dir
        // �s 32bit. With a bit of creativity, FAT32 could be extended to handle at least 2^28 clusters
        // There would need to be an extra field in the FSInfo sector, and the old sector count could
        // be set to 0xffffffff. This is non standard though, the Windows FAT driver FASTFAT.SYS won't
        // understand this. Perhaps a future version of FAT32 and FASTFAT will handle this.
        die ( "This drive is too big for FAT32 - max 2TB supported\n" );
    }

    pFAT32BootSect = (FAT_BOOTSECTOR32*) VirtualAlloc ( NULL, BytesPerSect, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    pFAT32FsInfo = (FAT_FSINFO*) VirtualAlloc( NULL, BytesPerSect, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    
    pFirstSectOfFat = (DWORD*) VirtualAlloc( NULL, BytesPerSect, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    if ( !pFAT32BootSect || !pFAT32FsInfo || !pFirstSectOfFat )
        die ( "Failed to allocate memory" );

    // fill out the boot sector and fs info
    pFAT32BootSect->sJmpBoot[0]=0xEB;
    pFAT32BootSect->sJmpBoot[1]=0x58; // jmp.s $+0x5a is 0xeb 0x58, not 0xeb 0x5a. Thanks Marco!
    pFAT32BootSect->sJmpBoot[2]=0x90;
    strcpy( pFAT32BootSect->sOEMName, "MSWIN4.1" );
    pFAT32BootSect->wBytsPerSec = (WORD) BytesPerSect;
    
    if ( params->sectors_per_cluster )
        SectorsPerCluster = params->sectors_per_cluster;
    else
        SectorsPerCluster = get_sectors_per_cluster( piDrive.PartitionLength.QuadPart, BytesPerSect );

    pFAT32BootSect->bSecPerClus = (BYTE) SectorsPerCluster ;
    pFAT32BootSect->wRsvdSecCnt = (WORD) ReservedSectCount;
    pFAT32BootSect->bNumFATs = (BYTE) NumFATs;
    pFAT32BootSect->wRootEntCnt = 0;
    pFAT32BootSect->wTotSec16 = 0;
    pFAT32BootSect->bMedia = 0xF8;
    pFAT32BootSect->wFATSz16 = 0;
    pFAT32BootSect->wSecPerTrk = (WORD) dgDrive.SectorsPerTrack;
    pFAT32BootSect->wNumHeads = (WORD) dgDrive.TracksPerCylinder;
    pFAT32BootSect->dHiddSec = (DWORD) piDrive.HiddenSectors;
    TotalSectors = (DWORD)  (piDrive.PartitionLength.QuadPart/dgDrive.BytesPerSector);
    pFAT32BootSect->dTotSec32 = TotalSectors;
    
    FatSize = get_fat_size_sectors ( pFAT32BootSect->dTotSec32, pFAT32BootSect->wRsvdSecCnt, pFAT32BootSect->bSecPerClus, pFAT32BootSect->bNumFATs, BytesPerSect ); ;
    
    pFAT32BootSect->dFATSz32 = FatSize;
    pFAT32BootSect->wExtFlags = 0;
    pFAT32BootSect->wFSVer = 0;
    pFAT32BootSect->dRootClus = 2;
    pFAT32BootSect->wFSInfo = 1;
    pFAT32BootSect->wBkBootSec = (WORD) BackupBootSect;
    pFAT32BootSect->bDrvNum = 0x80;
    pFAT32BootSect->Reserved1 = 0;
    pFAT32BootSect->bBootSig = 0x29;
    
    pFAT32BootSect->dBS_VolID = VolumeId;
    memcpy ( pFAT32BootSect->sVolLab, VolId, 11 );
    memcpy( pFAT32BootSect->sBS_FilSysType, "FAT32   ", 8 );
    ((BYTE*)pFAT32BootSect)[510] = 0x55;
    ((BYTE*)pFAT32BootSect)[511] = 0xaa;

	/* FATGEN103.DOC says "NOTE: Many FAT documents mistakenly say that this 0xAA55 signature occupies the "last 2 bytes of 
	the boot sector". This statement is correct if - and only if - BPB_BytsPerSec is 512. If BPB_BytsPerSec is greater than 
	512, the offsets of these signature bytes do not change (although it is perfectly OK for the last two bytes at the end 
	of the boot sector to also contain this signature)." 
	
	Windows seems to only check the bytes at offsets 510 and 511. Other OSs might check the ones at the end of the sector,
	so we'll put them there too.
	*/
	if ( BytesPerSect != 512 )
		{
		((BYTE*)pFAT32BootSect)[BytesPerSect-2] = 0x55;
		((BYTE*)pFAT32BootSect)[BytesPerSect-1] = 0xaa;
		}

    // FSInfo sect
    pFAT32FsInfo->dLeadSig = 0x41615252;
    pFAT32FsInfo->dStrucSig = 0x61417272;
    pFAT32FsInfo->dFree_Count = (DWORD) -1;
    pFAT32FsInfo->dNxt_Free = (DWORD) -1;
    pFAT32FsInfo->dTrailSig = 0xaa550000;

    // First FAT Sector
    pFirstSectOfFat[0] = 0x0ffffff8;  // Reserved cluster 1 media id in low byte
    pFirstSectOfFat[1] = 0x0fffffff;  // Reserved cluster 2 EOC
    pFirstSectOfFat[2] = 0x0fffffff;  // end of cluster chain for root dir

    // Write boot sector, fats
    // Sector 0 Boot Sector
    // Sector 1 FSInfo 
    // Sector 2 More boot code - we write zeros here
    // Sector 3 unused
    // Sector 4 unused
    // Sector 5 unused
    // Sector 6 Backup boot sector
    // Sector 7 Backup FSInfo sector
    // Sector 8 Backup 'more boot code'
    // zero'd sectors upto ReservedSectCount
    // FAT1  ReservedSectCount to ReservedSectCount + FatSize
    // ...
    // FATn  ReservedSectCount to ReservedSectCount + FatSize
    // RootDir - allocated to cluster2

    UserAreaSize = TotalSectors - ReservedSectCount - (NumFATs*FatSize);    
	ClusterCount = UserAreaSize/SectorsPerCluster;

    // Sanity check for a cluster count of >2^28, since the upper 4 bits of the cluster values in 
    // the FAT are reserved.
    if (  ClusterCount > 0x0FFFFFFF )
        {
        die ( "This drive has more than 2^28 clusters, try to specify a larger cluster size or use the default (i.e. don't use -cXX)\n" );
        }

	// Sanity check - < 64K clusters means that the volume will be misdetected as FAT16
	if ( ClusterCount < 65536 )
		{
		die ( "FAT32 must have at least 65536 clusters, try to specify a smaller cluster size or use the default (i.e. don't use -cXX)\n"  );
		}

	// Sanity check, make sure the fat is big enough
    // Convert the cluster count into a Fat sector count, and check the fat size value we calculated 
    // earlier is OK.
    FatNeeded = ClusterCount * 4;
    FatNeeded += (BytesPerSect-1);
    FatNeeded /= BytesPerSect;
    if ( FatNeeded > FatSize )
        {
        die ( "This drive is too big for this version of fat32format, check for an upgrade\n" );
        }


	// Now we're commited - print some info first
    printf ( "Size : %gGB %u sectors\n", (double) (piDrive.PartitionLength.QuadPart / (1000*1000*1000)), TotalSectors );
    printf ( "%d Bytes Per Sector, Cluster size %d bytes\n", BytesPerSect, SectorsPerCluster*BytesPerSect );
    printf ( "Volume ID is %x:%x\n", VolumeId>>16, VolumeId&0xffff );
    printf ( "%d Reserved Sectors, %d Sectors per FAT, %d fats\n", ReservedSectCount, FatSize, NumFATs );

    printf ( "%d Total clusters\n", ClusterCount );
    
    // fix up the FSInfo sector
    pFAT32FsInfo->dFree_Count = (UserAreaSize/SectorsPerCluster)-1;
    pFAT32FsInfo->dNxt_Free = 3; // clusters 0-1 resered, we used cluster 2 for the root dir

    printf ( "%d Free Clusters\n", pFAT32FsInfo->dFree_Count );
    // Work out the Cluster count
    

    
    printf ( "Formatting drive %c:...\n",vol  );

    // Once zero_sectors has run, any data on the drive is basically lost....

    // First zero out ReservedSect + FatSize * NumFats + SectorsPerCluster
    SystemAreaSize = (ReservedSectCount+(NumFATs*FatSize) + SectorsPerCluster);
    printf ( "Clearing out %d sectors for Reserved sectors, fats and root cluster...\n", SystemAreaSize );
    zero_sectors( hDevice, 0, BytesPerSect, SystemAreaSize, &dgDrive);
    printf ( "Initialising reserved sectors and FATs...\n" );
    // Now we should write the boot sector and fsinfo twice, once at 0 and once at the backup boot sect position
    for ( i=0; i<2; i++ )
        {
        int SectorStart = (i==0) ? 0 : BackupBootSect;
        write_sect ( hDevice, SectorStart, BytesPerSect, pFAT32BootSect, 1 );
        write_sect ( hDevice, SectorStart+1, BytesPerSect, pFAT32FsInfo, 1 );
        }

    // Write the first fat sector in the right places
    for ( i=0; i<NumFATs; i++ )
        {
        int SectorStart = ReservedSectCount + (i * FatSize );
        write_sect ( hDevice, SectorStart, BytesPerSect, pFirstSectOfFat, 1 );
        }

    // The filesystem recogniser in Windows XP doesn't use the partition type - in can be 
    // set to pretty much anything other Os's like Dos (still useful for Norton Ghost!) and Windows ME might, 
    // so we could fix it here 
    // On the other hand, I'm not sure that exposing big partitions to Windows ME/98 is a very good idea
    // There are a couple of issues here - 
    // 1) WinME/98 doesn't know about 48bit LBA, so IDE drives bigger than 137GB will cause it 
    //    problems. Rather than refuse to mount them, it uses 28bit LBA which wraps 
    //    around, so writing to files above the 137GB boundary will erase the FAT and root dirs.
    // 2) Win98 and WinME have 16 bit scandisk tools, which you need to disable, assuming you
    //    can get third party support for 48bit LBA, or use a USB external case, most of which 
    //    will let you use a 48bit LBA drive.
    //    see http://www.48bitlba.com/win98.htm for instructions

	// If we have a GPT disk, don't mess with the partition type
	if ( !bGPTMode )
		{
		spiDrive.PartitionType = 0x0c; // FAT32 LBA. 
		bRet = DeviceIoControl ( hDevice, 
			IOCTL_DISK_SET_PARTITION_INFO,
			&spiDrive, sizeof(spiDrive),
			NULL, 0, 
			&cbRet, NULL);

		if ( !bRet )
			{
			// This happens because the drive is a Super Floppy
			// i.e. with no partition table. Disk.sys creates a PARTITION_INFORMATION
			// record spanning the whole disk and then fails requests to set the 
			// partition info since it's not actually stored on disk. 
			// So only complain if there really is a partition table to set      
			if ( piDrive.HiddenSectors  )
				die( "Failed to set parition info" );
			}    
		}

    bRet = DeviceIoControl( hDevice, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL );

    if ( !bRet )
        die( "Failed to dismount device" );


    bRet = DeviceIoControl( hDevice, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL );

    if ( !bRet )
        die( "Failed to unlock device" );

    // CloseDevice
    CloseHandle( hDevice );

    printf ( "Done" );

    return( TRUE );
}

void usage( void )
{
        printf ( "Usage Fat32Format X:\n" );
        printf ( "Erase all data on disk X:, format it for FAT32\n" );
        printf ( "It is also possible to specify a cluster size for the disk, e.g\n" );
        printf ( "Fat32Format -c1 X:  - use 1 sector per cluster ( max size 137GB for 512 bytes per sect) \n" );
        printf ( "Fat32Format -c2 X:  - use 2 sectors per cluster ( max size 274GB for 512 bytes per sect )\n" );
        printf ( "Fat32Format -c4 X:  - use 4 sectors per cluster ( max size 549GB ... )\n" );
        printf ( "Fat32Format -c8 X:  - use 8 sectors per cluster ( max size 1TB ... ) \n" );
        printf ( "Fat32Format -c16 X: - use 16 sectors per cluster \n" );
        printf ( "Fat32Format -c32 X: - use 32 sectors per cluster \n" );
        printf ( "Fat32Format -c64 X: - use 64 sectors per cluster \n" );
        printf ( "Fat32Format -c128 X: - use 128 sectors per cluster (64K clusters) \n" );
        printf ( "Version 1.07, see http://www.ridgecrop.demon.co.uk/fat32format.htm \n" );
        printf ( "This software is covered by the GPL \n" );
        printf ( "Use with care - Ridgecrop are not liable for data lost using this tool \n" );
        exit(1);
}

int main(int argc, char* argv[])
{
    format_params p;
    char cVolume;
    int i=1;

    memset( &p, 0, sizeof(p) );
    if ( argc < 2 )
        {
		usage();
        }

    while ( (strlen(argv[i])>=2) && ((argv[i][0] == '-')||(argv[i][0] == '/')) )
    {
        switch ( argv[i][1] )
        {
        case 'c':
            if ( strlen(argv[i]) >=3 )
                {
                p.sectors_per_cluster = atol( &argv[i][2] );
                if (  (p.sectors_per_cluster != 1) &&  // 512 bytes, 0.5k
                  (p.sectors_per_cluster != 2) &&  // 1K
                  (p.sectors_per_cluster != 4) &&  // 2K
                  (p.sectors_per_cluster != 8) &&  // 4K
                  (p.sectors_per_cluster != 16) &&  // 8K
                  (p.sectors_per_cluster != 32) &&  // 16K
                  (p.sectors_per_cluster != 64) &&  // 32K 
                  (p.sectors_per_cluster != 128)    // 64K ( Microsoft say don't use 64K or bigger);               
				  )
                    {
                    printf ( "Ignoring bad cluster size %d\n", p.sectors_per_cluster );
                    p.sectors_per_cluster = 0;
                    }
                }
			else
				usage();
            break;
		case '?':
			usage();
			break;
        default:
            printf ( "Ignoring bad flag '-%c'\n", argv[i][1] ); 
			usage();
            break;
        }
        i++;
    }

    cVolume = argv[i][0];

#if 0
    if ( cVolume != 'f' )
        die( "Debug - only F: can be formatted\n" );
#endif

    format_volume( cVolume, &p );

    return 0;
}

