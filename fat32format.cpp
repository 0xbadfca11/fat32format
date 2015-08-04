// Fat32 formatter version 1.05
// (c) Tom Thornhill 2007,2008,2009
// This software is covered by the GPL. 
// By using this tool, you agree to absolve Ridgecrop of an liabilities for lost data.
// Please backup any data you value before using this tool.

#define STRICT
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES_MEMORY defined(_DEBUG)
#define _CRT_SECURE_CPP_OVERLOAD_SECURE_NAMES_MEMORY   defined(_DEBUG)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <regex>

#include <windows.h>
#include <versionhelpers.h>
#include <winioctl.h>

// Start of first data cluster is ALIGNING_SIZE * ( N * 2 + 1 ).
// | ALIGNING_SIZE | ALIGNING_SIZE * N | ALIGNING_SIZE * N |
// | BPB,FSInfo,.. | FAT1              | FAT2              | Cluster0
static constexpr unsigned ALIGNING_SIZE = 1024 * 1024;

#pragma pack(push, 1)
struct FAT_BOOTSECTOR32
{
	// Common fields.
	BYTE sJmpBoot[3] = { 0xEB, 0x58, 0x90 };
	BYTE sOEMName[8] = { 'M','S','W','I','N','4','.','1' };
	WORD wBytsPerSec;
	BYTE bSecPerClus;
	WORD wRsvdSecCnt;
	BYTE bNumFATs = 2;
	WORD wRootEntCnt = 0;
	WORD wTotSec16 = 0;
	BYTE bMedia = 0xF8;
	WORD wFATSz16 = 0;
	WORD wSecPerTrk;
	WORD wNumHeads;
	DWORD dHiddSec;
	DWORD dTotSec32;
	// Fat 32/16 only
	DWORD dFATSz32;
	WORD wExtFlags = 0;
	WORD wFSVer = 0;
	DWORD dRootClus = 2;
	WORD wFSInfo = 1;
	WORD wBkBootSec = 6;
	BYTE Reserved[12] = {};
	BYTE bDrvNum = 0x80;
	BYTE Reserved1 = 0;
	BYTE bBootSig = 0x29;
	DWORD dBS_VolID;
	BYTE sVolLab[11] = { 'N','O',' ','N','A','M','E',' ',' ',' ',' ' };
	BYTE sBS_FilSysType[8] = { 'F','A','T','3','2',' ',' ',' ' };
};

struct FAT_FSINFO
{
	DWORD dLeadSig = 0x41615252;
	BYTE sReserved1[480] = {};
	DWORD dStrucSig = 0x61417272;
	DWORD dFree_Count = 0xFFFFFFFF;
	DWORD dNxt_Free = 0xFFFFFFFF;
	BYTE sReserved2[12] = {};
	DWORD dTrailSig = 0xAA550000;
};

struct FAT_DIRECTORY
{
	char     DIR_Name[8+3];
	uint8_t  DIR_Attr;
	uint8_t  DIR_NTRes;
	uint8_t  DIR_CrtTimeTenth;
	uint16_t DIR_CrtTime;
	uint16_t DIR_CrtDate;
	uint16_t DIR_LstAccDate;
	uint16_t DIR_FstClusHI;
	uint16_t DIR_WrtTime;
	uint16_t DIR_WrtDate;
	uint16_t DIR_FstClusLO;
	uint32_t DIR_FileSize;
	enum : uint8_t
	{
		ATTR_VOLUME_ID = 0x8
	};
};
static_assert( sizeof( FAT_DIRECTORY ) == 32, "" );

#pragma pack(pop)

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

    GetLocalTime( &s );

	WORD lo = s.wDay + ( s.wMonth << 8 );
	WORD tmp = (s.wMilliseconds/10) + (s.wSecond << 8 );
    lo += tmp;

	WORD hi = s.wMinute + ( s.wHour << 8 );
    hi += s.wYear;
   
    return lo + ( hi << 16 );
}


struct format_params
{
	int sectors_per_cluster = 0;        // can be zero for default or 1,2,4,8,16,32 or 64
	bool make_protected_autorun = false;
	bool all_yes = false;
	PCSTR volume_label = nullptr;
};

[[noreturn]]
void die ( const char * error )
{
    // Retrieve the system error message for the last-error code

    DWORD dw = GetLastError(); 

	if ( dw != NO_ERROR )
		{
		LPSTR lpMsgBuf;
		FormatMessageA(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | 
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dw,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPSTR) &lpMsgBuf,
			0, NULL );

		// Display the error message and exit the process

		fprintf ( stderr, "%s\nGetLastError()=%lu: %s\n", error, dw, lpMsgBuf );
		LocalFree( lpMsgBuf );
		}
	else
		{
		fprintf ( stderr, "%s\n", error );	
		}

 
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
    ULONGLONG   FatElementSize = 4;

    // This is based on 
    // http://hjem.get2net.dk/rune_moeller_barnkob/filesystems/fat.html
    // I've made the obvious changes for FAT32
	ULONGLONG Numerator = FatElementSize * ( DskSize - ReservedSecCnt );
	ULONGLONG Denominator = ( SecPerClus * BytesPerSect ) + ( FatElementSize * NumFATs );
	ULONGLONG FatSz = Numerator / Denominator;
    // round up
    FatSz += 1;

	ULONG align_sector_count = ALIGNING_SIZE / BytesPerSect;
	FatSz = ( FatSz + align_sector_count - 1 ) / align_sector_count * align_sector_count;

    return (DWORD)FatSz;
}

void seek_to_sect( HANDLE hDevice, DWORD Sector, DWORD BytesPerSect )
{
	LONGLONG Offset = Sector * BytesPerSect ;
	LONG HiOffset = (LONG) (Offset>>32);
    SetFilePointer ( hDevice, (LONG) Offset , &HiOffset , FILE_BEGIN );
}

void write_sect ( HANDLE hDevice, DWORD Sector, DWORD BytesPerSector, void *Data, DWORD NumSects )
{
    seek_to_sect ( hDevice, Sector, BytesPerSector );
	DWORD dwWritten;
	BOOL ret=WriteFile ( hDevice, Data, NumSects*BytesPerSector, &dwWritten, NULL );

    if ( !ret )
        die ( "Failed to write" );
}

void zero_sectors ( HANDLE hDevice, DWORD Sector, DWORD BytesPerSect, DWORD NumSects )
{
    LONGLONG qBytesTotal=NumSects*BytesPerSect;

	DWORD BurstSize = 4096;

	BYTE* pZeroSect = (BYTE*) VirtualAlloc( NULL, BytesPerSect*BurstSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    seek_to_sect( hDevice, Sector, BytesPerSect  );

	LARGE_INTEGER Start, End, Ticks, Frequency;
    QueryPerformanceFrequency( &Frequency );
    QueryPerformanceCounter( &Start );
    while ( NumSects )
    {
		DWORD WriteSize = std::min<DWORD>( BurstSize, NumSects );

		DWORD dwWritten;
		BOOL ret=WriteFile ( hDevice, pZeroSect, WriteSize*BytesPerSect, &dwWritten, NULL );
        if ( !ret )
            die ( "Failed to write" );  
        
        NumSects -= WriteSize;
    }

    QueryPerformanceCounter( &End );
    Ticks.QuadPart = End.QuadPart - Start.QuadPart;
	double fTime = (double) ( Ticks.QuadPart ) / Frequency.QuadPart;
    

	double fBytesTotal = (double) qBytesTotal;
    printf ( "Wrote %I64d bytes in %.2f seconds, %.2f Megabytes/sec\n", qBytesTotal, fTime, fBytesTotal/(fTime*1024.0*1024.0) );

}

BYTE get_spc ( DWORD ClusterSizeKB, DWORD BytesPerSect )
{
    DWORD spc = ( ClusterSizeKB * 1024 ) / BytesPerSect;
    return (BYTE)spc;
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
    
    return ret;

}


int format_volume ( PCSTR vol, const format_params* params )
{
    DWORD cbRet;
    BOOL bRet;
    DISK_GEOMETRY         dgDrive;
	PARTITION_INFORMATION  piDrive = {};
	PARTITION_INFORMATION_EX xpiDrive;
	BOOL bGPTMode = FALSE;
    DWORD VolumeId= get_volume_id( );

	if( !IsDebuggerPresent() && !params->all_yes )
	{
		printf( "Warning ALL data on drive '%s' will be lost irretrievably, are you sure\n(y/n) :", vol );
		if( toupper( getchar() ) != 'Y' )
		{
			exit( EXIT_FAILURE );
		}
	}
    


    // open the drive
    HANDLE hDevice = CreateFileA (
		vol,
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

	if( !bRet )
		puts( "Failed to allow extended DASD on device" );
	else
		puts( "FSCTL_ALLOW_EXTENDED_DASD_IO OK" );

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
		puts( "IOCTL_DISK_GET_PARTITION_INFO failed, trying IOCTL_DISK_GET_PARTITION_INFO_EX" );
		bRet = DeviceIoControl ( hDevice, 
			IOCTL_DISK_GET_PARTITION_INFO_EX,
			NULL, 0, &xpiDrive, sizeof(xpiDrive),
			&cbRet, NULL);
  
			
		if (!bRet)
			die( "Failed to get partition info (both regular and _ex)" );

		piDrive.StartingOffset.QuadPart = xpiDrive.StartingOffset.QuadPart;
		piDrive.PartitionLength.QuadPart = xpiDrive.PartitionLength.QuadPart;
		piDrive.HiddenSectors = (DWORD) (xpiDrive.StartingOffset.QuadPart / dgDrive.BytesPerSector);
		

		bGPTMode = xpiDrive.PartitionStyle != PARTITION_STYLE_MBR;
		printf ( "IOCTL_DISK_GET_PARTITION_INFO_EX ok, GPTMode=%d\n", bGPTMode );

	}

    ULONG BytesPerSect = dgDrive.BytesPerSector;
	__analysis_assume( BytesPerSect >= 512 );

    // Checks on Disk Size
	ULONGLONG qTotalSectors = piDrive.PartitionLength.QuadPart/dgDrive.BytesPerSector;
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
        // is 32bit. With a bit of creativity, FAT32 could be extended to handle at least 2^28 clusters
        // There would need to be an extra field in the FSInfo sector, and the old sector count could
        // be set to 0xffffffff. This is non standard though, the Windows FAT driver FASTFAT.SYS won't
        // understand this. Perhaps a future version of FAT32 and FASTFAT will handle this.
        die ( "This drive is too big for FAT32 - max 2TB supported\n" );
    }

	if( IsWindowsVistaOrGreater() )
	{
		STORAGE_PROPERTY_QUERY Query = { StorageAccessAlignmentProperty, PropertyStandardQuery };
		STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR Alignment = {};
		if( DeviceIoControl(
			hDevice,
			IOCTL_STORAGE_QUERY_PROPERTY,
			&Query,
			sizeof Query,
			&Alignment,
			sizeof Alignment,
			&cbRet,
			NULL
			) )
		{
			if( Alignment.BytesOffsetForSectorAlignment )
				puts( "Warning This disk has 'alignment offset'" );
			if( piDrive.StartingOffset.QuadPart > 0 && piDrive.StartingOffset.QuadPart % Alignment.BytesPerPhysicalSector )
				puts( "Warning This partition isn't aligned" );
		}
	}

	FAT_BOOTSECTOR32* pFAT32BootSect = (FAT_BOOTSECTOR32*) VirtualAlloc ( NULL, BytesPerSect, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	FAT_FSINFO* pFAT32FsInfo = (FAT_FSINFO*) VirtualAlloc( NULL, BytesPerSect, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    
	DWORD* pFirstSectOfFat = (DWORD*) VirtualAlloc( NULL, BytesPerSect, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

	FAT_DIRECTORY* pFAT32Directory = (FAT_DIRECTORY*)VirtualAlloc( NULL, BytesPerSect, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

	if( !pFAT32BootSect || !pFAT32FsInfo || !pFirstSectOfFat || !pFAT32Directory )
        die ( "Failed to allocate memory" );

	new ( pFAT32BootSect ) FAT_BOOTSECTOR32;
	new ( pFAT32FsInfo ) FAT_FSINFO;

    // fill out the boot sector and fs info
    pFAT32BootSect->wBytsPerSec = (WORD) BytesPerSect;

	ULONG SectorsPerCluster = params->sectors_per_cluster
		? params->sectors_per_cluster
		: get_sectors_per_cluster( piDrive.PartitionLength.QuadPart, BytesPerSect );
    pFAT32BootSect->bSecPerClus = (BYTE) SectorsPerCluster ;
	pFAT32BootSect->wRsvdSecCnt = (WORD)( ALIGNING_SIZE / BytesPerSect );
    pFAT32BootSect->wSecPerTrk = (WORD) dgDrive.SectorsPerTrack;
    pFAT32BootSect->wNumHeads = (WORD) dgDrive.TracksPerCylinder;
    pFAT32BootSect->dHiddSec = (DWORD) piDrive.HiddenSectors;
    ULONG TotalSectors = (DWORD)  (piDrive.PartitionLength.QuadPart/dgDrive.BytesPerSector);
    pFAT32BootSect->dTotSec32 = TotalSectors;
    
    ULONG FatSize = get_fat_size_sectors ( pFAT32BootSect->dTotSec32, pFAT32BootSect->wRsvdSecCnt, pFAT32BootSect->bSecPerClus, pFAT32BootSect->bNumFATs, BytesPerSect ); ;
    
    pFAT32BootSect->dFATSz32 = FatSize;
    
    pFAT32BootSect->dBS_VolID = VolumeId;
	if( params->volume_label )
	{
		memset( pFAT32BootSect->sVolLab, ' ', sizeof( FAT_BOOTSECTOR32::sVolLab ) );
		_memccpy( pFAT32BootSect->sVolLab, params->volume_label, '\0', sizeof( FAT_BOOTSECTOR32::sVolLab ) );
	}
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

    ULONG UserAreaSize = TotalSectors - pFAT32BootSect->wRsvdSecCnt - ( pFAT32BootSect->bNumFATs*FatSize);
	ULONGLONG ClusterCount = UserAreaSize/SectorsPerCluster;

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
	ULONGLONG FatNeeded = ClusterCount * 4;
    FatNeeded += (BytesPerSect-1);
    FatNeeded /= BytesPerSect;
    if ( FatNeeded > FatSize )
        {
        die ( "This drive is too big for this version of fat32format, check for an upgrade\n" );
        }


	// Now we're commited - print some info first
    printf ( "Size : %gGB %lu sectors\n", (double) (piDrive.PartitionLength.QuadPart / (1000*1000*1000)), TotalSectors );
    printf ( "%lu Bytes Per Sector, Cluster size %lu bytes\n", BytesPerSect, SectorsPerCluster*BytesPerSect );
	printf( "Volume ID is %04lx:%04lx\n", VolumeId >> 16, VolumeId & 0xffff );
	if( params->volume_label )
	{
		printf( "Volume Label is %.*s\n", (int)sizeof( FAT_BOOTSECTOR32::sVolLab ), params->volume_label );
	}
    printf ( "%u Reserved Sectors, %lu Sectors per FAT, %u fats\n", pFAT32BootSect->wRsvdSecCnt, FatSize, pFAT32BootSect->bNumFATs );
    printf ( "%llu Total clusters\n", ClusterCount );
    
    // fix up the FSInfo sector
    pFAT32FsInfo->dFree_Count = (UserAreaSize/SectorsPerCluster)-1;
    pFAT32FsInfo->dNxt_Free = 3; // clusters 0-1 resered, we used cluster 2 for the root dir

    printf ( "%lu Free Clusters\n", pFAT32FsInfo->dFree_Count );
    // Work out the Cluster count
    
	_ASSERTE( ( pFAT32BootSect->wRsvdSecCnt + ( pFAT32BootSect->bNumFATs * FatSize ) ) % ( ALIGNING_SIZE / BytesPerSect ) == 0 );
    
    printf ( "Formatting drive %s...\n",vol  );

    // Once zero_sectors has run, any data on the drive is basically lost....

	// First zero out ReservedSect + FatSize * NumFats + SectorsPerCluster
	ULONG SystemAreaSize = ( pFAT32BootSect->wRsvdSecCnt + ( pFAT32BootSect->bNumFATs * FatSize ) + SectorsPerCluster );
    printf ( "Clearing out %lu sectors for Reserved sectors, fats and root cluster...\n", SystemAreaSize );
	zero_sectors( hDevice, 0, BytesPerSect, SystemAreaSize );
	puts( "Initialising reserved sectors and FATs..." );
	// Now we should write the boot sector and fsinfo twice, once at 0 and once at the backup boot sect position
	for( int i = 0; i < 2; i++ )
	{
		int SectorStart = ( i == 0 ) ? 0 : pFAT32BootSect->wBkBootSec;
		write_sect( hDevice, SectorStart, BytesPerSect, pFAT32BootSect, 1 );
		write_sect( hDevice, SectorStart + 1, BytesPerSect, pFAT32FsInfo, 1 );
	}

	// Write the first fat sector in the right places
	for( int i = 0; i < pFAT32BootSect->bNumFATs; i++ )
	{
		int SectorStart = pFAT32BootSect->wRsvdSecCnt + ( i * FatSize );
		write_sect( hDevice, SectorStart, BytesPerSect, pFirstSectOfFat, 1 );
	}

	unsigned i = 0;
	if( params->volume_label )
	{
		memcpy( pFAT32Directory[i].DIR_Name, pFAT32BootSect->sVolLab, sizeof( FAT_DIRECTORY::DIR_Name ) );
		pFAT32Directory[i].DIR_Attr = FAT_DIRECTORY::ATTR_VOLUME_ID;
		i++;
	}
	if( params->make_protected_autorun )
	{
		memcpy( pFAT32Directory[i].DIR_Name, "AUTORUN INF", sizeof( FAT_DIRECTORY::DIR_Name ) );
		pFAT32Directory[i].DIR_Attr = FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
		i++;
	}
	_ASSERTE( i < BytesPerSect / sizeof( FAT_DIRECTORY ) );
	write_sect( hDevice, pFAT32BootSect->wRsvdSecCnt + pFAT32BootSect->bNumFATs * FatSize, BytesPerSect, pFAT32Directory, 1 );

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
	if ( !bGPTMode && piDrive.HiddenSectors > 0)
		{
		SET_PARTITION_INFORMATION spiDrive = { PARTITION_FAT32_XINT13 };
		bRet = DeviceIoControl ( hDevice, 
			IOCTL_DISK_SET_PARTITION_INFO,
			&spiDrive, sizeof(spiDrive),
			NULL, 0, 
			&cbRet, NULL);

		if ( !bRet )
			{
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

    return TRUE;
}

[[noreturn]]
void usage( void )
{
	puts(
		"Usage Fat32Format [-cN] [-lLABEL] [-p] [-y] X:\n"
		"Erase all data on disk X:, format it for FAT32\n"
		"\n"
		"    -c  Specify a cluster size by sector count.\n"
		"        Accepts 1, 2, 4, 8, 16, 32, 64, 128\n"
		"        EXAMPLE: Fat32Format -c4 X:  - use 4 sectors per cluster\n"
		"    -l  Specify volume label.\n"
		"        If exceeds 11-bytes, truncate label.\n"
		"    -p  Make protected AUTORUN.INF on root directory.\n"
		"        You can not open, read, write, rename, move or delete this file on Windows.\n"
		"    -y  Does not confirm before format.\n"
		"\n"
		"Modified Version see https://github.com/0xbadfca11/fat32format \n"
		"\n"
		"Original Version 1.07, see http://www.ridgecrop.demon.co.uk/fat32format.htm \n"
		"This software is covered by the GPL \n"
		"Use with care - Ridgecrop are not liable for data lost using this tool"
		);
	exit( EXIT_FAILURE );
}

int main(int argc, char* argv[])
{
	if( argc < 2 )
	{
		usage();
	}

	format_params p;
	int i = 1;
	while( ( strlen( argv[i] ) >= 2 ) && ( ( argv[i][0] == '-' ) || ( argv[i][0] == '/' ) ) )
	{
		switch( argv[i][1] )
		{
		case 'c':
			if( strlen( argv[i] ) >= 3 )
			{
				p.sectors_per_cluster = atol( &argv[i][2] );
				if( ( p.sectors_per_cluster != 1 ) &&  // 512 bytes, 0.5k
					( p.sectors_per_cluster != 2 ) &&  // 1K
					( p.sectors_per_cluster != 4 ) &&  // 2K
					( p.sectors_per_cluster != 8 ) &&  // 4K
					( p.sectors_per_cluster != 16 ) &&  // 8K
					( p.sectors_per_cluster != 32 ) &&  // 16K
					( p.sectors_per_cluster != 64 ) &&  // 32K
					( p.sectors_per_cluster != 128 )    // 64K ( Microsoft say don't use 64K or bigger);
					)
				{
					printf( "Ignoring bad cluster size %d\n", p.sectors_per_cluster );
					p.sectors_per_cluster = 0;
				}
			}
			else
				usage();
			break;
		case 'l':
			size_t len;
			if( ( len = strlen( argv[i] ) ) >= 3 )
			{
				if( len - 2/* -l */ > sizeof( FAT_BOOTSECTOR32::sVolLab ) )
					puts( "Warning: truncate volume label." );
				p.volume_label = &argv[i][2];
			}
			else
				usage();
			break;
		case 'p':
			p.make_protected_autorun = true;
			break;
		case 'y':
			p.all_yes = true;
			break;
		case '?':
			usage();
			break;
		default:
			printf( "Ignoring bad flag '-%c'\n", argv[i][1] );
			usage();
			break;
		}
		i++;
	}
	std::cmatch match;
	if( std::regex_match( argv[i], match, std::regex{ R"((?:\\\\\.\\)?([A-Z]):\\?)", std::regex::icase } ) )
		format_volume( match.format( R"(\\.\$1:)" ).c_str(), &p );
	else if( std::regex_match( argv[i], match, std::regex{ R"((\\\\\?\\Volume{[-A-Z0-9]+})\\?)", std::regex::icase } ) )
		format_volume( match.format( "$1" ).c_str(), &p );
	else
		usage();
}