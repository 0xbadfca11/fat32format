# fat32format
```
Usage Fat32Format [-cN] [-lLABEL] [-p] [-y] X:
Erase all data on disk X:, format it for FAT32

    -c  Specify a cluster size by sector count.
        Accepts 1, 2, 4, 8, 16, 32, 64, 128
        EXAMPLE: Fat32Format -c4 X:  - use 4 sectors per cluster
    -l  Specify volume label.
        If exceeds 11-bytes, truncate label.
    -p  Make immutable AUTORUN.INF on root directory.
        This file cannot do anything on Windows.
    -y  Does not confirm before format.

Modified Version see https://github.com/0xbadfca11/fat32format 

Original Version 1.07, see http://www.ridgecrop.demon.co.uk/fat32format.htm 
This software is covered by the GPL 
Use with care - Ridgecrop are not liable for data lost using this tool
```

## Changes from original

### Alignment awareness
Original fat32format allocates only necessary size to metadata.
This isn't always aligned cluster.  
Modified fat32format always round up 1MiB.

NOTE: FAT32 is different from NTFS, metadata exists between start of the partition and first cluster.

### Strict drive letter
Original fat32format accepts

    fat32format.exe XYZABCDKGS!@#$%

This will format X: drive.  
Modified fat32format deny this.
Only accepts

    fat32format.exe X:
    fat32format.exe \\.\X:
    fat32format.exe \\?\Volume{GUID}

### Support volume label at format
use -l.

### Without confirm
use -y.

### Immutable AUTORUN.INF
use -p.  
You can not open, read, write, rename, move or delete on Windows OS.
Only re-format can delete this. (or delete from non-Windows OS)

NOTE: This behavior is undocumented. 
It does not guarantee also be the same behavior in the future.

## LICENSE
GPL
