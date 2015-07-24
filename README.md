# fat32format
Original fat32format is [here.](http://www.ridgecrop.demon.co.uk/fat32format.htm)  
http://www.ridgecrop.demon.co.uk/fat32format.htm

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
use -l. (lowercase of L)

### Without confirm
use -y.

### immutable AUTORUN.INF
use -p.  
You can not open, read, write, rename, move or delete on Windows OS.
Only re-format can delete this. (or delete from non-Windows OS)

NOTE: This behavior is undocumented. Can't guarantee to be also same from now on.

### Source no longer support VC++2013 or older.
to be lazy

## LICENSE
GPL