# Microsoft Surface Pro 2017 IRP Notes

The raw data files were gathered using a filter driver based on [IRPMon](https://github.com/MartinDrab/IRPMon). The data can be formatted and filtered using a python utility I threw together `batterylog_parse.py`. It started as a simple tool for basic data and has been quickly modified along the way to shoehorn in support for new data and functionality. The script could use a bit of refactoring but in its current condition it serves its purpose.

What follows are my _very rough_ notes. These were things that I identified while analyzing the IRPdata that the filter driver extracted and Ioctls I could observe. This data was collected over time and some of the assumptions may be a bit stale.

All the `Read :` and `Write:` entries in the formatted logs belong to the _iaLPSS2_UART2_ driver to simplify the output. In the hooked routine where an IRP completes all the IRP information is not readily available so games are played to go back and try to find the IRP entry when it came into the dispatch routine where this information is available, sometimes it fails. The -t (for time) was added when using a different tool to capture data, the logs now come from windbag and there are no time stamps. 

The raw logs contain all the data gathered however they are difficult to parse through. The formatted data is much easier to analyze so using the built in filtering of the utility in conjunction with grep is more productive than parsing the raw logs. As an example The command `./batterylog_parse.py -f empty_restart_replug_charge_to_full.log -c little -l 44 | grep "Read : aa 55 40"` will allow you to see what looks like capacity values increasing. 

The `IOCTL_SPB_EXECUTE_SEQUENCE` Ioctls only come into the _SurfaceAcpiNotify_ driver and are the only Ioctls we see come into that driver. This Ioctl is a sequence of read/write commands that are all executed before the Ioctl completes. Each entry in the sequence list includes a direction, delay, data buffer and a count. To date only lists containing one write followed by one read have been seen.  The write entries from the sequence list for these Ioctls will be listed in the logs as `AcpiNotifyIoctl Write:` entries directly following the `DeviceIocontrol Input` entries. The read entries from the sequence list for these Ioctls will be listed in the logs as `AcpiNotifyIoctl Read :` entries following the _iaLPSS2_UART2_ driver IRP entries. The data sent in for the sequence writes do not correlate with the data seen in the _iaLPSS2_UART2_ driver write IRPs except that for the 8 byte entries 2 bytes are seen in the IRP and for the 16 byte entries 8 bytes are seen in the IRP. There is nothing in the _iaLPSS2_UART2_ driver read IRP data that looks like the data returned for the sequence reads.

Most time has been spent looking at the IRP data, the Ioctl data logging was just added and has not had a lot of analysis.

When the Windows debugger is loaded at system boot and monitored via a USB debug cable on a Surface Pro 2017 with a fully charged battery sometimes we get the following message: `Capacity:46090, FullChargedCapacity:46090, Voltage:8266, Rate:0` This could be used to help understand the data coming back from some of the read commands.

_NOTE: the "minutes until full" messages in the charging log were taken from the Windows battery icon popup during charge and are totally bogus. When it hit the 2 minutes until fully charged point it actually took 35 minutes._

The _iaLPSS2_UART2_ driver appears to always have an outstanding Read IRP. A DeviceIocontrol `Ioctl:0x41808 IRP (IOCTL_SPB_EXECUTE_SEQUENCE)` comes into the _SurfaceAcpiNotify_ driver and we immediately see a write IRP come into the _iaLPSS2_UART2_ driver and complete. Next the outstanding read IRP in the _iaLPSS2_UART2_ driver completes followed by a new outstanding Read IRP coming in. Next another write IRP comes into the the _iaLPSS2_UART2_ driver which also completes. Finally we see the DeviceIocontrol IRP in the _SurfaceAcpiNotify_ driver complete. There are some cases where we see additional write IRPS and Read IRPs before the DeviceIocontrol IRP completes.

This sequence of the DeviceIocontrol followed by Write, Read, Write, DeviceIocontrol complete continues for the duration of a charge/discharge.

Also during the charge/discharge cycles we see DeviceIocontrol calls come in from the CmBatt driver which result in raed and write IRPS into the _iaLPSS2_UART2_ driver. These include IOCTL_BATTERY_QUERY_STATUS, IOCTL_BATTERY_QUERY_INFORMATION, and IOCTL_BATTERY_QUERY_TAG calls. 

All of the Ioctls sent to the _SurfaceAcpiNotify_ driver are the same Ioctl code: 0x41808. The data for these Ioctls is a SPB_TRANSFER_LIST structure and all are identical with the exception of byte 40 (zero based) which can be 0x08, 0x0c, or 0x10. This byte 40 appears to be the BufferCb member of the SPB_TRANSFER_LIST_ENTRY SPB_TRANSFER_LIST_ENTRY_INIT_SIMPLE structure and corrisponds to the byte count for the first sequence entry which is a write. 
 
 
DeviceIocontrol Input: 
`																																  (byte 40)`
`30 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 ca c7 7c 46 8c ce ff ff   0c    00 00 00 00`

This byte 40 from the Ioctl is used in the data for the _iaLPSS2_UART2_ drivers first write IRP following the DeviceIocontrol. This Byte 40 is used as byte 3 (zero based) of the write data and appears to be a count field. Also in that write data in byte 5(zero based) is a single byte id counter that increments by 1 with each write and rolls over to 0 after it hits 0xff. This id counter byte from the write IRP data is then returned in the following read IRP data in byte 5 (zero based) for some of the read types that come back after the write.

Thus far we have seen three different Byte 40 values in the DeviceIocontrol data, 0x08, 0x0c, and 0x10. By looking at the writes that use them 0x08 writes have a total length of 18, 0x0c a total length of 22, and 0x10 a total length of 26. If you assume the first 10 bytes of the data are header, then these count bytes indicate the number of bytes that follow the 10 byte header. 

```
index:
  CT = count
  ID = id counter
  DS = count data starts
  RO = rollover counter
               
		        (CT)    (ID)             (DS)      (ID)(RO)
Write: aa 55 80  08  00  e0  77 0d 80 02  01 00 01  f3  00  0d e7 f4
Write: aa 55 80  0c  00  24  7f 48 80 02  01 00 01  37  01  04 00 00 00 00 12 2a
Write: aa 55 80  10  00  1a  e0 a9 80 03  01 00 04  2d  01  09 78 0c 5c 05 00 00 00 00 15 7f
```

It appears that the byte sequences `aa 55 80` and `aa 55 40` are common patterns for both reads and writes, probably the start of a 10 byte header. 
* The `aa 55 80` sequence is also found as data in many of the `aa 55 40` reads directly following the 10 bytes of the `aa 55 40` header.
* For all of the `aa 55 40` commands, the two bytes following `aa 55 40` are always zero.
* For all of the `aa 55 80` commands, the first byte following `aa 55 80` is always a count byte and the second byte is always zero.
* The count byte appears to be a count of the number of data bytes following the 10 bytes of the `aa 55 80` header.
* For both `aa 55 40` and `aa 55 80` commands, the next byte (byte 5 zero based) is an id counter byte. 
* This id counter is incremented with each command of that sequence and rolls over to zero after it hits 0xff.

There are apparently different counters for different command sequences/types:

```
index:
  CT = count
  ID = id counter
  DS = count data starts
  RO = rollover counter

               (CT)    (ID)             (DS)      (ID)(RO)
Write: aa 55 80 08  00  20 3b d4 80 02   01 00 01  33  0d  03 82 45
               (CT)    (ID)                     (CT)    (ID)             (DS)      (ID)(RO) 
Read : aa 55 40 00  00  20 3e ce ff ff  aa 55 80 18  00  c1 57 7a 80 02   00 01 01  33  0d  03 01 00 00 00 00 00 00 00 ea b5 00 00 1a 22 00 00 23 5c
               (CT)    (ID)             
Write: aa 55 40 00  00  c1 31 23 ff ff
```
You will note the id counter `20` (byte 5 zero based) for the first two commands are in sync with each other, not sure if that is just a coincidence of these command sequences being in lock step or not. If you look at byte `15` (zero based) in the second command you will see the value `c1`. That offset corresponds to the id counter associated with the `aa 55 80` header embedded in the `aa 55 40` read command. That id counter byte value will be the id counter byte value for the `aa 55 40` write command that follows the read. It's possible that the write command following the read uses that id counter to signal the device behind the UART to clear that read data.

The two bytes following the id counter (6 and 7 zero based) are unique values that are associated with the id counter for that particular command sequence type. So for the first `aa 55 40` command above, the id counter is `20` and the next two bytes are `3b d4`. For all commands in this command sequence, `aa 55 40`, the two bytes following the id counter will be unique to the id counter byte value from 0 to `0xff` but it will always be the same for that counter byte value. So for every `aa 55 40` command sequence a counter id byte of `20` will be followed by the two bytes `3b d4`, and an id counter byte of dc will be followed by the two bytes `ad e0` , etc. I currently have no idea how these unique two byte values are generated. The two files sequence_aa5540 and sequence_aa5580 list all these unique values for that command sequence type.

 * The last two bytes of the 10 byte `aa 55 40` header are always `ff ff`. 
 * The last two bytes of the 10 byte `aa 55 80` header are `80 xx`. I have no idea what these bytes are but the only values I have seen for 
 * The `xx` are 00, 01, 02, 03,and 04. Perhaps a roll over counter.

For the `aa 55 80` headers that have data following the header there are some pereceived values in that data.
At offset 3 (zero based) of the data following the header is what appears to be another id counter.
At offset 4 (zero based) of the data following the header is what appears to be a roll over counter for that id counter.
```
index:
  CT = count
  ID = id counter
  DS = count data starts
  RO = rollover counter

                 (CT)    (ID)             (DS)      (ID)(RO)
Write: [aa 55 80] 08  00  f7  a1 6f 80 03  01 00 04  0a  05  01 79 b3

                      (ID)                         (CT)    (ID)             (DS)      (ID)(RO)
Read : aa 55 40 00 00  f7  a4 75 ff ff  [aa 55 80]  0a  00  7e  60 01 80 03  00 01 04  0a  05  01 76 0c 21 38
                                                                                        

                 (CT)    (ID)             (DS)      (ID)(RO)                                               
Write: [aa 55 80] 08  00  f8  4e 9e 80 03  01 00 04  0b  05  01 49 84
                                                                
                      (ID)                         (CT)    (ID)             (DS)      (ID)(RO)
Read : aa 55 40 00 00  f8  4b 84 ff ff  [aa 55 80]  0a  00  7f  41 11 80 03  00 01 04  0b  05  01 75 0c 23 c7
```
 
All writes that start with `aa 55 40` will consist of the 10 byte header only.
All reads that start with `aa 55 40` that are longer than 10 bytes will have an `aa 55 80` header sequence 
directly following the two "ff ff" bytes of the `aa 55 40` header. 

Some observations for reads:
There are 3 types of reads, `aa 55 40", `aa 55 80", and `aa 55 04"

Most of the `aa 55 80` reads have a 2 byte value at the end of the data that appear to be a 
change flag of some sort:
```
  0f 7c: power change
  These three may have to due with battery changes?
  2e 6c: could be related to change in battery percentage
  4d 5c: ?
  a6 9c: ?
```

The `aa 55 80` reads are the first thing we see following an unplug or replug of power. The unplug/replug event apparently causes an interrupt and the _iaLPSS2_UART2_ driver reads the data from the UART into the buffer of the outstanding read IRP and completes it:

  _NOTE: in all cases of the read complete following a unplug/replug the last two values of the read data are "0f 7c" which appears to indicate a power change. I don't see any way to tell from this read data if it is an unplug or replug. For all cases seen thus far the last 10 bytes of the read data are all identical for both the unplug and replug events:       `80 02 00 01 01 02 00 17 0f 7c`_
  
```
UNPLUG POWER #1
Read : aa 55 80 08 00 c0 15 29 80 02 00 01 01 02 00 17 0f 7c
Write: aa 55 40 00 00 c0 10 33 ff ff

REPLUG POWER #1
Read : aa 55 80 08 00 d7 c3 4b 80 02 00 01 01 02 00 17 0f 7c
Write: aa 55 40 00 00 d7 c6 51 ff ff

UNPLUG POWER #2
Read : aa 55 80 08 00 e8 7f 8c 80 02 00 01 01 02 00 17 0f 7c
Write: aa 55 40 00 00 e8 7a 96 ff ff

REPLUG POWER #2
Read : aa 55 80 08 00 fd eb ce 80 02 00 01 01 02 00 17 0f 7c
Write: aa 55 40 00 00 fd ee d4 ff ff

UNPLUG POWER #3
Read : aa 55 80 08 00 0e 97 11 80 02 00 01 01 02 00 17 0f 7c
Write: aa 55 40 00 00 0e 92 0b ff ff

REPLUG POWER #3
Read : aa 55 80 08 00 25 9e 84 80 02 00 01 01 02 00 17 0f 7c
Write: aa 55 40 00 00 25 9b 9e ff ff
```

Following the first read after an unplug or replug there is another DeviceIocontrol _SurfaceAcpiNotify_ `0x41808` which is followed by a read. 

From the unplug_replug_multiple.log these reads are as follows:

```
index:
  DS = count data starts
  EN = entry
                                                                          (DS)                           (EN)        (EN)        (EN)        (EN)
UNPLUG: Write: aa 55 80 08 00 20 3b d4 80 02                               01 00 01 33 0d 03 82 45
UNPLUG: Read : aa 55 40 00 00 20 3e ce ff ff aa 55 80 18 00 c1 57 7a 80 02 00 01 01 33 0d 03 01 00 00 00 00 00 00 00 ea b5 00 00 1a 22 00 00 23 5c
REPLUG: Write: aa 55 80 08 00 38 02 47 80 02                               01 00 01 4b 0d 03 2b 34
REPLUG: Read : aa 55 40 00 00 38 07 5d ff ff aa 55 80 18 00 d8 4f f9 80 02 00 01 01 4b 0d 03 01 00 00 00 58 16 00 00 86 b5 00 00 c1 21 00 00 bc 7b
UNPLUG: Write: aa 55 80 08 00 4a d7 19 80 02                               01 00 01 5d 0d 03 e8 c5
UNPLUG: Read : aa 55 40 00 00 4a d2 03 ff ff aa 55 80 18 00 e9 3d df 80 02 00 01 01 5d 0d 03 01 00 00 00 00 00 00 00 86 b5 00 00 0b 22 00 00 cf 78
REPLUG: Write: aa 55 80 08 00 60 ff 9c 80 02                               01 00 01 73 0d 03 2f 58
REPLUG: Read : aa 55 40 00 00 60 fa 86 ff ff aa 55 80 18 00 fe eb bd 80 02 00 01 01 73 0d 03 01 00 00 00 ec 15 00 00 42 b8 00 00 ad 21 00 00 cc c5
UNPLUG: Write: aa 55 80 08 00 72 8c ae 80 02                               01 00 01 85 0d 03 dd 09
UNPLUG: Read : aa 55 40 00 00 72 89 b4 ff ff aa 55 80 18 00 0f d5 42 80 02 00 01 01 85 0d 03 01 00 00 00 00 00 00 00 42 b8 00 00 fd 21 00 00 a3 84
REPLUG: Write: aa 55 80 08 00 8a 9b c0 80 02                               01 00 01 9d 0d 03 1f e3
REPLUG: Read : aa 55 40 00 00 8a 9e da ff ff aa 55 80 18 00 26 9e f7 80 02 00 01 01 9d 0d 03 01 00 00 00 bf 16 00 00 ae b5 00 00 b3 21 00 00 f9 27
```

There are 4 16 bit entries (EN) in the count data for these reads. In the first of these entries you will notice that after the unplug event this entry is 0 while after the replug event there is a non-zero value. This may be a way to tell when the adapter is plugged in and charging.

_NOTE: shortly after the unplug event a series of DeviceIocontrols come in that generate reads and writes and following these DeviceIocontrols this first entry of zero changes to some non-zero value. _

For each of those reads, the preceding write passed in data that is reflected in the read (only the first unplug is shown here):

_NOTE: The two bytes of data labled as "same" for these commands could possibly be an id counter and rollover counter._

```
                             (ID)                                          (swap)  (same)
UNPLUG: Write: aa 55 80 08 00 20 3b d4                               80 02 01 00 01 33 0d 03  82 45
UNPLUG: Read : aa 55 40 00 00 20 3e ce ff ff aa 55 80 18 00 c1 57 7a 80 02 00 01 01 33 0d 03  01 00 00 00 00 00 00 00 ea b5 00 00 1a 22 00 00 23 5c
```

The are other cases of `aa 55 80` reads however that only seem to appear in discharging/charging situations. In the unplug_replug_multiple.log where the unplugs and replugs were happening quickly, we also see one additional `aa 55 80` read after each unplug:
  _NOTE: in all cases the last two values of the read data are "4d 5c", not sure what these bytes mean._
```  
Read : aa 55 80 08 00 ce db c8 80 02 00 01 01 02 00 15 4d 5c
Write: aa 55 40 00 00 ce de d2 ff ff
Read : aa 55 80 08 00 f6 80 7f 80 02 00 01 01 02 00 15 4d 5c
Write: aa 55 40 00 00 f6 85 65 ff ff
Read : aa 55 80 08 00 1c e4 23 80 02 00 01 01 02 00 15 4d 5c
Write: aa 55 40 00 00 1c e1 39 ff ff
```

In the discharging_all.log there are many `aa 55 80` reads following a DeviceIocontrol Input(CmBatt:0x29404c) or DeviceIocontrol Output(_SurfaceAcpiNotify_:0x41808):
  _NOTE: in all cases the last two values of the read data are "4d 5c" or "a6 9c"_
  
```
DeviceIocontrol Input(CmBatt:0x29404c) : 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Read : aa 55 80 08 00 42 df 98 80 02 00 01 01 02 00 16 2e 6c
Write: aa 55 40 00 00 42 da 82 ff ff
DeviceIocontrol Output(_SurfaceAcpiNotify_:0x41808): 30 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 02 00 00
Read : aa 55 80 08 00 16 ae 82 80 03 00 01 04 03 00 0b a6 9c
Write: aa 55 40 00 00 16 ab 98 ff ff
DeviceIocontrol Output(_SurfaceAcpiNotify_:0x41808): 30 00 00 00 00 00 00 00 02 00 00 00
Read : aa 55 80 08 00 1d c5 33 80 02 00 01 01 02 00 16 2e 6c
Write: aa 55 40 00 00 1d c0 29 ff ff
```

In the charging log there are many `aa 55 80` reads following a DeviceIocontrol Input(CmBatt:0x29404c) or DeviceIocontrol Output(_SurfaceAcpiNotify_:0x41808) as in the discharging, however we see none with a last two values of "a6 9c". At the end of the log we alse see two different `aa 55 80` reads:
DeviceIocontrol Input(_SurfaceAcpiNotify_:`0x41808`) : `30 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 02 00 ...`

```
Write: aa 55 80 08 00 85 74 31 80 02 01 00 01 98 04 01 35 92
Read : aa 55 80 08 00 d4 a0 7b 80 02 00 01 01 02 00 16 2E 6c aa 55 40 00 00 85 71 2b ff ff (the count of 08 doesn't work here)
Write: aa 55 40 00 00 d4 a5 61 ff ff
Read : aa 55 80 0c 00 d5 41 b7 80 02 00 01 01 98 04 01 1f 00 00 00 8d 4e
Write: aa 55 40 00 00 d5 84 71 ff ff
```

These two Reads probably have to do with battery being fully charged as we also see them at the end of the full_unplug_95_replug_full.log:

DeviceIocontrol Input(_SurfaceAcpiNotify_:`0x41808`) : `30 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 02 00 ...`
```
Write: aa 55 80 08 00 a8 bb c4 80 02 01 00 01 bb 0c 01 0a c4
Read : aa 55 80 08 00 48 95 39 80 02 00 01 01 02 00 16 2E 6c aa 55 40 00 00 a8 be de ff ff (the count of 08 doesn't work here)
Write: aa 55 40 00 00 48 90 23 ff ff
Read : aa 55 80 0c 00 49 74 f5 80 02 00 01 01 bb 0c 01 1f 00 00 00 bb f5
Write: aa 55 40 00 00 49 b1 33 ff ff
```

All reads starting with `aa 55 04` have a length of 10, byte 3 of 0 and no counter, and no additional data. All are identical and are found in all logs. These reads appear after a write and directly following the read the exact same write goes out and the following read hav different data. I believe this `aa 55 04` read is an indication that the last write failed so re-send the write. 
```
Write: aa 55 80 08 00 36 cc a6 80 02 01 00 01 49 0d 03 4b 5a
Read : aa 55 04 00 00 00 31 4e ff ff
Write: aa 55 80 08 00 36 cc a6 80 02 01 00 01 49 0d 03 4b 5a
Read : aa 55 40 00 00 36 c9 bc ff ff aa 55 80 18 00 d5 e2 28 80 02 00 01 01 49 0d 03 01 00 00 00 58 16 00 00 86 b5 00 00 c1 21 00 00 a3 d7
Write: aa 55 40 00 00 d5 84 71 ff ff
```
Reads that start with `aa 55 40`:
index:
```
  CT = count
  ID = id counter
  DS = count data starts
  RO = rollover counter
                            (ID)                       (CT)    (ID)             (DS)      (ID)(RO)
Read (147) : aa 55 40 00 00  de  ef c0 ff ff  aa 55 80  7f  00  46  c3 85 80 02  00 01 01  f1  00  02 00 00 00 00 00 c8 af 00 00 cc b5 00 00 01 00 00 00 92 1d 00 00 5e 1a 00....
Read (44)  : aa 55 40 00 00  ce  de d2 ff ff  aa 55 80  18  00  37  8e f5 80 02  00 01 01  e1  00  03 01 00 00 00 00 00 00 00 94 b6 00 00 29 22 00 00 8f 23
Read (32)  : aa 55 40 00 00  cf  ff c2 ff ff  aa 55 80  0c  00  38  c2 9b 80 02  00 01 01  e2  00  0d 00 00 00 00 61 7b
Read (30)  : aa 55 40 00 00  d5  84 71 ff ff  aa 55 80  0a  00  3c  e6 69 80 03  00 01 04  e8  00  01 f9 0b aa 80
Read (29)  : aa 55 40 00 00  d6  e7 41 ff ff  aa 55 80  09  00  3d  97 20 80 03  00 01 04  e9  00  09 00 16 6e
Read (10)  : aa 55 40 00 00  d3  42 11 ff ff
```
Reads of length 147 only appeared in the logs where charging was going on, perhaps this happens when the charging starts or completes
Reads of length 44,32 appear in all logs
Reads of length 30 appear in the discharging logs, and only two times in the charging log
Reads of length 29 appear in all logs except idle

Some observations for the read that follows the first write:
Following the write with the 0x08 count, the following read is 32,44, or 30 bytes long
Following the write with the 0x0c count, the following read is 10 bytes long
Following the write with the 0x10 count, the following read is 29 bytes long

All reads starting with `aa 55 80` follow the `aa 55 80` sequence. 
index:
```
  CT = count
  ID = id counter
  DS = count data starts
  RO = rollover counter
```
Reads of `aa 55 80 08` are found in the charging and discharging logs but not the idle log
```
                  (CT)   (ID)             (DS)      (ID)(RO)
16 byte: aa 55 80  08 00  44  19 f8 80 02  00 01 01  02  00  15 4d 5c


Reads of `aa 55 80 0c" are not in the idle and discharging log, only one entry in the unplug_replug and charging logs 
                  (CT)   (ID)             (DS)      (ID)(RO)
22 byte: aa 55 80  0c 00  db  8f 56 80 02  00 01 01  8f  01  01 1f 00 00 00 b3 23


Reads of `aa 55 80 18", there was only one found in the unplug_replug log
                  (CT)   (ID)             (DS)      (ID)(RO)
34 byte: aa 55 80  18 00  f0  25 5c 80 02  00 01 01  a5  01  03 01 00 00 00 00 00 00 00 f4 b5 00 00 2a 22 00 00 33 94
```

In every read of length greater than 10 bytes there is an ID byte found in byte 13 (zero based). The ID byte increments
by one with each read. There will always be a 10 byte write following this read that contains this same ID byte in byte 5

During discharge and charge we see a sequence of:
Note: the ID byte (offset 5) is the same for the first write and the following read.
      the ID2 byte (offset 15) in the read is the same as the ID byte (offset 5) in the following write

DeviceIocontrol Input(_SurfaceAcpiNotify_:0x41808)
```
Write: aa 55 80 08 00 34 8e 86 80 03 01 00 04 47 01 01 41 20
Read : aa 55 40 00 00 34 8b 9c ff ff aa 55 80 0a 00 de 8a b4 80 03 00 01 04 47 01 01 0d 0c 61 16
Write: aa 55 40 00 00 de ef c0 ff ff
```
DeviceIocontrol Input(_SurfaceAcpiNotify_:0x41808)
```
Write: aa 55 80 10 00 35 6d 7c 80 03 01 00 04 48 01 09 78 0c 5c 05 00 00 00 00 b4 18
Read : aa 55 40 00 00 35 aa 8c ff ff aa 55 80 09 00 df fb fd 80 03 00 01 04 48 01 09 00 e4 c5
Write: aa 55 40 00 00 df ce d0 ff ff
```
DeviceIocontrol Input(_SurfaceAcpiNotify_:0x41808)
```
Write: aa 55 80 10 00 36 0e 4c 80 03 01 00 04 49 01 09 78 0c 5c 05 00 00 00 00 fd c0
Read : aa 55 40 00 00 36 c9 bc ff ff aa 55 80 09 00 e0 47 3a 80 03 00 01 04 49 01 09 00 50 b3
Write: aa 55 40 00 00 e0 72 17 ff ff
```

DeviceIocontrol Input(_SurfaceAcpiNotify_:0x41808)
```
  CT = count
  ID = id counter
  ID2= id counter2
  DS = count data starts
  RO = rollover counter
  
                (CT)    (ID)              (DS)      (ID)(RO)         
Write: aa 55 80  08  00  34  8e 86  80 03  01 00  04 47  01  01 41 20
                      (ID)                      (CT)    (ID2)             (DS)      (ID)(RO)   (ID) 
Read : aa 55 40 00 00  34 8b 9c ff ff  aa 55 80  0a  00  de  8a b4  80 03  00 01  04 47  01 01  0d 0c 61 16
                      (ID2) 
Write: aa 55 40 00 00  de  ef c0 ff ff
```

DeviceIocontrol Input(_SurfaceAcpiNotify_:0x41808)
```
                (CT)    (ID)              (DS)      (ID)(RO)         
Write: aa 55 80  10  00  35  6d 7c  80 03  01 00  04 48  01  09 78 0c 5c 05 00 00 00 00 b4 18
                      (ID)                      (CT)    (ID2)             (DS)      (ID)(RO)   (ID) 
Read : aa 55 40 00 00  35 aa 8c ff ff  aa 55 80  09  00  df  fb fd  80 03  00 01  04 48 01 09 00 e4 c5
                      (ID2) 
Write: aa 55 40 00 00  df  ce d0 ff ff
DeviceIocontrol Input(_SurfaceAcpiNotify_:0x41808)
                (CT)    (ID)              (DS)      (ID)(RO)         
Write: aa 55 80  10  00  36  0e 4c  80 03  01 00  04 49  01  09 78 0c 5c 05 00 00 00 00 fd c0
                      (ID)                      (CT)    (ID2)             (DS)      (ID)(RO)   (ID) 
Read : aa 55 40 00 00  36 c9 bc ff ff  aa 55 80  09  00  e0  47 3a  80 03  00 01  04 49 01 09 00 50 b3
                      (ID2) 
Write: aa 55 40 00 00  e0  72 17 ff ff
```

Some observations for the Writes:
There are only two types of writes, those that start with a `aa 55 40` header and those that start with  a `aa 55 80` header
The id counter byte found in byte 3 (zero based) of the header is specific to the type of write, so there is an id counter
for the `aa 55 40` writes and an id counter for the `aa 55 80` writes.
The reads of type `aa 55 40` and `aa 55 80` get their id counter byte found in byte 3 (zero based) of the header from the
write that preceded it, and it doesn't matter which write type preceded it, it always gets that preceding write id counter byte.  
Write Types:
index:
```
  CT = count
  ID = id counter
  DS = count data starts
  RO = rollover counter

                  (CT)   (ID)             (DS)      (ID)(RO)
34 byte: aa 55 80  18  00 34  ed c5 80 01  01 00 00  47  04  20 e2 07 08 09 0a 18 25 01 fb 02 f0 00 03 00 00 00 a2 a6
26 byte: aa 55 80  10  00 de  28 30 80 03  01 00 04  f1  03  09 78 0c 5c 05 00 00 00 00 14 ca
22 byte: aa 55 80  0c  00 0e  57 cd 80 02  01 00 01  21  05  04 00 00 00 00 ed ba
18 byte: aa 55 80  08  00 36  cc a6 80 03  01 00 04  49  05  01 84 f7

                        (ID)
10 byte: aa 55 40 00 00  fa  09 a4 ff ff
```

It appears that all first writes after the _SurfaceAcpiNotify_ DeviceIocontrol call are of type `aa 55 80`
In the data of the first write after a _SurfaceAcpiNotify_ DeviceIocontrol there is a sequence of bytes that get returned in
the read that directly follows. In the write data at offest 8 (zero based) there are two bytes `80 01`, `80 02`, or `80 03`
that will be found in the read at offset 18 (zero based). The next 2 bytes in the write data are always `01 00` however the
next two bytes in the read data are always `00 01`, swapped from the write. The next 4 bytes of the write data, offset 12, will 
be found in the read data at offset 22. In that 4 bytes of data, the second byte appears to be a counter that rolls over when 
it hits 0xff.

For this first `aa 55 80` write after the _SurfaceAcpiNotify_ DeviceIocontrol call it would appear that byte 15 (zero based) is
a control byte that defines the data coming back in the following read. The read lengths listed below are the count data
lengths returned in the `aa 55 80` header section of the `aa 55 40` read 
```
   byte 15 value  read length
        03            18
        0d            0c
        0b            0c
        01            0c, 0a
        04            no data
        09            09
```
In the sequence below:
     
Byte 40 in the DeviceIocontrol data is the count byte for the following write.
The counter byte in the write (byte 5 zero based) will be the first counter byte in the following read data (byte 5 zero based)
bytes 8,9 and bytes 12,13,14,15 from that first write will come back in the following read at bytes 18,19 and bytes 22,23,24,25 
There is a second counter in the read data at byte 15. If you count from the `aa 55 80` it is byte 5
This second counter will go out in the following write in byte 5
```
DeviceIocontrol Input: 30 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 ca a7 7d 43 0b a7 ff ff 08 00 00 ...
Write: aa 55 80 08 00 4d 30 69 80 02 01 00 01 60 00 03 40 34
Read : aa 55 40 00 00 4d 35 73 ff ff aa 55 80 18 00 34 ed c5 80 02 00 01 01 60 00 03 01 00 00 00 00 00 00 00 64 b4 00 00 ce 21 00 00 a0 ce
Write: aa 55 40 00 00 34 8b 9c ff ff
DeviceIocontrol Input: 30 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 ca a7 7d 43 0b a7 ff ff 08 00 00 ...
Write: aa 55 80 08 00 4e 53 59 80 02 01 00 01 61 00 0d be e2
Read : aa 55 40 00 00 4e 56 43 ff ff aa 55 80 0c 00 35 6f 4a 80 02 00 01 01 61 00 0d 00 00 00 00 1a 08
Write: aa 55 40 00 00 35 aa 8c ff ff
```
                                                                                                                                            
DeviceIocontrol Input: `30 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 ca a7 7d 43 0b a7 ff ff   08   00 00 ...`
```
index:
  CT = count
  ID = id counter
  ID2= id counter2
  DS = count data starts
  RO = rollover counter

              (byte 40)           (2 bytes) (swapped)   (4 bytes)
                (CT)    (ID)                 (DS)       (ID)(RO)         
Write: aa 55 80  08  00  4d  30 69  80 02    01 00    01 60  00 03  40 34

                                                                   (2 bytes)(swapped)   (4 bytes)
                      (ID)                       (CT)    (ID2)              (DS)        (ID)(RO)    (ID) 
Read : aa 55 40 00 00  4d  35 73 ff ff  aa 55 80  18  00  34  ed c5  80 02   00 01    01 60  00 03   01  00 00 00 00 00 00 00 64 b4 00 00 ce 21 00 00 a0 ce

                      (ID2)
Write: aa 55 40 00 00  34  8b 9c ff ff
```

                                                                                                                                    
DeviceIocontrol Input: `30 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 ca a7 7d 43 0b a7 ff ff   08   00 00 ...`
```
              (byte 40)           (2 bytes) (swapped)   (4 bytes)
                (CT)    (ID)                 (DS)       (ID)(RO)         
Write: aa 55 80  08  00  4e  53 59  80 02    01 00    01 61  00 0d  be e2

                                                                   (2 bytes)(swapped)   (4 bytes)
                      (ID)                       (CT)    (ID2)              (DS)        (ID)(RO)    (ID) 
Read : aa 55 40 00 00  4e  56 43 ff ff  aa 55 80  0c  00  35  6f 4a  80 02   00 01    01 61  00 0d   00  00  00 00 1a 08
                                                                                                       
                      (ID2)
Write: aa 55 40 00 00  35  aa 8c ff ff
```

In the discharging and charging logs there are `aa 55 40` reads with the `aa 55 80 18` header in them that appear to have decrementing data in the discharging log and incrementing data in the charging log.

It appears the the last 8 bytes of the log may be 2 32 bit values. The next to the last one decrements and increments

Some entries from the discharging log (lines missing between entries)
```
Read : aa 55 40 00 00 4d 35 73 ff ff aa 55 80 18 00 34 ed c5 80 02 00 01 01 60 00 03 01 00 00 00 00 00 00 00 64 b4 00 00 ce 21 00 00 a0 ce
Read : aa 55 40 00 00 50 a9 b0 ff ff aa 55 80 18 00 37 8e f5 80 02 00 01 01 63 00 03 01 00 00 00 00 00 00 00 64 b4 00 00 ce 21 00 00 a0 bc
Read : aa 55 40 00 00 57 4e c0 ff ff aa 55 80 18 00 3d c4 54 80 02 00 01 01 6a 00 03 01 00 00 00 e3 53 00 00 98 ad 00 00 4a 20 00 00 39 e7
Read : aa 55 40 00 00 74 4f d4 ff ff aa 55 80 18 00 56 09 89 80 02 00 01 01 87 00 03 01 00 00 00 46 56 00 00 7a a8 00 00 25 20 00 00 aa 9a
Read : aa 55 40 00 00 79 e2 05 ff ff aa 55 80 18 00 5b a4 58 80 02 00 01 01 8c 00 03 01 00 00 00 d0 56 00 00 54 a6 00 00 fd 1f 00 00 fe fd
Read : aa 55 40 00 00 f1 62 15 ff ff aa 55 80 18 00 c5 d3 3a 80 02 00 01 01 04 01 03 01 00 00 00 6b 56 00 00 f0 8c 00 00 02 1f 00 00 c1 bd
Read : aa 55 40 00 00 f6 85 65 ff ff aa 55 80 18 00 ca 3c cb 80 02 00 01 01 09 01 03 01 00 00 00 26 56 00 00 60 8b 00 00 de 1e 00 00 c6 7a
Read : aa 55 40 00 00 57 4e c0 ff ff aa 55 80 18 00 1f e4 50 80 02 00 01 01 6a 01 03 01 00 00 00 37 56 00 00 88 77 00 00 05 1e 00 00 21 38
Read : aa 55 40 00 00 5f 46 41 ff ff aa 55 80 18 00 26 9e f7 80 02 00 01 01 72 01 03 01 00 00 00 6d 56 00 00 02 76 00 00 f5 1d 00 00 91 7d
Read : aa 55 40 00 00 e1 53 07 ff ff aa 55 80 18 00 98 8b b1 80 02 00 01 01 f4 01 03 01 00 00 00 b7 57 00 00 ca 58 00 00 1d 1d 00 00 3e c6
Read : aa 55 40 00 00 e9 5b 86 ff ff aa 55 80 18 00 9f 6c c1 80 02 00 01 01 fc 01 03 01 00 00 00 7d 57 00 00 44 57 00 00 fb 1c 00 00 99 41
Read : aa 55 40 00 00 c4 94 73 ff ff aa 55 80 18 00 5b a4 58 80 02 00 01 01 d7 03 03 01 00 00 00 94 54 00 00 7e 22 00 00 10 1c 00 00 ab fa
Read : aa 55 40 00 00 ec fe d6 ff ff aa 55 80 18 00 7f 42 3c 80 02 00 01 01 ff 03 03 01 00 00 00 29 82 00 00 76 20 00 00 67 1b 00 00 30 6d
Read : aa 55 40 00 00 db 4a 90 ff ff aa 55 80 18 00 62 de ff 80 02 00 01 01 ee 04 03 01 00 00 00 f7 52 00 00 02 0d 00 00 26 1b 00 00 77 98
Read : aa 55 40 00 00 ef 9d e6 ff ff aa 55 80 18 00 78 a5 4c 80 02 00 01 01 02 05 03 01 00 00 00 91 52 00 00 9a 0b 00 00 f5 1a 00 00 9b 40
Read : aa 55 40 00 00 45 3d f2 ff ff aa 55 80 18 00 c9 5f fb 80 02 00 01 01 58 05 03 01 00 00 00 e2 4a 00 00 36 06 00 00 5e 1a 00 00 32 72
```
 
Some entries from the charging log (lines missing between entries)
```
Read : aa 55 40 00 00 26 f8 ae ff ff aa 55 80 18 00 d3 24 48 80 02 00 01 01 39 01 03 01 00 00 00 6b 14 00 00 00 0f 00 00 8f 1c 00 00 66 8c
Read : aa 55 40 00 00 2c b2 0f ff ff aa 55 80 18 00 d7 a0 08 80 02 00 01 01 3f 01 03 01 00 00 00 6b 14 00 00 00 0f 00 00 8f 1c 00 00 66 68
Read : aa 55 40 00 00 43 fb 92 ff ff aa 55 80 18 00 ed b9 9f 80 02 00 01 01 56 01 03 02 00 00 00 b4 4e 00 00 be 0f 00 00 1c 1e 00 00 2c 39
Read : aa 55 40 00 00 20 3e ce ff ff aa 55 80 18 00 b2 a3 34 80 02 00 01 01 33 02 03 02 00 00 00 ff 57 00 00 c2 33 00 00 ff 1e 00 00 76 57
Read : aa 55 40 00 00 36 c9 bc ff ff aa 55 80 18 00 c8 7e eb 80 02 00 01 01 49 02 03 02 00 00 00 7b 56 00 00 28 37 00 00 08 1f 00 00 2b 5c
Read : aa 55 40 00 00 f4 c7 45 ff ff aa 55 80 18 00 6d 31 0e 80 02 00 01 01 07 03 03 02 00 00 00 a3 5a 00 00 2e 5e 00 00 f0 1f 00 00 13 b3
Read : aa 55 40 00 00 f9 6a 94 ff ff aa 55 80 18 00 72 ef ed 80 02 00 01 01 0c 03 03 02 00 00 00 d9 5a 00 00 e6 5f 00 00 00 20 00 00 ec 13
Read : aa 55 40 00 00 76 0d f4 ff ff aa 55 80 18 00 e0 14 4e 80 02 00 01 01 89 03 03 02 00 00 00 9e 5d 00 00 a6 77 00 00 fa 20 00 00 fe 17
Read : aa 55 40 00 00 7e 05 75 ff ff aa 55 80 18 00 e7 f3 3e 80 02 00 01 01 91 03 03 02 00 00 00 dd 5d 00 00 54 79 00 00 10 21 00 00 90 44
Read : aa 55 40 00 00 cb 7b 82 ff ff aa 55 80 18 00 2b 33 26 80 02 00 01 01 de 03 03 02 00 00 00 72 60 00 00 52 8a 00 00 f9 21 00 00 ac 2c
Read : aa 55 40 00 00 d3 42 11 ff ff aa 55 80 18 00 32 2b a5 80 02 00 01 01 e6 03 03 02 00 00 00 64 5b 00 00 00 8c 00 00 00 22 00 00 a5 25
Read : aa 55 40 00 00 99 cc f8 ff ff aa 55 80 18 00 e8 1c cf 80 02 00 01 01 ac 04 03 01 00 00 00 00 00 00 00 ee b6 00 00 34 22 00 00 33 17
```
