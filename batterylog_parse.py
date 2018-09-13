#!/usr/bin/python

import os
import sys
import pprint
import getopt
import logging

def parseOptions(argv):
    '''
    '''

    programUsage = """\

USAGE: batterylog_parse.py -f /tmp/evntfile.log

Available Options
  -h   [ --help          ]   Print this message
  -v x [ --verbose=x     ]   (optional) level of verbosity, 0 minimal, 2 max
  -f x [ --filename=x    ]   (required) x = path name of file to parse
  -r   [ --read          ]   (optional) print reads, default -r -w -d until one is entered
  -w   [ --write         ]   (optional) print writes, default -r -w -d until one is entered
  -d   [ --devicecontrol ]   (optional) print devicecontrols, default -r -w -d until one is entered
  -l x [ --length=x      ]   (optional) only print data strings of passed in length
  -c x [ --convert=x     ]   (optional) convert data fields for reads and writes, x = big or little for endian
  -b x [ --base=x        ]   (optional) base for converted values, hex or decimal
  -t   [ --time          ]   (optional) add time stamp

"""

    shortOpts = "hv:f:rwdl:c:b:t"
    longOpts = ['help','verbose=','logfile=','filename=','read','write','devicecontrol','length=','convert=','base=','time']
    opts = ()
    args = ()

    verbose = 0
    logfile = None
    filename = None
    read_type = False
    write_type = False
    devicecontrol_type = False
    length_filter = None
    convert = None
    base = 'decimal'
    time_stamp = False

    try:
      opts,args = getopt.gnu_getopt(argv,shortOpts,longOpts)
    except getopt.GetoptError:
      sys.stderr.write("\nInvalid option passed in\n" + programUsage)
      sys.exit(1)
    if not len(opts):
      sys.stderr.write(programUsage)
      sys.exit(1)

    for opt, val in opts:
      if opt in ('-h','--help'):
        sys.stderr.write(programUsage)
        sys.exit(0)
      elif opt in ('-v','--verbose'):
        verbose = val
      elif opt in ('-f','--filename'):
        filename = val
      elif opt in ('-r','--read'):
        read_type = True
      elif opt in ('-w','--write'):
        write_type = True
      elif opt in ('-d','--devicecontrol'):
        devicecontrol_type = True
      elif opt in ('-l','--length'):
        length_filter = val
      elif opt in ('-c','--convert'):
        convert = val.lower()
      elif opt in ('-b','--base'):
        base = val.lower()
      elif opt in ('-t','--time'):
        time_stamp = True
         
    if filename is None:
      sys.stderr.write("\nfilename is required\n" + programUsage)
      sys.exit(1)
    if not os.path.isfile(filename):
      sys.stderr.write("\nfilename %s is nat a valid file\n" % (str(filename) + programUsage))
      sys.exit(1)

    if read_type == False and write_type == False and devicecontrol_type == False:
      read_type = True
      write_type = True
      devicecontrol_type = True

    try:
      i = int(verbose)
      if i < 0:
        verbose = 0
    except:
      sys.stderr.write("\nInvalid verbose passed in\n" + programUsage)
      sys.exit(1)

    if convert is not None:
      if convert != 'big' and convert != 'little':
        sys.stderr.write("\nconvert (%s) must be 'big' or 'little'\n" % str(convert) + programUsage)
        sys.exit(1)

    if base != 'hex' and base != 'decimal':
      sys.stderr.write("\nbase (%s) must be 'hex' or 'decimal'\n" % str(base) + programUsage)
      sys.exit(1)

    return (verbose,filename,read_type,write_type,devicecontrol_type,length_filter,convert,base,time_stamp)

def get_last_entry(entries,irp_address):
  # find the last entry in the list that has the same Irp address
  entry = None
  for e in entries:
    if e['Irp'] == irp_address:
      entry = e
  return entry

def get_ioctl_name(ioctl):
  ioctl_name = None
  if ioctl == '0x294044':
    ioctl_name = 'IOCTL_BATTERY_QUERY_INFORMATION'
  elif ioctl == '0x29404C':
    ioctl_name = 'IOCTL_BATTERY_QUERY_STATUS'
  elif ioctl == '0x294040':
    ioctl_name = 'IOCTL_BATTERY_QUERY_TAG'
  elif ioctl == '0x294048':
    ioctl_name = 'IOCTL_BATTERY_SET_INFORMATION'
  elif ioctl == '0x41808':
    ioctl_name = 'IOCTL_SPB_EXECUTE_SEQUENCE'
  return ioctl_name


def get_values(line):
  # a line looks something like this:
  #   00134294  39.45162201 DEBUG_HOOK_DATA_ONLY: Complete: Irp = 0xFFFFA80D355F3450, Length = 18
  # pull out the type, Irp Address, and Length values

  val_dict = {}
  line_parts = line.split(':')
  if len(line_parts) < 2:
    #return request_type,irp_address,length,driver,ioctl,note,time
    return val_dict

  # if this is a debug note return it
  if line_parts[0].lower().find('debug') >= 0:
    val_dict['request_type'] = 'Note'
    val_dict['note'] = line_parts[1].strip()
    #return request_type,irp_address,length,driver,ioctl,note,time
    return val_dict

  p = line_parts[0].split('\t') 
  if len(p) > 1:
    val_dict['time'] = p[0].strip()
  if line_parts[1].strip().find('Write Request') >= 0:
    val_dict['request_type'] = 'Write'
  elif line_parts[1].strip().find('Read Request') >= 0:
    val_dict['request_type'] = 'Read'
  elif line_parts[1].strip().find('DeviceIocontrol Request') >= 0:
    val_dict['request_type'] = 'DeviceIocontrol Output'
  elif line_parts[1].strip().find('DeviceIocontrol Dispatch') >= 0:
    val_dict['request_type'] = 'DeviceIocontrol Input'
  elif line_parts[1].strip().find('Complete') >= 0:
    val_dict['request_type'] = 'Complete'
  elif line_parts[1].strip().find('DbgAcpiNotifyIoctl') >= 0:
    if line_parts[1].strip().find('Write') >= 0:
      val_dict['request_type'] = 'AcpiNotifyIoctl Write'
    else:
      val_dict['request_type'] = 'AcpiNotifyIoctl Read'
    val_dict['driver'] = '\\Driver\\SurfaceAcpiNotify'
    val_dict['ioctl'] = '0x41808'
  else:
    #return request_type,irp_address,length,driver,ioctl,note,time
    return val_dict

  #print "line = %s" % line
  #print "line_parts = %s" % (str(line_parts))
  values = line_parts[2].split(',')
  for val in values:
    v = val.split('=')
    if v[0].lower().strip().find('irp') >= 0:
      val_dict['irp_address'] = v[1].strip()
    elif v[0].lower().strip().find('length') >= 0: 
      val_dict['length'] = v[1].strip()
    elif v[0].lower().strip().find('buffercb') >= 0: 
      val_dict['length'] = v[1].strip()
    elif v[0].lower().strip().find('driver') >= 0: 
      d = v[1].strip().split('\\')
      val_dict['driver'] = d[2]
    elif v[0].strip().find('Ioctl') >= 0: 
      val_dict['ioctl'] = v[1].strip()
    elif v[0].strip().find('Tag') >= 0: 
      val_dict['tag'] = v[1].strip()
    elif v[0].strip().find('InfoLevel') >= 0: 
      val_dict['infolevel'] = v[1].strip()
    elif v[0].strip().find('AtRate') >= 0: 
      val_dict['atrate'] = v[1].strip()
  return val_dict
     
def can_print(read_type,write_type,devicecontrol_type,entry_type):
  if entry_type.lower() == 'read' and read_type:
    return True
  if entry_type.lower() == 'write' and write_type:
    return True
  if entry_type.lower() == 'deviceiocontrol input' and devicecontrol_type:
    return True
  if entry_type.lower() == 'deviceiocontrol output' and devicecontrol_type:
    return True
  if entry_type.lower() == 'acpinotifyioctl write' and devicecontrol_type:
    return True
  if entry_type.lower() == 'acpinotifyioctl read' and devicecontrol_type:
    return True
  # for those entries that completed but the parent was prior to the logging
  if entry_type.lower() == 'complete':
    return True
  return False

def get_convert_value(line,convert,offset,length,base):

  # grab the values as bytes from the line
  values = []
  for i in xrange(length):
    values.append(line[offset:offset + 2])
    offset += 3

  #print "values = %s" % values
  # convert the bytes to a value, big endian or little endian as requested
  val = ''
  if convert == 'little':
    for i in reversed(xrange(len(values))):
     val += values[i] 
  else:
    for i in xrange(len(values)):
     val += values[i] 
  #print "val = %s" % val
  if base == 'decimal':
    val = int(val,16)
  else:
    val = '0x' + val
  return str(val)
    
def get_all_convert_values(line,convert,convert_offsets,base):

  convert_values = {}
  for val in convert_offsets:
    offset,num_bytes = val
    #print "offset = %s, num_bytes = %s" % (offset,str(num_bytes))
    val = get_convert_value(line,convert,offset,num_bytes,base)
    end_offset = offset + num_bytes * 3 - 1

    # right justify the val to the mas length it can be for easy comparisons
    if num_bytes == 4:
      val = "%10s" % val
    elif num_bytes == 2:
      val = "%5s" % val
    else:
      val = "%3s" % val
    convert_values[end_offset] = val
    #print "val = %s,end_offset = %s" % (str(val),str(end_offset))
  return convert_values
    

def print_line(line):
  # debug: print line with offset of each byte
  l = ''
  count = 0
  while count < len(line):
    if line[count] == ' ':
      l += ' '
      count = count + 1
    else:
      l += "%s%s(%s)" % (line[count],line[count + 1],str(count))    
      count += 2
  print l

def process_converted_line(line,convert_values):
  # create a new line with the converted values by walking the characters
  # and copying yjem over and when the offset is equal to a converted value
  # offset, add the converted value to the line
  new_line = ''
  i = 0
  while i < len(line):
    new_line += line[i]
    i += 1
    if i in convert_values:
      new_line += "(%s)" % str(convert_values[i])
  return new_line 

def process_convert_read(line,convert,base):
  # 44 byte: aa 55 40 00 00 4d 35 73 ff ff aa 55 80 18 00 34 ed c5 80 02 00 01 01 60 00 03 01 00 00 00 00 00 00 00 64 b4 00 00 ce 21 00 00 a0 ce
  # 32 byte: aa 55 40 00 00 5a e3 11 ff ff aa 55 80 0c 00 40 5d 64 80 02 00 01 01 6d 00 0d 00 00 00 00 71 5a
  # 30 byte: aa 55 40 00 00 d5 84 71 ff ff aa 55 80 0a 00 3c e6 69 80 03 00 01 04 e8 00 01 f9 0b aa 80
  # 29 byte: aa 55 40 00 00 37 e8 ac ff ff aa 55 80 09 00 e1 66 2a 80 03 00 01 04 4a 01 09 00 8c 28

  #print_line(line)
  # add the 4 bytes following aa 55 40 00 and the 4 bytes following aa 55 80 xx
  convert_offsets = [(18,2),(48,2)]
  
  # grab the data length for this read from aa 55 80 XX
  aa55_len = int(line[39:41],16)
  #print 'aa55_len = %s' % (str(aa55_len))

  if aa55_len == 24:
    convert_offsets.append((90,2))
    convert_offsets.append((102,2))
    convert_offsets.append((114,2))
    convert_offsets.append((126,2))
  elif aa55_len == 12:
    convert_offsets.append((90,2))
  elif aa55_len == 10:
    convert_offsets.append((84,2))
  elif aa55_len == 9:
    convert_offsets.append((81,2))
  elif aa55_len > 24:
    return line
  convert_values = get_all_convert_values(line,convert,convert_offsets,base)
  new_line = process_converted_line(line,convert_values)
  #print new_line
  return new_line
  
def process_convert_write_aa5540(line,convert,base):
  #print "process_convert_write_aa5540!!!!!!!!!!!!!!!!!!!!!!!!!!"
  # aa 55 40 00 00 fa 09 a4 ff ff
  # add the 4 bytes following aa 55 40 00 and the 4 bytes following aa 55 80 xx
  #print_line(line)
  convert_offsets = [(18,2)]
  convert_values = get_all_convert_values(line,convert,convert_offsets,base)
  new_line = process_converted_line(line,convert_values)
  #print new_line
  return new_line

def process_convert_aa5580(line,convert,base):
  #print "process_convert_aa5580!!!!!!!!!!!!!!!!!!!!!!!!!!"
  # 34 byte: aa 55 80 18 00 34 ed c5 80 01 01 00 00 47 04 20 e2 07 08 09 0a 18 25 01 fb 02 f0 00 03 00 00 00 a2 a6
  # 26 byte: aa 55 80 10 00 de 28 30 80 03 01 00 04 f1 03 09 78 0c 5c 05 00 00 00 00 14 ca
  # 22 byte: aa 55 80 0c 00 0e 57 cd 80 02 01 00 01 21 05 04 00 00 00 00 ed ba
  # 18 byte: aa 55 80 08 00 36 cc a6 80 03 01 00 04 49 05 01 84 f7
  convert_offsets = [(18,2)]

  # grab the data length for this read from aa 55 80 XX
  #print_line(line)
  aa55_len = int(line[9:12],16)
  #print 'aa55_len = %s' % (str(aa55_len))
  if aa55_len == 8:
    convert_offsets.append((48,2))
  elif aa55_len == 12:
    convert_offsets.append((60,2))
  elif aa55_len == 16:
    convert_offsets.append((72,2))
  elif aa55_len == 24:
    convert_offsets.append((96,2))
  else:
    return line
  convert_values = get_all_convert_values(line,convert,convert_offsets,base)
  new_line = process_converted_line(line,convert_values)
  #print new_line
  return new_line

def do_convert(data_str,convert,base):

  #print "in do_convert"

  Type = 'None'
  if data_str.find('Read') >= 0:
    Type = 'Read'
  elif data_str.find('Write') >= 0:
    Type = 'Write'
  if not Type in ['Read','Write']:
    #print "return 1 Type = %s" % Type
    return data_str
  parts = data_str.split(':')
  if len(parts) < 2:
    #print "return 2"
    return data_str
  if parts[1].find('aa 55') < 0:
    #print "return 3"
    return data_str
  aa55_type = ''
  if parts[1].find('aa 55 40') >= 0:
    aa55_type = '40'
  elif parts[1].find('aa 55 80') >= 0:
    aa55_type = '80'
  if aa55_type != '40' and aa55_type != '80':
    #print "return 4"
    return data_str
  #if Type == 'Read' and aa55_type == '80':
  #  #print "return 5"
  #  return data_str
  if Type == 'Read' and parts[1].find('aa 55 80') < 0:
    #print "return 6"
    return data_str

  #print "aa55_type = %s" % aa55_type
  #print "call process"
  #print parts[1].strip()
  if Type == 'Read':
    if aa55_type == '80':
      new_line = process_convert_aa5580(parts[1].strip(),convert,base)
    else:
      new_line = process_convert_read(parts[1].strip(),convert,base)
  elif aa55_type == '40':
    new_line = process_convert_write_aa5540(parts[1].strip(),convert,base)
  elif aa55_type == '80':
    new_line = process_convert_aa5580(parts[1].strip(),convert,base)
  else:
    return data_str
  new_line = parts[0] + ": " + new_line
  #print new_line
  return new_line
  
info_levels = {
    '0x0':'BatteryInformation',
    '0x1':'BatteryGranularityInformation',
    '0x2':'BatteryTemperature',
    '0x3':'BatteryEstimatedTime',
    '0x4':'BatteryDeviceName',
    '0x5':'BatteryManufactureDate',
    '0x6':'BatteryManufactureName',
    '0x7':'BatteryUniqueID',
    '0x8':'BatterySerialNumber'
}

def update_entry(entry, last_entry):
  entry_fields = ['Type','Irp','Length','Driver','Ioctl']
  for field in entry_fields:
    if field in entry:
      if entry[field] is None or entry[field] == 'Complete':
        entry[field] = last_entry[field]
    elif field in last_entry:
      entry[field] = last_entry[field]

if __name__ == "__main__":

  # Parse options from commandline
  verbose,filename,read_type,write_type,devicecontrol_type,length_filter,convert,base,time_stamp = parseOptions(sys.argv[1:])

  verbose = int(verbose)
  entries = []

  # walk the file and process each entry, they 
  with open(filename, 'r') as f:
    line = f.readline()
    while len(line):
      #print "Line = %s" % line

      # pull relavent values from the line
      values = get_values(line)
      request_type = values.get('request_type',None)
      irp_address = values.get('irp_address',None)
      length = values.get('length',None)
      driver = values.get('driver',None)
      ioctl = values.get('ioctl',None)
      note = values.get('note','')
      time = values.get('time','')
    
      # print any notes added to the log and move on
      if request_type == 'Note':
        print note
        line = f.readline()
        continue

      # skip unknown entries
      if request_type == None:
        line = f.readline()
        #print "SKIP Unknown!!!!!!!"
        continue
     
      # set up this entry
      entry = {}
      entry['Type'] = request_type
      entry['Irp'] = irp_address
      entry['Length'] = length 
      entry['Driver'] = driver
      if ioctl is not None: 
        entry['Ioctl'] = ioctl  
      line = f.readline()

      #print "line = %s" % line
      #print "entry = %s" % (str(entry))

      # for IOCTLS, get the actual name if we have it
      ioctl_name = None
      if ioctl is not None:
        ioctl_name = get_ioctl_name(ioctl)
        if ioctl_name is None:
          ioctl_name = ioctl
        else:
          ioctl_name = ioctl_name + "(%s)" % ioctl

      # a Complete request or DeviceIocontrol Input has data entries following it so process them
      data_str = None
      last_entry = None
      if request_type in ['Complete','DeviceIocontrol Input','AcpiNotifyIoctl Write', 'AcpiNotifyIoctl Read']:
        if request_type == 'Complete':
          last_entry = get_last_entry(entries,irp_address)
          #print "last_entry =%s" % (str(last_entry))

        # for entries with a parent update the fields if necessary
        if last_entry is not None:
          update_entry(entry, last_entry)
          #print "entry updated = %s" % (str(entry))
        
        # grab the data values if there are any
        data_values = ''
        if length != '0':
          line_parts = line.split(':')
          #print "line_parts = %s" % (str(line_parts))
          while line_parts[1].find('0x') >= 0:
            data = line_parts[2].strip()
            data = data.replace(' - ', ' ')
            if not len(data_values):
              data_values = data
            else:
              data_values = data_values + ' ' + data        
            line = f.readline()
            line_parts = line.split(':')

            # for valid data lines there must be at least three parts
            if len(line_parts) < 3:
              break
        else:
          data_values = 'None'

        #print "data_values = %s" % data_values
        #print "entry = %s" % (str(entry))

        if data_values is not None:
          # print out the data
          Type = entry['Type']

          # filter according to passed in values (or default)
          if can_print(read_type,write_type,devicecontrol_type,Type):
            #print "CAN PRINT!!!, Type = %s" % Type
            if length_filter is None or length == length_filter:

              # try to align data value prints across reads and writes for comparisions
              if Type == 'Read':
                Type += ' '
              elif Type == 'DeviceIocontrol Input' or Type == 'DeviceIocontrol Output':
                Type += "(%s:%s)" % (entry['Driver'],entry['Ioctl'])
              if verbose > 0:
                Type += "(%s)" % entry['Irp']

              # try to align data value prints across DeviceIocontrols for comparisions
              if request_type == 'DeviceIocontrol Input' or request_type == 'AcpiNotifyIoctl Read':
                Type += ' '
              data_str = "%s: %s" % (Type,data_values)
              driver = entry['Driver']

      if verbose > 1:
        if last_entry is not None:
          Type = entry['Type']
          request_type = Type + ' Complete'
        else:
          Type = request_type

        if can_print(read_type,write_type,devicecontrol_type,Type):
          if ioctl_name is not None:
            st = "%s: Irp:%s Length:%s Driver:%s Ioctl:%s" % (request_type,irp_address,length,driver,ioctl_name) 
          else:
            st = "%s: Irp:%s Length:%s Driver:%s" % (request_type,irp_address,length,driver) 
          if time_stamp and len(time):
            st = "(%s)" % time + st

          if 'tag' in values:
            st = st + "Tag:%s InfoLevel:%s(%s)" % (str(values['tag']),info_levels[values['infolevel']],str(values['infolevel']))
            if values['infolevel'] == '0x3':
              st = st + " AtRate:%s" % (str(values['atrate']))
          print "%s" % st

      # due to incomplete data from the log file filter out empty complete entries
      if data_str is not None and data_str != 'Complete: None':
        if convert is not None:
          l = data_str
          data_str = do_convert(data_str,convert,base) 

        if time_stamp and len(time):
          data_str = "(%s)" % time + data_str
        print data_str

      # add this entry to the list for later processing
      entries.append(entry)
