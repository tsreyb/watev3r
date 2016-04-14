#!/usr/bin/python

import re
import time
import subprocess as sp
from datetime import datetime
from datetime import timedelta

STATSFILE = '/proc/net/dev'

parseIpStats = re.compile("^\
(?P<srcip>\d+\.\d+\.\d+\.\d+)\s+<->\s+\
(?P<dstip>\d+\.\d+\.\d+\.\d+)\s+\
(?P<rxframes>\d+)\s+\
(?P<rxbytes>\d+)\s+\
(?P<txframes>\d+)\s+\
(?P<txbytes>\d+)\s+\
(?P<totframes>\d+)\s+\
(?P<totbytes>\d+)\s+\
(?P<relstart>\S+)\s+\
(?P<duration>\S+)\s*$")

#   +-------+
#---| touch |------------------------------------------------------------------
#   +-------+
#
# Like /bin/touch, but not quite as mature

def touch(file):
    open(file, 'a').close()

#   +-------------+
#---| do_capinfos |------------------------------------------------------------
#   +-------------+
#
# Display an overall summary of the pcap file (number packets, duration, etc.)

def do_capinfos(pcapfile):

    child = sp.Popen([ '/usr/sbin/capinfos', '-cuyxm', pcapfile ], shell=False, stdout=sp.PIPE, stderr=sp.PIPE)

    outbuf = ''
    for line in child.stdout:
      outbuf += line

    streamdata = child.communicate()[0]
    rc = child.returncode

    if rc != 0:
      print '     WARNING: capinfos returned non-zero status:',rc

    for line in outbuf.split('\n'):
      print '    ', line.strip()
      
      
#   +-----------+
#---| ignorable |--------------------------------------------------------------
#   +-----------+
#
# Returns True if a line contains something we do not care about.
#
# TO DO:
#
# Make regular expressions more stringent.
#
# Parse actual values to do integer comparisons (rather than counting
# spaces between fields)

def ignorable(line):

  THRESH_totframes = 25

  if re.search("^..:..:..:..:..:..    .-. ..:..:..:..:..:..          .", line):
    return True

  parsed = re.search(parseIpStats, line)

  if parsed:
    if int(parsed.group('totframes')) <= THRESH_totframes:
      return True

  if re.search("^Filter:.No Filter.", line):
    return True

  # if we get this far it isn't ignorable
  return False

#   +------------------+
#---| uty_capsummaries |-------------------------------------------------------
#   +------------------+
#
# Display a summary of top conversations for traffic of a particular category
#
#   -----        ----------------------------
#   categ        Meaning
#   -----        ----------------------------
#    eth         MAC Addresses conversations
#    ip          IP Address conversations
#
#------------------------------------------------------------------------------
def uty_capsummaries(pcapfile, categ):

    child = sp.Popen([ '/usr/sbin/tshark', '-zconv,'+categ, '-nqr', pcapfile ], shell=False, stdout=sp.PIPE, stderr=sp.PIPE)

    outbuf = ''
    for line in child.stdout:
      outbuf += line

    streamdata = child.communicate()[0]
    rc = child.returncode

    if rc != 0:
      print 'WARNING: tshark -zconv, '+categ+' returned non-zero status:',rc

    for line in outbuf.split('\n'):
      #Ignore some output that we have no interest in
      if not ignorable(line):
        print line.strip()

#   +-----------------+
#---| do_capsummaries |--------------------------------------------------------
#   +-----------------+
#
# Does tshark summaries for several categories

def do_capsummaries(pcapfile):

    uty_capsummaries(pcapfile, 'eth')
    uty_capsummaries(pcapfile, 'ip')

#   +-----------+
#---| do_tshark |--------------------------------------------------------------
#   +-----------+
#
# This function spawns an instance of tshark which collects packets on a
# particular interface for a period of time, saving the results to disk for
# later analysis.

def do_tshark(iface,duration):

    OUTDIR = 'PCAPS'
    MAX_PKTS   =  1000000
    MAX_FILESZ = 10000000

    now = datetime.now()
    OUTFILE = "%s/tsharkout_%s_%s.pcap" % (OUTDIR, iface, now.strftime('%Y-%m%d-%H%M%S'))

    #-- Create the pcap file as regular user (otherwise only root can read it)
    touch(OUTFILE)

    #-- Run tshark
    child = sp.Popen([ '/usr/bin/sudo', '/usr/sbin/tshark', '-qn',
     '-i'+iface, '-c'+str(MAX_PKTS), '-aduration:'+str(duration),
     '-afilesize:'+str(MAX_FILESZ), '-w'+OUTFILE ], shell=False, stdout=sp.PIPE, stderr=sp.PIPE)

    streamdata = child.communicate()[0]
    rc = child.returncode

    if rc == 0:
      do_capinfos(OUTFILE)
      do_capsummaries(OUTFILE)
      
    else:
      print 'WARNING: tshark returned non-zero status:', rc

#   +----------+
#---| getstats |---------------------------------------------------------------
#   +----------+

def getstats():

  stats = {}

  FH = open(STATSFILE, 'r')

  for line in FH:

    line = line.strip()

    if line != "":

      groups = re.match("^([^:]+)\s*:\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", line)

      if groups:

        iface = groups.group(1)

        stats[iface] = {
         'rxbytes' : groups.group(2),
         'rxpkts' : groups.group(3),
         'rxerrs' : groups.group(4),
         'rxdrop' : groups.group(5),
         'rxfifo' : groups.group(6),
         'rxframe' : groups.group(7),
         'rxcompressed' : groups.group(8),
         'rxmulticast' : groups.group(9),
         'txbytes' : groups.group(10),
         'txpackets' : groups.group(11),
         'txerrs' : groups.group(12),
         'txdrop' : groups.group(13),
         'txfifo' : groups.group(14),
         'txcolls' : groups.group(15),
         'txcarrier' : groups.group(16),
         'txcompressed' : groups.group(17)
        }

  FH.close()

#   +-------------+
#---| check_stats |------------------------------------------------------------
#   +-------------+

def check_stats(prevstats, stats, direction, capifs):

    print
    print '==',direction.upper()

    THRESH = 1000000

    for iface in sorted(stats):

      for key in stats[iface].keys():

        if re.search(direction, key, re.IGNORECASE):

          diff = int(stats[iface][key]) - int(prevstats[iface][key])

          if diff >= 10:
            print '%4s %13s : %20s - %20s = %d' % (iface, key, stats[iface][key], prevstats[iface][key], diff)

          if diff > THRESH:
            capifs.add(iface)

#   +------+
#---| MAIN |-------------------------------------------------------------------
#   +------+

first = True

while True:

  stats = getstats()

  if first:
    first = False

  else:

    print
    print '='*64
    print '===', datetime.now().strftime('%Y-%m%d-%H:%M:%S')

    capifs = set()

    check_stats(prevstats, stats, 'rx', capifs)
    check_stats(prevstats, stats, 'tx', capifs)

    for iface in capifs:
      do_tshark(iface,4)

  prevstats = stats
  time.sleep(10)

  return stats
