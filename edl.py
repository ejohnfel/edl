#!/usr/bin/env python3.8

import os
import re
import sys
import time
import argparse
import ipaddress
import random
import uuid
import csv
import getpass
import subprocess
import shutil

# Ma Stoof

import py_helper as ph
from py_helper import Msg,DbgMsg,DebugMode,CmdLineMode,ModuleMode
from py_helper import Taggable, AuditTrail, ValidIP
from py_helper import Clear, NewLine, Pause, Menu
from py_helper import SwapFile, Dump, BackUp, Restore, Touch, TmpFilename

# My module for getting whois info about IPs being placed in the EDL.
import whois

from datetime import datetime
from datetime import timedelta

#
# Classes and Support
#

# EDL Columns
Columns = [ "ip","user","timestamp","owner","abuse","comment" ]

# EDl Dictionary Row Template
EDLRowTemplate = {
	"ip" : None,
	"user" : None,
	"timestamp" : None,
	"owner" : None,
	"abuse" : None,
	"comment" : None
}

# EDL Entry
class EDLEntry(Taggable):
	"""
	Wrapper around an EDL Row line in the EDL file
	"""
	entry = {}
	is_new = True

	# Init Instance
	def __init__(self,entry=None,is_new=None):
		"""Init instance"""
		global Columns

		super().__init__()

		if entry:
			if type(entry) == dict:
				self.entry = entry
			elif type(entry) == list:
				self.entry = dict(zip(Columns,entry))

			if is_new != None:
				self.is_new = is_new

	# Get IP from entry
	def IP(self,value=None):
		"""Return the blocked IP from the EDL Line"""

		if value:
			self.entry["ip"] = value

		return self.entry["ip"] if self.entry else None

	# Get User from entry
	def User(self,value=None):
		"""Return the submitting user from the EDL line"""

		if value:
			self.entry["user"] = value

		return self.entry["user"] if self.entry else None

	# Get Timestamp from entry
	def Timestamp(self,value=None):
		"""Return the time stamp the EDL entry was created from the EDL line"""

		if value:
			self.entry["timestamp"] = value

		return self.entry["timestamp"] if self.entry else None

	# Get Owner from entry
	def Owner(self,value=None):
		"""Return the Owner of the IP from the EDL line"""

		if value:
			self.entry["owner"] = value

		return self.entry["owner"] if self.entry else None

	# Get Abuse Contact from entry
	def Abuse(self,value=None):
		"""Return the abuse email address from the EDL line"""

		if value:
			self.entry["abuse"] = value

		return self.entry["abuse"] if self.entry else None

	# Get Comment from entry
	def Comment(self,value=None):
		"""Return the comment from the EDL line"""

		if value:
			self.entry["comment"] = value

		return self.entry["comment"] if self.entry else None

	# Get Row For Appending To EDL File
	def GetRow(self):
		"""Get Row Suitable to appending to the EDL File"""

		row = None

		if entry:
			row = entry.values()

		return row

# Ask before sumbit
Confirm=False

# Version
VERSION = (0,0,6)
Version = __version__ = ".".join([ str(x) for x in VERSION ])

# Response list
responses = [ ]

# Test File
DMEDLFile="/tmp/edl.test.txt"
# EDL File
EDLFile="/srv/storage/data/edl.txt"
# Exclude File
Excludes="/srv/storage/data/edl-excl.txt"
# Audit Trail File
AuditFile=None

# Cull Interval
# See Unix 'man date' for details on the -d option for format of this string
INTERVAL=timedelta(days=90)

# Last added item
LASTADD=""

# Skip Flag
SKIPFLAG=0

#
# State Initializers
#

random.seed()

#
# Functions
#

# Add To Audit Trail
def Audit(message):
	"""Wrapper for writing to an audit trail, IF the audit file is defined"""

	if AuditFile:
		AuditTrail(AuditFile,message)

# Determine if supplied IP address is in the excludes list
def Excluded(ipstr):
	"""
	Determine if the supplied IP string appears inside the exlude file, if an exclude file is supplied and exists.
	"""

	global Excludes

	excluded = False

	if Excludes and os.path.exists(Excludes):
		with open(Excludes,"rt") as excludes:
			for entry in excludes:
				cleaned = entry.strip().split("#")
				item = cleaned[0].strip()

				if re.search(ph.NETIPv4_Exp,item) or re.search(ph.NETIPv6_Exp,item):
					ip = ipaddress.ip_address(ipstr)

					net = ipaddress.ip_network(item)

					if ip in net:
						excluded = True
						Audit(aud_msg.format(ip))
						break
				elif item == ipstr:
					excluded = True
					break

	return excluded

# Preset Comment for adds
def AddResponse(comment):
	"""
	Add a comment to the cached comment list
	"""
	responses.append(comment)

# Show Comments List
def ShowComments():
	"""
	Show currently cached comments"
	"""

	global responses

	Msg("\nComments\n===========")

	count = 1

	for response in responses:
		Msg("{}. {}".format(count,response))
		count += 1

	NewLine()

# Direct Edit EDL List
def DirectEditEDL():
	"""
	Direct edit the EDL
	Only active in CmdLineMode
	"""
	global EDLFile

	if ModuleMode(): return

	reply = input("====> WARNING : Direct Editting is discouraged continue (y/N)? ")

	if reply == "y":
		BackUp(EDLFile)

		# Execute nano with the edl file
		subprocess.call(["nano",EDLFile])
		Audit("EDL File was editted manually")

# Find Single Entry
def FindEntry(ip):
	"""
	Find a Block Entry in the EDL
	"""

	global EDLFile

	entry = None

	with open(EDLFile,newline='') as csvfile:
		reader = csv.DictReader(csvfile,Columns)

		for row in reader:
			if ip == row["ip"]:
				entry = list(row.values())
				break

	return entry

# Search for item in Exclude List
def SearchExclude(entry):
	"""
	Search for, and return, exclude item in the exlude file (if defined and exists)
	"""
	global Excludes

	found = False

	if Excludes and os.path.exists(Excludes):
		with open(Excludes,"rt") as excludes:
			for line in excludes:
				items = line.split("#")

				if entry in items[0].strip():
					found = True
					break

	return found


# Search For Block
def Search(src_ip,exit_early=False,silent=False):
	"""Search the EDL for an existing block"""

	global EDLFile

	hits = []

	with open(EDLFile, newline="") as csvfile:
		reader = csv.DictReader(csvfile,Columns)

		for row in reader:
			if src_ip == row["ip"]:
				values = list(row.values())
				hits.append(values)

				if not silent: Msg(values)

				if exit_early: break

	return hits

# Get Comment
def GetComment():
	"""Get the currently cached comments"""

	global responses
	global SKIPFLAG # Why did I make this global?

	if ModuleMode(): return

	SKIPFLAG=0

	comment = None

	if len(responses) > 0:
		Msg("q|quit To Quit\nEnter any string for new comment\nOr select provided comment(s)\n=============")

		eo = { "q":"Quit", }
		reply = Menu(responses,extra_options=eo,no_match=True)

		if reply and not reply == "q":
			if reply == "":
				reply = "No comment"

			if not reply in responses:
				AddResponse(reply)

			comment = reply
	else:
		comment = input("Enter comment : ")

		if comment == "":
			comment = "No Comment"

		AddResponse(comment)

	return comment

# Append TO EDL
def AppendToEDL(entry):
	"""
	Append new entry to the EDL
	"""
	global EDLFile

	success = True

	if ValidIP(entry[0]):
		if type(entry) == EDLEntry:
			entry = entry.GetRow()
		elif type(entry) == dict:
			entry = entry.values()

		with open(EDLFile,"a",newline='') as csvfile:
			writer = csv.writer(csvfile)

			writer.writerow(entry)

		if Audit: Audit("Appended {} to edl".format(entry))
	else:
		success = False

	return success

# Add Block
def Add(ip,user=None,timestamp=None,owner=None,abuse=None,comment=None,simulate=False,as_incident=None):
	"""
	Add IP to EDL list, if not excluded and does not already exist in the list.
	If an attempt is made to add something exclude, or existing, and an audit trail
	is enabled, these are recorded.
	The output indicates the EDL entry, whether the IP was invalid and whether it
	is existing or new.
	If you expect to add entries quickly, the you must delay the add for about 4 seconds
	a WHOIS throttles queries.
	If module is in CmdLineMode, this function will prompt the user.
	The simulate parameter carries out every thing except adding the IP to the EDL.
	The EDL is not backed up automatically before adds. If you want this, you must back it up yourself
	before adding.
	"""
	global Confirm, SKIPFLAG, LASTADD

	entry = None
	existing = False
	invalid = True

	aud_excluded_msg = "Attempt to add {} to EDL was stopped because it has been excluded"
	aud_exists_msg = "Attempt to add {} to EDL was stopped because it already exists"

	if ValidIP(ip):
		invalid = False
		# Process
		# 1.a Determine if it exists in EDL already or in exclude list
		# 1.b If exists, prompt user to see it (if not in module mode), return (True,entry)
		# 1.c If exists, and in Module mode, prep return tuple (False,new_entry)
		# 2.a If not exists and NOT in module mode, prompt for comment
		# 2.b If prompt, prompt with review
		# 2.c If accepted (or not prompted) add to EDL, otherwise (False,None)

		# if exclude, bump
		if not Excluded(ip):
			existing_entry = FindEntry(ip)

			if existing_entry:
				existing = True
				entry = existing_entry

				Audit(aud_exists_msg.format(ip))
			else:
				if user == None:		# Get user if not provided
					user = getpass.getuser()

				if CmdLineMode() and comment == None:	# Get comment, if not provided
					comment = GetComment()
				elif comment == None:
					comment = 'No Comment'	# If in ModuleMode and no comment supplied

				if timestamp == None:
					now = datetime.now()
					timestamp = now.strftime(r"%m/%d/%Y %H:%M:%S %P")

				if abuse == None or owner == None:
					response = whois.GetIPInfo(ip)

					if response and response[0] == 200:
						owner = response[1] if len(response) > 1 and response[1] else "unknown"
						abuse = response[7] if len(response) > 7 and response[7] else ""
					else:
						owner = "unknown" if owner == None else owner
						abuse = "" if abuse == None else abuse

				entry = [ ip, user, timestamp, owner, abuse, comment ]

				if CmdLineMode() and Confirm:
					Msg(entry)

					reply = Pause("Add to EDL (y/N)? ")

					if reply == "y" and not simulate:
						AppendToEDL(entry)
				elif not simulate:
					AppendToEDL(entry)
		else:
			Audit(aud_excluded_msg.format(ip))
			entry = [ ip, user, timestamp, None, None, "excluded" ]
			existing = True
	else:
		Msg("{} not a valid IP".format(ip))

	if not entry == None:
		LASTADD = entry

	if as_incident != None and as_incident:
		entry = EDLEntry(entry,is_new=(not existing))

	return [ invalid, existing, entry ]

# Bulk Add
def BulkAdd(fname,user=None,timestamp=None,owner=None,abuse=None,comment=None,simulate=False):
	"""
	Bulk add file of IP address to EDL. The file should be on IP per line.
	"""
	success = True

	adds = []

	if os.path.exists(fname):
		with open(fname,"rt") as ip_list:
			for line in ip_list:
				invalidFlag, existingFlag, entry = Add(line.strip(),user,timestamp,owner,abuse,comment,simulate=simulate)

				if existingFlag or invalidFlag: # If exists or is invalid, skip the sleep interval
					continue
				else:
					adds.append(entry)

				# Must sleep to avoid WHOIS from Rate Limiting us
				time.sleep(4)
	else:
		Msg("File, {}, does not exist".format(fname))
		success = False

	return success, adds

# Rolling Adds
def RollingAdd(simulate=False):
	"""
	Designed to be a command line feature, this is essentially an EDL shell.
	You can add IP's, show the current list of input comments, directly edit and dump the EDL.
	Only active during CmdLineMode.
	"""
	global Confirm, LASTADD

	success = False

	if CmdLineMode():
		success = True

		while True:
			Msg("Type dump, to dump\nType clear to clear screen\nType comments to see comment list\nBlank line to quit\n================")
			reply = input("IP To Block : ")

			args = None

			if " " in reply:
				reply, args = reply.split(" ",maxsplit=1)

			NewLine()

			if reply == "" or reply == "q" or reply == "quit":
				break
			elif reply == "rm" or reply == "remove":
				Remove(args)
			elif reply == "dump":
				Dump(EDLFile)
			elif reply == "comments":
				ShowComments()
			elif reply == "edit":
				DirectEditEDL()
			elif reply == "clear":
				Clear()
			else:
				invalidFlag, existingFlag, entry = Add(reply,simulate=simulate)

	return success

# Remove Block
def Remove(ip,removal_message="{} was removed from the EDL"):
	"""
	Remove an IP from the EDL if an audit trail is defined, it is recorded in the audit trail.
	The EDL is backed  up before changes
	"""
	global EDLFile,Columns

	hitcount = 0

	TMP=TmpFilename(".edl_rem")

	# Backup Existing EDLFile
	BackUp(EDLFile)

	# Open Existing EDL File
	with open(EDLFile,newline='') as csvfile:
		reader = csv.DictReader(csvfile,Columns)

		# Open Temp file
		with open(TMP,"a",newline='') as tmpfile:
			writer = csv.writer(tmpfile)

			# Read in existing entries and compare to the item(s) we want removed
			# Only copy non-hits to temp file
			for row in reader:
				if type(ip) is list:
					if not row["ip"] in ip:
						r = list(row.values())
						writer.writerow(r)
					else:
						hitcount += 1
				elif row["ip"] != ip:
					r = list(row.values())
					writer.writerow(r)
				else:
					hitcount += 1

	if hitcount == 0:
		os.remove(TMP)
	else:
		SwapFile(TMP,EDLFile)
		Audit(removal_message.format(ip))

	return hitcount

# Bulk Remove
def BulkRemove(fname):
	"""
	Given a file with one IP per line, remove the given IPs from the EDL if they are in there
	"""
	success = True

	if os.path.exists(fname):
		with open(fname,"rt") as ip_list:
			items = []

			for ip in ip_list:
				items.append(ip.strip())

			Remove(items,"{} removed during bulk remove")
	else:
		success = False
		Msg("File, {}, does not exist".format(fname))

	return success

# Replace IP Record in EDL
def Replace(fields):
	"""
	Replace an EDL line (defined by the blocked IP), with the new supplied one.
	"""
	Remove(fields[0])

	DbgMsg(fields)

	Add(fields[0],fields[1],fields[2],fields[3],fields[4],fields[5])

# Edit One Entry
def EditEntry(ip):
	"""
	Edit a single entry of the EDL (based on the IP).
	Only active in CmdLineMode
	"""
	entry = FindEntry(ip)

	if entry and CmdLineMode():
		DbgMsg(entry)

		TMP = TmpFilename()

		ip = entry["ip"]
		old_line = ",".join(list(entry.values())[1:])

		with open(TMP,"wt") as tmpfile:
			print(old_line,file=tmpfile)

		subprocess.call([ "nano", TMP ])

		new_line = ""

		with open(TMP,"rt") as tmpfile:
			new_line = tmpfile.read().strip()

		if old_line != new_line:
			fields = new_line.split(",")
			fields.insert(0,ip)

			Replace(fields)
			Audit("{} entry was manually editted - was '{}'".format(ip,old_line))

# Cull Records
def Cull():
	"""
	Using the module level INTERVAL, remove entries from the EDL, older then the interval.
	"""

	global EDLFile, INTERVAL, Columns

	too_old = datetime.now() - INTERVAL

	matches = list()

	expr = "^(?P<month>\d{1,2})/(?P<day>\d{1,2})/(?P<year>\d{1,4})([\s]+(?P<hour>\d{1,2}):(?P<minute>\d{1,2}):(?P<seconds>\d{1,2})\s+(?P<meridian>(am|AM|pm|PM))){0,1}$"

	m = re.compile(expr)

	lines = 0

	ts = None

	with open(EDLFile,newline='') as csvfile:
		reader = csv.DictReader(csvfile,Columns)

		for row in reader:
			lines += 1

			match = m.match(row['timestamp'])

			if match != None:
				DbgMsg(f"{row['timestamp']}")
				month = int(match.group("month"))
				day = int(match.group("day"))
				year = int(match.group("month"))

				if match.group("hour") != None:
					hour = int(match.group("hour"))
					minute = int(match.group("minute"))
					seconds = int(match.group("seconds"))
					meridian = match.group("meridian")
				else:
					hour = 8
					minute = 0
					seconds = 0
					meridian = "AM"

				if meridian == "PM":
					hour += 12

				ts = datetime(year,month,day,hour,minute,seconds)
			else:
				DbgMsg(f"hmmm {row['timestamp']}")
				continue

			# ts = datetime.strptime("%m/%d/%Y %I:%M:%S %p",row["timestamp"])

			if ts <= too_old:
				DbgMsg(f"removing {row['ip']}")
				Audit("{} was culled from edl, inerted on {}".format(row["ip"],row["timestamp"]))
				matches.append(row["ip"])

	if len(matches) > 0:
		DbgMsg(f"Removing old items")
		if not DebugMode(): Remove(matches,"{} culled")

	Msg(f"{lines} processed")

	if DebugMode():
		Dump(EDLFile)

	return len(matches)

# Add Item to Exclude List
def AddExclude(item,comment=None):
	"""
	Add an IP or network exclude to the exclusion list
	"""
	global Excludes

	success = True

	BackUp(Excludes)

	if SearchExclude(item):
		Msg("{} already in list".format(item))
		success = False
	else:
		with open(Excludes,"at") as excludes:
			line = item

			if comment:
				line += (" # " + comment)

			excludes.write(line + "\n")
			Msg("{}, added".format(line))
			Audit("{} added to excludes".format(item))

	return success

# Remove Excluded IP/Range
def RemoveExclude(item):
	"""
	Remove the given IP or subnet from the excludes list
	"""
	global Excludes

	success = False

	tmp = TmpFilename()

	BackUp(Excludes)

	hits = 0

	with open(tmp,"wt") as tmpfile:
		with open(Excludes,"rt") as excludes:
			for line in excludes:
				if item in line:
					hits += 1
					Msg("{}, being removed".format(line))
					Audit("{} removed from excludes".format(item))
				else:
					line = line.strip()
					tmpfile.write(line + "\n")

	if hits > 0:
		os.remove(Excludes)
		SwapFile(tmp,Excludes)
		success = True
	else:
		os.remove(tmp)

	return success

#
# Diags, tests and reformatters
#

# Prep for Debug Mode Ops
def PrepDebug():
	"""Prep the module for DebugMode, which include operating on a temporary copy of the EDL"""

	global EDLFile, DMEDLFile
	# Copies current EDLFile to temp and
	# switchs to temp file for test operations
	# This way the actual EDLFile does not get messed up by accident

	DebugMode(True)

	print("Entering Debug Mode...")

	# Setup working file
	shutil.copyfile(EDLFile,DMEDLFile)

	EDLFile=DMEDLFile

	print("Working EDL is now {}".format(EDLFile))

# Reformat EDL File
def ReformatEDL():
	"""
	Seldom ued function for reformatting the EDL if another column is added
	"""
	global EDLFile, Columns

	current = [ "ip", "user", "timestamp", "comment" ]

	TMP = TmpFilename()

	BackUp(EDLFile)

	Audit("Attempting to reformat EDL")

	try:
		with open(EDLFile,newline='') as csvfile:
			reader = csv.DictReader(csvfile,current)

			DbgMsg("Source CSV Open")

			with open(TMP,"w",newline='') as tmpfile:
				writer = csv.writer(tmpfile)

				DbgMsg("Dest CSV Open, beginning reformatting")

				for row in reader:
					DbgMsg("Processing old row")

					ip = row["ip"]
					user = row["user"]
					timestamp = row["timestamp"]
					comment = row["comment"]

					DbgMsg("Trying whois for {}".format(ip))
					reply = whois.GetIPInfo(ip)

					DbgMsg("Response {}".format(reply[0]))

					if reply and reply[0] == 200:
						owner = reply[1]
						abuse = reply[7]
					else:
						owner = "unknown"
						abuse = ""

					DbgMsg("Forming new row")
					newrow = [ ip,user,timestamp,owner,abuse,comment ]

					DbgMsg("Writing - {}".format(newrow))

					writer.writerow(newrow)

					DbgMsg("Sleeping.....")
					time.sleep(4)

		SwapFile(TMP,EDLFile)
	except Exception as err:
		Msg("Shit!!!!!!!!!!!!!!\n{}".format(repr(err)))
	finally:
		if os.path.exists(TMP):
			os.remove(TMP)

#
# Test Stub
#

# Run Test
def test():
	"""Test stub"""
	PrepDebug()
	# ReformatEDL()

	# print("I do nothing ATM")

#
# Main Loop
#

if __name__ == "__main__":
	"""Main loop for using the EDL as a cmd line script"""

	# What is this CmdLineMode/ModuleMode bidness?
	# In short I write my modules to be both callable as scripts
	# And modules from other Python Scripts.
	# Having same that, the module needs to know when to act
	# like it's being called from the command line or another
	# python script.
	# ModuleMode(False) and CmdLineMode(True) are equivalent
	# as is ModuleMode(True) and CmdLineMode(False), they
	# are actually, internally, the same flag. Just the inverse of
	# each other.

	CmdLineMode(True)	# Place instance in cmdline mode

	# Make sure EDL Exists, if not, provision a new one
	if not os.path.isfile(EDLFile):
		Touch(EDLFile)

	# Check for preset comment in ENV, preset if there
	comment = os.environ.get("COMMENT")

	if comment:
		AddResponse(comment)

	# Config Argument Parser
	parser = argparse.ArgumentParser(description="EDL Manager")

	parser.add_argument("-x","--debug",action="store_true",help="Place app in debug mode")
	parser.add_argument("-e","--edit",action="store_true",help="Directly edit EDL file")
	parser.add_argument("-a","--add",help="Add given IP to EDL list")
	parser.add_argument("-b","--bulkadd",help="Bulk Add IP's in given file to EDL list")
	parser.add_argument("-y","--roll",action="store_true",help="Rolling Add")
	parser.add_argument("-r","--remove",help="Remove given IP from EDL list")
	parser.add_argument("-m","--bulkrem",help="Bulk remove IP's in given file from EDL")
	parser.add_argument("-t",help="Set cull interval in days (90 days default)")
	parser.add_argument("-z","--cull",action="store_true",help="Cull EDL items older then set interval")
	parser.add_argument("-s","--search",help="Search EDL for given IP")
	parser.add_argument("-c","--comment",help="Preset Comment provided")
	parser.add_argument("-d","--dump",action="store_true",help="Dump EDL file")
	parser.add_argument("-p","--prompt",action="store_true",help="Set prompt before actions committed")
	parser.add_argument("-q","--test",action="store_true",help="Run internal test function")
	parser.add_argument("--ex",help="Add excluded IP or CIDR range (can use -c for comments)")
	parser.add_argument("--rmex",help="Remove exclusion from exclude list")
	parser.add_argument("--vex",action="store_true",help="View/dump exclude list")
	parser.add_argument("--chex",help="Check exclude list for item")
	parser.add_argument("--backup",action="store_true",help="Backup EDL file")
	parser.add_argument("--restore",action="store_true",help="Restore simple backup if it exists")
	parser.add_argument("--editip",help="Edit one IP Entry")

	# Parse 'dem args my brother
	args = parser.parse_args()

	#
	# Set State Items that need to come first
	#

	# Set Debug Mode
	if args.debug:
		PrepDebug()

	# Backup EDL File if Asked
	if args.backup:
		BackUp(EDLFile)

	# Restore EDL Backup, if it exists
	if args.restore:
		Restore(EDLFile)

	# Set Interval
	if args.t and args.t.isdigit():
		INTERVAL = timedelta(days=int(args.t))
	elif args.t:
		Msg("Interval must be in days and numeric")

	# Preset Comment
	if args.comment:
		AddResponse(args.comment)

	# Prompt state
	if args.prompt:
		Confirm=True

	#
	# Now Check for actions
	#

	if args.edit:
		DirectEditEDL()
	elif args.editip:
		EditEntry(args.editip)
	elif args.add:
		Msg("Fast repeated adds may get rate limited by WHOIS")
		invalidFlag, existingFlag, entry = Add(args.add)
		if existingFlag:
			reply = input("Show (y/n)? ")
			if reply == "y":
				Msg(entry)
	elif args.bulkadd:
		Msg("Bulk adds have a builtin pause to prevent WHOIS from rate limiting this functionality")
		if len(responses) > 0:
			comment = responses[0]

		success,adds = BulkAdd(args.bulkadd,comment=comment)
	elif args.roll:
		RollingAdd()
	elif args.remove:
		Remove(args.remove)
	elif args.bulkrem:
		BulkRemove(args.bulkrem)
	elif args.cull:
		Cull()
	elif args.search:
		Search(args.search)
	elif args.dump:
		Dump(EDLFile)
	elif args.ex:
		AddExclude(args.ex,args.comment)
	elif args.rmex:
		RemoveExclude(args.rmex)
	elif args.vex:
		Dump(Excludes)
	elif args.chex:
		if SearchExclude(args.chex):
			Msg("Is in exclude list")
		else:
			Msg("Not in exclude list")

	if args.test:
		TestFunction()

#if DebugMode: Pause()
#if DebugMode: Dump()

