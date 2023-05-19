#!/usr/bin/env python3.8

"""
EDL - Edit an External Dynamic List

Many firewalls or other security services can import EDL's, or, lists of hosts to block.
This project can be used as command line tool and as a module. It has the capability to
to search, add, delete and view the designated list.

This module produces 2 EDL's, a master list and the actual EDL. The actual EDL is one IP
address per line.

By default, this script only takes IP addresses and will reject anything that is NOT
resolvable into an IP address.

The master list contains the IP, user who submitted the IP, the timestamp, whois owner and
abuse contact and finally a comment about the block. This information is for accounting purposes
only (although you might find the abuse contact useful), but the actual EDL is derived from it.
The actual EDL is just a list of IP's with no commentary or other designators. You must save the
master EDL and consumable EDL's, although in some places you can set the module to save the
consumable EDL automatically.

The Exclude file, will take IPs or CIDR ranges.

The reason for IPs only, we discovered a bug in Palo Alto's code for consuming EDL's that *really*
messed up our PA Cluster.

This module relies on two other modules from the same author, whois-rdap and py-helper-mod.
You must have them installed for this to work properly.

The module also has a shell mode.

Lastly, the module will also look at the environment variables, EDLMASTER, EDLFILE, EDLEXCLUDES
and EDLCOMMENTS for the EDL list and any excluded addresses or ranges and the default comment.
The default comment is only used when one is not provided.
"""

import os, sys
import re
import time
import argparse
import ipaddress
import random
import uuid
import copy
import csv
import getpass
import subprocess
import shutil
import socket
import cmd
import configparser

# Ma Stoof

import py_helper as ph
from py_helper import Msg,DbgMsg,ErrMsg,DebugMode,CmdLineMode,ModuleMode
from py_helper import Taggable, AuditTrail, ValidIP, IsIPv4, IsIPv6, IsNetwork
from py_helper import Clear, NewLine, Pause, Menu
from py_helper import SwapFile, Dump, BackUp, Restore, Touch, TmpFilename
from py_helper import TimestampConverter

# My module for getting whois info about IPs being placed in the EDL.
import whois

from datetime import datetime, timedelta
import datetime as dt

#
# Classes and Support
#

# Enviroment Variables to look for
__EnvEDLMaster__ = "EDLMASTER"
__EnvEDLFile__ = "EDLFILE"
__EnvEDLExcludes__ = "EDLEXCLUDE"
__EnvComment__ = "EDLCOMMENT"

# EDL Columns
Columns = [ "ip","user","timestamp","owner","abuse","comment","status" ]

# EDL Dictionary Row Template
EDLRowTemplate = {
	"ip" : None,
	"user" : None,
	"timestamp" : None,
	"owner" : None,
	"abuse" : None,
	"comment" : None,
	"status" : None
}

Timeformat = "%m/%d/%Y %H:%M:%S %p"

# EDL Entry
class EDLEntry(Taggable):
	"""
	Wrapper around an EDL Row line in the EDL file
	"""
	entry = None

	# Init Instance
	def __init__(self,**kwargs):
		"""Init instance"""
		global EDLRowTemplate, Columns

		super().__init__()

		entry = kwargs.get("entry",None)

		ip = kwargs.get("ip",None)
		user = kwargs.get("user",None)
		timestamp = kwargs.get("timestamp",datetime.now())
		owner = kwargs.get("owner",None)
		abuse = kwargs.get("abuse",None)
		comment = kwargs.get("comment",None)
		status = kwargs.get("status",False)

		if entry:
			if type(entry) == dict:
				self.entry = entry
			elif type(entry) == list:
				self.entry = dict(zip(Columns,entry))
		elif ip != None:
			self.entry = copy.deepcopy(EDLRowTemplate)

			self.entry["ip"] = ip
			self.entry["user"] = user
			self.entry["timestamp"] = timestamp
			self.entry["owner"] = owner
			self.entry["abuse"] = abuse
			self.entry["comment"] = comment
			self.entry["status"] = status

	# Print Entry
	def Print(output=None):
		"""Print Entry"""

		if output:
			output.write(entry)
			output.write("\n")
		else:
			print(self.entry)

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

	# Get or Set Status
	def Status(self,value=None):
		"""Return the status from the EDL Line"""

		if value:
			self.entry["status"] = value

		return self.entry["status"] if self.entry else None

	# Return Internal Dictionary
	def GetDict(self):
		"""Return the underlying Dictionary"""

		return self.entry

	#
	# Object to CSV Row or CSV Row to Object Operations
	#

	# Get Row For Appending To EDL File
	def GetRow(self):
		"""Get Row Suitable to appending to the EDL File"""

		global EDLRowTemplate, Timeformat

		row = None

		if self.entry != None:
			row = copy.deepcopy(EDLRowTemplate)

			for key,value in self.entry.items():
				if key == "timestamp":
					value = value.strftime(Timeformat)
				elif key == "status":
					value = "1" if value else "0"

				row[key] = value

		return row

	# Read Row
	def ReadRow(self,row):
		"""Read CSV Row Into EDL Entry"""

		global EDLRowTemplate, Timeformat

		self.entry = copy.deepcopy(EDLRowTemplate)

		for key,value in row.items():
			if key == "timestamp":
				value = datetime.strptime(value,Timeformat)
			elif key == "status":
				value = True if value == "1" else False

			self.entry[key] = value

		return self

	# Write Row
	def WriteRow(self,writer):
		"""Write Entry to CSV File"""

		global EDLRowTemplate, Timeformat

		if self.entry != None:
			row = self.GetRow()

			writer.writerow(row)

		return self

	#
	# Support Functions
	#

	# Get Whois Info
	def GetWhois(self):
		"""Get Whois Information"""

		if self.entry != None:
			owner = None
			abuse = None

			response = whois.GetIPInfo(self.entry["ip"])

			if response and response[0] == 200:
				owner = response[1] if len(response) > 1 and response[1] else "unknown"
				abuse = response[7] if len(response) > 7 and response[7] else ""
			else:
				owner = "unknown" if owner == None else owner
				abuse = "" if abuse == None else abuse

			self.entry["owner"] = owner
			self.entry["abuse"] = abuse

# EDL Shell
class EDLShell(cmd.Cmd):
	# cmd.Cmd attributes
	intro = "Welcome to the EDL Shell. Type help or ? to list commands.\n"
	prompt = "edl > "
	file = None

	# Parsers
	__parser__ = None
	# Create Command Parer
	__create_parser__ = None
	# Save Parser
	__save_parser__ = None
	# Dump Parser
	__dump_parser__ = None

	# Set Parser
	def SetParser(self,parser):
		"""Set Parser"""

		self.__parser__ = parser

	# Init Internal Parsers
	def InitParsers(self):
		"""Init Parsers"""

		if self.__create_parser__ == None:
			self.__create_parser__ = parser = argparse.ArgumentParser(description="File creation sub command")
			subparser = parser.add_subparsers(help="File creation operations",dest="operation")

			all_parser = subparser.add_parser("all",help="Create all files")
			all_parser.add_argument("masterfile",nargs="?",help="New Master file")
			all_parser.add_argument("edlfile",nargs="?",help="New edl file")
			all_parser.add_argument("excludes",nargs="?",help="New exclude file")

			master_parser = subparser.add_parser("master",help="Create master file")
			master_parser.add_argument("masterfile",nargs="?",help="Path to masterfile")

			edl_parser = subparser.add_parser("edl",help="Create edl file")
			edl_parser.add_argument("edl",nargs="?",help="Path to EDL file")

			ex_parser = subparser.add_parser("excludes",help="Create excludes file")
			ex_parser.add_argument("excludes",nargs="?",help="Path to excludes file")

		if self.__save_parser__ == None:
			self.__save_parser__ = parser = argparse.ArgumentParser(description="Save EDL sub command")
			parser.add_argument("edl",help="EDL file to save to")
			parser.add_argument("master",help="Master file for EDL")

		if self.__dump_parser__ == None:
			self.__dump_parser__ = parser = argparse.ArgumentParser(description="Dump file sub command")
			parser.add_argument("file",nargs="?",help="Dump selected file (master,edl,excludes)")

	# Create All Files
	def do_create(self,arguments):
		"""
		Create Masterfile, EDLFile and exlcudes, if they do not current exist
		"""

		global EDLMaster, EDLFile, Excludes

		if self.__create_parser__ == None: self.InitParsers()

		arguments = ph.ParseDelimitedString(arguments)

		try:
			args,unknowns = self.__create_parser__.parse_known_args(arguments)

			if args.operation == "all":
				DbgMsg("Creating ALL - {args.master}, {args.edl}, {args.excludes}")

				if args.masterfile != None:
					EDLMaster = args.masterfile

				CreateMaster()

				if args.edlfile != None:
					EDLFile = args.edlfile

				ph.Touch(EDLFile)

				if args.excludes != None:
					Excludes = args.excludes

				ph.Touch(Excludes)
			elif args.operation == "master":
				DbgMsg(f"Creating Master {args.master}")

				if args.masterfile != None:
					EDLMaster = args.masterfile

				CreateMaster()
			elif args.operation == "edl":
				DbgMsg(f"Creating edl {args.edl}")

				if args.edlfile != None:
					EDLFile = args.edlfile

				ph.Touch(EDLFile)
			elif args.operation == "excludes":
				DbgMsg(f"Creating Excludes - {args.excludes}")

				if args.excludes != None:
					Excludes = args.excludes

				ph.Touch(Excludes)
			else:
				Msg("No operation, all, master, edl, excludes provided, can't do anything")

		except SytemExit:
			pass

	# Get or Set Debugmode
	def do_debugmode(self,arguments):
		"""Get or set DebugMode"""

		if arguments != None and arguments != "":
			try:
				DebugMode(ParseBool(arguments))
			except:
				Msg(f"What is {arguments}?")
		else:
			Msg(f"Debugmode = {DebugMode()}")

	# Get or Set EDL Master file
	def do_masterfile(self,arguments):
		"""Get or Set Masterfile"""

		global EDLMaster

		if arguments != None and arguments != "":
			EDLMaster = arguments

		Msg(f"EDL Master file is currently {EDLMaster}")

	# Get or Set EDL File
	def do_edlfile(self,arguments):
		"""Get or Set EDL File"""

		global EDLFile

		if arguments != None and arguments != "":
			EDLFile = arguments

		Msg(f"EDL file is currently {EDLFile}")

	# Get or Set Excludes File
	def do_excludes(self,arguments):
		"""Get or Set Excludes File"""

		global Excludes

		if arguments != None and arguments != "":
			Excludes = arguments

		Msg(f"Excludes file is currently {Excludes}")

	# Add Comment To Responses
	def do_comment(self,arguments):
		"""Add comments to responses"""

		global Responses

		arguments = arguments.replace("'","").replace('"',"")

		if not arguments in Responses:
			AddResponse(arguments)
			Msg(f"Added {arguments}")
		else:
			Msg("Already exists in list")

	# Show Comments
	def do_comments(self,arguments):
		"""Show comments"""

		global Responses

		Msg("\nComments\n===========")

		count = 1

		for response in Responses:
			Msg("{}. {}".format(count,response))
			count += 1

		NewLine()

	# Get or set audit file
	def do_auditfile(self,arguments):
		"""Set or Get Audit File"""

		global AuditFile

		if arguments != None and arguments != "":
			AuditFile = arguments

		Msg(f"Audit file is currently {AuditFile}")

	# Do DNS Query for Arguments.
	def do_dns(self,arguments):
		"""Do DNS Check For Arguments"""

		hosts = re.split("\s+",arguments)

		iplist = HostIPCheck(hosts)

		for ip in iplist:
				Msg(f"{ip}")

	# Command handlers

	# Save EDL File
	def do_save(self,arguments):
		"""Save EDL File"""

		global EDLMaster, EDLFile

		if self.__save_parser__ == None: self.InitParsers()

		arguments = arguments.split(" ")

		try:
			args,unknowns = self.__save__parser__.parse_known_args(arguments)

			edlfile = EDLFIle if args.edl == None else args.edl
			masterfile = EDLMaster if args.master == None else args.master

			Save(edlfile,masterfile)
		except SystemExit:
			pass

	# Add To EDL
	def do_add(self,arguments):
		"""Add Entry to EDL"""

		global Responses

		params = list()

		params.append("add")

		args = ph.ParseDelimitedString(arguments)

		params.extend(args)

		try:
			args, unknowns = self.__parser__.parse_known_args(params)

			comment = args.comment

			if CmdLineMode() and comment in [ None, "" ]:
				comment = GetComment()
			elif len(Responses) > 0:
				comment = Responses[0]
			else:
				comment = "No comment provided"

			entries = Add(args.host,comment=args.comment)

			for entry in entries:
				Msg(f"Added {entry}")
		except SystemExit:
			pass

	# Bulk Add
	def do_bulkadd(self,args):
		"""Bulk Add"""

		filename,comment = args.split(" ",1)

		if comment == "": comment = None

		BulkAdd(filename,comment=comment)

	# Remove From EDL
	def do_remove(self,arguments):
		"""Remove Entry From EDL"""

		params = list()

		params.append("remove")

		params.extend(re.split("\s+",arguments))

		args = __parser__.parse_args(params)

		removed = Remove(args.host)

	# Remove Alias
	def do_del(self,arguments):
		"""Remove Alias"""

		self.do_remove(arguments)

	# Bulk Remove
	def do_bulkrm(self,args):
		"""Bulk Remove"""

		BulkRemove(args)

	# Search From EDL
	def do_search(self,arguments):
		"""Search EDL"""

		params = list()

		params.append("search")

		targs = ph.ParseDelimitedString(arguments)

		params.extend(targs)

		try:
			args,unknowns = ParseArgs(arguments=params)

			results = Search(args.search_str,by_type=args.by_type)

			for result in results:
				Msg(result)
		except SystemExit:
			pass

	# Cull
	def do_cull(self,args):
		"""Cull Entries from File"""

		if args == "simulate":
			items = Cull(simulate=True)
		else:
			items = Cull()

		buffer = ""

		for item in items:
			buffer += f"{item}\n"

		ph.Page(buffer)

	# Dump File
	def do_dump(self,arguments):
		"""Dump File"""

		global EDLMaster,EDLFile,Excludes

		if self.__dump_parser__ == None: self.InitParsers()

		try:
			args,unknowns = self.__dump_parser__.parse_known_args(arguments.split(" "))

			file = None

			if args.file == "master":
				file = EDLMaster
			elif args.file == "edl":
				file = EDLFile
			elif args.file == "excludes":
				file = Excludes
			else:
				Msg(f"Don't know what '{args.file}' is")

			if file:
				if os.path.exists(file):
					ph.Page(file)
				else:
					Msg(f"File, {file} does not presently exist")
		except SystemExit:
			pass

	# Show Data Information
	def do_info(self,args):
		"""Show Information About Data"""

		global EDLMaster, EDLFile, Excludes, AuditFile, DMEDLFile
		global MaxAge, LastAdd, Responses, Version
		global __EnvEDLMaster__, __EnvEDLFile__, __EnvEDLExcludes__,__EnvComment__

		def GetInfo(filename):
			msg = "does not presently exist"

			if os.path.exists(filename):
				value = ph.BestUnits(os.path.getsize(filename),units=1)
				lines = ph.LineCount(filename=filename)

				msg = f"{value} {lines} lines"

			return msg

		Msg("{:<20} : {}".format("Version",Version))
		Msg("{:<20} : {} {}".format("EDL Master File",EDLMaster,GetInfo(EDLMaster)))
		Msg("{:<20} : {} {}".format("EDL File",EDLFile,GetInfo(EDLFile)))
		Msg("{:<20} : {} {}".format("Exclude File",Excludes,GetInfo(Excludes)))
		Msg("{:<20} : {} {}".format("Test EDL File",DMEDLFile,GetInfo(DMEDLFile)))
		Msg("{:<20} : {}".format("Audit File",AuditFile))
		Msg("{:<20} : {} days".format("MaxAge",MaxAge.days))
		Msg("{:<20} : {}".format("LastAdd",LastAdd))
		Msg("{:<20} : {}".format("EDL Master Env",os.environ.get(__EnvEDLMaster__,"Not present")))
		Msg("{:<20} : {}".format("EDL File Env",os.environ.get(__EnvEDLFile__,"Not Present")))
		Msg("{:<20} : {}".format("Excludes Env",os.environ.get(__EnvEDLExcludes__,"Not Present")))
		Msg("{:<20} : {}".format("Comment Env",os.environ.get(__EnvComment__,"Not Present")))
		Msg("{:<20} : {}".format("Responses",""))
		for comment in Responses:
			Msg(f"\t{comment}")

	# Exit
	def do_quit(self,args):
		"""Exit Shell"""
		return True

	# Exit
	def do_exit(self,arguments):
		"""Exit Shell"""
		return True

#
# Variables and Constants
#

# Ask before sumbit
Confirm=False

# Explicit No Prompt
NoPrompt=False

# Autosave EDLFIle
AutoSave=False

# Version
VERSION=(0,0,33)
Version = __version__ = ".".join([ str(x) for x in VERSION ])

# Parser
__Parser__ = None

# Config File
__Config__ = "/etc/edl/config"

# Response list
Responses = list()

# Test File
DMEDLFile="/tmp/edl.test.txt"
# EDL Master File
EDLMaster = "/tmp/edlmaster.csv"
# EDL File
EDLFile="/tmp/edl.txt"
# Exclude File
Excludes="/tmp/edl-excl.txt"
# Audit Trail File
AuditFile=None

# Acceptable IPs
NoIPv6 = False

# Cull MaxAge
# See Unix 'man date' for details on the -d option for format of this string
MaxAge=timedelta(days=90)

# Last added item
LastAdd=""

# Audit Messages
# Excluded Audit Message
AuditMsg_Excluded = "The IP {} is excluded from being blocked"

#
# Lambdas
#

# Parse Text String Into Boolean Value
ParseBool = lambda S : False if S.lower() == "false" else True

#
# Functions
#

#
# Support Functions
#

# Add To Audit Trail
def Audit(message):
	"""Wrapper for writing to an audit trail, IF the audit file is defined"""

	if AuditFile:
		AuditTrail(AuditFile,message)

# Check Host/IP Submitted
def HostIPCheck(host):
	"""
	Check Host String, if IP, pass through, if not, attempt DNS resolution.
	If resolution fails, return None

	"""

	hosts = None
	iplist = list()

	if not type(host) is list:
		hosts = [ host ]
	else:
		hosts = host

	for host in hosts:
		if not ValidIP(host):
			try:
				# host = socket.gethostbyname(host)

				records = socket.getaddrinfo(host,None)

				for record in records:
					ip = record[4][0]

					if not ip in iplist:
						iplist.append(ip)
			except:
				# Pass errors silently
				pass
		else:
			iplist.append(host)

	return iplist

# Create or Convert Timestamp
def Timestamp(timestamp=None):
	"""Create or Convert Timestamp"""

	global Timeformat

	tsc = TimestampConverter()

	reg_ex = "^\d{1,2}/\d{1,2}/\d{4}$\s+ \d{1,2}\:\d{1,2}\:\d{1,2}\s+([aA]|[pP])[mM]$"
	fmt = Timeformat

	tsc.AddTimeFormat(reg_ex,fmt)

	dt = None

	if timestamp == None:
		dt = datetime.now()
		timestamp = dt.strftime(fmt)
	elif type(timestamp) is datetime:
		dt = timestamp
		timestamp = timestamp.strftime(fmt)
	elif type(timestamp) is str:
		tsc = ph.TimestampConverter()

		dt = tsc.ConvertTimestamp(timestamp)
		timestamp = dt.strftime(fmt)

	return timestamp,dt

# Preset Comment for adds
def AddResponse(comment):
	"""
	Add a comment to the cached comment list
	"""
	global Responses

	if not comment in Responses:
		Responses.append(comment)

#
# Business Functions
#

# Save Consumable EDL
def Save(edlfile=None,masterfile=None):
	"""Save Consumable EDL"""

	global EDLMaster, EDLFile

	if masterfile == None: masterfile = EDLMaster
	if edlfile == None: edlfile = EDLFile

	with open(masterfile,"r",newline="") as csvfile:
		reader = csv.DictReader(csvfile)

		with open(edlfile,"w") as f_out:
			for row in reader:
				entry = EDLEntry().ReadRow(row)

				ip = entry.IP()

				f_out.write(f"{ip}\n")

# Create Master File
def CreateMaster(masterfile=None):
	"""
	Create Master File

	Since the master file is a CSV with a header, this function will create
	an empty CSV with header.
	"""

	global EDLMaster, Columns

	if masterfile == None: masterfile = EDLMaster

	DbgMsg(f"Masterfile = {masterfile}")

	with open(masterfile,"w",newline='') as csvfile:
		writer = csv.DictWriter(csvfile,fieldnames=Columns)

		DbgMsg("Writing header")
		writer.writeheader()

# Determine if supplied IP address is in the excludes list
def Excluded(ip,exclude_file=None):
	"""
	Determine if the supplied IP string appears inside the exclude file, if an exclude file is supplied and exists.
	"""

	global Excludes

	excluded = False

	if exclude_file == None: exclude_file = Excludes

	if ValidIP(ip) and exclude_file and os.path.exists(exclude_file):
		with open(exclude_file,"rt") as excludes:
			for entry in excludes:
				cleaned = entry.strip().split("#")
				item = cleaned[0].strip()

				if IsNetwork(item):
					ip = ipaddress.ip_address(ip)

					net = ipaddress.ip_network(item)

					if ip in net:
						excluded = True
						Audit(AuditMsg_Excluded.format(ip))
						break
				elif item == ip:
					excluded = True
					break

	return excluded

# Find Single Entry
def FindEntry(ip,masterfile=None):
	"""
	Find a Block Entry in the EDL
	"""

	global EDLMaster, Columns

	if masterfile == None: masterfile = EDLMaster

	entry = None

	if ValidIP(ip):
		if os.path.exists(masterfile):
			with open(masterfile,newline='') as csvfile:
				reader = csv.DictReader(csvfile)

				for row in reader:
					if ip == row["ip"]:
						entry = EDLEntry().ReadRow(row)
						break

	return entry

# Search For Block
def Search(search_str,by_type="ip",exit_early=False,silent=False,masterfile=None):
	"""Search the EDL for an existing block"""

	global EDLMaster, Columns

	if masterfile == None: masterfile = EDLMaster

	hits = list()

	tsc = TimestampConverter()

	with open(masterfile, newline="") as csvfile:
		reader = csv.DictReader(csvfile)

		for row in reader:
			entry = EDLEntry().ReadRow(row)

			if by_type != "timestamp" and search_str == row[by_type]:
				values = list(row.values())
				hits.append(values)

				if exit_early: break
			elif by_type == "timestamp":
				sts = tsc.ConvertTimestamp(search_str)

				if sts != None:
					if sts == enty.Timestamp():
						hits.append(entry)

						if exit_early: break

	return hits

# Append TO EDL
def AppendToEDL(entry,masterfile=None,edlfile=None):
	"""
	Append new entry to the EDL
	"""
	global EDLMaster, Columns, AutoSave, NoIPv6, AuditFile

	DbgMsg("Entering AppendToEDL")

	if masterfile == None: masterfile = EDLMaster

	success = True

	if type(entry) is EDLEntry:
		pass
	elif type(entry) is list:
		entry = dict(zip(Columns,entry))

		entry = EDLEntry(entry=entry)
	elif type(entry) is dict:
		entry = EDLEntry(entry=entry)

	ip = entry.IP()

	if IsIPv4(ip) or (IsIPv6(ip) and not NoIPv6):
		if not os.path.exists(masterfile):
			CreateMaster(masterfile=masterfile)

		with open(masterfile,"a",newline='') as csvfile:
			writer = csv.DictWriter(csvfile,Columns)

			entry.WriteRow(writer)

		if AuditFile: Audit("Appended {} to edl master".format(entry.GetRow()))

		if AutoSave: Save(edlfile,masterfile)
	else:
		DbgMsg(f"Rejected {ip}, NoIPv6 = {NoIPv6}")
		success = False

	return success

# Add EntryEntry
def AddEDLEntry(entry,masterfile=None,edlfile=None):
	"""Add Filled In EDLEntry To EDL"""

	existing = False
	excluded = False
	success = True

	if entry != None:
		if not Excluded(entry.IP()):
			found = FindEntry(entry.IP(),masterfile)

			if found == None:
				if entry.Owner() == None or entry.Abuse() == None:
					entry.GetWhois()

				AppendToEDL(entry,masterfile=masterfile,edlfile=edlfile)
			else:
				existing = True
		else:
			exclude = True
			success = False
	else:
		success = False

	return (success,excluded,existing)

# Add IP (or list of IPs, or DNS Names) To EDL Master
def Add(host,user=None,timestamp=None,owner=None,abuse=None,comment=None,protect=False,nosleep=False,masterfile=None,edlfile=None):
	"""Add Host/List of Hosts/Subnets/List of subnets/DNS names to EDL Master"""

	global LastAdd, Responses, EDLRowTemplate

	if user == None:
		user = getpass.getuser()

	if timestamp == None:
		timestamp = datetime.now()
	elif type(timestamp) == str:
		old_timestamp,timestamp = Timestamp(timestamp)

	if comment == None:
		if len(Responses) > 0:
			comment = Responses[0]
		else:
			comment = "No comment supplied"

	results = list()
	hosts = None

	if type(host) is list:
		hosts = host
	else:
		hosts = [ host ]

	sanity_check = list()

	# Check for DNS names
	for host in hosts:
		if IsNetwork(host) or ValidIP(host):
			sanity_check.append(host)
		else:
			# Not subnet or IP
			ips = HostIPCheck(host)

			sanity_check.extend(ips)

	hosts = sanity_check

	# Builds a list of 5-tuples (invalid-flag,exists-flag,entry,excluded-flag,edl_entry)
	for host in hosts:
		# Determine if Excluded
		# Determine if already in EDL
		# If abuse/owner None, do Whois
		# if comment None, try to get comment
		# Create EDLEntry, give to AppendToEDL

		entry = EDLEntry(ip=host,user=user,timestamp=timestamp,owner=owner,abuse=abuse,comment=comment,status=protect)

		result = {
			"invalid" : False,
			"exists" : False,
			"entry" : None,
			"excluded" : False,
			"edl_entry" : None
			}

		if not Excluded(host):
			found = FindEntry(host)

			if found == None:
				if owner == None or abuse == None:
					entry.GetWhois()

				AppendToEDL(entry,masterfile=masterfile,edlfile=edlfile)
				result["entry"] = list(entry.GetRow())
				result["edl_entry"] = entry
				results.append(tuple(result.values()))
			else:
				# Exists
				result["exists"] = True
				result["entry"] = found.GetRow()
				result["edl_entry"] = found
				results.append(tuple(result.values()))
		else:
			# Excluded
			entry["excluded"] = True
			results.append(tuple(entry.values()))

		if len(hosts) > 1 and not nosleep:
			time.sleep(4)

	return results

# Bulk Add
def BulkAdd(fname,user=None,timestamp=None,owner=None,abuse=None,comment=None,protect=False,masterfile=None,edlfile=None):
	"""
	Bulk add file of IP address to EDL. The file should be on IP per line.
	"""

	global AutoSave

	success = True

	adds = list()

	# Because of the way this is built, disable autosave temporarily to prevent excessive i/o
	tmp = AutoSave
	AutoSave = False

	try:
		if os.path.exists(fname):
			with open(fname,"rt") as ip_list:
				for line in ip_list:
					results = Add(line.strip(),user,timestamp,owner,abuse,comment,protect=protect,nosleep=True,masterfile=masterfile,edlfile=edlfile)

					for result in results:
						invalidFlag, existingFlag, entry,excluded, edl_entry = result

						if existingFlag or invalidFlag: # If exists or is invalid, skip the sleep interval
							continue
						else:
							adds.append(entry)

					# Must sleep to avoid WHOIS from Rate Limiting us
					time.sleep(4)
		else:
			success = False
	finally:
		AutoSave = tmp

	if len(adds) > 0 and AutoSave: Save(edlfile,masterfile)

	return success, adds

# Remove Block
def Remove(hosts,masterfile=None,edlfile=None):
	"""
	Remove an IP from the EDL Master if an audit trail is defined, it is recorded in the audit trail.
	The EDL is backed up before changes
	"""
	global EDLMaster, EDLFile, Columns, AutoSave

	if masterfile == None: masterfile = EDLMaster
	if edlfile == None: edlfile = EDLFile

	hitcount = 0

	TMP=TmpFilename(".edl_rem")

	# Backup Existing EDLMaster
	BackUp(masterfile)

	hosts = HostIPCheck(hosts)

	# Open Existing EDL Master
	with open(masterfile,newline='') as csvfile:
		reader = csv.DictReader(csvfile,Columns)

		# Open Temp file
		with open(TMP,"a",newline='') as tmpfile:
			writer = csv.writer(tmpfile)

			# Read in existing entries and compare to the item(s) we want removed
			# Only copy non-hits to temp file
			for row in reader:
				if type(hosts) is list:
					if not row["ip"] in hosts:
						r = list(row.values())
						writer.writerow(r)
					else:
						Audit(f"{row['ip']} removed from EDL")
						hitcount += 1
				elif row["ip"] != hosts:
					r = list(row.values())
					writer.writerow(r)
				else:
					Audit(f"{row['ip']} removed from EDL")
					hitcount += 1

	if hitcount == 0:
		os.remove(TMP)
	else:
		SwapFile(TMP,masterfile)

		if AutoSave:
			Save(edlfile,masterfile)

	return hitcount

# Bulk Remove
def BulkRemove(fname,masterfile=None,edlfile=None):
	"""
	Given a file with one IP per line, remove the given IPs from the EDL if they are in there
	"""
	global AutoSave

	success = True

	removes = list()

	if os.path.exists(fname):
		with open(fname,"rt") as ip_list:
			for ip in ip_list:
				removes.append(ip.strip())

		Remove(removes,masterfile,edlfile)
	else:
		success = False

	return success

# Replace IP Record in EDL
def Replace(fields,masterfile=None,edlfile=None):
	"""
	Replace an EDL line (defined by the blocked IP), with the new supplied one.
	"""

	Remove(fields[0])

	DbgMsg(fields)

	Add(fields[0],fields[1],fields[2],fields[3],fields[4],fields[5],masterfile=masterfile,edlfile=edlfile)

# Cull Records
def Cull(max_age=None,masterfile=None,edlfile=None,simulate=False):
	"""
	Using the module level MaxAge, remove entries from the EDL, older then the interval.
	"""

	global EDLMaster, MaxAge, Columns, AutoSave

	if masterfile == None: masterfile = EDLMaster

	if max_age == None:
		max_age = MaxAge
	else:
		if type(max_age) == str and max_age.isdigit():
			max_age = timedelta(days=int(max_age))
		elif type(max_age) == int:
			max_age = timedelta(days=max_age)
		elif type(max_age) == timedelta:
			pass
		else:
			max_age = MaxAge

	too_old = datetime.now() - max_age

	matches = list()

	lines = 0

	with open(masterfile,newline='') as csvfile:
		# Assuming here that the CSV file has a header... if not, an error may result here
		# reader = csv.DictReader(csvfile,Columns)
		reader = csv.DictReader(csvfile)

		for row in reader:
			lines += 1

			entry = EDLEntry()
			entry.ReadRow(row)

			if entry.Status():
				continue

			if entry.Timestamp() <= too_old:
				DbgMsg(f"removing {row['ip']}")
				Audit(f"{entry.IP()} was culled from edl, inserted on {entry.Timestamp()}")
				matches.append(entry.IP())

	if len(matches) > 0 and not simulate:
		DbgMsg(f"Removing old items")

		if not DebugMode(): Remove(matches,masterfile,edlfile)

		# No need to autosave here, Remove will handle it

	DbgMsg(f"{lines} processed, {len(matches)} matched")

	if DebugMode():
		Dump(masterfile)

	return matches

# Search for item in Exclude List
def SearchExclude(entry,exclude_file=None):
	"""
	Search for, and return, exclude item in the exlude file (if defined and exists)
	"""
	global Excludes

	if exclude_file == None: exclude_file = Excludes

	found = False

	if exclude_file and os.path.exists(exclude_file):
		with open(exclude_file,"rt") as excludes:
			for line in excludes:
				items = line.split("#")

				if entry in items[0].strip():
					found = True
					break

	return found

# Add Item to Exclude List
def AddExclude(item,comment=None,exclude_file=None):
	"""
	Add an IP or network exclude to the exclusion list
	"""
	global Excludes

	if exclude_file == None: exclude_file = Excludes

	success = True

	BackUp(exclude_file)

	if SearchExclude(item,exclude_file):
		Msg("{} already in list".format(item))
		success = False
	else:
		with open(exclude_file,"at") as excludes:
			line = item

			if comment:
				line += (" # " + comment)

			excludes.write(line + "\n")
			DbgMsg("{}, added".format(line))
			Audit("{} added to excludes".format(item))

	return success

# Remove Excluded IP/Range
def RemoveExclude(item,exclude_file=None):
	"""
	Remove the given IP or subnet from the excludes list
	"""
	global Excludes

	if exclude_file == None: exclude_file = Excludes

	success = False

	tmp = TmpFilename()

	BackUp(exclude_file)

	hits = 0

	with open(tmp,"wt") as tmpfile:
		with open(exclude_file,"rt") as excludes:
			for line in excludes:
				if item in line:
					hits += 1
					DbgMsg("{}, being removed".format(line))
					Audit("{} removed from excludes".format(item))
				else:
					line = line.strip()
					tmpfile.write(line + "\n")

	if hits > 0:
		os.remove(exclude_file)
		SwapFile(tmp,exclude_file)
		success = True
	else:
		os.remove(tmp)

	return success

#
# Interactive Functions
#

# Direct Edit EDL List
def DirectEditEDL(masterfile=None,edlfile=None,filename=None,save=False):
	"""
	Direct edit the EDL
	Only active in CmdLineMode
	"""
	global EDLMaster, EDLFile, AutoSave

	if masterfile != None:
		filename = EDLMaster
	elif edlfile != None:
		filename = EDLFile
	elif filename == None:
		filename = EDLMaster

	if ModuleMode(): return

	reply = "y"

	if not NoPrompt:
		reply = input("====> WARNING : Direct Editting is discouraged, continue anyway (y/N)? ").strip()

	if reply in [ "y", "Y", "yes" ]:
		BackUp(filename)

		# Execute nano with the edl master
		subprocess.call(["nano",filename])
		Audit("EDL Master was editted manually")

		if save or AutoSave: Save(EDLFile,EDLMaster)

# Get Comment
def GetComment():
	"""Get the currently cached comments"""

	global Responses

	if ModuleMode(): return

	comment = None

	if len(Responses) > 0:
		Msg("q|quit To Quit\nEnter any string for new comment\nOr select provided comment(s)\n=============")

		eo = { "q":"Quit", }
		reply = Menu(Responses,extra_options=eo,no_match=True)

		if reply and not reply == "q":
			if reply == "":
				reply = "No comment"

			if not reply in Responses:
				AddResponse(reply)

			comment = reply
	else:
		comment = input("Enter comment : ")

		if comment == "":
			comment = "No Comment"

		AddResponse(comment)

	return comment

# Edit One Entry
def EditEntry(ip,masterfile=None,edlfile=None):
	"""
	Edit a single entry of the EDL (based on the IP).
	Only active in CmdLineMode
	"""

	global EDLMaster, EDLFile

	if masterfile == None: masterfile = EDLMaster
	if edlfile == None: edlfile = EDLFILE

	entry = FindEntry(ip,masterfile)

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

			Replace(fields,masterfile,edlfile)
			Audit("{} entry was manually editted - was '{}'".format(ip,old_line))

#
# Parser functions, Diags and tests
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

# Build Parser
def BuildParser():
	"""Build Parser"""

	global __Parser__

	if __Parser__ == None:
		# Config Argument Parser
		__Parser__ = argparse.ArgumentParser(description="EDL Manager")

		__Parser__.add_argument("-v","--version",action="store_true",help="Show version")
		__Parser__.add_argument("-d","--debug",action="store_true",help="Place app in debug mode")
		__Parser__.add_argument("--noipv6",action="store_true",help="IPv6 addresses are not accepted")
		__Parser__.add_argument("--master",help="Set Master file")
		__Parser__.add_argument("--edl",help="Set EDL Data file")
		__Parser__.add_argument("--exclude",help="Set Exclude file")
		__Parser__.add_argument("--age",help="Set maximum age in days for cull operations")
		__Parser__.add_argument("-p","--prompt",action="store_true",help="Set prompt before actions committed")
		__Parser__.add_argument("-n","--noprompt", action="store_true",help="Set to no prompting")
		__Parser__.add_argument("--autosave",action="store_true",help="Set Autosave mode for EDLFile")

		# Create Sub parsers
		subparsers = __Parser__.add_subparsers(help="Operations on EDL",dest="operation")

		# One offs

		# Shell Mode (Completely Interactive Feature)
		shell_parser = subparsers.add_parser("shell",help="Enter shell mode")

		# Test Mode
		test_parser = subparsers.add_parser("test",help="Enter Test Code")

		# Save Command
		save_parser = subparsers.add_parser("save",help="Save master file contents to EDL File")
		save_parser.add_argument("edl",nargs="?",default=None,help="Optional EDL file path")
		save_parser.add_argument("master",nargs="?",default=None,help="Optional masterfile, EDL file must be supplied first")

		# Edit Master File (Completely Interactive Feature)
		edit_master_parser = subparsers.add_parser("edit",help="Edit Masterfile")
		edit_master_parser.add_argument("-s","--save",action="store_true",help="Once master edit completes, save EDL")
		edit_master_parser.add_argument("file",nargs="?",help="File to edit, masterfile by default")

		# Backup command (Non-Interactive)
		backup_parser = subparsers.add_parser("backup",help="Backup data files")

		# Restore command (Non-Interactive)
		restore_parser = subparsers.add_parser("restore",help="restore data files")

		# Cull (Non-Interactive Feature)
		cull_parser = subparsers.add_parser("cull",aliases=["expire"],help="Cull Master/EDL file of older records")
		cull_parser.add_argument("days",nargs="?",default=None,help="Maximum age of entry in days")

		# Dump Master File (Completely Interactive)
		dump_parser = subparsers.add_parser("dump",aliases=["get","getmaster","getm"],help="Dump Master file")
		dump_parser.add_argument("file_spec",nargs="?",choices=["master","masterfile","edl","edlfile","excludes"],help="Optional file specification")

		# More complex sub commands

		# Add Functionality (Partially Interactive Feature)
		add_parser = subparsers.add_parser("add",help="Add an entry to EDL")
		add_parser.add_argument("-p","--protect",action="store_true",help="Set protection for record")
		add_parser.add_argument("host",help="Host to block (by default, IPv4 or hostname")
		add_parser.add_argument("comment",help="Comment for EDL Entry")

		# Bulk Add (Partially Interactive Feature)
		bulkadd_parser = subparsers.add_parser("bulkadd",aliases=['ba',"bulk"],help="Bulk Add")
		bulkadd_parser.add_argument("-p","--protect",action="store_true",help="Set protection")
		bulkadd_parser.add_argument("file",help="File to import for bulk add")
		bulkadd_parser.add_argument("comment",nargs="?",help="Bulk comment (optional)")

		# Remove (Partially Interactive)
		remove_parser = subparsers.add_parser("remove",aliases=["rm","del","delete"],help="Remove specified EDL Entry")
		remove_parser.add_argument("host",help="Host to remove (IP or DNS name)")

		# Bulk Remove (Partially Interactive)
		bulkremove_parser = subparsers.add_parser("bulkremove",aliases=["bulkrm","bulkdel","bulkdelete"],help="Bulk Remove")
		bulkremove_parser.add_argument("file",help="File to import for bulk remove")

		# Search (Partially Interactive)
		search_parser = subparsers.add_parser("search",help="Search Master file")
		search_parser.add_argument("by_type",choices=["ip","cidr","dns","user","owner","abuse","timestamp"],default="ip",help="Search by given type")
		search_parser.add_argument("search_str",help="Thing to search for")

		# Exclude (Non-Interactive)
		exclude_parser = subparsers.add_parser("exclude",aliases=["ex"],help="Exclude Host or CIDR Range")
		exclude_parser.add_argument("host",help="Host or CIDR Range to add to excludes")
		exclude_parser.add_argument("comment",nargs="?",help="Comment for entry")

		# Remove Exclusion (Partially Interactive)
		rmexclude_parser = subparsers.add_parser("removeexclude",aliases=["rmex","removeex","rmx","removex"],help="Remove exclusion")
		rmexclude_parser.add_argument("hosts",help="Host or CIDR to remove from excludes")

		# View/Dump Exclude List (Partially Interactive)
		viewexclude_parser = subparsers.add_parser("viewexcludes",aliases=["vex","viewx","dumpex","getex"],help="View/Dump/Return excludes list")

		# Check Exclude for item
		checkex_parser = subparsers.add_parser("checkexcludes",aliases=["chex","checkex"],help="Check excludes for item")
		checkex_parser.add_argument("exclude",help="Exclude to check for")

		# Edit IP (Completely Interactive)
		editip_parser = subparsers.add_parser("edithost",aliases=["editip"],help="Edit single host record in master")
		editip_parser.add_argument("host",help="Host entry to edit")

	return __Parser__

# Parse Arguments
def ParseArgs(arguments=None):
	"""Parse Arguments"""

	global __Parser__, MaxAge, Confirm, NoPrompt, EDLMaster, EDLFile, Excludes, AutoSave, NoIPv6
	global Version

	args = None

	if arguments == None:
		args,unknowns = __Parser__.parse_known_args()
	else:
		args,unknowns = __Parser__.parse_known_args(arguments)

	#
	# Set State Items that need to come first
	#

	# Set Debug Mode
	if args.debug:
		PrepDebug()

	if args.noipv6:
		NoIPv6 = True

	# Check for Master File Change
	if args.master:
		EDLMaster = args.master

	# Check for EDL File Change
	if args.edl:
		EDLFile = args.edl

	# Check for Exclude Change
	if args.exclude:
		Excludes = args.exclude

	# Set Interval
	if args.age and args.age.isdigit():
		MaxAge = timedelta(days=int(args.age))
	elif args.age:
		Msg("Interval must be in days and numeric")

	# Prompt state
	if args.prompt:
		Confirm = True
		NoPrompt = False

	if args.noprompt:
		Confirm = False
		NoPrompt = True

	# Check Autosave
	if args.autosave:
		AutoSave = True

	if args.version:
		Msg(f"Version : {Version}")

	return args, unknowns

# Plugin Run Pattern Handler
def run(**kwargs):
	"""Plugin Pattern Handler"""

	global EDLMaster, EDLFile, __Parser__

	# Check Kwargs

	arguments = kwargs.get("arguments",None)
	args = kwargs.get("args",None)

	# Make sure EDL Exists, if not, provision a new one
	if not os.path.isfile(EDLFile):
		Touch(EDLFile)

	if args == None:
		# Parse 'dem args my brother
		if arguments != None:
			args,unknowns = ParseArgs(arguments)
		else:
			args,unknowns = ParseArgs()

	#
	# Now Check for actions
	#

	results = None
	success = True

	op = args.operation

	if op == "test":
		results = test()
	elif op == "shell" and CmdLineMode():
		shell = EDLShell()
		shell.SetParser(__Parser__)
		shell.cmdloop()
	elif op == "save":
		edlfile = args.edl
		masterfile = args.master

		Save(edlfile,masterfile)
	elif op == "edit" and CmdLineMode():
		filename = args.file

		if filename == None or filename in [ "masterfile", "master" ]:
			filename = EDLMaster
		elif filename == "edl":
			filename = EDLFile

		if filename != None and os.path.exists(filename):
			DirectEditEDL(filename=filename,save=args.save)
		else:
			Msg(f"'{filename}' either doesn't exist, is not readable or is pure pish, fix it")
	elif op in [ "cull", "expire" ]:
		results = Cull(args.days)

		items_culled = len(results)

		if items_culled > 0:
			Msg(f"{items_culled} records culled")

			for item in results:
				Msg(item)

	elif op == "backup":
		Backup(EDLMaster)
		Backup(EDLFile)
	elif op == "restore":
		Restore(EDLMaster)
		Restore(EDLFile)
	elif op in [ "dump", "get", "getmaster", "getm" ]:
		try:
			if args.file_spec != None:
				if args.file_spec in ["edl","edlfile"]:
					Dump(EDLFile)
				elif args.file_spec in ["excludes"]:
					Dump(Excludes)
				else:
					Dump(EDLMaster)

			else:
				Dump(EDLMaster)
		except Exception as err:
			Msg("Could not open requested file")

	elif op in [ "edithost", "editip" ]:
		host = args.host
		EditEntry(host)
	elif op == "add":
		Msg("Fast repeated adds may get rate limited by WHOIS")

		host = args.host
		comment = args.comment

		results = Add(host,comment=comment,protect=args.protect)

		for result in results:
			invalid,existing,entry,excluded,edl_entry = result

			if invalid:
				Msg(f"Invalid entry - {entry}")
			if existing:
				Msg(f"{entry['ip']} exists in EDL")

				if NoPrompt: continue

				reply = input("Exists, Show (y/n)? ")

				if reply == "y":
					Msg(entry)

			if excluded:
				Msg(f"{entry[0]} is an excluded address, it was not added to the EDL")

		success = True
	elif op in [ "bulkadd","ba","bulk" ]:
		Msg("Bulk adds have a builtin pause to prevent WHOIS from rate limiting this functionality")

		file = args.file
		comment = args.comment

		if len(Responses) > 0 and comment == None:
			comment = Responses[0]
		elif comment == None:
			comment = "No comment provided"
		else:
			AddResponse(comment)

		success,results = BulkAdd(file,comment=comment,protect=args.protect)
	elif op in [ "remove", "rm", "del", "delete" ]:
		Remove(args.host)
	elif op in [ "bulkremove", "bulkrm", "bulkdel", "bulkdelete" ]:
		BulkRemove(args.file)
	elif op == "search":
		results = Search(args.search_str,by_type=args.by_type)

		for result in results:
			Msg(result)
	elif op in [ "exclude", "ex" ]:
		AddExclude(args.host,args.comment)
	elif op in [ "removeexclude", "rmex", "removeex", "rmx", "removex" ]:
		RemoveExclude(args.hosts)
	elif op in [ "viewexcludes", "vex", "viewx", "dumpex","getex" ]:
		Dump(Excludes)
	elif op in [ "checkexcludes", "chex", "checkex", "checkx" ]:
		if SearchExclude(args.exclude):
			Msg("Is in exclude list")
		else:
			Msg("Not in exclude list")

	return results

#
# Initialization
#

# Initialize Module
def Initialize():
	"""Initialize Module"""

	global __EnvEDLMaster__,__EnvEDLFile__,__EnvEDLExcludes__,__EnvComment__,__Config__
	global EDLFile, EDLMaster, Excludes

	random.seed()

	comment = "No comment at this time"

	if os.path.exists(__Config__):
		cfg = configparser.ConfigParser()

		cfg.read(__Config__)

		EDLMaster = cfg.get("appsettings","EDLMaster",fallback="/tmp/edlmaster.csv")
		EDLFile = cfg.get("appsettings","EDLFile",fallback="/tmp/edlfile.csv")
		Excludes = cfg.get("appsettings","Excludes",fallback="/tmp/excludes.txt")

		comment = cfg.get("appsettings","Comment",fallback=comment)

	# Check Environment
	if __EnvEDLMaster__ in os.environ: EDLMaster = os.environ.get(__EnvEDLMaster__,EDLMaster)
	if __EnvEDLFile__ in os.environ: EDLFile = os.environ.get(__EnvEDLFile__,EDLFile)
	if __EnvEDLExcludes__ in os.environ: Excludes = os.environ.get(__EnvEDLExcludes__,Excludes)

	# Check for preset comment in ENV, preset if there
	comment = os.environ.get(__EnvComment__,None)

	if comment:
		AddResponse(comment)

	BuildParser()


# Init Instance
Initialize()

#
# Test Stub
#

# Run Test
def test():
	"""Test stub"""
	PrepDebug()

	DbgMsg("Life is THE test... don't fail it.")

#
# Main Loop
#

if __name__ == "__main__":
	"""Main loop for using the EDL as a cmd line script"""

	CmdLineMode(True)	# Place instance in cmdline mode

	run()
