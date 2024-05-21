#!/usr/bin/env python3

"""
EDL - Edit an External Dynamic List

Many firewalls or other security services can import EDL's, or, lists of hosts to block.
This project can be used as command line tool and as a module. It has the capability to
to search, add, delete and view the designated list.

This module produces 2 EDL's, a master list and the actual EDL. The actual EDL is one IP
address or FQDN per line. IP's and FQDN's are kept in separate files for, er, reasons.

The master list contains the IP/FQDN, user who submitted the item, the timestamp, whois owner and
abuse contact and finally a comment about the block. This information is for accounting purposes
only (although you might find the abuse contact useful), but the actual EDL is derived from it.
The actual EDL is just a list of IP's or FQDNs with no commentary or other designators. You must save the
master EDL and consumable EDL's, although in some places you can set the module to save the
consumable EDL automatically.

The Exclude file, will take IPs, CIDR ranges or domain names.

We discovered a bug in Palo Alto's code for consuming EDL's that *really* messed up our PA Cluster.
This has likely been fixed by now, though. But due to this, this app/module, keeps IPs and FQDNs
separate. (Hint, the FQDN's really upset the Palo Altos if not formatted correctly, it didn't just
outright reject badly formatted items).

This module relies on two other modules from the same author, whois-rdap and py-helper-mod.
You must have them installed for this to work properly. And py-helper-mod requires, requests.

The module also has a shell mode.

Lastly, the module will also look at the environment variables, EDLMASTER, EDLFILE, EDLEXCLUDES
and EDLCOMMENTS for the EDL list and any excluded addresses, ranges and FQDNs and the default comment.
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
from py_helper import Msg,DbgMsg,DbgAuto,ErrMsg,DebugMode,CmdLineMode,ModuleMode
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
Columns = [ "item","user","timestamp","owner","abuse","comment","status" ]


# EDL Dictionary Row Template
EDLRowTemplate = {
	"item" : None,
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

		item = kwargs.get("ip",None)
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
		elif item != None:
			self.entry = copy.deepcopy(EDLRowTemplate)

			self.entry["item"] = item
			self.entry["user"] = user
			self.entry["timestamp"] = timestamp
			self.entry["owner"] = owner
			self.entry["abuse"] = abuse
			self.entry["comment"] = comment
			self.entry["status"] = status

	# Print Entry
	def Print(self,output=None):
		"""Print Entry"""

		if output:
			output.write(self.entry)
			output.write("\n")
		else:
			print(self.entry)

	# Check format of Item
	def IsIP(self):
		"""Check ITEM to see if it's an IP"""

		is_ip = False

		if self.entry is not None:
			item = self.entry["item"]

			try:
				ip = ipaddress.ip_address(item)
				is_ip = True
			except:
				is_ip = False

		return is_ip

	# Get IP from entry
	def Item(self,value=None):
		"""Return the blocked IP from the EDL Line"""

		if value:
			self.entry["item"] = value

		return self.entry["item"] if self.entry else None

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

		# 0 means protected (perma ban)
		# >0 means days banned

		if value:
			self.entry["status"] = value

		return self.entry["status"] if self.entry else None

	# Return Internal Dictionary
	def GetDict(self):
		"""Return the underlying Dictionary"""

		return self.entry

	def Values(self):
		"""Get Values from Entry Dict"""

		results = list()

		if self.entry is not None:
			results = self.entry.values()

		return results

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
				elif key == 'ip':
					key = "item"

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
			elif key == 'ip':
				key = "item"

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
			item = self.entry["item"]

			if not self.IsIP():
				# Get Resolve to IP... if possible
				try:
					name, aliases, addresslist = socket.gethostbyname_ex(item)
					if name is not None:
						item = socket.gethostbyname(name)
					else:
						item = addresslist[0]
				except:
					return

			owner = None
			abuse = None

			response = whois.GetIPInfo(item)

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
	parsers = dict()

	def __init__(self):
		"""Init Instance"""

		# Init Super class
		super().__init__()

		# Edit Master File (Completely Interactive Feature)
		#edit_master_parser = subparsers.add_parser("edit",help="Edit Masterfile")
		#edit_master_parser.add_argument("-s","--save",action="store_true",help="Once master edit completes, save EDL")
		#edit_master_parser.add_argument("file",nargs="?",help="File to edit, masterfile by default")

		# Backup command (Non-Interactive)
		#backup_parser = subparsers.add_parser("backup",help="Backup data files")

		# Restore command (Non-Interactive)
		#restore_parser = subparsers.add_parser("restore",help="restore data files")

		# Cull (Non-Interactive Feature)
		#cull_parser = subparsers.add_parser("cull",aliases=["expire"],help="Cull Master/EDL file of older records")
		#cull_parser.add_argument("days",nargs="?",default=None,help="Maximum age of entry in days")

		# Dump Master File (Completely Interactive)
		#dump_parser = subparsers.add_parser("dump",aliases=["get","getmaster","getm"],help="Dump Master file")
		#dump_parser.add_argument("file_spec",nargs="?",choices=["master","masterfile","edl","edlfile","excludes"],help="Optional file specification")

		# More complex sub commands

		# Remove (Partially Interactive)
		#remove_parser = subparsers.add_parser("remove",aliases=["rm","del","delete"],help="Remove specified EDL Entry")
		#remove_parser.add_argument("host",help="Host to remove (IP or DNS name)")

		# Bulk Remove (Partially Interactive)
		#bulkremove_parser = subparsers.add_parser("bulkremove",aliases=["bulkrm","bulkdel","bulkdelete"],help="Bulk Remove")
		#bulkremove_parser.add_argument("file",help="File to import for bulk remove")

		# Search (Partially Interactive)
		#search_parser = subparsers.add_parser("search",help="Search Master file")
		#search_parser.add_argument("by_type",choices=["ip","cidr","dns","user","owner","abuse","timestamp"],default="ip",help="Search by given type")
		#search_parser.add_argument("search_str",help="Thing to search for")

		# Exclude (Non-Interactive)
		#exclude_parser = subparsers.add_parser("exclude",aliases=["ex"],help="Exclude Host or CIDR Range")
		#exclude_parser.add_argument("host",help="Host or CIDR Range to add to excludes")
		#exclude_parser.add_argument("comment",nargs="?",help="Comment for entry")

		# Remove Exclusion (Partially Interactive)
		#rmexclude_parser = subparsers.add_parser("removeexclude",aliases=["rmex","removeex","rmx","removex"],help="Remove exclusion")
		#rmexclude_parser.add_argument("hosts",help="Host or CIDR to remove from excludes")

		# View/Dump Exclude List (Partially Interactive)
		#viewexclude_parser = subparsers.add_parser("viewexcludes",aliases=["vex","viewx","dumpex","getex"],help="View/Dump/Return excludes list")

		# Check Exclude for item
		#checkex_parser = subparsers.add_parser("checkexcludes",aliases=["chex","checkex"],help="Check excludes for item")
		#checkex_parser.add_argument("exclude",help="Exclude to check for")

		# Edit IP (Completely Interactive)
		#editip_parser = subparsers.add_parser("edithost",aliases=["editip"],help="Edit single host record in master")
		#editip_parser.add_argument("host",help="Host entry to edit")

	# Init Internal Parsers
	def InitParsers(self):
		"""Init Parsers"""

		if not "debug" in self.parsers:
			# Debug Mode Parser
			self.parsers["debug"] = parser = argparse.ArgumentParser(description="Enable or disable debugmode")
			parser.add_argument("operation",choices=["get","true","false","enable","disable"],help="Enable or disable debugmode")

		if not "create" in self.parsers:
			# Create Parser
			self.parsers["create"] = parser = argparse.ArgumentParser(description="File creation sub command")
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

		if not "save" in self.parsers:
			# Save Parser
			self.parsers["save"] = parser = argparse.ArgumentParser(description="Save EDL sub command")
			parser.add_argument("edl",help="EDL file to save to")
			parser.add_argument("master",help="Master file for EDL")

		if not "add" in self.parsers:
			# Add Functionality (Partially Interactive Feature)

			self.parsers["add"] = parser = argparse.ArgumentParser(description="Add EDL Sub command")

			parser.add_argument("-p","--protect",action="store_true",help="Set protection for record")
			parser.add_argument("-b","--ban",help="Ban for supplied days")
			parser.add_argument("host",help="Host to block (by default, IPv4 or hostname")
			parser.add_argument("comment",nargs='?',help="Comment for EDL Entry")

		if not "bulkadd" in self.parsers:
			# Bulk Add Functionality

			self.parsers["bulkadd"] = parser = argparse.ArgumentParser(description="Bulk add sub command")

			parser.add_argument("-p","--protect",action="store_true",help="Set protection")
			parser.add_argument("-c","--comment",default=None,help="Add comment")
			parser.add_argument("filenames",nargs="+",help="Filenames containing new adds")

		if not "remove" in self.parsers:
			# Remove Functionality

			self.parsers["remove"] = parser = argparse.ArgumentParser(description="Remove sub command")

			parser.add_argument("host",help="Host entry to remove")

		if not "bulkremove" in self.parsers:
			# Bulk Remove Functionality

			self.parsers["bulkremove"] = parser = argparse.ArgumentParser(description="Bulk Remove sub command")

			parser.add_argument("filenames",nargs="+",help="Files containing hosts to remove")

		if not "status" in self.parsers:
			# Status Parser
			self.parsers["status"] = parser = argparse.ArgumentParser(description="Status sub command")
			subparser = parser.add_subparsers(help="Entry status operations",dest="operation")

			ssearch = subparser.add_parser("search",help="Search by status")

			ssearch.add_argument("value",help="Status value to search for, (0|1)")
			ssearch.add_argument("op",nargs="?",choices=["eq","ne","lt","le","gt","ge"],default="eq",help="Search operation")

			modify = subparser.add_parser("modify",help="Modify entry status")

			modify.add_argument("ip",help="IP of entry to modify")
			modify.add_argument("value",help="New status value")

		if not "dump" in self.parsers:
			self.parsers["dump"] = parser = argparse.ArgumentParser(description="Dump file sub command")
			parser.add_argument("file",nargs="?",choices=["master","edl","excludes",""],default="master",help="Dump selected file (master,edl,excludes)")

		if not "cull" in self.parsers:
			self.parsers["cull"] = parser = argparse.ArgumentParser(description="Cull records")
			parser.add_argument("-s","--simulate",action="store_true",help="Run in simulation mode")
			parser.add_argument("--show",action="store_true",help="Show culled items after culling")
			parser.add_argument("days",nargs="?",help="Max age in days, optional")

	# Get or Set Debugmode (done)
	def do_debug(self,arguments):
		"""Get or set DebugMode"""

		if not "debug" in self.parsers: self.InitParsers()

		arguments = ph.ParseDelimitedString(arguments)

		args,unknowns = self.parsers["debug"].parse_known_args(arguments)

		if args.operation == "get":
			Msg(f"Debug mode {DebugMode()}")
		elif args.operation in [ "true","enable" ]:
			Msg("Enabling debugmode")
			DebugMode(True)
		elif args.operation in [ "false", "disable" ]:
			Msg("Disabling debug mode")
			DebugMode(False)

	# Enter Internal Test (done)
	def do_test(self,arguments):
		"""
		Enter Internal Test Mode
		"""

		# Test is expected to do it's own cmdlime parsing
		test(arguments)

	# Create All Files (done)
	def do_create(self,arguments):
		"""
		Create Masterfile, EDLFile and exlcudes, if they do not current exist
		"""

		global EDLMaster, EDLFile, Excludes

		if not "create" in self.parsers: self.InitParsers()

		arguments = ph.ParseDelimitedString(arguments)

		try:
			args,unknowns = self.parsers["create"].parse_known_args(arguments)

			if args.operation == "all":
				DbgMsg(f"Creating ALL - {args.master}, {args.edl}, {args.excludes}")

				if args.masterfile != None:
					EDLMaster = args.masterfile

				CreateMaster()

				if args.edlfile != None:
					EDLFile = args.edlfile

				# We now have 2 EDL files, EDLFILE and EDLFILE_fqdn
				ph.Touch(EDLFile)
				ph.Touch(f"{EDLFile}_fqdn")

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

	# Get or Set EDL Master file
	def do_masterfile(self,arguments):
		"""Get or Set Masterfile"""

		global EDLMaster

		if arguments != None and arguments != "":
			EDLMaster = arguments

			if not os.path.exists(EDLMaster):
				Touch(EDLMaster)

		Msg(f"EDL Master file is currently {EDLMaster}")

	# Get or Set EDL File
	def do_edlfile(self,arguments):
		"""Get or Set EDL File"""

		global EDLFile, EDLFile_FQDN

		if arguments != None and arguments != "":
			EDLFile = arguments
			EDLFile_FQDN = EDLFileToFQDN(EDLFile)

			if not os.path.exists(EDLFile):
				Touch(EDLFile)
			if not os.path.exists(EDLFile_FQDN):
				Touch(EDLFile_FQDN)

		Msg(f"EDL file is currently {EDLFile}/{EDLFile_FQDN}")

	# Get or Set Excludes File
	def do_excludes(self,arguments):
		"""Get or Set Excludes File"""

		global Excludes

		if arguments != None and arguments != "":
			Excludes = arguments

			if not os.path.exists(Excludes):
				Touch(Excludes)

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

		iplist, fqdns = HostCheck(hosts)

		for ip in iplist:
			Msg(f"{ip}")
		for fqdn in fqdns:
			Msg(f"{fqdn}")

	# Command handlers

	# Save EDL File
	def do_save(self,arguments):
		"""Save EDL File"""

		global EDLMaster, EDLFile, EDLFile_FQDN

		if not "save" in self.parsers: self.InitParsers()

		arguments = arguments.split(" ")

		try:
			args,unknowns = self.parsers["save"].parse_known_args(arguments)

			edlfile = EDLFile if args.edl == None else args.edl
			edlfile_fqdn = EDLFileToFQDN(edlfile)
			masterfile = EDLMaster if args.master == None else args.master

			Save(edlfile,edlfile_fqdn,masterfile)
		except SystemExit:
			pass

	# Add To EDL (done)
	def do_add(self,arguments):
		"""Add Entry to EDL"""

		global Responses, EDLMaster, EDLFile

		if not "add" in self.parsers: self.InitParsers()

		arguments = ph.ParseDelimitedString(arguments)

		try:
			args, unknowns = self.parsers["add"].parse_known_args(arguments)

			status = 90

			if args.protect:
				status = 0

			if args.ban:
				status = int(args.ban)

			comment = args.comment

			if CmdLineMode() and comment in [ None, "" ]:
				comment = GetComment()
			elif len(Responses) > 0:
				comment = Responses[0]
			else:
				comment = "No comment provided"

			entries = Add(args.host,comment=args.comment,protect=args.protect)

			for entry in entries:
				invalid,exists,entry,excluded,edl_entry = entry

				if not invalid and not exists and not excluded:
					Msg(f"Added {edl_entry.GetRow()}")
				elif excluded:
					Msg(f"Excluded {edl_entry.GetRow()}")
				elif exists:
					Msg(f"Exists {edl_entry.GetRow()}")
				elif invalid:
					Msg(f"Invalid {edl_entry.GetRow()}")
		except SystemExit:
			pass

	# Bulk Add (done)
	def do_bulkadd(self,arguments):
		"""Bulk Add"""

		if not "bulkadd" in self.parsers: self.InitParsers()

		arguments = ph.ParseDelimitedString(arguments)

		args,unknowns = self.parsers["bulkadd"].parse_known_args(arguments)

		comment = args.comment if args.comment != '' else None

		for fname in args.filenames:
			BulkAdd(fname,comment,protect=args.protect)

	# Remove From EDL (done)
	def do_remove(self,arguments):
		"""Remove Entry From EDL"""

		if not "remove" in self.parsers: self.InitParsers()

		arguments = ph.ParseDelimitedString(arguments)

		args,unknowns = self.parsers["remove"].parse_known_args(arguments)

		removed = Remove(args.host)

		if removed > 0:
			Msg(f"Removed {args.host}")
		else:
			Msg(f"{args.host} not found in masterfile")

	# Remove Alias (done)
	def do_del(self,arguments):
		"""Remove Alias"""

		self.do_remove(arguments)

	# Remove Alias (done)
	def do_rm(self,arguments):
		"""Remove Alias"""

		self.do_remove(arguments)

	# Bulk Remove (done)
	def do_bulkremove(self,arguments):
		"""Bulk Remove"""

		if not "bulkremove" in self.parsers: self.InitParsers()

		arguments = ph.ParseDelimitedString(arguments)

		args,unknowns = self.parsers["bulkremove"].parse_known_args(arguments)

		for fname in args.filenames:
			BulkRemove(fname)

	# Bulk Remove (done)
	def do_bulkrm(self,arguments):
		"""Bulk Remove"""

		self.do_bulkremove(arguments)

	# Status Search (done)
	def do_status(self,arguments):
		"""Search By Status With Different Operations"""

		global EDLMaster

		if not "status" in self.parsers: self.InitParsers()

		arguments = ph.ParseDelimitedString(arguments)

		try:
			args,unknowns = self.parsers["status"].parse_known_args(arguments)

			if args.operation == "search":
				DbgMsg(f"Searching entries in {EDLMaster} by status {args.op} {args.value}")

				results = StatusSearch(int(args.value),op=args.op,masterfile=EDLMaster)

				for result in results:
					Msg(result)
			elif args.operation in [ "modify", "mod" ]:
				DbgMsg(f"Modifying entry with {args.ip} to {args.value}")

				result = StatusModify(args.ip,int(args.value),masterfile=EDLMaster)

				if result is not None:
					Msg(result)
				else:
					Msg("{args.ip} record not found")
			else:
				Msg("No operation, search or modify, can't do anything, you did not provide a proper sub command")

		except SystemExit:
			pass
		except Exception as err:
			ErrMsg(err,"An error occured when trying search by status")

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

		simulate=False
		days = None

		if "cull" in self.parsers and args is not None:
			parser = self.parsers["cull"]

			p_args = parser.parse_args(args)

			simulate = p_args.simulate

			if p_args.days is not None:
				days = int(p_args.days)

		items = Cull(max_age=days,simulate=simulate)

		if p_args.show:
			buffer = ""

			for item in items:
				buffer += f"{item}\n"

			ph.Page(buffer)

	# Dump File (done)
	def do_dump(self,arguments):
		"""Dump File"""

		global EDLMaster,EDLFile,Excludes

		if not "dump" in self.parsers: self.InitParsers()

		if arguments == "": arguments = "master"

		arguments = ph.ParseDelimitedString(arguments)

		try:
			args,unknowns = self.parsers["dump"].parse_known_args(arguments)

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
		global D_EDLMaster, D_EDLFile, __Config__, LastAdd
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
		Msg("{:<20} : {} {}".format("Test EDL Master",D_EDLMaster,GetInfo(D_EDLMaster)))
		Msg("{:<20} : {} {}".format("Test EDL File",D_EDLFile,GetInfo(D_EDLFile)))
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

	# Exit (done)
	def do_quit(self,args):
		"""Exit Shell"""
		return True

	# Exit (done)
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
VERSION=(0,0,41)
Version = __version__ = ".".join([ str(x) for x in VERSION ])

# Parser
__Parser__ = None

# Config File
__Config__ = "/etc/edl/config"

# Response list
Responses = list()

# Debug Files
D_EDLMaster = "/tmp/edlmaster.csv"
D_EDLFile = "/tmp/edl.test.txt"
D_EDLFile_FQDN = "/tmp/edl_fqdn.test.txt"

# Test File
DMEDLFile="/tmp/edl.test.txt"
# EDL Master File
EDLMaster = "/tmp/edlmaster.csv"
# EDL File(s)
EDLFile="/tmp/edl.txt"
EDLFile_FQDN="/tmp/edl_fqdn.txt"
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

def EDLFileToFQDN(pathname):
	"""Convert EDLFile name to EDLFile_FQDN"""

	parent = os.path.dirname(pathname)
	basename = os.path.basename(pathname)
	root,ext = os.path.splitext(basename)

	fqdn_name = os.path.join(parent,f"{root}_fqdn",ext)

	return fqdn_name

# Add To Audit Trail
def Audit(message):
	"""Wrapper for writing to an audit trail, IF the audit file is defined"""

	if AuditFile:
		AuditTrail(AuditFile,message)

# Check Host/IP Submitted
def HostCheck(host):
	"""
	Check Host String, if IP, pass through, if not, attempt DNS resolution.
	If resolution fails, return None

	"""

	hosts = None
	iplist = list()
	fqdn = list()

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
				fqdn.append(host)
		else:
			iplist.append(host)

	return iplist, fqdn

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
def Save(edlfile=None,edlfile_fqdn=None,masterfile=None):
	"""Save Consumable EDL"""

	global EDLMaster, EDLFile, EDLFile_FQDN

	if masterfile == None: masterfile = EDLMaster
	if edlfile == None: edlfile = EDLFile
	if edlfile_fqdn is None: edlfile_fqdn = EDLFile_FQDN

	with open(masterfile,"r",newline="") as csvfile:
		reader = csv.DictReader(csvfile)

		with open(edlfile,"w") as edl_out:
			with open(edlfile_fqdn,"w") as edlfqdn_out:
				for row in reader:
					entry = EDLEntry().ReadRow(row)

					item = entry.Item()

					if ValidIP(item):
						edl_out.write(f"{item}\n")
					else:
						edlfqdn_out.write(f"{item}\n")


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

# Determine if supplied IP address or FQDN is in the excludes list
def Excluded(item,exclude_file=None):
	"""
	Determine if the supplied IP/FQDN string appears inside the exclude file, if an exclude file is supplied and exists.
	"""

	global Excludes

	DbgMsg("Entering edl::Excluded",dbglabel="edl")

	excluded = False

	if exclude_file == None: exclude_file = Excludes

	if exclude_file and os.path.exists(exclude_file):
		with open(exclude_file,"rt") as excludes:
			for entry in excludes:
				cleaned = entry.strip().split("#")
				cleaned_item = cleaned[0].strip()

				if ValidIP(item) and IsNetwork(cleaned_item):
					ip = ipaddress.ip_address(item)

					net = ipaddress.ip_network(cleaned_item)

					if ip in net:
						excluded = True
						Audit(AuditMsg_Excluded.format(ip))
						break
				elif cleaned_item == item:
					excluded = True
					break

	DbgMsg("Exiting edl::Excluded",dbglabel="edl")

	return excluded

# Find Single Entry
def FindEntry(item,masterfile=None):
	"""
	Find a Block Entry in the EDL
	"""

	global EDLMaster, Columns

	if masterfile == None: masterfile = EDLMaster

	entry = None

	if ValidIP(item):
		if os.path.exists(masterfile):
			with open(masterfile,newline='') as csvfile:
				reader = csv.DictReader(csvfile)

				for row in reader:
					key = "ip" if "ip" in row else "item"

					if item == row[key]:
						entry = EDLEntry().ReadRow(row)
						break

	return entry

# Search Entries by Status Value
def StatusSearch(value,op="eq",masterfile=None):
	"""Search EDL Records by Status"""

	global EDLMaster

	if masterfile == None: masterfile = EDLMaster

	hits = list()

	with open(masterfile,newline="") as csvfile:
		reader = csv.DictReader(csvfile)

		try:
			for row in reader:
				status = int(row["status"])

				if op == "eq" and status == value:
					hits.append(row)
				elif op == "ne" and status != value:
					hits.append(row)
				elif op == "lt" and status < value:
					hits.append(row)
				elif op == "le" and status <= value:
					hits.append(row)
				elif op == "gt" and status > value:
					hits.append(row)
				elif op == "ge" and status >= value:
					hits.append(row)
		except Exception as err:
			ErrMsg(err,f"There was an error while searching {masterfile}")

	return hits

# Modify Status of EDL Entry
def StatusModify(record_id,value,masterfile=None):
	"""Modify Status of EDL Entry"""

	global EDLMaster, Columns

	if masterfile == None: masterfile = EDLMaster

	try:
		with open(masterfile,newline="") as master:
			reader = csv.DictReader(master)

			tmpfilename = TmpFilename()

			with open(tmpfilename,"w",newline="") as tmpfile:
				writer = csv.DictWriter(tmpfile,Columns)

				for row in reader:
					key = "item"
					if "ip" in row:
						key = "ip"

					if row[key] == record_id:
						row["status"] = value

					writer.writerow(row)

		BackUp(masterfile)
		SwapFile(tmpfilename,masterfile)
	except Exception as err:
		ErrMsg(err,f"An error occurred while trying to modify a status value in {masterfile} for {record_id}")

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
			key = "item"

			if "ip" in row:
				key="ip"

			entry = EDLEntry().ReadRow(row)

			if by_type == "status" and int(search_str) == int(row[by_type]):
				values = list(row.values())
				hits.append(values)

				if exit_early: break
			elif by_type != "timestamp" and search_str == row[by_type]:
				values = list(row.values())
				hits.append(values)

				if exit_early: break
			elif by_type == "timestamp":
				sts = tsc.ConvertTimestamp(search_str)

				if sts != None:
					if sts == entry.Timestamp():
						hits.append(entry)

						if exit_early: break
			elif (by_type == "ip" or by_type == "item") and (search_str == row[key] or re.search(search_str,row[key]) is not None):
				hits.append(entry)

				if exit_early: break
			elif by_type == "comment" and (search_str == row["comment"] or re.search(search_str,row["comment"])):
				hits.append(entry)

				if exit_early: break
			elif by_type == "user" and (search_str == row["user"] or re.search(search_str,row["user"])):
				hits.append(entry)

				if exit_early: break
			elif by_type == "owner" and (search_str == row["owner"] or re.search(search_str,row["owner"])):
				hits.append(entry)

				if exit_early: break
			elif by_type == "abuse" and (search_str == row["abuse"] or re.search(search_str,row["abuse"])):
				hits.append(entry)

				if exit_early: break
				
	return hits

# Append TO EDL
def AppendToEDL(entry,masterfile=None,edlfile=None,edlfile_fqdn=None):
	"""
	Append new entry to the EDL
	"""
	global EDLMaster,EDLFile,EDLFile_FQDN, Columns, AutoSave, NoIPv6, AuditFile

	DbgMsg("Entering edl::AppendToEDL",dbglabel="edl")

	if masterfile == None: masterfile = EDLMaster

	success = True

	if type(entry) is EDLEntry:
		pass
	elif type(entry) is list:
		entry = dict(zip(Columns,entry))

		entry = EDLEntry(entry=entry)
	elif type(entry) is dict:
		entry = EDLEntry(entry=entry)

	item = entry.Item()

	if IsIPv4(item) or (IsIPv6(item) and not NoIPv6):
		if not os.path.exists(masterfile):
			CreateMaster(masterfile=masterfile)

		with open(masterfile,"a",newline='') as csvfile:
			writer = csv.DictWriter(csvfile,Columns)

			entry.WriteRow(writer)

		if AuditFile: Audit("Appended {} to edl master".format(entry.GetRow()))

		if AutoSave: Save(edlfile,edlfile_fqdn,masterfile)
	else:
		if not os.path.exists(masterfile):
			CreateMaster(masterfile=masterfile)
		
		with open(masterfile,"a",newline="") as csvfile:
			writer = csv.DictWriter(csvfile,Columns)

			entry.WriteRow(writer)

		if AuditFile: Audit(f"Appended {entry.GetRow()} to edl master")

		if AutoSave: Save(edlfile,edlfile_fqdn,masterfile)
	#else:
	#	DbgMsg(f"Rejected {item}, NoIPv6 = {NoIPv6}")
	#	success = False

	DbgMsg("Exiting edl::AppendToEDL",dbglabel="edl")

	return success

# Add EntryEntry
def AddEDLEntry(entry,masterfile=None,edlfile=None,edlfile_fqdn=None):
	"""Add Filled In EDLEntry To EDL"""

	DbgMsg("Entering edl::AddEDLEntry",dbglabel="edl")

	existing = False
	excluded = False
	success = True

	if entry != None:
		if not Excluded(entry.Item()):
			found = FindEntry(entry.Item(),masterfile)

			if found == None:
				if entry.Owner() == None or entry.Abuse() == None:
					entry.GetWhois()

				AppendToEDL(entry,masterfile=masterfile,edlfile=edlfile,edlfile_fqdn=edlfile_fqdn)
			else:
				existing = True
		else:
			exclude = True
			success = False
	else:
		success = False

	DbgMsg("Exiting edl::AddEDLEntry",dbglabel="edl")

	return (success,excluded,existing)

# Add IP (or list of IPs, or DNS Names) To EDL Master
def Add(host,user=None,timestamp=None,owner=None,abuse=None,comment=None,protect=MaxAge,nosleep=False,masterfile=None,edlfile=None,edlfile_fqdn=None):
	"""Add Host/List of Hosts/Subnets/List of subnets/DNS names to EDL Master"""

	global LastAdd, Responses, EDLRowTemplate

	DbgMsg("Entering edl::Add",dbglabel="edl")

	fqdns_list = list()

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
			ips, fqdns = HostCheck(host)

			sanity_check.extend(ips)

			if len(fqdns) > 0:
				fqdns_list.extend(fqdns)

	hosts = sanity_check

	if len(fqdns_list) > 0:
		hosts.extend(fqdns_list)

	# Builds a list of 5-tuples (invalid-flag,exists-flag,entry,excluded-flag,edl_entry)
	for host in hosts:
		# Determine if Excluded
		# Determine if already in EDL
		# If abuse/owner None, do Whois
		# if comment None, try to get comment
		# Create EDLEntry, give to AppendToEDL

		entry = EDLEntry(item=host,user=user,timestamp=timestamp,owner=owner,abuse=abuse,comment=comment,status=protect)

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

				AppendToEDL(entry,masterfile=masterfile,edlfile=edlfile,edlfile_fqdn=edlfile_fqdn)

				if DebugMode(): breakpoint()

				result["entry"] = list(entry.GetRow().values())
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
			result["excluded"] = True
			result["entry"] = entry.GetRow()
			result["edl_entry"] = entry
			results.append(result)

		if len(hosts) > 1 and not nosleep:
			time.sleep(4)

	DbgMsg("Exiting edl::Add",dbglabel="edl")

	return results

# Bulk Add
def BulkAdd(fname,user=None,timestamp=None,owner=None,abuse=None,comment=None,protect=90,masterfile=None,edlfile=None,edlfile_fqdn=None):
	"""
	Bulk add file of IP address/fqdn to EDL. The file should be one IP/fqdn per line.
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
					results = Add(line.strip(),user,timestamp,owner,abuse,comment,protect=protect,nosleep=True,masterfile=masterfile,edlfile=edlfile,edlfile_fqdn=edlfile_fqdn)

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

	if len(adds) > 0 and AutoSave: Save(edlfile,edlfile_fqdn,masterfile)

	return success, adds

# Remove Block
def Remove(hosts,masterfile=None,edlfile=None,edlfile_fqdn=None):
	"""
	Remove an IP/FQDN from the EDL Master if an audit trail is defined, it is recorded in the audit trail.
	The EDL is backed up before changes
	"""
	global EDLMaster, EDLFile, EDLFile_FQDN, Columns, AutoSave

	if masterfile is None: masterfile = EDLMaster
	if edlfile is None: edlfile = EDLFile
	if edlfile_fqdn is None: edlfile_fqdn = EDLFile_FQDN

	hitcount = 0

	TMP=TmpFilename(".edl_rem")

	# Backup Existing EDLMaster
	BackUp(masterfile)

	hosts, fqdns = HostCheck(hosts)

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
					key = "item"
					if "ip" in row:
						key = "ip"

					if not row[key] in hosts and not row[key] in fqdns:
						r = list(row.values())
						writer.writerow(r)
					else:
						Audit(f"{row[key]} removed from EDL")
						hitcount += 1
				elif row[key] != hosts:
					r = list(row.values())
					writer.writerow(r)
				else:
					Audit(f"{row[key]} removed from EDL")
					hitcount += 1

	if hitcount == 0:
		os.remove(TMP)
	else:
		SwapFile(TMP,masterfile)

		if AutoSave:
			Save(edlfile,edlfile_fqdn,masterfile)

	return hitcount

# Bulk Remove
def BulkRemove(fname,masterfile=None,edlfile=None,edlfile_fqdn=None):
	"""
	Given a file with one IP per line, remove the given IPs from the EDL if they are in there
	"""
	global AutoSave

	success = True

	removes = list()

	if os.path.exists(fname):
		with open(fname,"rt") as item_list:
			for item in item_list:
				removes.append(item.strip())

		Remove(removes,masterfile,edlfile,edlfile_fqdn)
	else:
		success = False

	return success

# Replace IP/FQDN Record in EDL
def Replace(original,replacement,masterfile=None,edlfile=None,edlfile_fqdn=None):
	"""
	Replace an EDL line (defined by the blocked Item [IP or FQDN]), with the new supplied one.
	"""

	if type(original) is str:
		Remove(original)
	elif type(original) is list:
		Remove(original[0])
	elif type(original) is EDLEntry:
		Remove(original.Item)

	DbgMsg(original)

	Add(replacement[0],replacement[1],replacement[2],replacement[3],replacement[4],replacement[5],masterfile=masterfile,edlfile=edlfile,edlfile_fqdn=edlfile_fqdn)

# Cull Records
def Cull(max_age=None,masterfile=None,edlfile=None,edlfile_fqdn=None,simulate=False):
	"""
	Using the module level MaxAge, remove entries from the EDL, older then the interval.
	"""

	global EDLMaster, EDLFile, EDLFile_FQDN, MaxAge, Columns, AutoSave

	if masterfile is None: masterfile = EDLMaster
	if edlfile is None: edfile = EDLFile
	if edlfile_fqdn is None: edlfile_fqdn = EDLFile_FQDN

	if max_age is not None:
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

			if entry.Status() == 0:
				# 0 means no ban day count (i.e. protected, so we don't allow
				# culling)
				# if status is non-zero, then the value indicates the days it
				# should remain untouched.
				continue

			removal_date = entry.Timestamp() + timedelta(days=entry.Status())

			if (datetime.now() > removal_date) or (entry.Timestamp() >= too_old):
				DbgMsg(f"removing {row['item']}")
				Audit(f"{entry.Item()} was culled from edl, inserted on {entry.Timestamp()}")
				matches.append(entry.Item())

	if len(matches) > 0 and not simulate:
		DbgMsg(f"Removing old items")

		# No need to autosave here, Remove will handle it
		Remove(matches,masterfile,edlfile,edlfile_fqdn)

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
def DirectEditEDL():
	"""
	Direct edit the EDL
	Only active in CmdLineMode
	"""
	global EDLMaster, EDLFile, EDLFile_FQDN, AutoSave

	if ModuleMode(): return

	print("1. Masterfile")
	print("2. EDLFile")
	print("3. EDLFile FQDN")
	print("Q. Quit")

	reply = input("Select a number : ")

	filename = None

	if reply == "1":
		filename = EDLMaster
	elif reply == "2":
		filename = EDLFile
	elif reply == "3":
		filename = EDLFile_FQDN
	else:
		return
	
	reply = "y"

	if not NoPrompt:
		reply = input("====> WARNING : Direct Editting is discouraged, continue anyway (y/N)? ").strip()

	if reply in [ "y", "Y", "yes" ]:
		BackUp(filename)

		# Execute nano with the edl master
		subprocess.call(["nano",filename])
		Audit(f"EDL file, {filename}, was editted manually")

		Save(EDLFile,EDLFile_FQDN,EDLMaster)

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
def EditEntry(item,masterfile=None,edlfile=None,edlfile_fqdn=None):
	"""
	Edit a single entry of the EDL.
	Only active in CmdLineMode
	"""

	global EDLMaster, EDLFile, EDLFile_FQDN

	if masterfile == None: masterfile = EDLMaster
	if edlfile == None: edlfile = EDLFile
	if edlfile_fqdn is None: edlfile_fqdn = EDLFile_FQDN

	entry = FindEntry(item,masterfile)

	if entry and CmdLineMode():
		DbgMsg(entry)

		TMP = TmpFilename()

		item = entry["item"]
		old_line = ",".join(list(entry.values())[1:])

		with open(TMP,"wt") as tmpfile:
			print(old_line,file=tmpfile)

		subprocess.call([ "nano", TMP ])

		new_line = ""

		with open(TMP,"rt") as tmpfile:
			new_line = tmpfile.read().strip()

		if old_line != new_line:
			fields = new_line.split(",")
			fields.insert(0,item)

			Replace(fields,masterfile,edlfile,edlfile_fqdn)
			Audit("{} entry was manually editted - was '{}'".format(item,old_line))

#
# Parser functions, Diags and tests
#

# Prep for Debug Mode Ops
def PrepDebug():
	"""Prep the module for DebugMode, which include operating on a temporary copy of the EDL"""

	global EDLMaster, EDLFile, EDLFile_FQDN, D_EDLMaster, D_EDLFile, D_EDLFile_FQDN
	# Copies current EDLFile to temp and
	# switches to temp file for test operations
	# This way the actual EDLFile does not get messed up by accident

	DebugMode(True)

	Msg("Entering Debug Mode...")

	# Setup working file(s)
	if not os.path.exists(D_EDLMaster):
		shutil.copyfile(EDLMaster,D_EDLMaster)
	if not os.path.exists(D_EDLFile):
		shutil.copyfile(EDLFile,D_EDLFile)
	if not os.path.exists(D_EDLFile_FQDN):
		shutil.copyfile(EDLFile_FQDN, D_EDLFile_FQDN)

	EDLMaster = D_EDLMaster
	EDLFile=D_EDLFile
	EDLFile_FQDN = D_EDLFile_FQDN

	Msg("Working Master is not {}".format(EDLMaster))
	Msg("Working EDL is now {}/{}".format(EDLFile, EDLFile_FQDN))

# Clear Test Files
def ClearTests():
	"""Clear Test Files"""

	global D_EDLMaster, D_EDLFile, D_EDLFile_FQDN

	if os.path.exists(D_EDLMaster):
		os.remove(D_EDLMaster)
	if os.path.exists(D_EDLFile):
		os.remove(D_EDLFile)
	if os.path.exists(D_EDLFile_FQDN):
		os.remove(D_EDLFile_FQDN)

# Build Parser
def BuildParser():
	"""Build Parser"""

	global __Parser__

	if __Parser__ == None:
		# Config Argument Parser
		__Parser__ = argparse.ArgumentParser(description="EDL Manager",add_help=False)

		__Parser__.add_argument("-v","--version",action="store_true",help="Show version")
		__Parser__.add_argument("-d","--debug",action="store_true",help="Place app in debug mode")
		__Parser__.add_argument("-c","--clear",action="store_true",help="Remove test files")
		__Parser__.add_argument("--test",action="store_true",help="Run internal tests")
		__Parser__.add_argument("--noipv6",action="store_true",help="IPv6 addresses are not accepted")
		__Parser__.add_argument("--master",help="Set Master file")
		__Parser__.add_argument("--edl",help="Set EDL Data file")
		__Parser__.add_argument("--exclude",help="Set Exclude file")
		__Parser__.add_argument("--age",help="Set maximum age in days for cull operations")
		__Parser__.add_argument("-p","--prompt",action="store_true",help="Set prompt before actions committed")
		__Parser__.add_argument("-n","--noprompt", action="store_true",help="Set to no prompting")
		__Parser__.add_argument("--autosave",action="store_true",help="Set Autosave mode for EDLFile")
		__Parser__.add_argument("-h","--help",action="store_true",help="Print Help")

		# Create Sub parsers
		#subparsers = __Parser__.add_subparsers(help="Operations on EDL",dest="operation")

		# One offs

		# Shell Mode (Completely Interactive Feature)
		#shell_parser = subparsers.add_parser("shell",help="Enter shell mode")

		# Test Mode
		#test_parser = subparsers.add_parser("test",help="Enter Test Code")

		# Save Command
		#save_parser = subparsers.add_parser("save",help="Save master file contents to EDL File")
		#save_parser.add_argument("edl",nargs="?",default=None,help="Optional EDL file path")
		#save_parser.add_argument("master",nargs="?",default=None,help="Optional masterfile, EDL file must be supplied first")

		# Edit Master File (Completely Interactive Feature)
		#edit_master_parser = subparsers.add_parser("edit",help="Edit Masterfile")
		#edit_master_parser.add_argument("-s","--save",action="store_true",help="Once master edit completes, save EDL")
		#edit_master_parser.add_argument("file",nargs="?",help="File to edit, masterfile by default")

		# Backup command (Non-Interactive)
		#backup_parser = subparsers.add_parser("backup",help="Backup data files")

		# Restore command (Non-Interactive)
		#restore_parser = subparsers.add_parser("restore",help="restore data files")

		# Cull (Non-Interactive Feature)
		#cull_parser = subparsers.add_parser("cull",aliases=["expire"],help="Cull Master/EDL file of older records")
		#cull_parser.add_argument("days",nargs="?",default=None,help="Maximum age of entry in days")

		# Dump Master File (Completely Interactive)
		#dump_parser = subparsers.add_parser("dump",aliases=["get","getmaster","getm"],help="Dump Master file")
		#dump_parser.add_argument("file_spec",nargs="?",choices=["master","masterfile","edl","edlfile","excludes"],help="Optional file specification")

		# More complex sub commands

		# Add Functionality (Partially Interactive Feature)
		#add_parser = subparsers.add_parser("add",help="Add an entry to EDL")
		#add_parser.add_argument("-p","--protect",action="store_true",help="Set protection for record")
		#add_parser.add_argument("host",help="Host to block (by default, IPv4 or hostname")
		#add_parser.add_argument("comment",help="Comment for EDL Entry")

		# Bulk Add (Partially Interactive Feature)
		#bulkadd_parser = subparsers.add_parser("bulkadd",aliases=['ba',"bulk"],help="Bulk Add")
		#bulkadd_parser.add_argument("-p","--protect",action="store_true",help="Set protection")
		#bulkadd_parser.add_argument("file",help="File to import for bulk add")
		#bulkadd_parser.add_argument("comment",nargs="?",help="Bulk comment (optional)")

		# Remove (Partially Interactive)
		#remove_parser = subparsers.add_parser("remove",aliases=["rm","del","delete"],help="Remove specified EDL Entry")
		#remove_parser.add_argument("host",help="Host to remove (IP or DNS name)")

		# Bulk Remove (Partially Interactive)
		#bulkremove_parser = subparsers.add_parser("bulkremove",aliases=["bulkrm","bulkdel","bulkdelete"],help="Bulk Remove")
		#bulkremove_parser.add_argument("file",help="File to import for bulk remove")

		# Status Parser
		#status_parser = subparsers.add_parser("status",help="Entry Status operations")

		#ss_parser = status_parser.add_subparsers(help="Status operations")

		#search_parser = ss_parser.add_parser("search",help="Search entries by status")
		#search_parser.add_argument("value",help="Status value to search for")
		#search_parser.add_argument("op",choices=["eq","ne","lt","le","gt","ge"],default="eq",help="Search operation")

		#modify_parser = ss_parser.add_parser("modify",aliases=["mod"],help="Status modification")
		#modify_parser.add_argument("ip",help="IP of entry to modify")
		#modify_parser.add_argument("value",help="New status value")

		# Search (Partially Interactive)
		#search_parser = subparsers.add_parser("search",help="Search Master file")
		#search_parser.add_argument("by_type",choices=["ip","cidr","dns","user","owner","abuse","timestamp"],default="ip",help="Search by given type")
		#search_parser.add_argument("search_str",help="Thing to search for")

		# Exclude (Non-Interactive)
		#exclude_parser = subparsers.add_parser("exclude",aliases=["ex"],help="Exclude Host or CIDR Range")
		#exclude_parser.add_argument("host",help="Host or CIDR Range to add to excludes")
		#exclude_parser.add_argument("comment",nargs="?",help="Comment for entry")

		# Remove Exclusion (Partially Interactive)
		#rmexclude_parser = subparsers.add_parser("removeexclude",aliases=["rmex","removeex","rmx","removex"],help="Remove exclusion")
		#rmexclude_parser.add_argument("hosts",help="Host or CIDR to remove from excludes")

		# View/Dump Exclude List (Partially Interactive)
		#viewexclude_parser = subparsers.add_parser("viewexcludes",aliases=["vex","viewx","dumpex","getex"],help="View/Dump/Return excludes list")

		# Check Exclude for item
		#checkex_parser = subparsers.add_parser("checkexcludes",aliases=["chex","checkex"],help="Check excludes for item")
		#checkex_parser.add_argument("exclude",help="Exclude to check for")

		# Edit IP (Completely Interactive)
		#editip_parser = subparsers.add_parser("edithost",aliases=["editip"],help="Edit single host record in master")
		#editip_parser.add_argument("host",help="Host entry to edit")

	return __Parser__

# Parse Arguments
def ParseArgs(arguments=None):
	"""Parse Arguments"""

	global __Parser__, MaxAge, Confirm, NoPrompt, EDLMaster, EDLFile, EDLFile_FQDN, Excludes, AutoSave, NoIPv6
	global Version

	args = None

	if arguments == None:
		args,unknowns = __Parser__.parse_known_args()
	else:
		args,unknowns = __Parser__.parse_known_args(arguments)

	#
	# Set State Items that need to come first
	#

	# Clear Test File(s)
	if args.clear:
		ClearTests()

	# Set Debug Mode
	if args.debug and not DebugMode():
		PrepDebug()

	if args.noipv6:
		NoIPv6 = True

	# Check for Master File Change
	if args.master:
		EDLMaster = args.master

	# Check for EDL File Change
	if args.edl:
		EDLFile = args.edl
		EDLFile_FQDN = EDLFileToFQDN(EDLFile)

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

	DbgMsg("Entering run",dbglabel="edl")

	# Check Kwargs

	# Provided Arguments (optional)
	arguments = kwargs.get("arguments",None)
	# Processed Args (optional)
	args = kwargs.get("args",None)

	# Make sure EDL Exists, if not, provision a new one
	if not os.path.isfile(EDLFile):
		Touch(EDLFile)

	if not os.path.isfile(EDLFile_FQDN):
		Touch(EDLFile_FQDN)

	if args == None:
		# If no processed args, we assume either arguments were provided OR
		# We go with the actual command line args if not.

		if arguments is not None:
			args,unknowns = ParseArgs(arguments)
		else:
			args,unknowns = ParseArgs()

	shell = EDLShell()

	#
	# Now Check for actions
	#

	results = None
	success = True

	help_me = ("-h" in sys.argv or "--help" in sys.argv)

	if len(unknowns) > 0:
		if help_me:
			unknowns.append("-h")

		shell.onecmd(" ".join(unknowns))
	elif help_me:
		__Parser__.print_help()

	quit()

	###
	op = args.operation

	if op == "test" or args.test:
		results = test()
	elif (op == "shell" or op is None or op == "") and CmdLineMode():
		shell.cmdloop()
	elif op == "save":
		edlfile = args.edl
		masterfile = args.master

		Save(edlfile,masterfile)
	elif op == "status":
		shell.onecmd(" ".join(sys.argv))
	elif op == "edit" and CmdLineMode():
		DirectEditEDL()
	elif op in [ "cull", "expire" ]:
		results = Cull(max_age=args.days)

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
				Msg(f"{entry['ip']} is an excluded address, it was not added to the EDL")

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

	DbgMsg("Exiting run",dbglabel="edl")

	return results
	###

#
# Initialization
#

# Initialize Module
def Initialize():
	"""Initialize Module"""

	global __EnvEDLMaster__,__EnvEDLFile__,__EnvEDLExcludes__,__EnvComment__,__Config__
	global EDLFile, EDLFile_FQDN, EDLMaster, Excludes

	random.seed()

	comment = "No comment at this time"

	if os.path.exists(__Config__):
		cfg = configparser.ConfigParser()

		cfg.read(__Config__)

		EDLMaster = cfg.get("appsettings","EDLMaster",fallback="/tmp/edlmaster.csv")
		EDLFile = cfg.get("appsettings","EDLFile",fallback="/tmp/edlfile.csv")
		EDLFile_FQDN = EDLFileToFQDN(EDLFile)
		Excludes = cfg.get("appsettings","Excludes",fallback="/tmp/excludes.txt")

		comment = cfg.get("appsettings","Comment",fallback=comment)

	# Check Environment
	if __EnvEDLMaster__ in os.environ: EDLMaster = os.environ.get(__EnvEDLMaster__,EDLMaster)
	if __EnvEDLFile__ in os.environ:
		EDLFile = os.environ.get(__EnvEDLFile__,EDLFile)
		EDLFile_FQDN = EDLFileToFQDN(EDLFile)
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
def test(arguments):
	"""Test stub"""

	if not DebugMode(): PrepDebug()

	DbgMsg("Life is THE test... don't fail it.")

#
# Main Loop
#

if __name__ == "__main__":
	"""Main loop for using the EDL as a cmd line script"""

	CmdLineMode(True)	# Place instance in cmdline mode

	run()
