#!/usr/bin/env python

__author__ = "Zack Link"
__maintainer__ = "Zack Link"
__email__ = "zlink@cylance.com"
__version__ = "0.5"
__credits__ = []
__license__ = "GPL"

from cmd import Cmd
import json
import cylance
import subprocess

class MyPrompt(Cmd):
    tenant = ""
    app_id = ""
    app_secret = ""
    auth_token = ""
    authed = 0

    def do_auth(self, arg):
        """Set authentication credentials for cloud.  Shell automatically checks expiration and renews token periodically.  \nExample:\n auth <tenant> <app_id> <app_secret> [region suffix].  Region suffixes are -apne1, -au, -euc1, -us, -sae1"""
        args = arg.split()
        #print "len of args is " + str(len(args))
        # for x in args:
        #    print x
        cylance.set_creds(*args)

    def do_saveConfig(self, arg):
        """Save authentication credentials to file.\nExample:\n saveConfig file=config.json"""
        args = arg.split("=")
        # TODO: Do some error checking here to see if this is a legit file path
        cylance.save_creds(args[1])

    def do_loadConfig(self, arg):
        """Load authentication credentials from file.\nExample:\n loadConfig file=config.json"""
        args = arg.split("=")
        # TODO: Do some error checking here to see if this is a legit file 
        cylance.load_creds(args[1])

    def do_shell(self, args):
        """shell <command> <args>\n run a shell command, e.g. cat users.csv | grep <email>"""
        try:
            print subprocess.check_output(args, shell=True)
        except subprocess.CalledProcessError as e:
            print e.output
    
    def do_getUsers(self, args):
        """Get all Users.\nOptions:\n  email=<string> (contains <string>)\n  first_name=<string>\n  last_name=<string>\n  has_logged_in=<True|False>\n  user_role=<role> (e.g. Administrator is 00000000-0000-0000-0000-000000000002)\n  date_last_login=<date> (e.g.  2018-01- for Jan 2018)\n  date_email_confirmed=<date> (e.g.  2018-01- for Jan 2018)\n  date_created=<date> (e.g.  2018-01- for Jan 2018)\n  date_modified=<date> (e.g.  2018-01- for Jan 2018)\n  out=<filename> (suports .json and .csv)\nOptions should be in the format: <field1>=<value1>,<field2>=<value2>,etc"""
        print cylance.get_data("USERS", args)

    def do_getUser(self, args):
        """Get User by ID.\n getUser id=<id> or getUser email=<email address>"""
        fields = args.split("=")
        print cylance.get_data_by_id("USERS", fields[1])

    def do_deleteUser(self, args):
        """Delete User by ID.\n deleteUser id=XXX\n deleteUser in=users.csv"""
        # print "deleteUser " + args
        fields = args.split("=")
        # print "0 = " + fields[0] + " 1 = " + fields[1]
        if fields[0] == 'in':
            with open(fields[1]) as f:
                line = f.readlines().strip()
                if len(lines) == 36:
                    print cylance.delete_data("USER", line)
        elif fields[0] == 'id':
            print cylance.delete_data("USERS", args)

    def do_updateUser(self, args):
        """Update User by ID.\n updateUser id=XXX in=user.json"""
        all_args = args.split()
        id_k,id_v = all_args[0].split("=")
        # print "updating user id = " + id_v
        print cylance.update_data("USERS", all_args[0], all_args[1])

    def do_getDevices(self, args):
        """Get all Devices.\nOptions:\n  name=<string> (i.e. name contains <string>)\n  date_first_registered=<date> (e.g.  2018-01- for Jan 2018)\n  id=<devicce id>\n  version=<version>\n  state=<Online|Offline>\n  out=<filename> (suports .json and .csv)"""
        print cylance.get_data("DEVICES", args)

    def do_getDevice(self, args):
        """Get Device by ID.\n getDevice id=<id>\n"""
        fields = args.split("=")
        print cylance.get_data_by_id("DEVICES", fields[1])

    def do_getPolicies(self, args):
        """Get all Policies.\nOptions:\n  name=<string> (i.e. name contains <string>)\n  <field2=XXX>\n  <field3=YYY>\n  <field4=ZZZ>\n  out=<filename> (suports .json and .csv)"""
        # TODO fix comments above for help
        print cylance.get_data("POLICIES", args)

    def do_getPolicy(self, args):
        """Get Policy by ID.\nExample:\n getPolicy id=XYZ out=policy.json"""
        fields = args.split("=")
        print cylance.get_data_by_id("POLICIES", fields[1])

    def do_getZones(self, args):
        """Get all Zones.\nOptions:\n  name=<string> (i.e. name contains <string>)\n  <field2=XXX>\n  <field3=YYY>\n  <field4=ZZZ>\n  out=<filename> (suports .json and .csv)"""
        # TODO fix comments above for help
        print cylance.get_data("ZONES", args)

    def do_getThreats(self, args):
        """Get all Threats.\nOptions:\n  name=<string> (i.e. name contains <string>)\n  <field2=XXX>\n  <field3=YYY>\n  <field4=ZZZ>\n  out=<filename> (suports .json and .csv)"""
        # TODO fix comments above for help
        print cylance.get_data("THREATS", args)

    def do_getRegions(self, args):
        """Get available geographical regions"""
        for x in cylance.get_regions():
            print x

    def do_getCurrentRegion(self, args):
        """Get current setting for selected region"""
        print cylance.get_region()

    def do_setRegion(self, args):
        """"Set region.  For a list of available regions use 'getRegions'"""
        cylance.set_region(args)

    def do_filtering(self, args):
        """All top level attributes can be filtered on.  Multiple filters can be used by putting a comma (no spaces) in between the filters.  Search string uses contains, not exact match.  Searches are case-insensitive\nExample: getDevices state=Online,name=US\n"""
        print ""

    def parse(arg):
        """parse command line args into array"""
        return arg.split(" ")

    def do_quit(self, args):
        """Quits the program."""
        print "Quitting."
        raise SystemExit

    def do_exit(self, args):
        """Exits the program."""
        print "Exitting."
        raise SystemExit

if __name__ == '__main__':
    prompt = MyPrompt()
    prompt.prompt = 'CyPy> '
    prompt.cmdloop('Starting CyPy...')
