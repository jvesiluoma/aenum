#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
#
# AENUM
#
# Autoenumerator is a quick script that combines some
# other (great) tools to collect data from given domain.
#
# Made by Jarkko Vesiluoma - 2016
#


import argparse,thread,time,sys,os,random
import subprocess
from subprocess import call
from subprocess import Popen, PIPE

# Config >>>>>
currdir = os.getcwd() + "/" 
sublist3rloc = currdir + "Sublist3r-master/sublist3r.py"
sublist3rtmpfile = "aenum_sublist3rtmp"
sublist3rdefargs = " -t 10" 
masscandefargs = " --rate 10000 "
ipoutfile = "aenum_networks_"
httpscreenshotloc = currdir + "httpscreenshots/httpscreenshot.py"
pythoncmd = "/usr/bin/python2.7"
screenshotdefargs = "-p -t 30 -w 50 -a -vH -r 1"
# <<<<< Config


# Blaargh not working in windowz, oh well.. :)
G = '\033[92m' #green
Y = '\033[93m' #yellow
B = '\033[94m' #blue
R = '\033[91m' #red
W = '\033[0m'  #white


def parse_args():
    # Parse args
    parser = argparse.ArgumentParser(description="""

    "Aenum" is autoenumerator, a tool to help enumeration of 
    (pentesting) target. Aenum will use few tools to gather 
    information (masscan, sublist3r and knockpy) and create
    a detailed output (including screenshots of the webpages)
    of the target addresses so user can quickly pinpoint the
    best servers to hack, hopefully.
    """, epilog = """
    Example: 
        ./aenum.py -d google.fi -m -mo "--rate 100" -s -o google.fi/
    """)

    parser._optionals.title = "OPTIONS"
    parser.add_argument('-o', '--output', help="Output directory for files.",required=True)
    parser.add_argument('-d', '--domain', help="Target domain.",required=True)
    parser.add_argument('-f', '--file', help="List of IP addresses.")
    parser.add_argument('-a', '--aliases', help="Check aliases.", action='store_true')
    parser.add_argument('-sl', '--sublisteropt', help="Sublist3r args (default: -b -t 50 )")
    parser.add_argument('-s', '--screenshots', help="Take screenshot from found website.", action='store_true')
    parser.add_argument('-so', '--screenshotopt', help="httpscreenshot options (default: -p -t 30 -w 30 -a -vH -r 1)")
    parser.add_argument('-m', '--masscan', help="Run masscan against the ipaddresses from domain enumeration", action='store_true')
    parser.add_argument('-mo', '--masscanopts', help="masscan custom options (default: --rate 10000 )")
    parser.add_argument('-p', '--ports', help="Custom ports to scan (default: 80 & 443)")

    return parser.parse_args()

def banner(id):

    if id == 0:
        print G + """
       █████╗ ███████╗███╗   ██╗██╗   ██╗███╗   ███╗      
      ██╔══██╗██╔════╝████╗  ██║██║   ██║████╗ ████║      
█████╗███████║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║█████╗
╚════╝██╔══██║██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║╚════╝
      ██║  ██║███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║      
      ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝      
        """ + W

def enum_sublist3r(domain,sublist3rtmpfile,subargs,outputpath):
    # 1. Enumerate DNS names from given domain
    print G+"[*] Running domain enumeration agains " + domain
    subargs = " -d " + domain + subargs + " -o " + sublist3rtmpfile + "_" + domain + ".lst"
    sublist3rcmd = pythoncmd + " " + sublist3rloc + subargs
    try:
        p = Popen(sublist3rcmd, stdin=PIPE, stdout=PIPE, stderr=PIPE,shell=True)
        sublist3routput, err = p.communicate()
    except:
        print R + "[ ] Error running sublist3r, is it installed and configured? Try running it manually to check." + W
        print R + "sublist3rcmd"
        exit(1)


def enum_knockpy(outputpath,sublist3rtmpfile,domain):
    infile = sublist3rtmpfile + "_" + domain + ".lst"
    subsfile = "subs_" + domain + ".lst"
    # We need a 'wordlist' for knockpy, so...
    subs = set()
    subsf = open(subsfile,'w')
    for line in open(infile,'r'):
	if line not in subs:
            chars = len(line) - (len(domain) + 3)
            sub = line[:chars] + "\n"
            subs.add(line)
            subsf.write(sub)
    subsf.close()

    knockpycmd = "/usr/local/bin/knockpy -w " + subsfile + " " + domain
    try:
        p = Popen(knockpycmd, stdin=PIPE, stdout=PIPE, stderr=PIPE,shell=True)
        knockpyoutput, err = p.communicate()
        for line in knockpyoutput.splitlines():
            if "Output saved in CSV format" in line:
                print G + "[*] " + line + W
                knockpycsv = os.getcwd() + "/" + line.split(":")[1].strip()
    except:
        print R + "[ ] Error running knockpy, is it installed? Try running it manually to check." + W
        print R + "knockpycmd"
        exit(1)

    return knockpycsv


def enum_addresses(infile,domain,ipoutfile,outputpath):
    # Loop through IP addresses (IP addresses from dns enum)
    # This is done to provide a decent list for masscan
    print G + "[*] Parsing IP addresses..." + W

    ipoutfilename = ipoutfile + domain + ".lst"
    ipoutfilestr = open(ipoutfilename,'w')
    targets = []
    for line in open(infile,'r'):
        if "ip address" in line:
            continue
        if line.split(',')[1] not in targets:
            targets.append(line.split(',')[1])
            ipoutfilestr.write(line.split(',')[1]+ "\n")
    ipoutfilestr.close()

    return ipoutfilename

def enum_masscan(ipaddrlistfile,ports,masscanargs,domain):
    with open(ipaddrlistfile) as ipfile:
        for i, l in enumerate(ipfile):
            pass

    # masscan -p80,443 -iL blaa.txt -oG http.gnmap --rate 10000 --http-user-agent "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36"
    print G + "[*] Scanning " + Y + str(i + 1) + G + " targets, ports: " + Y + ports + W

    massoutfile = "aenum_masscan_" + domain + ".gnmap"
    masscancmd = "/usr/bin/masscan -p" + ports + " -iL " + ipaddrlistfile + " -oG " + massoutfile + " " + masscanargs
    try:
        p = Popen(masscancmd, stdin=PIPE, stdout=PIPE, stderr=PIPE,shell=True)
        masscanoutput, err = p.communicate()
    except:
        print R + "[ ] Error running masscan, is it installed? Running as root? Try running it manually to check." + W
        print R + "    with parameters: " + R + masscancmd + W
        exit(1)
    with open(massoutfile) as massfile:
        for ii, ll in enumerate(massfile):
            pass
    print G + "[*] Found " + str(ii-1) + " possible targets with masscan." + W

    return massoutfile



def enum_httpscreenshots(httpscreenshotloc,masscanoutfile,screenshotopt,outputpath):
    if httpscreenshotloc == "":
        print R + "[ ] Error, httpscreenshot not check, check config or install it!" + W
        print R + "[ ] https://github.com/breenmachine/httpscreenshot" + W
        exit(1)
    print G + "[*] Crawling the websites with httpscreenshot..." + W

    httpscreenshotcmd = httpscreenshotloc + " -i " + masscanoutfile + " " + screenshotopt
    try:
        p = Popen(httpscreenshotcmd, stdin=PIPE, stdout=PIPE, stderr=PIPE,shell=True)
        httpscreenshotout, err = p.communicate()
    except:
        print R + "[ ] Error running httpscreenshot.py, is it installed? Try running it manually to check:" + W
        print R + "    with parameters: " + R + httpscreenshotcmd + W
        exit(1)
def main():

    args = parse_args()
    domain = args.domain
    masscan = args.masscan
    outputpath = args.output

    if not os.path.exists(outputpath):
        try:
            os.makedirs(outputpath)
        except:
            print R + "Error, can't create output dir."
            exit(1)

    os.chdir(outputpath)

    if args.sublisteropt:
        sublist3rargs = args.sublisteropt
    else:
        sublist3rargs = sublist3rdefargs

    if args.masscanopts: 
        masscanargs = args.masscanopts 
    else: 
        masscanargs = masscandefargs

    if args.ports:
        ports = args.ports
    else:
        ports = "80,443"

    screenshots = args.screenshots

    if args.screenshotopt:
        screenshotopt = args.screenshotopt
    else:
        screenshotopt = "-p -t 30 -w 50 -a -vH -r 1"

    # Print config
    print G+"[*] Config: "
    print G+"    [*] Sublist3r location:      " + Y + sublist3rloc + W
    print G+"    [*] Sublist3r args:          " + Y + sublist3rargs + W
    print G+"    [*] Masscan args:            " + Y + masscanargs + W
    print G+"    [*] httpscreenshot location: " + Y + httpscreenshotloc + W
    print G+"    [*] httpscreenshot args:     " + Y + screenshotopt + W

    # Step 1:
    if domain:
        print G + "[*] Finding subdomains for domain " + Y + domain+W
        domainlist = enum_sublist3r(domain.rstrip("\n"),sublist3rtmpfile,sublist3rargs,outputpath)

    print G + "[*] Starting knockpy checks..."+W
    knockpyoutput = enum_knockpy(outputpath,sublist3rtmpfile,domain)

    ipaddrlistfile = enum_addresses(knockpyoutput,domain,ipoutfile,outputpath)

    # masscan
    if masscan:
        masscanoutfile = enum_masscan(ipaddrlistfile,ports,masscanargs,domain)

    # httpscreenshots
    if screenshots:
        enum_httpscreenshots(httpscreenshotloc,masscanoutfile,screenshotopt,outputpath)

    print G + "[*] All done, enjoy." + W

    # Compile overview




if __name__=="__main__":
    banner(0)
    main()

