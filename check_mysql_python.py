#!/usr/bin/python
#
#External auth script for ejabberd that enable auth against MySQL db with
#use of custom fields and table. It works with hashed passwords.
#Inspired by Lukas Kolbe script.
#Released under GNU GPLv3
#Author: iltl. Contact: iltl@free.fr
#Version: 27 July 2009

#modifications by elm:
# - use sha512 instead of md5
# - allow password changes

########################################################################
#DB Settings
#Just put your settings here.
########################################################################
db_name="my_db"
db_user="my_id"
db_pass="my_pass"
db_host="localhost"
db_table="my_table"
db_username_field="name"
db_password_field="pass"
domain_suffix="@exemple.net" #JID= user+domain_suffix
########################################################################
#Setup
########################################################################
import sys, logging, struct, hashlib, MySQLdb
from struct import *
sys.stderr = open('/var/log/ejabberd/extauth_err.log', 'a')
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s',
                    filename='/var/log/ejabberd/extauth.log',
                    filemode='a')
try:
	database=MySQLdb.connect(db_host, db_user, db_pass, db_name)
except:
	logging.debug("Unable to initialize database, check settings!")
dbcur=database.cursor()
logging.info('extauth script started, waiting for ejabberd requests')
class EjabberdInputError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
########################################################################
#Declarations
########################################################################
def ejabberd_in():
		logging.debug("trying to read 2 bytes from ejabberd:")
		try:
			input_length = sys.stdin.read(2)
		except IOError:
			logging.debug("ioerror")
		if len(input_length) is not 2:
			logging.debug("ejabberd sent us wrong things!")
			raise EjabberdInputError('Wrong input from ejabberd!')
		logging.debug('got 2 bytes via stdin: %s'%input_length)
		(size,) = unpack('>h', input_length)
		logging.debug('size of data: %i'%size)
		income=sys.stdin.read(size).split(':')
		logging.debug("incoming data: %s"%income)
		return income
def ejabberd_out(bool):
		logging.debug("Ejabberd gets: %s" % bool)
		token = genanswer(bool)
		logging.debug("sent bytes: %#x %#x %#x %#x" % (ord(token[0]), ord(token[1]), ord(token[2]), ord(token[3])))
		sys.stdout.write(token)
		sys.stdout.flush()
def genanswer(bool):
		answer = 0
		if bool:
			answer = 1
		token = pack('>hh', 2, answer)
		return token
def db_entry(in_user):
	ls=[None, None]
	dbcur.execute("SELECT %s,%s FROM %s WHERE %s ='%s'"%(db_username_field,db_password_field , db_table, db_username_field, in_user))
	return dbcur.fetchone()
def isuser(in_user, in_host):
	data=db_entry(in_user)
	out=False #defaut to O preventing mistake
	if data==None:
		out=False
		logging.debug("Wrong username: %s"%(in_user))
	elif in_user+"@"+in_host==data[0]+domain_suffix:
		out=True
	return out
def auth(in_user, in_host, password):
	data=db_entry(in_user)
	out=False #defaut to O preventing mistake
	if data==None:
		out=False
		logging.debug("Wrong username: %s"%(in_user))
	elif in_user+"@"+in_host==data[0]+domain_suffix:
		if hashlib.sha512(password).hexdigest()==data[1]:
			out=True
		else:
			logging.debug("Wrong password for user: %s"%(in_user))
			out=False
	else:
		out=False
	return out
def setpass(in_user, in_host, password):
	out=False
	new_password=hashlib.sha512(password).hexdigest()
	dbcur.execute("UPDATE %s SET %s = '%s' WHERE %s = '%s'"%(db_table, db_password_field, new_password, db_username_field, in_user))
	data=db_entry(in_user)
	if new_password==data[1]:
		logging.debug("Password successfully changed for user: %s"%(in_user))
		out=True
	else:
		logging.debug("Could not set new password for user: %s"%(in_user))
		out=False
	return out
def log_result(op, in_user, bool):
	if bool:
		logging.info("%s successful for %s"%(op, in_user))
	else:
		logging.info("%s unsuccessful for %s"%(op, in_user))
########################################################################
#Main Loop
########################################################################
while True:
	logging.debug("start of infinite loop")
	try:
		ejab_request = ejabberd_in()
	except EjabberdInputError, inst:
		logging.info("Exception occured: %s", inst)
		break
	logging.debug('operation: %s'%(ejab_request[0]))
	op_result = False
	if ejab_request[0] == "auth":
		op_result = auth(ejab_request[1], ejab_request[2], ejab_request[3])
		ejabberd_out(op_result)
		log_result(ejab_request[0], ejab_request[1], op_result)
	elif ejab_request[0] == "isuser":
		op_result = isuser(ejab_request[1], ejab_request[2])
		ejabberd_out(op_result)
		log_result(ejab_request[0], ejab_request[1], op_result)
	elif ejab_request[0] == "setpass":
		op_result = setpass(ejab_request[1], ejab_request[2], ejab_request[3])
		ejabberd_out(op_result)
		log_result(ejab_request[0], ejab_request[1], op_result)
logging.debug("end of infinite loop")
logging.info('extauth script terminating')
database.close()
