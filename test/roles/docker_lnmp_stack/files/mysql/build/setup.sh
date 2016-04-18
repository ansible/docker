#!/bin/bash

# If a volume is mounted on /var/lib/mysql, the db installed by apt-get will be replaced by the files in the volume.
#  - if this folder is empty (fresh install), we need to run mysql_install_db in order to start the daemon.
#  - if this folder is not empty, we assume it is a "working" mysql datadir (w/ potential data in it) and do nothing.
#  - TODO if no volume is mounted (-> db is hosted in the container), only create the admin account.
if [ "$(ls -A /var/lib/mysql)" ]; then
	
	echo "========================================================================="
	echo "# The volume mounted on /var/lib/mysql is not empty, mysql_install_db will not run."
	echo "# If you need a fresh mysql db, please clear the volume and re-build the image."
	echo "#"

	# already has a databse, simply starting the daemon
	mysqld_safe --skip-syslog

else

   # We will create a new db in the volume with mysql_install_db.
   # Since the db is "fresh", we will have lost the accounts created by apt-get on the install stage and
   # need to recreate them. We will need a root account and one for debian-sys-maint (as this user is the 
   # one "interracting" with the daemon).
   
	echo "========================================================================="
	echo "# No database found, installing one."
	
	/usr/bin/mysql_install_db
	
	echo "========================================================================="
	echo "# A database has been created in the volume mounted on /var/lib/mysql."
	echo "#"
	echo "========================================================================="
	echo "#  Fixing root password from mysql_install_db"
	echo "#"

	# Find out the debian-sys-maint password
	debSysPwd=`cat /etc/mysql/debian.cnf | grep -m 1 "password =" | awk '{gsub("password = ", ""); print}'`
	
	# To set up the accounts after the install, we need to briefly run mysql with no auth (--skip-grant-tables)
	# as the root account set up by `mysql_install_db` has no password and thus will refuse any connection attempt.
	mysqld_safe --skip-grant-tables 2>&1 &

	sleep 1
		while ! grep -m1 'ready for connections.' < /var/log/mysql/error.log; do
			sleep 1
		done
	sleep 5

	# set the new root password
	mysql -e "UPDATE mysql.user SET Password=PASSWORD('root') WHERE User='root'; FLUSH PRIVILEGES;"
	# add some privileges to debian-sys-maint (-> mysql daemon)
	mysql -u root -proot -e "GRANT ALL PRIVILEGES ON *.* TO 'debian-sys-maint'@'localhost' IDENTIFIED BY '$debSysPwd'; FLUSH PRIVILEGES;"

	# kill the unsecure service
	service mysql stop

	# ... and start a more secure one
	mysqld_safe --skip-syslog > /home/docker_mysql.log 2>&1 &
	sleep 1
	while ! grep -m1 'ready for connections.' < /var/log/mysql/error.log; do
		sleep 1
	done
	sleep 5

	echo "========================================================================="
	echo "#  Creating admin account..."

	# setup an "admin" with a random password and allowing remote connections
	admin_password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9-_!@#$%^&*()_+{}|:<>?=' | fold -w 12 | head -n 1)
	mysql -u root -proot -e "GRANT ALL ON *.* TO 'admin'@'%' IDENTIFIED BY '$admin_password' WITH GRANT OPTION;"

	echo "========================================================================="
	echo "#"
	echo "#  YOUR MYSQL CREDENTIALS"
	echo "#    login: admin"
	echo "#    password: $admin_password"
	echo "#"
	echo "#  * root is only accessible from within this container."
	echo "#  It does not accept any connection except from localhost."
	echo "#"
	echo "========================================================================="

	# last service reboot, rock n roll
	service mysql stop
	mysqld_safe --skip-syslog

fi
