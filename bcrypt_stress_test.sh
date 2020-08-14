#!/bin/bash -x
#creating variables
i=1
max_it=50
last_pw=`cat lpw.inc`
pw=`pwgen -s -1`
suffix='ou=People,dc=cc,dc=private,dc=ssystems,dc=de'
port=389
echo "generated password: ".$pw
pw_hash=`php hash_test.php $pw`
echo $pw_hash
	LDIF=$(cat<<EOF
dn: uid=testuser,$suffix
changetype: modify
replace: userPassword
userPassword: $pw

EOF
)
  echo "$LDIF" | ldapmodify -D uid=testuser,$suffix -p $port -h localhost -x -w $last_pw

if [ $? -gt 0 ]; then
  echo "ldapmodify failed."
else
  echo $pw > lpw.inc
fi
#while [ $i -le $max_it ]
#do
#	pw=`pwgen -s -1`
#
#	LDIF=$(cat<<EOF
#dn: uid=testuser,ou=People,dc=intern
#changetype: modify
#replace: userPassword
#userPassword: $pw
#
#EOF
#)
#	echo "$LDIF" | ldapmodify -D uid=testuser,ou=People,dc=intern -p 21107 -h localhost -x -w $last_pw
#	last_pw=$pw
#	let i++
#done
