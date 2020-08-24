#!/bin/bash
#creating variables
i=1
max_it=50
last_pw='IpFR52T1'
while [ $i -le $max_it ]
do
	pw=`pwgen -s -1`
	LDIF=$(cat<<EOF
dn: uid=testuser,ou=People,dc=intern
changetype: modify
replace: userPassword
userPassword: $pw

EOF
)
	echo "$LDIF" | ldapmodify -D uid=testuser,ou=People,dc=intern -p 21107 -h localhost -x -w $last_pw
	last_pw=$pw
	let i++
done 
