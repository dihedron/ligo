# shellcheck shell=bash
# The identity scenario's LDAP directory: OpenLDAP over ldaps only, seeded
# from ldap/seed.ldif (.specs/ligo-test-environment.md, "LDAP"). Passwords
# are random, kept in the state directory, and stored hashed.

LDAP_BASE="dc=ligo,dc=lab"
LDAP_URL="ldaps://ldap.ligo.lab:636"

# ldap_password NAME: the password of a directory account, created once.
ldap_password() {
	local file="$LAB_STATE_DIR/passwords/ldap-$1"
	[[ -f "$file" ]] || (umask 077 && openssl rand -hex 16 >"$file")
	cat "$file"
}

# ldap_admin_conf ARGS: ldapmodify/ldapadd as root over ldapi (SASL EXTERNAL),
# for the directory's configuration and seed.
ldap_admin() { inner_exec ldap "$@" -Q -Y EXTERNAL -H ldapi:///; }

# ldapsearch_as ACCOUNT ARGS: ldapsearch over ldaps as an account of
# ou=services (the bind password from the state directory).
ldapsearch_as() {
	local account="$1"
	shift
	inner_exec ldap env LDAPTLS_CACERT=/etc/ldap/lab-ca.crt ldapsearch -LLL -H "$LDAP_URL" \
		-D "cn=$account,ou=services,$LDAP_BASE" -w "$(ldap_password "$account")" "$@"
}

# ldap_up: slapd with the lab's TLS certificate, ldaps and ldapi only, its
# access rules and the seed.
ldap_up() {
	section "LDAP (OpenLDAP)"
	inner_container ldap "$LAB_LDAP_MEMORY"
	pki_issue ldap "DNS:ldap.ligo.lab,IP:$(inner_ip ldap),IP:127.0.0.1"
	if ! inner_exec ldap test -x /usr/sbin/slapd; then
		# the database's admin password: never used (the lab administers slapd
		# over ldapi as root); both answers must match, or slapd asks forever
		local admin
		admin="$(openssl rand -hex 16)"
		inner_exec ldap sh -ec "
			echo 'slapd slapd/no_configuration boolean false' | debconf-set-selections
			echo 'slapd slapd/domain string ligo.lab' | debconf-set-selections
			echo 'slapd shared/organization string ligo lab' | debconf-set-selections
			echo 'slapd slapd/password1 password $admin' | debconf-set-selections
			echo 'slapd slapd/password2 password $admin' | debconf-set-selections
			DEBIAN_FRONTEND=noninteractive apt-get install -y -qq slapd ldap-utils </dev/null >/dev/null 2>&1"
		info "ldap: slapd installed"
	fi
	inner_exec ldap mkdir -p /etc/ldap/tls
	inner_push "$LAB_STATE_DIR/pki/ldap.crt" ldap /etc/ldap/tls/server.crt 0644
	inner_push "$LAB_STATE_DIR/pki/ldap.key" ldap /etc/ldap/tls/server.key 0640
	inner_push "$LAB_STATE_DIR/pki/ca.crt" ldap /etc/ldap/lab-ca.crt 0644
	inner_exec ldap sh -ec "
		chgrp openldap /etc/ldap/tls/server.key
		sed -i 's#^SLAPD_SERVICES=.*#SLAPD_SERVICES=\"ldapi:/// ldaps:///\"#' /etc/default/slapd
		systemctl restart slapd"
	ldap_admin ldapmodify >/dev/null <<LDIF
dn: cn=config
changetype: modify
replace: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ldap/lab-ca.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ldap/tls/server.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ldap/tls/server.key
-
replace: olcTLSProtocolMin
olcTLSProtocolMin: 3.3
LDIF
	# access: root in the container (ldapi, SASL EXTERNAL) manages the data,
	# for the seed; passwords are only compared (bind); ou=ligo-accounts is
	# written by the identity provider alone; nothing is readable anonymously
	ldap_admin ldapmodify >/dev/null <<LDIF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to * by dn.exact="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage by * break
olcAccess: {1}to attrs=userPassword by dn.exact="cn=ligo-idp,ou=services,$LDAP_BASE" write by self write by anonymous auth by * none
olcAccess: {2}to dn.subtree="ou=ligo-accounts,$LDAP_BASE" by dn.exact="cn=ligo-idp,ou=services,$LDAP_BASE" write by users read by * none
olcAccess: {3}to * by users read by * none
LDIF
	ldap_seed
	ldap_check
	env_set .ldap "$(jq -n --arg url "$LDAP_URL" --arg base "$LDAP_BASE" '{url: $url, base: $base}')"
}

# ldap_seed adds the entries of seed.ldif that are missing, with fresh
# password hashes.
ldap_seed() {
	if inner_exec ldap ldapsearch -LLL -Q -Y EXTERNAL -H ldapi:/// -b "ou=users,$LDAP_BASE" -s base dn 2>/dev/null | grep -q '^dn:'; then
		info "ldap: directory already seeded"
		return
	fi
	local tmp name hash
	tmp="$(mktemp)"
	cp "$LAB_DIR/ldap/seed.ldif" "$tmp"
	for name in $(grep -o '{{PASSWORD:[a-z-]*}}' "$tmp" | sort -u | sed 's/{{PASSWORD:\(.*\)}}/\1/'); do
		hash="$(inner_exec ldap slappasswd -h '{SSHA}' -s "$(ldap_password "$name")")"
		sed -i "s#{{PASSWORD:$name}}#$hash#" "$tmp"
	done
	inner_push "$tmp" ldap /root/seed.ldif 0600
	rm -f "${tmp:?}"
	inner_exec ldap sh -c "ldapadd -Q -Y EXTERNAL -H ldapi:/// -f /root/seed.ldif >/dev/null && rm -f /root/seed.ldif" ||
		die "ldap: cannot load the seed"
	info "ldap: seeded from ldap/seed.ldif"
}

# ldap_check: ligo-admin-auth binds over ldaps and finds marco and his
# groups; anonymous reads find nothing (step 4's done criterion).
ldap_check() {
	local i
	for i in $(seq 1 30); do
		ldapsearch_as ligo-admin-auth -b "$LDAP_BASE" -s base dn >/dev/null 2>&1 && break
		sleep 1
	done
	ldapsearch_as ligo-admin-auth -b "ou=users,$LDAP_BASE" "(uid=marco)" dn | grep -q "^dn: uid=marco," ||
		die "ldap: ligo-admin-auth cannot find uid=marco over ldaps"
	local groups
	groups="$(ldapsearch_as ligo-admin-auth -b "ou=groups,$LDAP_BASE" "(member=uid=marco,ou=users,$LDAP_BASE)" cn | awk '/^cn:/ {print $2}' | sort | tr '\n' ' ')"
	[[ "$groups" == "infosec-approvers ledger-leads " ]] || die "ldap: marco's groups are \"$groups\""
	inner_exec ldap env LDAPTLS_CACERT=/etc/ldap/lab-ca.crt ldapwhoami -H "$LDAP_URL" -x \
		-D "uid=marco,ou=users,$LDAP_BASE" -w "$(ldap_password marco)" >/dev/null ||
		die "ldap: marco cannot bind with his password"
	if inner_exec ldap env LDAPTLS_CACERT=/etc/ldap/lab-ca.crt ldapwhoami -H "$LDAP_URL" -x \
		-D "uid=marco,ou=users,$LDAP_BASE" -w wrong >/dev/null 2>&1; then
		die "ldap: a wrong password binds"
	fi
	if inner_exec ldap env LDAPTLS_CACERT=/etc/ldap/lab-ca.crt ldapsearch -LLL -x -H "$LDAP_URL" -b "ou=users,$LDAP_BASE" "(uid=marco)" dn 2>/dev/null | grep -q '^dn:'; then
		die "ldap: anonymous search finds people"
	fi
	if inner_exec ldap ldapsearch -LLL -x -H ldap://127.0.0.1 -b "$LDAP_BASE" -s base 2>/dev/null; then
		die "ldap: plain ldap:// answers"
	fi
	info "ldap: ligo-admin-auth binds over ldaps and finds marco in: $groups; marco binds with his password, a wrong one fails; anonymous search and plain ldap:// refused"
}
