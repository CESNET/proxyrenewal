#! /bin/sh
# The primary purpose of this script is to document the procedure that may
# be followed in case MyProxy server cannot be configured by YAIM

DN=`openssl x509 -in /etc/grid-security/hostcert.pem -noout -subject |sed 's/subject= //'`
echo "$DN"
#cp -p /etc/myproxy-server.config /tmp
cat >> /etc/myproxy-server.config <<EOF

# local configuration for `uname -n`
authorized_renewers "$DN"
authorized_retrievers "*"
EOF

cp -pv /etc/grid-security/host*.pem /etc/grid-security/myproxy
chown -v myproxy:myproxy /etc/grid-security/myproxy/host*.pem

/etc/init.d/myproxy-server restart

chkconfig myproxy-server on

#
# setup BDII resource (optional)
#
# required packages: bdii glite-info-provider-service sudo redhat-lsb
#

INFO_SERVICE_CONFIG='/etc/glite/info/service'
SITE_NAME='sitename'

cp ${INFO_SERVICE_CONFIG}/glite-info-service-myproxy.conf.template ${INFO_SERVICE_CONFIG}/glite-info-service-myproxy.conf
cp ${INFO_SERVICE_CONFIG}/glite-info-glue2-myproxy.conf.template ${INFO_SERVICE_CONFIG}/glite-info-glue2-myproxy.conf
cat <<EOF >/var/lib/bdii/gip/provider/glite-info-provider-service-myproxy-wrapper
/usr/bin/glite-info-service ${INFO_SERVICE_CONFIG}/glite-info-service-myproxy.conf $SITE_NAME
/usr/bin/glite-info-glue2-simple ${INFO_SERVICE_CONFIG}/glite-info-glue2-myproxy.conf $SITE_NAME
EOF
chmod +x /var/lib/bdii/gip/provider/glite-info-provider-service-myproxy-wrapper

# newer slapd with rwm backend required for SL5
[ -x /usr/sbin/slapd2.4 ] && echo "SLAPD=/usr/sbin/slapd2.4" >> /etc/sysconfig/bdii

chkconfig bdii on
/etc/init.d/bdii restart
