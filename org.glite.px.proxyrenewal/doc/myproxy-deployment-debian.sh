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

#cp -p /etc/init.d/myproxy-server /tmp/
sed -i /etc/init.d/myproxy-server -e 's/\(# Default-Start:\).*/\1     2 3 4 5/'
sed -i /etc/init.d/myproxy-server -e 's/\(# Default-Stop:\).*/\1      0 1 6/'
update-rc.d myproxy-server defaults


#
# setup BDII resource (optional)
#
# required packages: bdii glite-info-provider-service sudo lsb-release
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

BDII_PASSWD=`dd if=/dev/random bs=1 count=10 2>/dev/null | base64`
cat << EOF > /etc/default/bdii
RUN=yes
SLAPD_CONF=
SLAPD=
BDII_RAM_DISK=
EOF
sed -i  "s#.*rootpw.*#rootpw\t${BDII_PASSWD}#" /etc/bdii/bdii-slapd.conf

/etc/init.d/bdii restart
