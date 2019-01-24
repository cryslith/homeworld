#!/bin/sh
set -e

case "$1" in
    configure|abort-remove)
        rm -f /etc/nginx/sites-enabled/default
        rm -f /etc/nginx/sites-enabled/homeworld
        ln -s /etc/nginx/sites-available/homeworld /etc/nginx/sites-enabled/
    ;;

    abort-upgrade|abort-deconfigure)
    ;;

    *)
        echo "postinst called with unknown argument \`$1'" >&2
        exit 1
    ;;
esac

# dh_installdeb will replace this with shell code automatically
# generated by other debhelper scripts.

#DEBHELPER#

exit 0