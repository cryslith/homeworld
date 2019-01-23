#!/bin/bash
# this script is designed for ubuntu 14.04 and other systems that don't use
# systemd or don't have systemd-nspawn.

# this script is not capable of properly tearing down the chroots that it
# creates, and is only appropriate for use in CI environments.
set -e -u

if [ "${HOMEWORLD_CHROOT:-}" = "" -o ! -e "${HOMEWORLD_CHROOT}" ]
then
    echo "invalid path to chroot: ${HOMEWORLD_CHROOT:-}" 1>&2
    echo '(have you populated $HOMEWORLD_CHROOT?)'
    echo '(have you created a chroot?)'
    exit 1
fi

cd "$(dirname "$0")"

# for CircleCI, since it uses an old version of GPG
if [ -e "$HOME/.gnupg/pubring.gpg" ]
then
	mkdir -p "$HOMEWORLD_CHROOT/home/$USER/.gnupg"
	cp "$HOME/.gnupg/pubring.gpg" "$HOMEWORLD_CHROOT/home/$USER/.gnupg/pubring.gpg"
fi

if [ -e "$HOME/.gnupg/pubring.kbx" ]
then
	mkdir -p "$HOMEWORLD_CHROOT/home/$USER/.gnupg/private-keys-v1.d/"
	chmod 0700 "$HOMEWORLD_CHROOT/home/$USER/.gnupg"
	cp "$HOME/.gnupg/pubring.kbx" "$HOMEWORLD_CHROOT/home/$USER/.gnupg/pubring.kbx"
	cp "$HOME/.gnupg/trustdb.gpg" "$HOMEWORLD_CHROOT/home/$USER/.gnupg/trustdb.gpg"
	cp -R "$HOME/.gnupg/private-keys-v1.d/"* "$HOMEWORLD_CHROOT/home/$USER/.gnupg/private-keys-v1.d"
fi
sudo mkdir -p "$HOMEWORLD_CHROOT/homeworld"
sudo mount --bind "$(pwd)" "$HOMEWORLD_CHROOT/homeworld"
sudo mount -t proc procfs "$HOMEWORLD_CHROOT/proc"
NEWPATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
sudo chroot "$HOMEWORLD_CHROOT" su "$USER" -c "cd /homeworld/platform/ && PATH=$NEWPATH bash && bazel shutdown"
sudo umount "$HOMEWORLD_CHROOT/proc"
# keep trying until all processes have been killed
echo "Trying to unmount $HOMEWORLD_CHROOT/homeworld..."
until sudo umount "$HOMEWORLD_CHROOT/homeworld"; do sleep 1; done
echo "Successfully unmounted $HOMEWORLD_CHROOT/homeworld!"
