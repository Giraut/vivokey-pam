#!/bin/sh

# Directories and files
BUILDSCRIPTPATH=$(realpath "$0")
BUILDSCRIPTDIR=$(dirname ${BUILDSCRIPTPATH})
SRC=$(realpath ${BUILDSCRIPTDIR}/../..)
PKGSRC=${BUILDSCRIPTDIR}/vivokey-pam
VERSION=$(grep -E "^ +v[0-9]+\.[0-9]+\.[0-9]+ *$" ${SRC}/README | sed -E 's/[ v]*//')
PKGBUILD=${PKGSRC}-${VERSION}-0_all
PKG=${PKGBUILD}.deb

# Create a fresh skeleton package build directory
rm -rf ${PKGBUILD}
cp -a ${PKGSRC} ${PKGBUILD}

# Create empty directory structure
mkdir -p ${PKGBUILD}/usr/bin
mkdir -p ${PKGBUILD}/usr/share/pam-configs

# Populate the package build directory with the source files
install -m 644 ${SRC}/README ${PKGBUILD}/usr/share/doc/vivokey-pam
install -m 644 ${SRC}/README.cryptsetup ${PKGBUILD}/usr/share/doc/vivokey-pam
install -m 644 ${SRC}/LICENSE ${PKGBUILD}/usr/share/doc/vivokey-pam

install -m 755 ${SRC}/vivokey_pam.py ${PKGBUILD}/usr/bin
install -m 755 ${SRC}/vivokey_setup_account.py ${PKGBUILD}/usr/bin

install -m 644 ${SRC}/vivokey_pam.config ${PKGBUILD}/usr/share/pam-configs

# Set the version in the control file
sed -i "s/^Version:.*\$/Version: ${VERSION}/" ${PKGBUILD}/DEBIAN/control

# Fixup permissions
find ${PKGBUILD} -type d -exec chmod 755 {} \;
chmod 644 ${PKGBUILD}/DEBIAN/control
chmod 644 ${PKGBUILD}/usr/share/doc/vivokey-pam/copyright

# Build the .deb package
fakeroot dpkg -b ${PKGBUILD} ${PKG}
