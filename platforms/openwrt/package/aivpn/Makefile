include $(TOPDIR)/rules.mk

PKG_NAME:=aivpn
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/infosave2007/aivpn.git
# Pinned to the v1.0.1 release commit on PKG_SOURCE_URL's origin/master
# (verified present on that remote — a local/fork-only commit would make
# OpenWrt's git fetch fail outright), not the floating `master` branch — an
# unpinned branch means every OpenWrt rebuild can silently pull in
# unreviewed upstream changes at package-build time. Bump this (and
# PKG_MIRROR_HASH below) deliberately on each package release.
PKG_SOURCE_VERSION:=182c5fa2477635714e8455051739b7a12051d125
# TODO(security): "skip" disables OpenWrt's mirror-tarball integrity check —
# it is a placeholder, not a real hash. A real value can only be produced by
# the OpenWrt build system itself: inside an OpenWrt buildroot/SDK with this
# package staged, run `make package/aivpn/download V=s` (or
# `./scripts/download.pl` per the OpenWrt docs) against PKG_SOURCE_VERSION
# above and copy the sha256 it prints here. Do not hand-fabricate this value
# — a wrong-but-present hash is worse than an honest "skip" because it looks
# verified while verifying nothing.
PKG_MIRROR_HASH:=skip

PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
# Cargo build infrastructure from the OpenWrt packages feed (provides
# Build/Compile/Cargo, RUST_TARGET, cargo env). Requires the packages feed
# to be installed in the buildroot/SDK (feeds/packages/lang/rust).
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/aivpn
  SECTION:=net
  CATEGORY:=Network
  TITLE:=AIVPN censorship-resistant VPN client
  URL:=https://github.com/infosave2007/aivpn
  DEPENDS:=+kmod-tun
endef

define Package/aivpn/description
  Censorship-resistant VPN client with DPI evasion via traffic mimicry.
  Provides CLI client for OpenWrt routers.
endef

define Package/aivpn/conffiles
/etc/config/aivpn
endef

define Build/Compile
	$(call Build/Compile/Cargo,crates/aivpn-client)
endef

define Package/aivpn/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/aivpn-client \
		$(1)/usr/bin/aivpn-client
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/aivpn.config $(1)/etc/config/aivpn
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/aivpn.init $(1)/etc/init.d/aivpn
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_DATA) ./files/aivpn.hotplug $(1)/etc/hotplug.d/iface/50-aivpn
endef

$(eval $(call BuildPackage,aivpn))
