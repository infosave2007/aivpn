include $(TOPDIR)/rules.mk

PKG_NAME:=aivpn
PKG_VERSION:=1.2.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/infosave2007/aivpn.git
# Рецепт выпуска использует тег основного репозитория.
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
# TODO(security): значение "skip" отключает проверку архива исходников.
# Настоящий хеш можно получить только средствами OpenWrt. В buildroot или SDK
# с этим пакетом выполните `make package/aivpn/download V=s` либо
# `./scripts/download.pl`, затем укажите полученный sha256 вместо "skip".
PKG_MIRROR_HASH:=skip

PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
# Средства сборки Cargo предоставляются пакетом Rust из OpenWrt packages feed.
# В buildroot или SDK должен быть установлен feeds/packages/lang/rust.
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/aivpn
  SECTION:=net
  CATEGORY:=Network
  TITLE:=AIVPN censorship-resistant VPN client
  URL:=https://github.com/infosave2007/aivpn
  DEPENDS:=+kmod-tun +ip-full +nftables-json
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
