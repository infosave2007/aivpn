# AIVPN for iOS and Android: Privacy Policy

Effective date: 26 November 2026

AIVPN is open-source software published at <https://github.com/infosave2007/aivpn>. This policy describes how the AIVPN apps for iPhone, iPad and Android handle your data. It does not cover VPN servers: a server is run by you or by a provider you choose, and that operator is responsible for the data on it.

## Summary

The app does not send your personal data, browsing activity or usage statistics to its developers. It has no accounts, ads, analytics or trackers.

## What the app connects to

- **Your VPN server.** The app connects to the server named in your connection key. The app has no built-in servers.
- **Server discovery, if you use it.** The app requests signed server descriptors from the CDN address, GitHub repository or Telegram bot that you enter.
- **Server installation over SSH, if you use it.** The app connects to the host you enter and uses the SSH credentials you type. The credentials are not saved.

## What the server operator can see

While the VPN is on, your traffic passes through your VPN server. As with any VPN, its operator can see your IP address, connection times and traffic volume. The app also creates a random key on first connection and presents its public part to the server, so the server can recognise this device.

## What is stored on your device

- On iPhone and iPad, connection keys, certificates, the device key and the Telegram bot token for server discovery are kept in the device Keychain.
- On Android, connection keys and the device key are kept in the app's private storage, encrypted with a key held in the Android Keystore.
- Settings, Split Tunnel lists and server discovery settings are stored in the app's storage on the device.

Deleting the app removes its settings. Connection keys can be deleted in the app at any time.

## Optional sharing

"Share blocked-mask feedback" is off by default. If you turn it on, the app tells your VPN server which traffic masks worked or were blocked, together with the two-letter country code you entered. "Receive mask hints" lets the server send back which masks work best in that country.

## Permissions

- **VPN configuration.** Required to create the tunnel.
- **Notifications.** Used to tell you when the VPN connects or disconnects. Optional.
- **Local network (iPhone and iPad).** Used only when your VPN server is on your local network.
- **List of installed apps (Android).** Used only on the device to show the apps you can send around or through the VPN with Split Tunneling. The list is not sent anywhere.
- **Start at boot (Android).** Reconnects the VPN after a restart, only if you turn on automatic connection.
- **Ignore battery optimisation (Android).** Requested only when you choose it on the Background Health screen, so that the system does not stop the VPN in the background.

## Children

The app is not directed at children and does not knowingly collect data from anyone.

## Changes

Changes to this policy are published in this file. The history is available in the repository.

## Contact

Questions about this policy: <https://github.com/infosave2007/aivpn/issues>
