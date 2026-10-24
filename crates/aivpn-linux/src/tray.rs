use ksni::menu::StandardItem;
use ksni::{Icon, MenuItem, Tray, TrayMethods};
use std::sync::OnceLock;
use tokio::sync::mpsc::UnboundedSender;

/// Brandbook tray asset (64×64, RGBA) — see assets/brand/BRANDBOOK.md. Decoded
/// once and cached, since ksni queries `icon_pixmap()` on every property
/// refresh, not just once at registration.
static BRAND_ICON: &[u8] = include_bytes!("../../../assets/brand/tray-dark.png");

fn brand_icon() -> &'static Icon {
    static ICON: OnceLock<Icon> = OnceLock::new();
    ICON.get_or_init(|| {
        let decoder = png::Decoder::new(std::io::Cursor::new(BRAND_ICON));
        let mut reader = decoder
            .read_info()
            .expect("bundled tray-dark.png must decode");
        let mut rgba = vec![
            0u8;
            reader
                .output_buffer_size()
                .expect("bundled tray-dark.png must have a known buffer size")
        ];
        let info = reader
            .next_frame(&mut rgba)
            .expect("bundled tray-dark.png must decode");
        rgba.truncate(info.buffer_size());
        // ksni::Icon wants ARGB32 (network byte order, A,R,G,B per pixel);
        // png decodes to RGBA (R,G,B,A per pixel) for this asset's color type.
        let mut argb = Vec::with_capacity(rgba.len());
        for px in rgba.as_chunks::<4>().0 {
            argb.extend_from_slice(&[px[3], px[0], px[1], px[2]]);
        }
        Icon {
            width: info.width as i32,
            height: info.height as i32,
            data: argb,
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    Open,
    Connect,
    Disconnect,
    Quit,
}

pub struct AivpnTray {
    sender: UnboundedSender<TrayAction>,
}

impl AivpnTray {
    fn send(&self, action: TrayAction) {
        let _ = self.sender.send(action);
    }
}

impl Tray for AivpnTray {
    fn id(&self) -> String {
        "aivpn".into()
    }

    fn title(&self) -> String {
        "AIVPN".into()
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        vec![brand_icon().clone()]
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(TrayAction::Open);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            StandardItem {
                label: "Open".into(),
                activate: Box::new(|this: &mut Self| this.send(TrayAction::Open)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Connect".into(),
                activate: Box::new(|this: &mut Self| this.send(TrayAction::Connect)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Disconnect".into(),
                activate: Box::new(|this: &mut Self| this.send(TrayAction::Disconnect)),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(|this: &mut Self| this.send(TrayAction::Quit)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

/// Spawn the tray and return a receiver for menu/activation events.
/// Uses the native org.kde.StatusNotifierItem D-Bus protocol directly (via
/// `ksni`/`zbus`) instead of going through GTK + libappindicator — that
/// older stack reports success locally but its DBus registration can be
/// silently ignored by some StatusNotifierWatcher implementations (notably
/// observed on KDE Plasma: `tray-icon`'s `build()` returns `Ok` yet no entry
/// ever appears in System Tray Settings). ksni talks the protocol Plasma's
/// systray actually implements natively.
pub async fn spawn() -> Result<tokio::sync::mpsc::UnboundedReceiver<TrayAction>, ksni::Error> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let tray = AivpnTray { sender: tx };
    // ksni's background service task (spawned inside `.spawn()`) holds its
    // own strong Arc to the tray state independently of the returned
    // `Handle` (which only holds a Weak), so dropping the handle here does
    // not stop the tray — it keeps running for the process lifetime.
    let _handle = tray.spawn().await?;
    Ok(rx)
}
