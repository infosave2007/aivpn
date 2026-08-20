# AIVPN Brand Book

Visual identity guidelines for AIVPN — Resonance Ring concept.

---

## Color Palette

| Role | Name | Hex | Usage |
|------|------|-----|-------|
| Background | Deep Space | `#160F2F` | App icon background, dark surfaces |
| Background gradient dark | Abyss | `#0A0518` | Radial gradient endpoint |
| Background gradient mid | Midnight | `#211060` | Radial gradient midpoint |
| Primary ring | Resonance Purple | `#7B61FF` | Mid ring, primary accent |
| Inner ring | Soft Violet | `#A893FF` | Inner ring, secondary accent |
| Inner ring bright | Bloom | `#B8A8FF` | Packet dots on inner ring |
| Accent | Lemon | `#E8FF6B` | Outer ring, center dot, key highlights |
| Accent soft | Pale Lemon | `#FAFFB8` | Center pulse |
| Text | White | `#FFFFFF` | All wordmarks and labels |
| Subtitle | Muted Violet | `#9B85FF` | Tagline text |

### Dark surface gradients

App icon uses a radial gradient centered at (50%, 40%):
- Center: `#1E1040`
- Edge: `#0A0518`

Horizontal logo uses a linear gradient left-to-right:
- Left 0%: `#1A0D3D`
- Right 100%: `#0D0820`

---

## Logo

### Resonance Ring Symbol

Three concentric rings with packet dots, centered on a pulsing core:

| Ring | Stroke | Radius (512px canvas) | Role |
|------|--------|-----------------------|------|
| Outer | `#E8FF6B` (lemon) | r=196 | Outermost signal propagation |
| Mid | `#7B61FF` (purple) | r=140 | Primary identity ring |
| Inner | `#A893FF` (soft violet) | r=82 | Core resonance |
| Center | `#E8FF6B` fill | r=9 | Central node |

Packet dots mark three positions per ring to suggest distributed nodes and signal propagation.

### Wordmark

- Font family: `'Arial Black', 'Helvetica Neue', sans-serif`
- Weight: 900 (Black)
- Text: `AIVPN`
- Letter-spacing: −2 px (at display size)
- Tagline: `ADAPTIVE INTELLIGENCE VPN` — regular weight, 5px letter-spacing, muted violet

---

## Icon Sizes

| File | Size | Platform usage |
|------|------|----------------|
| `icon-512.png` | 512×512 | Android Play Store, general |
| `icon-1024.png` | 1024×1024 | iOS App Store |
| `logo-horizontal.png` | 1200×500 | Website, press kit, banners |
| `logo-stacked.png` | 500×600 | Splash screens, documents |
| `tray-dark.png` | 64×64 | macOS menu bar — dark mode |
| `tray-light.png` | 64×64 | macOS menu bar — light mode |
| `favicon-32.png` | 32×32 | Website favicon |

---

## Platform-specific icons

| Platform | File | Notes |
|----------|------|-------|
| macOS | `platforms/macos/AppIcon.icns` | Multi-size ICNS generated from SVG |
| Windows | `crates/aivpn-windows/assets/aivpn.ico` | Multi-size ICO (256,128,64,48,32,16 px) |
| Android | `assets/brand/android/mipmap-*/ic_launcher.png` | Per-density PNGs, copied into the app at build time |
| iOS | `assets/brand/ios/Assets.xcassets/AppIcon.appiconset/` | Generated via Xcode |

---

## Source files

All source files are SVG — editable in any vector editor (Inkscape, Figma, Illustrator):

| File | Description |
|------|-------------|
| `icon-512.svg` | App icon master (512×512, rounded rect) |
| `logo-horizontal.svg` | Horizontal banner (1200×500) |
| `logo-stacked.svg` | Stacked logo — mark above text (500×600) |
| `tray-dark.svg` | macOS tray — dark mode (64×64) |
| `tray-light.svg` | macOS tray — light mode (64×64) |
| `favicon-32.svg` | Web favicon (32×32) |

---

## Do / Don't

**Do:**
- Use the SVG sources as masters; always export PNGs from them
- Keep the lemon dot (`#E8FF6B`) at the exact center — it is the identity anchor
- On light backgrounds, use `tray-light.svg` which uses darker ring strokes

**Don't:**
- Change the ring proportions (outer:mid:inner = 196:140:82)
- Use the wordmark without the ring symbol
- Place the logo on backgrounds lighter than `#444` without switching to the light variant
- Compress or recolor the center lemon dot
