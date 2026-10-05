//! Прием подписанных масок через DNS TXT, PNG LSB и blockchain.
//!
//! AVM1 содержит тело и подпись Ed25519 из 64 байт. DNS разбивает контейнер
//! на строки до 255 байт, Bitcoin на OP_RETURN до 80 байт. Ethereum передает
//! контейнер через calldata. PNG ограничен по размеру файла и числу пикселей
//! до распаковки. Сетевой опрос требует явного allow_network.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use image::ImageEncoder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{debug, info, warn};

use aivpn_common::error::{Error, Result};
use aivpn_common::mask::MaskProfile;

const ENVELOPE_MAGIC: &[u8; 4] = b"AVM1";
const FLAG_DEFLATE: u8 = 0x01;
const SIG_LEN: usize = 64;
const MAX_ENVELOPE: usize = 256 * 1024;
const MAX_PLAINTEXT: usize = 256 * 1024;
const DNS_PREFIX: &str = "aivpn-mask-v1";
const TXT_MAX: usize = 255;
const MAX_DNS_RECORDS: usize = 128;
const BTC_MAGIC: &[u8; 2] = b"AV";
const BTC_HEADER: usize = 15;
const BTC_DATA: usize = 65;
const MAX_BTC_CHUNKS: usize = 4096;
const ETH_MAGIC: &[u8] = b"AIVPN-ETH1";
const CHAIN_MAGIC: &[u8; 4] = b"AVBC";
const MAX_CHAIN_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_IMAGE_PIXELS: u64 = 4_000_000;

fn default_max_image_bytes() -> usize {
    DEFAULT_MAX_IMAGE_BYTES
}

fn default_max_image_pixels() -> u64 {
    DEFAULT_MAX_IMAGE_PIXELS
}

/// Настройки пассивного получения масок.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PassiveDistributionConfig {
    /// Включить прием масок.
    pub enable: bool,
    /// Домены для опроса DNS TXT.
    pub dns_domains: Vec<String>,
    /// URL изображений с контейнером в LSB.
    pub image_urls: Vec<String>,
    /// Сети blockchain для чтения контейнеров.
    pub blockchain_networks: Vec<BlockchainNetwork>,
    /// Интервал опроса в секундах.
    pub check_interval_secs: u64,
    /// Открытый ключ оператора: 32 байта в base64.
    #[serde(default)]
    pub operator_pubkey_b64: Option<String>,
    /// DNS resolver в формате host:port, используется при allow_network.
    #[serde(default)]
    pub dns_resolver: Option<String>,
    /// URL источников транзакций. В тестах URL служит ключом фикстуры.
    #[serde(default)]
    pub chain_endpoints: Vec<String>,
    /// Максимальный размер загружаемого изображения в байтах.
    #[serde(default = "default_max_image_bytes")]
    pub max_image_bytes: usize,
    /// Лимит пикселей PNG проверяется по IHDR до распаковки.
    #[serde(default = "default_max_image_pixels")]
    pub max_image_pixels: u64,
    /// Разрешить сетевые запросы DNS и HTTP. По умолчанию выключено.
    #[serde(default)]
    pub allow_network: bool,
}

impl Default for PassiveDistributionConfig {
    fn default() -> Self {
        Self {
            enable: false,
            dns_domains: vec![],
            image_urls: vec![],
            blockchain_networks: vec![BlockchainNetwork::Bitcoin, BlockchainNetwork::Ethereum],
            check_interval_secs: 300,
            operator_pubkey_b64: None,
            dns_resolver: None,
            chain_endpoints: vec![],
            max_image_bytes: DEFAULT_MAX_IMAGE_BYTES,
            max_image_pixels: DEFAULT_MAX_IMAGE_PIXELS,
            allow_network: false,
        }
    }
}

/// Поддерживаемые сети blockchain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockchainNetwork {
    Bitcoin,
    Ethereum,
}

/// Каналы получения масок.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeliveryMethod {
    DnsTxt {
        domain: String,
        record_type: String,
    },
    ImageLsb {
        url: String,
        extraction_key: u32,
    },
    BlockchainOpReturn {
        network: BlockchainNetwork,
        txid_prefix: String,
    },
    Webhook {
        url: String,
        secret: String,
    },
}

/// Приемник подписанных масок.
pub struct PassiveMaskReceiver {
    config: PassiveDistributionConfig,
    cached_masks: HashMap<String, MaskProfile>,
    dns_fixtures: HashMap<String, Vec<String>>,
    image_fixtures: HashMap<String, Vec<u8>>,
    chain_fixtures: HashMap<String, Vec<u8>>,
    webhook_fixtures: Vec<Vec<u8>>,
    operator_pubkey: Option<[u8; 32]>,
}

impl PassiveMaskReceiver {
    /// Создать приемник.
    pub fn new(config: PassiveDistributionConfig) -> Self {
        let operator_pubkey = config
            .operator_pubkey_b64
            .as_deref()
            .and_then(|b64| decode_pubkey(b64).ok());
        Self {
            config,
            cached_masks: HashMap::new(),
            dns_fixtures: HashMap::new(),
            image_fixtures: HashMap::new(),
            chain_fixtures: HashMap::new(),
            webhook_fixtures: Vec::new(),
            operator_pubkey,
        }
    }

    pub fn set_operator_pubkey(&mut self, key: [u8; 32]) {
        self.operator_pubkey = Some(key);
    }

    pub fn set_dns_fixture(&mut self, domain: &str, records: Vec<String>) {
        self.dns_fixtures.insert(domain.to_string(), records);
    }

    pub fn set_image_fixture(&mut self, url: &str, png: Vec<u8>) {
        self.image_fixtures.insert(url.to_string(), png);
    }

    pub fn set_chain_fixture(&mut self, key: &str, payload: Vec<u8>) {
        self.chain_fixtures.insert(key.to_string(), payload);
    }

    pub fn push_webhook_fixture(&mut self, body: Vec<u8>) {
        self.webhook_fixtures.push(body);
    }

    /// Проверить подписанный контейнер и добавить маску в кеш.
    pub fn ingest_signed_bytes(&mut self, bytes: &[u8]) -> Result<Option<MaskProfile>> {
        let mut found = Vec::new();
        let mut missing_key = false;
        self.accept_envelope(bytes, &mut found, &mut missing_key);
        if missing_key {
            return Err(Error::Session(
                "operator public key is required to verify the mask signature".into(),
            ));
        }
        Ok(found.pop())
    }

    /// Получить новые маски.
    pub async fn poll_masks(&mut self) -> Result<Vec<MaskProfile>> {
        if !self.config.enable {
            return Ok(vec![]);
        }
        let mut found = Vec::new();
        let mut missing_key = false;

        let domains = self.config.dns_domains.clone();
        for domain in domains {
            if let Some(records) = self.dns_fixtures.get(&domain).cloned() {
                self.accept_dns(&records, &mut found, &mut missing_key);
                continue;
            }
            if !self.config.allow_network {
                continue;
            }
            let Some(resolver) = self.config.dns_resolver.clone() else {
                warn!("DNS lookup skipped for {domain}: dns_resolver is not set");
                continue;
            };
            match lookup_dns_txt(&domain, &resolver).await {
                Ok(records) => self.accept_dns(&records, &mut found, &mut missing_key),
                Err(e) => warn!("DNS lookup {domain} failed: {e}"),
            }
        }

        let images = self.config.image_urls.clone();
        let max_bytes = self.config.max_image_bytes;
        let max_pixels = self.config.max_image_pixels;
        for url in images {
            let png = if let Some(bytes) = self.image_fixtures.get(&url).cloned() {
                bytes
            } else if self.config.allow_network {
                match fetch_bounded(&url, max_bytes).await {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        warn!("image fetch {url} failed: {e}");
                        continue;
                    }
                }
            } else {
                continue;
            };
            match decode_png_lsb(&png, max_bytes, max_pixels) {
                Ok(envelope) => self.accept_envelope(&envelope, &mut found, &mut missing_key),
                Err(e) => debug!("image LSB rejected for {url}: {e}"),
            }
        }

        let networks = self.config.blockchain_networks.clone();
        for network in networks {
            let key = match network {
                BlockchainNetwork::Bitcoin => "bitcoin",
                BlockchainNetwork::Ethereum => "ethereum",
            };
            if let Some(bytes) = self.chain_fixtures.get(key).cloned() {
                self.accept_chain(&bytes, &mut found, &mut missing_key);
            }
        }
        let endpoints = self.config.chain_endpoints.clone();
        for url in endpoints {
            if let Some(bytes) = self.chain_fixtures.get(&url).cloned() {
                self.accept_chain(&bytes, &mut found, &mut missing_key);
                continue;
            }
            if !self.config.allow_network {
                continue;
            }
            match fetch_bounded(&url, MAX_CHAIN_BYTES).await {
                Ok(bytes) => self.accept_chain(&bytes, &mut found, &mut missing_key),
                Err(e) => warn!("chain fetch failed: {e}"),
            }
        }
        for body in self.webhook_fixtures.clone() {
            self.accept_envelope(&body, &mut found, &mut missing_key);
        }

        if missing_key && found.is_empty() {
            return Err(Error::Session(
                "operator public key is required to verify the mask signature".into(),
            ));
        }
        Ok(found)
    }

    /// Получить маску из кеша по идентификатору.
    pub fn get_cached_mask(&self, mask_id: &str) -> Option<&MaskProfile> {
        self.cached_masks.get(mask_id)
    }

    /// Получить все маски кеша.
    pub fn get_all_masks(&self) -> Vec<&MaskProfile> {
        self.cached_masks.values().collect()
    }

    /// Очистить кеш и идентификаторы, разрешив повторное получение масок.
    pub fn clear_cache(&mut self) {
        self.cached_masks.clear();
    }

    fn operator_pubkey(&self) -> Option<[u8; 32]> {
        self.operator_pubkey
    }

    fn accept_dns(
        &mut self,
        records: &[String],
        found: &mut Vec<MaskProfile>,
        missing_key: &mut bool,
    ) {
        let Some(pk) = self.operator_pubkey() else {
            *missing_key = true;
            warn!("operator public key is required to verify the mask signature");
            return;
        };
        match decode_dns_txt_records(records, &pk) {
            Ok(mask) => self.remember(mask, found),
            Err(e) => debug!("DNS TXT rejected: {e}"),
        }
    }

    fn accept_chain(&mut self, bytes: &[u8], found: &mut Vec<MaskProfile>, missing_key: &mut bool) {
        let Some(pk) = self.operator_pubkey() else {
            *missing_key = true;
            warn!("operator public key is required to verify the mask signature");
            return;
        };
        match decode_chain_bytes(bytes, &pk) {
            Ok(masks) => {
                for mask in masks {
                    self.remember(mask, found);
                }
            }
            Err(e) => debug!("chain payload rejected: {e}"),
        }
    }

    fn accept_envelope(
        &mut self,
        bytes: &[u8],
        found: &mut Vec<MaskProfile>,
        missing_key: &mut bool,
    ) {
        let Some(pk) = self.operator_pubkey() else {
            *missing_key = true;
            warn!("operator public key is required to verify the mask signature");
            return;
        };
        match open_signed_envelope(bytes, &pk) {
            Ok(mask) => self.remember(mask, found),
            Err(e) => debug!("signed envelope rejected: {e}"),
        }
    }

    fn remember(&mut self, mask: MaskProfile, found: &mut Vec<MaskProfile>) {
        if self
            .cached_masks
            .get(&mask.mask_id)
            .is_some_and(|old| old.signature == mask.signature)
        {
            return;
        }
        if self.cached_masks.len() >= 256 {
            if let Some(old) = self.cached_masks.keys().next().cloned() {
                self.cached_masks.remove(&old);
            }
        }
        info!("Discovered mask {}", mask.mask_id);
        self.cached_masks.insert(mask.mask_id.clone(), mask.clone());
        found.push(mask);
    }
}

/// Кодировщик контейнеров для публикации масок.
pub struct SteganographicEncoder {
    signing_key: SigningKey,
}

impl SteganographicEncoder {
    /// signing_key содержит пару seed || pubkey либо seed в первых 32 байтах.
    /// Размер подписи во всех каналах - 64 байта.
    pub fn new(signing_key: [u8; 64]) -> Self {
        Self {
            signing_key: signing_key_from_material(&signing_key),
        }
    }

    /// Строки TXT разделяются переводом строки. Контейнер разбивается,
    /// если не помещается в 255 символов.
    pub fn encode_for_dns(&self, mask: &MaskProfile) -> Result<String> {
        Ok(self.encode_dns_txt_strings(mask)?.join("\n"))
    }

    pub fn encode_dns_txt_strings(&self, mask: &MaskProfile) -> Result<Vec<String>> {
        encode_dns_txt_strings(&sign_envelope(mask, &self.signing_key)?)
    }

    /// PNG с подписанным контейнером в младших битах RGB.
    pub fn encode_for_image(&self, mask: &MaskProfile) -> Result<Vec<u8>> {
        encode_png_lsb(&sign_envelope(mask, &self.signing_key)?)
    }

    /// Набор частей Bitcoin OP_RETURN: AVBC, сеть 1. Маска разбивается
    /// на payload до 80 байт каждый.
    pub fn encode_for_blockchain(&self, mask: &MaskProfile) -> Result<Vec<u8>> {
        self.encode_for_network(mask, BlockchainNetwork::Bitcoin)
    }

    pub fn encode_for_network(
        &self,
        mask: &MaskProfile,
        network: BlockchainNetwork,
    ) -> Result<Vec<u8>> {
        let envelope = sign_envelope(mask, &self.signing_key)?;
        match network {
            BlockchainNetwork::Bitcoin => {
                let scripts = bitcoin_scripts(&envelope)?;
                pack_avbc(1, &scripts_blob(&scripts)?)
            }
            BlockchainNetwork::Ethereum => {
                let calldata = ethereum_calldata(&envelope)?;
                pack_avbc(2, &calldata)
            }
        }
    }
}

fn signing_key_from_material(material: &[u8; 64]) -> SigningKey {
    if let Ok(key) = SigningKey::from_keypair_bytes(material) {
        key
    } else {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&material[..32]);
        SigningKey::from_bytes(&seed)
    }
}

fn sign_envelope(mask: &MaskProfile, key: &SigningKey) -> Result<Vec<u8>> {
    let mut mask = mask.clone();
    if let Some(reverse) = mask.reverse_profile.as_mut() {
        reverse.sign(key);
    }
    mask.sign(key);
    let raw = rmp_serde::to_vec(&mask)?;
    if raw.len() > MAX_PLAINTEXT {
        return Err(Error::Session("mask plaintext exceeds limit".into()));
    }
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&raw)?;
    let compressed = encoder.finish()?;
    let (flags, body) = if compressed.len() < raw.len() {
        (FLAG_DEFLATE, compressed)
    } else {
        (0u8, raw)
    };
    if body.len() > MAX_ENVELOPE {
        return Err(Error::Session("signed envelope exceeds limit".into()));
    }
    let mut prefix = Vec::with_capacity(10 + body.len() + SIG_LEN);
    prefix.extend_from_slice(ENVELOPE_MAGIC);
    prefix.push(flags);
    prefix.push(0);
    prefix.extend_from_slice(&(body.len() as u32).to_be_bytes());
    prefix.extend_from_slice(&body);
    let signature = key.sign(&prefix);
    prefix.extend_from_slice(&signature.to_bytes());
    Ok(prefix)
}

fn open_signed_envelope(bytes: &[u8], pubkey: &[u8; 32]) -> Result<MaskProfile> {
    if bytes.len() < 10 + SIG_LEN || &bytes[..4] != ENVELOPE_MAGIC {
        return Err(Error::Session("envelope magic".into()));
    }
    let flags = bytes[4];
    if flags & !FLAG_DEFLATE != 0 {
        return Err(Error::Session("envelope flags".into()));
    }
    let body_len = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
    if body_len > MAX_ENVELOPE || 10 + body_len + SIG_LEN != bytes.len() {
        return Err(Error::Session("envelope length".into()));
    }
    let prefix = &bytes[..bytes.len() - SIG_LEN];
    let mut sig = [0u8; SIG_LEN];
    sig.copy_from_slice(&bytes[bytes.len() - SIG_LEN..]);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pubkey)
        .map_err(|e| Error::Crypto(format!("operator key: {e}")))?;
    vk.verify_strict(prefix, &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| Error::Session("envelope signature".into()))?;
    let body = &bytes[10..10 + body_len];
    let plain = if flags & FLAG_DEFLATE != 0 {
        inflate_limited(body)?
    } else {
        body.to_vec()
    };
    Ok(rmp_serde::from_slice(&plain)?)
}

fn inflate_limited(body: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = flate2::read::DeflateDecoder::new(body);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = decoder.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if out.len().saturating_add(n) > MAX_PLAINTEXT {
            return Err(Error::Session("deflate output exceeds limit".into()));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

fn encode_dns_txt_strings(envelope: &[u8]) -> Result<Vec<String>> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(envelope);
    let header = format!("{DNS_PREFIX}:000/000:");
    if header.len() >= TXT_MAX {
        return Err(Error::Session("DNS TXT header exceeds 255".into()));
    }
    let room = TXT_MAX - header.len();
    let count = b64.len().div_ceil(room).max(1);
    if count > MAX_DNS_RECORDS || count > 999 {
        return Err(Error::Session("DNS TXT record limit".into()));
    }
    let mut records = Vec::with_capacity(count);
    for index in 0..count {
        let start = index * room;
        let end = (start + room).min(b64.len());
        let record = format!(
            "{DNS_PREFIX}:{:03}/{:03}:{}",
            index + 1,
            count,
            &b64[start..end]
        );
        if record.len() > TXT_MAX {
            return Err(Error::Session("DNS TXT string exceeds 255".into()));
        }
        records.push(record);
    }
    Ok(records)
}

fn decode_dns_txt_records(records: &[String], pubkey: &[u8; 32]) -> Result<MaskProfile> {
    let mut parts: Vec<(u16, u16, String)> = Vec::new();
    for record in records {
        for line in record.split(['\n', '\r']) {
            let line = line.trim().trim_matches('"');
            if line.is_empty() {
                continue;
            }
            if let Some((idx, cnt, data)) = parse_dns_chunk(line) {
                parts.push((idx, cnt, data.to_string()));
            }
        }
    }
    if parts.is_empty() {
        return Err(Error::Session("DNS TXT has no mask chunks".into()));
    }
    let count = parts[0].1;
    if count == 0 || count as usize > MAX_DNS_RECORDS || parts.iter().any(|part| part.1 != count) {
        return Err(Error::Session("DNS TXT chunk count".into()));
    }
    let mut ordered = vec![None; count as usize];
    for (idx, _, data) in parts {
        if idx == 0 || idx > count {
            return Err(Error::Session("DNS TXT chunk index".into()));
        }
        let slot = &mut ordered[(idx - 1) as usize];
        if slot.is_some() {
            return Err(Error::Session("DNS TXT duplicate chunk".into()));
        }
        *slot = Some(data);
    }
    let mut b64 = String::new();
    for slot in ordered {
        let Some(data) = slot else {
            return Err(Error::Session("DNS TXT incomplete".into()));
        };
        b64.push_str(&data);
    }
    let envelope = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| Error::Session(format!("DNS TXT base64: {e}")))?;
    open_signed_envelope(&envelope, pubkey)
}

fn parse_dns_chunk(line: &str) -> Option<(u16, u16, &str)> {
    let rest = line.strip_prefix(DNS_PREFIX)?.strip_prefix(':')?;
    let (idx, rest) = rest.split_once('/')?;
    let (cnt, data) = rest.split_once(':')?;
    let idx: u16 = idx.parse().ok()?;
    let cnt: u16 = cnt.parse().ok()?;
    if idx == 0 || cnt == 0 || idx > cnt {
        return None;
    }
    Some((idx, cnt, data))
}

fn encode_png_lsb(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_ENVELOPE {
        return Err(Error::Session("png payload exceeds limit".into()));
    }
    let bits = (4 + payload.len()) * 8;
    let mut side = 1u32;
    while (side as u64) * (side as u64) * 3 < bits as u64 {
        if side >= 2048 {
            return Err(Error::Session("png pixel limit".into()));
        }
        side *= 2;
    }
    let mut img = image::RgbaImage::from_pixel(side, side, image::Rgba([0x80, 0x80, 0x80, 0xff]));
    let mut data = Vec::with_capacity(4 + payload.len());
    data.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    data.extend_from_slice(payload);
    write_lsb(&mut img, &data)?;
    let mut png = Vec::new();
    image::codecs::png::PngEncoder::new(&mut png)
        .write_image(img.as_raw(), side, side, image::ExtendedColorType::Rgba8)
        .map_err(|e| Error::Session(format!("png encode: {e}")))?;
    Ok(png)
}

fn decode_png_lsb(bytes: &[u8], max_bytes: usize, max_pixels: u64) -> Result<Vec<u8>> {
    if bytes.len() > max_bytes {
        return Err(Error::Session("image byte limit".into()));
    }
    let (width, height) = png_ihdr_dimensions(bytes)?;
    let pixels = (width as u64).saturating_mul(height as u64);
    if pixels == 0 || pixels > max_pixels {
        return Err(Error::Session("png pixel limit".into()));
    }
    let image = image::load_from_memory(bytes)
        .map_err(|e| Error::Session(format!("png decode: {e}")))?
        .to_rgba8();
    if image.width() != width || image.height() != height {
        return Err(Error::Session("png dimension mismatch".into()));
    }
    let len_bits = read_lsb(&image, 0, 32)?;
    let len = u32::from_be_bytes([len_bits[0], len_bits[1], len_bits[2], len_bits[3]]) as usize;
    if len == 0 || len > MAX_ENVELOPE {
        return Err(Error::Session("png payload length".into()));
    }
    let capacity = pixels.saturating_mul(3);
    if 32u64.saturating_add((len as u64).saturating_mul(8)) > capacity {
        return Err(Error::Session("png payload truncated".into()));
    }
    read_lsb(&image, 32, len * 8)
}

fn png_ihdr_dimensions(bytes: &[u8]) -> Result<(u32, u32)> {
    const SIG: &[u8] = b"\x89PNG\r\n\x1a\n";
    if bytes.len() < 24 || &bytes[..8] != SIG || &bytes[12..16] != b"IHDR" {
        return Err(Error::Session("not a png".into()));
    }
    let width = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let height = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    Ok((width, height))
}

fn write_lsb(img: &mut image::RgbaImage, data: &[u8]) -> Result<()> {
    let total_bits = data.len() * 8;
    let mut bit_index = 0usize;
    for pixel in img.pixels_mut() {
        for channel in 0..3 {
            if bit_index >= total_bits {
                return Ok(());
            }
            let bit = (data[bit_index / 8] >> (7 - (bit_index % 8))) & 1;
            pixel.0[channel] = (pixel.0[channel] & 0xfe) | bit;
            bit_index += 1;
        }
    }
    if bit_index < total_bits {
        return Err(Error::Session("png payload truncated".into()));
    }
    Ok(())
}

fn read_lsb(img: &image::RgbaImage, start_bit: usize, bit_count: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; bit_count.div_ceil(8)];
    let mut seen = 0usize;
    let end = start_bit + bit_count;
    for pixel in img.pixels() {
        for channel in 0..3 {
            let absolute = seen;
            seen += 1;
            if absolute < start_bit {
                continue;
            }
            if absolute >= end {
                return Ok(out);
            }
            let offset = absolute - start_bit;
            if pixel.0[channel] & 1 == 1 {
                out[offset / 8] |= 1 << (7 - (offset % 8));
            }
        }
    }
    if seen < end {
        return Err(Error::Session("png payload truncated".into()));
    }
    Ok(out)
}

fn bitcoin_scripts(envelope: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut id = [0u8; 8];
    id.copy_from_slice(&blake3::hash(envelope).as_bytes()[..8]);
    let chunks = envelope.len().div_ceil(BTC_DATA);
    if chunks == 0 || chunks > MAX_BTC_CHUNKS {
        return Err(Error::Session("bitcoin chunk limit".into()));
    }
    let mut scripts = Vec::with_capacity(chunks);
    for index in 0..chunks {
        let start = index * BTC_DATA;
        let end = (start + BTC_DATA).min(envelope.len());
        let mut payload = Vec::with_capacity(BTC_HEADER + (end - start));
        payload.extend_from_slice(BTC_MAGIC);
        payload.push(1);
        payload.extend_from_slice(&id);
        payload.extend_from_slice(&(index as u16).to_be_bytes());
        payload.extend_from_slice(&(chunks as u16).to_be_bytes());
        payload.extend_from_slice(&envelope[start..end]);
        if payload.len() > 80 {
            return Err(Error::Session("OP_RETURN payload exceeds 80".into()));
        }
        scripts.push(op_return_script(&payload));
    }
    Ok(scripts)
}

fn op_return_script(payload: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(3 + payload.len());
    script.push(0x6a);
    if payload.len() < 76 {
        script.push(payload.len() as u8);
    } else {
        script.push(0x4c);
        script.push(payload.len() as u8);
    }
    script.extend_from_slice(payload);
    script
}

fn scripts_blob(scripts: &[Vec<u8>]) -> Result<Vec<u8>> {
    if scripts.len() > u16::MAX as usize {
        return Err(Error::Session("bitcoin chunk limit".into()));
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(scripts.len() as u16).to_be_bytes());
    for script in scripts {
        if script.len() > u16::MAX as usize {
            return Err(Error::Session("OP_RETURN script exceeds limit".into()));
        }
        out.extend_from_slice(&(script.len() as u16).to_be_bytes());
        out.extend_from_slice(script);
    }
    Ok(out)
}

fn ethereum_calldata(envelope: &[u8]) -> Result<Vec<u8>> {
    if envelope.len() > MAX_ENVELOPE {
        return Err(Error::Session("ethereum calldata exceeds limit".into()));
    }
    let mut out = Vec::with_capacity(ETH_MAGIC.len() + 4 + envelope.len());
    out.extend_from_slice(ETH_MAGIC);
    out.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
    out.extend_from_slice(envelope);
    Ok(out)
}

fn pack_avbc(network: u8, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_CHAIN_BYTES {
        return Err(Error::Session("chain payload exceeds limit".into()));
    }
    let mut out = Vec::with_capacity(10 + payload.len());
    out.extend_from_slice(CHAIN_MAGIC);
    out.push(1);
    out.push(network);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn decode_chain_bytes(bytes: &[u8], pubkey: &[u8; 32]) -> Result<Vec<MaskProfile>> {
    if bytes.len() > MAX_CHAIN_BYTES {
        return Err(Error::Session("chain payload exceeds limit".into()));
    }
    if matches!(
        bytes.iter().find(|b| !b.is_ascii_whitespace()),
        Some(b'{' | b'[')
    ) {
        return decode_chain_json(bytes, pubkey);
    }
    if bytes.starts_with(CHAIN_MAGIC) {
        return decode_avbc(bytes, pubkey).map(|mask| vec![mask]);
    }
    if bytes.starts_with(ETH_MAGIC) {
        return decode_ethereum_calldata(bytes, pubkey).map(|mask| vec![mask]);
    }
    if let Ok(mask) = decode_bitcoin_script_blob(bytes, pubkey) {
        return Ok(vec![mask]);
    }
    Err(Error::Session("chain payload".into()))
}

// Поддерживаются ответы Esplora, Bitcoin Core и Ethereum с полем input.
// Источник данных не заменяет проверку подписи оператора.
fn decode_chain_json(bytes: &[u8], pubkey: &[u8; 32]) -> Result<Vec<MaskProfile>> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| Error::Session("invalid chain JSON".into()))?;
    let root = value.get("result").unwrap_or(&value);
    let transactions: Vec<&serde_json::Value> = match root.as_array() {
        Some(items) if items.len() <= 256 => items.iter().collect(),
        Some(_) => return Err(Error::Session("chain transaction limit".into())),
        None => vec![root],
    };
    let mut masks = Vec::new();
    let mut scripts: HashMap<[u8; 8], Vec<Vec<u8>>> = HashMap::new();
    let mut script_count = 0;
    for transaction in transactions {
        if let Some(input) = transaction.get("input").and_then(|v| v.as_str()) {
            let data = hex::decode(input.strip_prefix("0x").unwrap_or(input))
                .map_err(|_| Error::Session("invalid transaction input hex".into()))?;
            if data.starts_with(ETH_MAGIC) {
                masks.push(decode_ethereum_calldata(&data, pubkey)?);
            }
        }
        if let Some(outputs) = transaction.get("vout").and_then(|v| v.as_array()) {
            for output in outputs {
                let encoded = output
                    .get("scriptpubkey")
                    .and_then(|v| v.as_str())
                    .or_else(|| output.get("scriptPubKey")?.get("hex")?.as_str());
                let Some(encoded) = encoded else { continue };
                if !encoded.starts_with("6a") || encoded.len() > 166 {
                    continue;
                }
                let script = hex::decode(encoded)
                    .map_err(|_| Error::Session("invalid script hex".into()))?;
                let Ok(payload) = op_return_payload(&script) else {
                    continue;
                };
                if payload.len() < BTC_HEADER || !payload.starts_with(BTC_MAGIC) || payload[2] != 1
                {
                    continue;
                }
                script_count += 1;
                if script_count > MAX_BTC_CHUNKS {
                    return Err(Error::Session("bitcoin chunk limit".into()));
                }
                let id = payload[3..11].try_into().unwrap();
                scripts.entry(id).or_default().push(script);
            }
        }
    }
    for group in scripts.into_values() {
        masks.push(decode_bitcoin_script_blob(&scripts_blob(&group)?, pubkey)?);
    }
    if masks.is_empty() {
        return Err(Error::Session("no signed masks in chain response".into()));
    }
    Ok(masks)
}

fn decode_avbc(bytes: &[u8], pubkey: &[u8; 32]) -> Result<MaskProfile> {
    if bytes.len() < 10 || &bytes[..4] != CHAIN_MAGIC || bytes[4] != 1 {
        return Err(Error::Session("chain header".into()));
    }
    let network = bytes[5];
    let len = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
    if len > MAX_CHAIN_BYTES || 10 + len != bytes.len() {
        return Err(Error::Session("chain length".into()));
    }
    let payload = &bytes[10..];
    match network {
        1 => decode_bitcoin_script_blob(payload, pubkey),
        2 => decode_ethereum_calldata(payload, pubkey),
        _ => Err(Error::Session("chain network".into())),
    }
}

fn decode_bitcoin_script_blob(bytes: &[u8], pubkey: &[u8; 32]) -> Result<MaskProfile> {
    if bytes.len() < 2 {
        return Err(Error::Session("bitcoin blob".into()));
    }
    let count = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if count == 0 || count > MAX_BTC_CHUNKS {
        return Err(Error::Session("bitcoin chunk count".into()));
    }
    let mut scripts = Vec::with_capacity(count);
    let mut offset = 2;
    for _ in 0..count {
        if offset + 2 > bytes.len() {
            return Err(Error::Session("bitcoin blob truncated".into()));
        }
        let len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        if offset + len > bytes.len() {
            return Err(Error::Session("bitcoin blob truncated".into()));
        }
        scripts.push(bytes[offset..offset + len].to_vec());
        offset += len;
    }
    if offset != bytes.len() {
        return Err(Error::Session("bitcoin blob trailing".into()));
    }
    reassemble_bitcoin(&scripts, pubkey)
}

fn reassemble_bitcoin(scripts: &[Vec<u8>], pubkey: &[u8; 32]) -> Result<MaskProfile> {
    let mut groups: HashMap<[u8; 8], Vec<(u16, u16, Vec<u8>)>> = HashMap::new();
    for script in scripts {
        let payload = op_return_payload(script)?;
        if payload.len() < BTC_HEADER || &payload[..2] != BTC_MAGIC || payload[2] != 1 {
            return Err(Error::Session("OP_RETURN chunk header".into()));
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&payload[3..11]);
        let idx = u16::from_be_bytes([payload[11], payload[12]]);
        let cnt = u16::from_be_bytes([payload[13], payload[14]]);
        groups
            .entry(id)
            .or_default()
            .push((idx, cnt, payload[BTC_HEADER..].to_vec()));
    }
    if groups.len() != 1 {
        return Err(Error::Session("bitcoin chunk set".into()));
    }
    let chunks = groups.into_values().next().unwrap_or_default();
    let count = chunks.first().map(|chunk| chunk.1).unwrap_or(0) as usize;
    if count == 0 || count != chunks.len() || chunks.iter().any(|chunk| chunk.1 as usize != count) {
        return Err(Error::Session("bitcoin incomplete".into()));
    }
    let mut ordered = vec![None; count];
    for (idx, _, data) in chunks {
        if idx as usize >= count || ordered[idx as usize].is_some() {
            return Err(Error::Session("bitcoin chunk index".into()));
        }
        ordered[idx as usize] = Some(data);
    }
    let mut envelope = Vec::new();
    for part in ordered {
        let Some(part) = part else {
            return Err(Error::Session("bitcoin incomplete".into()));
        };
        envelope.extend_from_slice(&part);
    }
    open_signed_envelope(&envelope, pubkey)
}

fn op_return_payload(script: &[u8]) -> Result<Vec<u8>> {
    if script.first() != Some(&0x6a) {
        return Err(Error::Session("not an OP_RETURN script".into()));
    }
    let rest = &script[1..];
    if rest.is_empty() {
        return Err(Error::Session("OP_RETURN push".into()));
    }
    let (len, at) = if rest[0] < 76 {
        (rest[0] as usize, 1)
    } else if rest[0] == 0x4c && rest.len() >= 2 {
        (rest[1] as usize, 2)
    } else {
        return Err(Error::Session("OP_RETURN push".into()));
    };
    if len > 80 || rest.len() != at + len {
        return Err(Error::Session("OP_RETURN payload exceeds 80".into()));
    }
    Ok(rest[at..].to_vec())
}

fn decode_ethereum_calldata(bytes: &[u8], pubkey: &[u8; 32]) -> Result<MaskProfile> {
    if bytes.len() < ETH_MAGIC.len() + 4 || &bytes[..ETH_MAGIC.len()] != ETH_MAGIC {
        return Err(Error::Session("ethereum calldata magic".into()));
    }
    let len_at = ETH_MAGIC.len();
    let len = u32::from_be_bytes([
        bytes[len_at],
        bytes[len_at + 1],
        bytes[len_at + 2],
        bytes[len_at + 3],
    ]) as usize;
    let start = len_at + 4;
    if len > MAX_ENVELOPE || start + len != bytes.len() {
        return Err(Error::Session("ethereum calldata length".into()));
    }
    open_signed_envelope(&bytes[start..], pubkey)
}

fn decode_pubkey(b64: &str) -> Result<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| Error::Session(format!("operator key: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::Session("operator key length".into()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub async fn lookup_dns_txt(domain: &str, resolver: &str) -> Result<Vec<String>> {
    let addr = resolver_addr(resolver)?;
    let socket = tokio::net::UdpSocket::bind(if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    })
    .await?;
    socket.connect(addr).await?;
    let id: u16 = rand::random();
    let query = build_txt_query(domain, id)?;
    socket.send(&query).await?;
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buf))
        .await
        .map_err(|_| Error::Session("dns timeout".into()))??;
    if n < 12 || buf[..2] != query[..2] || buf[2] & 0xf8 != 0x80 || buf[3] & 0x0f != 0 {
        return Err(Error::Session("DNS response does not match query".into()));
    }
    if buf[2] & 0x02 != 0 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        return tokio::time::timeout(Duration::from_secs(5), async {
            let mut stream = tokio::net::TcpStream::connect(addr).await?;
            stream.write_u16(query.len() as u16).await?;
            stream.write_all(&query).await?;
            let length = stream.read_u16().await? as usize;
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await?;
            if body.len() < query.len()
                || body[..2] != query[..2]
                || body[2] & 0xfa != 0x80
                || body[3] & 15 != 0
                || body[4..6] != [0, 1]
                || body[12..query.len()] != query[12..]
            {
                return Err(Error::Session(
                    "DNS TCP response does not match query".into(),
                ));
            }
            parse_dns_txt_response(&body)
        })
        .await
        .map_err(|_| Error::Session("DNS TCP timeout".into()))?;
    }
    if n < query.len() || buf[4..6] != [0, 1] || buf[12..query.len()] != query[12..] {
        return Err(Error::Session("DNS question does not match query".into()));
    }
    parse_dns_txt_response(&buf[..n])
}

fn resolver_addr(resolver: &str) -> Result<SocketAddr> {
    if let Ok(addr) = resolver.parse::<SocketAddr>() {
        return Ok(addr);
    }
    format!("{resolver}:53")
        .parse()
        .map_err(|e| Error::Session(format!("dns resolver: {e}")))
}

fn build_txt_query(domain: &str, id: u16) -> Result<Vec<u8>> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::Session("dns name".into()));
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&16u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    Ok(query)
}

fn parse_dns_txt_response(packet: &[u8]) -> Result<Vec<String>> {
    if packet.len() < 12 {
        return Err(Error::Session("dns response too short".into()));
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let answers = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_dns_name(packet, offset)?;
        if offset + 4 > packet.len() {
            return Err(Error::Session("dns question truncated".into()));
        }
        offset += 4;
    }
    let mut texts = Vec::new();
    for _ in 0..answers {
        offset = skip_dns_name(packet, offset)?;
        if offset + 10 > packet.len() {
            return Err(Error::Session("dns answer truncated".into()));
        }
        let kind = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > packet.len() {
            return Err(Error::Session("dns rdata truncated".into()));
        }
        if kind == 16 {
            let mut cursor = offset;
            let end = offset + rdlen;
            let mut text = String::new();
            while cursor < end {
                let len = packet[cursor] as usize;
                cursor += 1;
                if cursor + len > end {
                    return Err(Error::Session("dns txt truncated".into()));
                }
                text.push_str(&String::from_utf8_lossy(&packet[cursor..cursor + len]));
                cursor += len;
            }
            if !text.is_empty() {
                texts.push(text);
            }
        }
        offset += rdlen;
    }
    Ok(texts)
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> Result<usize> {
    for _ in 0..128 {
        if offset >= packet.len() {
            return Err(Error::Session("dns name truncated".into()));
        }
        let len = packet[offset];
        if len == 0 {
            return Ok(offset + 1);
        }
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= packet.len() {
                return Err(Error::Session("dns name truncated".into()));
            }
            return Ok(offset + 2);
        }
        if len & 0xc0 != 0 {
            return Err(Error::Session("dns name".into()));
        }
        offset += 1 + len as usize;
    }
    Err(Error::Session("dns name".into()))
}

#[cfg(feature = "passive-distribution")]
async fn fetch_bounded(url: &str, max_bytes: usize) -> Result<Vec<u8>> {
    aivpn_client::bootstrap_loader::fetch_public_bytes(url, max_bytes).await
}

#[cfg(not(feature = "passive-distribution"))]
async fn fetch_bounded(_url: &str, _max_bytes: usize) -> Result<Vec<u8>> {
    Err(Error::Session(
        "passive-distribution feature is required for network fetch".into(),
    ))
}

/// Запускает прием подписанных масок в рабочий каталог сервера.
pub fn spawn_receiver(
    config: PassiveDistributionConfig,
    store: std::sync::Arc<crate::mask_store::MaskStore>,
) -> Result<tokio::task::JoinHandle<()>> {
    if config.check_interval_secs == 0
        || config.dns_domains.len() + config.image_urls.len() + config.chain_endpoints.len() > 64
        || config.max_image_bytes == 0
        || config.max_image_bytes > DEFAULT_MAX_IMAGE_BYTES
        || config.max_image_pixels == 0
        || config.max_image_pixels > DEFAULT_MAX_IMAGE_PIXELS
    {
        return Err(Error::Session("Invalid passive distribution limits".into()));
    }
    let key = config.operator_pubkey_b64.as_deref().ok_or_else(|| {
        Error::Session("Passive distribution requires operator_pubkey_b64".into())
    })?;
    decode_pubkey(key)?;
    #[cfg(not(feature = "passive-distribution"))]
    if config.allow_network && (!config.image_urls.is_empty() || !config.chain_endpoints.is_empty())
    {
        return Err(Error::Session(
            "Build requires passive-distribution feature".into(),
        ));
    }
    let interval = Duration::from_secs(config.check_interval_secs);
    let mut receiver = PassiveMaskReceiver::new(config);
    Ok(tokio::spawn(async move {
        let mut timer = tokio::time::interval(interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            timer.tick().await;
            match receiver.poll_masks().await {
                Ok(masks) => {
                    for profile in masks {
                        let id = profile.mask_id.clone();
                        let entry = crate::mask_store::MaskEntry {
                            profile,
                            stats: crate::mask_store::MaskStats {
                                mask_id: id.clone(),
                                times_used: 0,
                                times_failed: 0,
                                success_rate: 1.0,
                                confidence: 0.0,
                                is_active: true,
                                created_by: "passive".into(),
                                created_at: aivpn_common::mask::current_unix_secs(),
                                last_used: None,
                            },
                        };
                        if let Err(error) = store.add_mask(entry) {
                            receiver.cached_masks.remove(&id);
                            warn!("Passive mask storage failed: {error}");
                        }
                    }
                }
                Err(error) => warn!("Passive mask poll failed: {error}"),
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (SteganographicEncoder, [u8; 32], SigningKey) {
        let seed = [9u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let mut material = [0u8; 64];
        material[..32].copy_from_slice(&seed);
        let encoder = SteganographicEncoder::new(material);
        (encoder, signing.verifying_key().to_bytes(), signing)
    }

    fn sample() -> MaskProfile {
        let (_, _, signing) = keys();
        let mut mask = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
        mask.sign(&signing);
        mask
    }

    #[test]
    fn weak_operator_cannot_authenticate_a_container() {
        let (_, _, signing) = keys();
        let mut envelope = sign_envelope(&sample(), &signing).unwrap();
        let start = envelope.len() - SIG_LEN;
        envelope[start..].fill(0);
        envelope[start] = 1;
        let mut weak = [0u8; 32];
        weak[0] = 1;
        assert!(open_signed_envelope(&envelope, &weak).is_err());
    }

    #[test]
    fn keypair_material_is_accepted() {
        let signing = SigningKey::from_bytes(&[4u8; 32]);
        let mut material = [0u8; 64];
        material[..32].copy_from_slice(&signing.to_bytes());
        material[32..].copy_from_slice(&signing.verifying_key().to_bytes());
        let encoder = SteganographicEncoder::new(material);
        let mask = sample();
        let envelope = sign_envelope(&mask, &encoder.signing_key).unwrap();
        assert!(envelope.len() > SIG_LEN);
        assert_eq!(&envelope[..4], b"AVM1");
        open_signed_envelope(&envelope, &signing.verifying_key().to_bytes()).unwrap();
    }

    #[test]
    fn signature_tamper_and_length_are_rejected() {
        let (encoder, pubkey, _) = keys();
        let mask = sample();
        let mut envelope = sign_envelope(&mask, &encoder.signing_key).unwrap();
        assert_eq!(envelope.len() - SIG_LEN + SIG_LEN, envelope.len());
        assert!(envelope.len() > 10 + SIG_LEN);
        let last = envelope.len() - 1;
        envelope[last] ^= 0xff;
        assert!(open_signed_envelope(&envelope, &pubkey).is_err());
        envelope[last] ^= 0xff;
        envelope[12] ^= 0xff;
        assert!(open_signed_envelope(&envelope, &pubkey)
            .unwrap_err()
            .to_string()
            .contains("signature"));
        let mut short = b"AVM1".to_vec();
        short.extend_from_slice(&[0, 0]);
        short.extend_from_slice(&u32::MAX.to_be_bytes());
        short.extend_from_slice(&[0u8; SIG_LEN]);
        assert!(open_signed_envelope(&short, &pubkey)
            .unwrap_err()
            .to_string()
            .contains("length"));
    }

    #[test]
    fn dns_image_and_chain_roundtrip_real_mask() {
        let (encoder, pubkey, _) = keys();
        let mask = sample();

        let records = encoder.encode_dns_txt_strings(&mask).unwrap();
        assert!(
            records.len() > 1,
            "a real mask must be chunked across TXT strings"
        );
        assert!(records.iter().all(|record| record.len() <= TXT_MAX));
        let joined = encoder.encode_for_dns(&mask).unwrap();
        let decoded = decode_dns_txt_records(&[joined], &pubkey).unwrap();
        assert_eq!(decoded.mask_id, mask.mask_id);
        assert!(decoded.verify_signature(&pubkey).unwrap());

        let mut tampered = records.clone();
        let end = tampered[0].len() - 1;
        let byte = tampered[0].as_bytes()[end] ^ 0x01;
        tampered[0].replace_range(end..end + 1, &char::from(byte).to_string());
        assert!(decode_dns_txt_records(&tampered, &pubkey).is_err());

        let png = encoder.encode_for_image(&mask).unwrap();
        let extracted =
            decode_png_lsb(&png, DEFAULT_MAX_IMAGE_BYTES, DEFAULT_MAX_IMAGE_PIXELS).unwrap();
        let from_png = open_signed_envelope(&extracted, &pubkey).unwrap();
        assert_eq!(from_png.mask_id, mask.mask_id);

        let bitcoin = encoder
            .encode_for_network(&mask, BlockchainNetwork::Bitcoin)
            .unwrap();
        let scripts = bitcoin_script_list(&bitcoin).unwrap();
        assert!(scripts.len() > 1, "full mask is not one OP_RETURN");
        for script in &scripts {
            assert_eq!(script[0], 0x6a);
            assert!(op_return_payload(script).unwrap().len() <= 80);
        }
        let from_btc = decode_chain_bytes(&bitcoin, &pubkey).unwrap();
        assert_eq!(from_btc[0].mask_id, mask.mask_id);

        let ethereum = encoder
            .encode_for_network(&mask, BlockchainNetwork::Ethereum)
            .unwrap();
        assert!(ethereum.windows(ETH_MAGIC.len()).any(|w| w == ETH_MAGIC));
        assert_ne!(
            ethereum[10], 0x6a,
            "ethereum calldata is not an OP_RETURN script"
        );
        let from_eth = decode_chain_bytes(&ethereum, &pubkey).unwrap();
        assert_eq!(from_eth[0].mask_id, mask.mask_id);
    }

    #[test]
    fn public_chain_json_responses_verify_signatures_and_chunks() {
        let (encoder, pubkey, _) = keys();
        let mask = sample();
        let btc = encoder.encode_for_blockchain(&mask).unwrap();
        let scripts = bitcoin_script_list(&btc).unwrap();
        let outputs: Vec<_> = scripts
            .iter()
            .map(|s| serde_json::json!({"scriptpubkey": hex::encode(s)}))
            .collect();
        let json = serde_json::to_vec(&serde_json::json!([{"vout": outputs}])).unwrap();
        assert_eq!(
            decode_chain_bytes(&json, &pubkey).unwrap()[0].mask_id,
            mask.mask_id
        );
        assert!(decode_chain_bytes(&json, &[0; 32]).is_err());
        let partial = serde_json::to_vec(&serde_json::json!({"result": {"vout": [{"scriptPubKey": {"hex": hex::encode(&scripts[0])}}]}})).unwrap();
        assert!(decode_chain_bytes(&partial, &pubkey).is_err());
        let data = ethereum_calldata(&sign_envelope(&mask, &encoder.signing_key).unwrap()).unwrap();
        let json = serde_json::to_vec(
            &serde_json::json!({"result": {"input": format!("0x{}", hex::encode(data))}}),
        )
        .unwrap();
        assert_eq!(
            decode_chain_bytes(&json, &pubkey).unwrap()[0].mask_id,
            mask.mask_id
        );
    }

    fn bitcoin_script_list(blob: &[u8]) -> Result<Vec<Vec<u8>>> {
        assert!(blob.starts_with(CHAIN_MAGIC));
        let len = u32::from_be_bytes([blob[6], blob[7], blob[8], blob[9]]) as usize;
        let payload = &blob[10..10 + len];
        let count = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        let mut scripts = Vec::new();
        let mut offset = 2;
        for _ in 0..count {
            let slen = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;
            scripts.push(payload[offset..offset + slen].to_vec());
            offset += slen;
        }
        Ok(scripts)
    }

    #[test]
    fn incomplete_bitcoin_chunks_fail() {
        let (encoder, pubkey, _) = keys();
        let mask = sample();
        let mut blob = encoder.encode_for_blockchain(&mask).unwrap();
        let declared = u16::from_be_bytes([blob[10], blob[11]]);
        blob[10] = ((declared + 1) >> 8) as u8;
        blob[11] = (declared + 1) as u8;
        let raised = decode_chain_bytes(&blob, &pubkey).unwrap_err();
        assert!(
            raised.to_string().contains("truncated"),
            "a raised chunk count without the extra script must fail closed: {raised}"
        );

        let envelope = sign_envelope(&mask, &encoder.signing_key).unwrap();
        let scripts = bitcoin_scripts(&envelope).unwrap();
        assert!(scripts.len() > 1);
        let partial = scripts_blob(&scripts[..1]).unwrap();
        let packed = pack_avbc(1, &partial).unwrap();
        let incomplete = decode_chain_bytes(&packed, &pubkey).unwrap_err();
        assert!(
            incomplete.to_string().contains("incomplete"),
            "one OP_RETURN chunk of a multi-chunk mask must fail closed: {incomplete}"
        );
    }

    #[test]
    fn image_limits_reject_before_decode() {
        let (_, pubkey, _) = keys();
        let _ = pubkey;
        let huge = vec![0u8; 64];
        assert!(decode_png_lsb(&huge, 32, DEFAULT_MAX_IMAGE_PIXELS)
            .unwrap_err()
            .to_string()
            .contains("byte"));
        let mut header = Vec::new();
        header.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        header.extend_from_slice(&13u32.to_be_bytes());
        header.extend_from_slice(b"IHDR");
        header.extend_from_slice(&80_000u32.to_be_bytes());
        header.extend_from_slice(&80_000u32.to_be_bytes());
        let err =
            decode_png_lsb(&header, DEFAULT_MAX_IMAGE_BYTES, DEFAULT_MAX_IMAGE_PIXELS).unwrap_err();
        assert!(err.to_string().contains("pixel"), "{err}");
    }

    #[test]
    fn dns_parser_reads_txt_without_a_socket() {
        let mut packet = build_txt_query("mask.test", 0xA17B).unwrap();
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[6] = 0;
        packet[7] = 1;
        let name_end = packet.len();
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&16u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        let text = b"aivpn-mask-v1:001/001:QQ==";
        packet.extend_from_slice(&((text.len() + 1) as u16).to_be_bytes());
        packet.push(text.len() as u8);
        packet.extend_from_slice(text);
        let parsed = parse_dns_txt_response(&packet).unwrap();
        assert_eq!(parsed, vec!["aivpn-mask-v1:001/001:QQ==".to_string()]);
        assert!(name_end > 12);
    }

    #[tokio::test]
    async fn truncated_dns_uses_tcp_and_rejects_mismatched_questions() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for bad_question in [false, true] {
            let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = tcp.local_addr().unwrap();
            let udp = tokio::net::UdpSocket::bind(address).await.unwrap();
            let server = tokio::spawn(async move {
                let mut query = [0u8; 512];
                let (_, peer) = udp.recv_from(&mut query).await.unwrap();
                let mut truncated = query[..12].to_vec();
                truncated[2] = 0x83;
                truncated[3] = 0x80;
                udp.send_to(&truncated, peer).await.unwrap();
                let (mut stream, _) = tcp.accept().await.unwrap();
                let length = stream.read_u16().await.unwrap() as usize;
                let mut response = vec![0; length];
                stream.read_exact(&mut response).await.unwrap();
                response[2] = 0x81;
                response[3] = 0x80;
                response[7] = 1;
                if bad_question {
                    response[13] ^= 1;
                }
                response
                    .extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 0, 0, 3, 2, b'o', b'k']);
                stream.write_u16(response.len() as u16).await.unwrap();
                stream.write_all(&response).await.unwrap();
            });
            let result = lookup_dns_txt("mask.test", &address.to_string()).await;
            if bad_question {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), vec!["ok"]);
            }
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn poll_uses_fixtures_cache_and_clear_without_network() {
        let (encoder, pubkey, _) = keys();
        let mask = sample();
        let records = encoder.encode_dns_txt_strings(&mask).unwrap();
        let png = encoder.encode_for_image(&mask).unwrap();
        let bitcoin = encoder
            .encode_for_network(&mask, BlockchainNetwork::Bitcoin)
            .unwrap();
        let mut config = PassiveDistributionConfig {
            enable: true,
            allow_network: false,
            dns_domains: vec!["mask.test".into()],
            image_urls: vec!["https://fixture.invalid/mask.png".into()],
            blockchain_networks: vec![BlockchainNetwork::Bitcoin, BlockchainNetwork::Ethereum],
            chain_endpoints: vec!["https://fixture.invalid/chain".into()],
            ..PassiveDistributionConfig::default()
        };
        config.dns_resolver = Some("127.0.0.1:9".into());
        let mut receiver = PassiveMaskReceiver::new(config);
        receiver.set_operator_pubkey(pubkey);
        receiver.set_dns_fixture("mask.test", records);
        receiver.set_image_fixture("https://fixture.invalid/mask.png", png);
        receiver.set_chain_fixture("bitcoin", bitcoin);

        let first = receiver.poll_masks().await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].mask_id, mask.mask_id);
        let second = receiver.poll_masks().await.unwrap();
        assert!(second.is_empty());
        assert!(receiver.get_cached_mask(&mask.mask_id).is_some());
        receiver.clear_cache();
        assert!(receiver.get_all_masks().is_empty());
        let third = receiver.poll_masks().await.unwrap();
        assert_eq!(third.len(), 1);

        receiver.clear_cache();
        receiver.operator_pubkey = None;
        let err = receiver.poll_masks().await.unwrap_err();
        assert!(err.to_string().contains("operator public key"));
    }

    #[tokio::test]
    async fn disabled_poll_is_empty() {
        let mut receiver = PassiveMaskReceiver::new(PassiveDistributionConfig::default());
        assert!(!receiver.config.enable);
        assert!(receiver.poll_masks().await.unwrap().is_empty());
        assert!(receiver.get_all_masks().is_empty());
    }
}
