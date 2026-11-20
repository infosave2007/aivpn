//! Применение сохраненной маски и возврат прежней после отката настройки.

use super::*;
use std::collections::HashMap;

struct AppliedOverride {
    requested: String,
    previous: MaskProfile,
}

type AppliedOverrides = HashMap<[u8; 16], AppliedOverride>;

impl Gateway {
    pub(super) async fn watch_mask_overrides(self: Arc<Self>) {
        let mut applied = AppliedOverrides::new();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            self.refresh_mask_overrides(&mut applied).await;
        }
    }

    async fn refresh_mask_overrides(&self, applied: &mut AppliedOverrides) {
        applied.retain(|id, _| self.session_manager.get_session(id).is_some());
        let sessions: Vec<_> = self
            .session_manager
            .iter_sessions()
            .map(|entry| entry.value().clone())
            .collect();
        for session in sessions {
            if let Err(error) = self.refresh_session_override(&session, applied).await {
                warn!("Не удалось применить сохраненную маску: {error}");
            }
        }
    }

    async fn refresh_session_override(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        applied: &mut AppliedOverrides,
    ) -> Result<()> {
        let (id, client_id, address, current) = {
            let state = session.lock();
            if !state.client_admitted || state.pending_mask.is_some() {
                return Ok(());
            }
            let (Some(client_id), Some(mask)) = (&state.client_id, &state.mask) else {
                return Ok(());
            };
            (
                state.session_id,
                client_id.clone(),
                state.client_addr,
                mask.clone(),
            )
        };
        let requested = read_override(&self.config.mask_dir, &client_id).await?;
        if requested.as_deref() == applied.get(&id).map(|value| value.requested.as_str())
            && requested
                .as_deref()
                .is_none_or(|name| name == current.mask_id)
        {
            return Ok(());
        }
        let target = match &requested {
            Some(name) => self.override_profile(name).await?,
            None => match applied.get(&id) {
                Some(value) => value.previous.clone(),
                None => return Ok(()),
            },
        };
        if target.mask_id != current.mask_id {
            let Some(socket) = &self.udp_socket else {
                return Ok(());
            };
            let packets = self
                .session_manager
                .build_mask_update_packets(session, &target)?;
            socket.send_packets_to(&packets, address).await?;
            self.session_manager.update_session_mask(&id, target);
        }
        match requested {
            Some(requested) => {
                let previous = applied
                    .remove(&id)
                    .map(|value| value.previous)
                    .unwrap_or(current);
                applied.insert(
                    id,
                    AppliedOverride {
                        requested,
                        previous,
                    },
                );
            }
            None => {
                applied.remove(&id);
            }
        }
        Ok(())
    }

    async fn override_profile(&self, name: &str) -> Result<MaskProfile> {
        if let Some(store) = self.mask_store.as_ref() {
            if let Some(profile) = store.read_verified_profile(name).await? {
                return Ok(profile);
            }
        }
        let mut profile = aivpn_common::mask::preset_masks::by_id(name).ok_or_else(|| {
            Error::Session(format!("Маска {name} отсутствует в проверенном каталоге"))
        })?;
        if let Some(key) = self
            .mask_store
            .as_ref()
            .and_then(|store| store.operator_signing_key())
        {
            profile.sign(key)?;
        }
        Ok(profile)
    }
}

async fn read_override(directory: &std::path::Path, client_id: &str) -> Result<Option<String>> {
    use tokio::io::AsyncReadExt;
    if !valid_name(client_id) {
        return Err(Error::InvalidPacket("Недопустимый идентификатор клиента"));
    }
    let path = directory
        .join(".overrides")
        .join(format!("{client_id}.mask"));
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut content = String::new();
    file.take(257).read_to_string(&mut content).await?;
    let name = content.trim();
    if content.len() > 256 || !valid_name(name) {
        return Err(Error::InvalidPacket("Недопустимое имя сохраненной маски"));
    }
    Ok(Some(name.to_owned()))
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn uploaded_mask_is_available_without_restart_and_is_verified_again() {
        let directory = tempfile::tempdir().unwrap();
        let mut initial = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
        crate::test_masks::sign(
            &mut initial,
            &ed25519_dalek::SigningKey::from_bytes(&[71; 32]),
        );
        std::fs::write(
            directory.path().join("webrtc_zoom_v3.json"),
            serde_json::to_vec(&initial).unwrap(),
        )
        .unwrap();
        let gateway = Gateway::new(GatewayConfig {
            mask_dir: directory.path().to_path_buf(),
            client_db: Some(Arc::new(
                ClientDatabase::load(&directory.path().join("clients.json"), Default::default())
                    .unwrap(),
            )),
            mask_signing_key: Some([71; 32]),
            mask_verify_mode: aivpn_common::mask::MaskVerifyMode::Enforce,
            enable_nat: false,
            enable_neural: false,
            ..Default::default()
        })
        .unwrap();
        let mut profile = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
        profile.mask_id = "uploaded_reference".into();
        crate::test_masks::sign(
            &mut profile,
            &ed25519_dalek::SigningKey::from_bytes(&[71; 32]),
        );
        let path = directory.path().join("uploaded_reference.json");
        std::fs::write(&path, serde_json::to_vec(&profile).unwrap()).unwrap();
        assert_eq!(
            gateway
                .override_profile("uploaded_reference")
                .await
                .unwrap()
                .mask_id,
            profile.mask_id
        );
        profile.signature = [0; 64];
        std::fs::write(&path, serde_json::to_vec(&profile).unwrap()).unwrap();
        assert!(gateway
            .override_profile("uploaded_reference")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn persisted_override_applies_and_removal_restores_previous_mask() {
        let directory = tempfile::tempdir().unwrap();
        let mask_dir = directory.path().join("masks");
        std::fs::create_dir_all(mask_dir.join(".overrides")).unwrap();
        let mut original = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
        crate::test_masks::sign(
            &mut original,
            &ed25519_dalek::SigningKey::from_bytes(&[71; 32]),
        );
        std::fs::write(
            mask_dir.join(format!("{}.json", original.mask_id)),
            serde_json::to_vec(&original).unwrap(),
        )
        .unwrap();
        let database = Arc::new(
            ClientDatabase::load(&directory.path().join("clients.json"), Default::default())
                .unwrap(),
        );
        let client = database.add_client("override-client").unwrap();
        let mut gateway = Gateway::new(GatewayConfig {
            mask_dir: mask_dir.clone(),
            client_db: Some(database),
            mask_signing_key: Some([71; 32]),
            enable_nat: false,
            enable_neural: false,
            ..Default::default()
        })
        .unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        gateway.udp_socket = Some(MaskSocket::new(socket));
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let session = gateway
            .session_manager
            .create_session(
                peer.local_addr().unwrap(),
                crypto::KeyPair::generate().public_key_bytes(),
                None,
                None,
            )
            .unwrap();
        {
            let mut state = session.lock();
            state.client_id = Some(client.id.clone());
            state.client_admitted = true;
            state.is_ratcheted = true;
            state.mask = Some(original.clone());
        }
        let file = mask_dir
            .join(".overrides")
            .join(format!("{}.mask", client.id));
        std::fs::write(&file, "webrtc_vk_teams_v1").unwrap();
        let mut applied = AppliedOverrides::new();
        gateway.refresh_mask_overrides(&mut applied).await;
        assert_eq!(
            session
                .lock()
                .pending_mask
                .as_ref()
                .map(|(m, _)| m.mask_id.clone()),
            Some("webrtc_vk_teams_v1".into())
        );
        let sent = session.lock().send_counter;
        gateway.refresh_mask_overrides(&mut applied).await;
        assert_eq!(
            session.lock().send_counter,
            sent,
            "Повтор чтения не должен сбрасывать переход"
        );
        tokio::time::sleep(Duration::from_millis(501)).await;
        session.lock().commit_pending_mask();
        // Автоматическая адаптация не должна отменять закрепленную администратором маску.
        session.lock().mask = Some(original.clone());
        gateway.refresh_mask_overrides(&mut applied).await;
        assert_eq!(
            session
                .lock()
                .pending_mask
                .as_ref()
                .map(|(mask, _)| mask.mask_id.as_str()),
            Some("webrtc_vk_teams_v1")
        );
        tokio::time::sleep(Duration::from_millis(501)).await;
        session.lock().commit_pending_mask();
        std::fs::remove_file(file).unwrap();
        gateway.refresh_mask_overrides(&mut applied).await;
        assert_eq!(
            session
                .lock()
                .pending_mask
                .as_ref()
                .map(|(m, _)| m.mask_id.clone()),
            Some(original.mask_id)
        );
        let id = session.lock().session_id;
        gateway.session_manager.remove_session(&id);
        gateway.refresh_mask_overrides(&mut applied).await;
        assert!(applied.is_empty());
    }
}
