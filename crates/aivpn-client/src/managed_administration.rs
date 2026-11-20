//! Отдельный локальный канал управления не участвует в передаче IP-пакетов.
use aivpn_client::session_admin::SessionAdministration;
use aivpn_desktop_agent::administration::{
    decode_payload, encode_payload, AdministrationReply, AdministrationRequest, ReplyText,
    SessionQuery, MAX_ADMIN_FRAME_BYTES,
};
use std::{io, num::NonZeroU64, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, watch},
    task::{JoinHandle, JoinSet},
};

#[derive(Clone)]
struct Bound {
    generation: NonZeroU64,
    administration: SessionAdministration,
}

pub(super) struct AdministrationServer {
    binding: watch::Sender<Option<Bound>>,
    task: JoinHandle<io::Result<()>>,
}
impl AdministrationServer {
    pub fn start(stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) -> Self {
        let (binding, changed) = watch::channel(None);
        Self {
            binding,
            task: tokio::spawn(serve(stream, changed)),
        }
    }
    pub fn bind(&self, generation: u64, administration: SessionAdministration) -> io::Result<()> {
        let generation = NonZeroU64::new(generation).ok_or(io::ErrorKind::InvalidInput)?;
        if self.task.is_finished() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.binding.send_replace(Some(Bound {
            generation,
            administration,
        }));
        Ok(())
    }
    pub fn clear(&self) {
        self.binding.send_replace(None);
    }
}
impl Drop for AdministrationServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    mut binding: watch::Receiver<Option<Bound>>,
) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (incoming, mut requests) = mpsc::channel::<AdministrationRequest>(16);
    let (outgoing, mut replies) = mpsc::channel::<AdministrationReply>(32);
    let mut io_tasks = JoinSet::new();
    io_tasks.spawn(async move {
        loop {
            let length = reader.read_u32().await? as usize;
            if length == 0 || length > MAX_ADMIN_FRAME_BYTES {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes).await?;
            let request = decode_payload(&bytes)?;
            incoming
                .send(request)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        }
    });
    io_tasks.spawn(async move {
        while let Some(reply) = replies.recv().await {
            let bytes = encode_payload(&reply)?;
            tokio::time::timeout(Duration::from_secs(5), async {
                writer.write_u32(bytes.len() as u32).await?;
                writer.write_all(&bytes).await
            })
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        }
        Ok(())
    });
    let mut jobs = JoinSet::new();
    loop {
        tokio::select! {
            Some(result) = io_tasks.join_next() => {
                return result.map_err(|_| io::Error::other("Прерван I/O управления"))?;
            }
            Some(result) = jobs.join_next(), if !jobs.is_empty() => {
                result.map_err(|_| io::Error::other("Прерван запрос управления"))?;
            }
            Some(request) = requests.recv() => {
                let scope = binding.borrow_and_update().clone();
                let Some(scope) = scope.filter(|scope| scope.generation == request.generation) else {
                    outgoing.send(refusal(&request, "unavailable")?).await.map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
                    continue;
                };
                if jobs.len() >= 16 {
                    outgoing.send(refusal(&request, "busy")?).await.map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
                    continue;
                }
                let mut changed = binding.clone();
                let outgoing = outgoing.clone();
                jobs.spawn(async move {
                    let result = tokio::select! {
                        _ = changed.changed() => return,
                        result = execute(&scope.administration, &request.query) => result,
                    };
                    if changed.borrow().as_ref().is_none_or(|scope| scope.generation != request.generation) {
                        return;
                    }
                    let reply = match result.and_then(ReplyText::new) {
                        Ok(output) => AdministrationReply { generation: request.generation, id: request.id, success: true, output },
                        Err(_) => match refusal(&request, "unavailable") { Ok(reply) => reply, Err(_) => return },
                    };
                    let _ = outgoing.send(reply).await;
                });
            }
        }
    }
}

async fn execute(handle: &SessionAdministration, query: &SessionQuery) -> io::Result<String> {
    match query {
        SessionQuery::Statistics {} => {
            serde_json::to_string(&handle.statistics().await?).map_err(io::Error::from)
        }
        SessionQuery::Execute { command } => handle.execute(command.as_str()).await,
    }
}
fn refusal(request: &AdministrationRequest, reason: &str) -> io::Result<AdministrationReply> {
    Ok(AdministrationReply {
        generation: request.generation,
        id: request.id,
        success: false,
        output: ReplyText::new(reason.into())?,
    })
}
