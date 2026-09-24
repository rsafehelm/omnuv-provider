// Fixtures for review-classes.yml. Not compiled: shapes, as they shipped and
// as they were fixed.

// --- await-on-a-sender-from-a-shared-table ---------------------------------

impl TunnelRegistry {
    // Core's deliver before PROVIDER-29 (f14f0ee^).
    async fn deliver_before(&self, frame: TunnelFrame) {
        let sender = self.pending.lock().await.get(&id).cloned();
        if let Some(tx) = sender {
            // ruleid: await-on-a-sender-from-a-shared-table
            let _ = tx.send(frame).await;
        }
    }

    // Core's deliver after it.
    async fn deliver_after(&self, frame: TunnelFrame) {
        let sender = self.pending.lock().await.get(&id).cloned();
        if let Some(tx) = sender {
            // ok: await-on-a-sender-from-a-shared-table
            match tx.try_send(frame) {
                Ok(()) => {}
                Err(_) => {}
            }
        }
    }
}

impl TunnelRegistry {
    // The shapes Core's registry takes its provider's sender in: a binding
    // that shadows its source, `?`, and `let ... else`. Each one awaits.
    pub async fn cancel(&self, provider_id: Uuid, id: &str) {
        let out = self.live.lock().await.get(&provider_id).cloned();
        if let Some(out) = out {
            // ruleid: await-on-a-sender-from-a-shared-table
            let _ = out.send(TunnelFrame::Cancel { id: id.to_string() }).await;
        }
    }
    pub async fn send(&self, provider_id: Uuid) -> Option<()> {
        let out = self.live.lock().await.get(&provider_id).cloned()?;
        // ruleid: await-on-a-sender-from-a-shared-table
        out.send(frame).await.ok()
    }
    pub async fn send_frame(&self, provider_id: Uuid, frame: TunnelFrame) -> bool {
        let Some(out) = self.live.lock().await.get(&provider_id).cloned() else { return false };
        // ruleid: await-on-a-sender-from-a-shared-table
        out.send(frame).await.is_ok()
    }
}

async fn read_loop_before() {
    // The agent's console input before f06392b.
    while let Some(msg) = stream.next().await {
        match frame {
            TunnelFrame::ConsoleData { id, data } => {
                if let (Some(to_vm), Ok(bytes)) = (
                    sessions.lock().await.get(&id).cloned(),
                    base64::engine::general_purpose::STANDARD.decode(data),
                ) {
                    // ruleid: await-on-a-sender-from-a-shared-table
                    let _ = to_vm.send(ConsoleInput::Data(bytes)).await;
                }
            }
            _ => {}
        }
    }
}

async fn read_loop_after() {
    while let Some(msg) = stream.next().await {
        match frame {
            TunnelFrame::ConsoleData { id, data } => {
                let to_vm = sessions.lock().await.get(&id).cloned();
                if let Some(to_vm) = to_vm {
                    // ok: await-on-a-sender-from-a-shared-table
                    let _ = to_vm.try_send(ConsoleInput::Data(data));
                }
                // ok: await-on-a-sender-from-a-shared-table
                let _ = out_tx.send(TunnelFrame::End { id }).await;
            }
            _ => {}
        }
    }
}

// --- work-after-a-stream-loop ------------------------------------------------

// The gateway's streamed relay before 277da75.
fn relay_before() {
    // ruleid: work-after-a-stream-loop
    let body_stream = async_stream::stream! {
        let mut usage = None;
        // Until `End` arrives this is not a finished stream: a channel that
        // closes first was cut off, and is recorded as that, not as ok.
        let mut status = "cut_off";
        while let Some(frame) = rx.recv().await {
            match frame {
                omnuv_protocol::TunnelFrame::Chunk { data, .. } => {
                    if usage.is_none() {
                        usage = usage_from_sse(data.as_bytes());
                    }
                    yield Ok::<_, std::io::Error>(axum::body::Bytes::from(data));
                }
                omnuv_protocol::TunnelFrame::End { .. } => {
                    status = "ok";
                    break;
                }
                omnuv_protocol::TunnelFrame::Error { message, .. } => {
                    tracing::warn!(%message, "tunnelled stream failed");
                    status = "stream_error";
                    break;
                }
                _ => {}
            }
        }
        // The client may have gone away mid-stream; tell the provider to stop
        // rather than letting the worker generate into a void.
        tunnels.cancel(provider_id, &req_id).await;
        let caller = ApiCaller { project_id, api_key_id };
        record(&db, &caller, &p, usage, started.elapsed().as_millis() as i32, true, status).await;
    };
}

// And after it: what must happen on every ending is in the Meter's drop.
fn relay<F>(
    mut rx: tokio::sync::mpsc::Receiver<omnuv_protocol::TunnelFrame>,
    finish: F,
) -> impl futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>>
where
    F: FnOnce(StreamEnd) + Send + 'static,
{
    // ok: work-after-a-stream-loop
    async_stream::stream! {
        // Until the loop below ends by itself, an ending is the buyer leaving.
        let mut meter = Meter { end: StreamEnd { status: "client_gone", usage: None }, finish: Some(finish) };
        // Until `End` arrives this is not a finished stream: a channel that
        // closes first was cut off, and is recorded as that, not as ok.
        let mut status = "cut_off";
        while let Some(frame) = rx.recv().await {
            match frame {
                omnuv_protocol::TunnelFrame::Chunk { data, .. } => {
                    if meter.end.usage.is_none() {
                        meter.end.usage = usage_from_sse(data.as_bytes());
                    }
                    yield Ok::<_, std::io::Error>(axum::body::Bytes::from(data));
                }
                omnuv_protocol::TunnelFrame::End { .. } => {
                    status = "ok";
                    break;
                }
                omnuv_protocol::TunnelFrame::Error { message, .. } => {
                    tracing::warn!(%message, "tunnelled stream failed");
                    status = "stream_error";
                    break;
                }
                _ => {}
            }
        }
        meter.end.status = status;
    }
}

// --- an-insert-whose-failure-is-discarded -------------------------------------

async fn escalate_before(db: &PgPool) {
    // provider_removal.rs as it stands (queued): 0075 refuses the addressee.
    // ruleid: an-insert-whose-failure-is-discarded
    let _ = sqlx::query!(
        "insert into escalations (addressee, kind) values ('operator', )",
        kind
    )
    .execute(db)
    .await;
}

async fn removal_before(state: &AppState) {
    // provider_removal.rs before this rule: the refusal thrown away.
    // ruleid: an-insert-whose-failure-is-discarded
    let _ = crate::escalations::raise(&state.db, "provider.removed", "operator", None, &detail).await;
}

async fn removal_after(state: &AppState) {
    // ok: an-insert-whose-failure-is-discarded
    if let Err(e) = crate::escalations::raise(&state.db, "provider.removed", "marketplace", None, &detail).await {
        tracing::error!(error = %e, "a provider's removal could not be escalated");
    }
}

async fn touch_is_not_an_insert(db: &PgPool) {
    // ok: an-insert-whose-failure-is-discarded
    let _ = sqlx::query!("update sessions set last_seen = now() where id = ", id)
        .execute(db)
        .await;
}

async fn escalate_after(db: &PgPool) -> anyhow::Result<()> {
    // ok: an-insert-whose-failure-is-discarded
    sqlx::query!("insert into escalations (addressee, kind) values ('marketplace', )", kind)
        .execute(db)
        .await?;
    Ok(())
}

// --- a-socket-authorized-only-at-its-upgrade ----------------------------------

// The console's upgrade before fc47405.
// ruleid: a-socket-authorized-only-at-its-upgrade
async fn open(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    CurrentUser(user_id): CurrentUser,
    Path(instance_id): Path<Uuid>,
    Query(p): Query<Params>,
) -> AppResult<Response> {
    let kind = match p.kind.as_str() {
        "serial" => ConsoleKind::Serial,
        "vnc" => ConsoleKind::Vnc,
        _ => return Err(AppError::BadRequest("kind must be serial or vnc".into())),
    };
    // Members of the machine's organization, and nobody else; a foreign id is
    // a 404, not a hint.
    let row = sqlx::query!(
        r#"select i.provider_id, i.status, im.console_kind as "console_kind!"
           from instances i
           join images im on im.id = i.image
           join projects p on p.id = i.project_id
           join organization_members m on m.organization_id = p.organization_id
           where i.id = $1 and m.user_id = $2 and i.desired_state <> 'deleted'"#,
        instance_id,
        user_id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;
    // The image decides which console a machine logs in on; the screen is
    // always there as well — to watch a boot, or to rescue a machine whose
    // serial console is not answering.
    if kind == ConsoleKind::Serial && row.console_kind != "serial" {
        return Err(AppError::BadRequest("this machine has no serial console; open its screen".into()));
    }
    let provider_id = row.provider_id;
    if !state.tunnels.is_connected(provider_id).await {
        return Err(AppError::Conflict("the machine's provider is not reachable right now".into()));
    }

    let session_id: Uuid = sqlx::query_scalar!(
        "insert into console_sessions (instance_id, user_id, kind) values ($1, $2, $3) returning id",
        instance_id,
        user_id,
        kind.as_str()
    )
    .fetch_one(&state.db)
    .await?;
    tracing::info!(%instance_id, %user_id, session = %session_id, kind = kind.as_str(), "console opened");

    Ok(ws.on_upgrade(move |socket| async move {
        let outcome = relay(socket, &state, provider_id, instance_id, kind).await;
        let _ = sqlx::query!(
            "update console_sessions set ended_at = now(), outcome = $2 where id = $1",
            session_id,
            outcome
        )
        .execute(&state.db)
        .await;
        tracing::info!(%instance_id, session = %session_id, outcome, "console closed");
    }))
}

// And after it: the credential is kept and asked again while open.
// ok: a-socket-authorized-only-at-its-upgrade
async fn open(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    CurrentUser(user_id): CurrentUser,
    Path(instance_id): Path<Uuid>,
    Query(p): Query<Params>,
    headers: axum::http::HeaderMap,
) -> AppResult<Response> {
    // What signed this in, so the open console can ask again whether it
    // still holds. `CurrentUser` has just read the same headers.
    let cred = crate::auth::credential(&headers, &state.cookie_key).ok_or(AppError::Unauthorized)?;
    let kind = match p.kind.as_str() {
        "serial" => ConsoleKind::Serial,
        "vnc" => ConsoleKind::Vnc,
        _ => return Err(AppError::BadRequest("kind must be serial or vnc".into())),
    };
    // Members of the machine's organization, and nobody else; a foreign id is
    // a 404, not a hint.
    let row = sqlx::query!(
        r#"select i.provider_id, i.status, im.console_kind as "console_kind!"
           from instances i
           join images im on im.id = i.image
           join projects p on p.id = i.project_id
           join organization_members m on m.organization_id = p.organization_id
           where i.id = $1 and m.user_id = $2 and i.desired_state <> 'deleted'"#,
        instance_id,
        user_id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;
    // The image decides which console a machine logs in on; the screen is
    // always there as well — to watch a boot, or to rescue a machine whose
    // serial console is not answering.
    if kind == ConsoleKind::Serial && row.console_kind != "serial" {
        return Err(AppError::BadRequest("this machine has no serial console; open its screen".into()));
    }
    let provider_id = row.provider_id;
    if !state.tunnels.is_connected(provider_id).await {
        return Err(AppError::Conflict("the machine's provider is not reachable right now".into()));
    }

    let session_id: Uuid = sqlx::query_scalar!(
        "insert into console_sessions (instance_id, user_id, kind) values ($1, $2, $3) returning id",
        instance_id,
        user_id,
        kind.as_str()
    )
    .fetch_one(&state.db)
    .await?;
    tracing::info!(%instance_id, %user_id, session = %session_id, kind = kind.as_str(), "console opened");

    Ok(ws.on_upgrade(move |socket| async move {
        let lapsed = Box::pin(lapsed(state.db.clone(), instance_id, user_id, cred, RECHECK));
        let outcome = relay(socket, &state, provider_id, instance_id, kind, lapsed).await;
        // A session termination already ended keeps its `terminated`.
        let _ = sqlx::query!(
            "update console_sessions set ended_at = now(), outcome = $2 where id = $1 and ended_at is null",
            session_id,
            outcome
        )
        .execute(&state.db)
        .await;
        tracing::info!(%instance_id, session = %session_id, outcome, "console closed");
    }))
}