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
        tracing::error!(error = %format_args!("{e:#}"), "a provider's removal could not be escalated");
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
// an-error-logged-without-its-causes: the edge's forward, as it shipped and fixed.
fn forward_failed(e: anyhow::Error, port: u16) {
    // ruleid: an-error-logged-without-its-causes
    tracing::warn!(port, error = %e, "forward failed");
    // ok: an-error-logged-without-its-causes
    tracing::warn!(port, error = %format_args!("{e:#}"), "forward failed");
    // ok: an-error-logged-without-its-causes
    tracing::warn!(port, target = %e, "not an error field");
}

// --- a-supervisor-removal-not-from-its-plan ---------------------------------
// The edge supervisor's removals (supervise/mod.rs), as they are and as the
// three shapes that would bypass claim() would be.

async fn remove(ctx: &Ctx, r: &Remove) {
    for id in r.relays.iter().chain(&r.edges) {
        // ok: a-supervisor-removal-not-from-its-plan
        if let Err(e) = ctx.docker.remove(id, grace).await {
            return;
        }
    }
    for v in &r.volumes {
        // ok: a-supervisor-removal-not-from-its-plan
        if let Err(e) = ctx.docker.remove_volume(v).await {
            return;
        }
    }
}

async fn converge(ctx: &Ctx, c: &Converge) {
    for id in &c.relays {
        // ok: a-supervisor-removal-not-from-its-plan
        if let Err(e) = ctx.docker.remove(id, grace).await {
            break;
        }
    }
    // ok: a-supervisor-removal-not-from-its-plan
    let restarted = ctx.docker.restart(&c.relays[0], grace).await;
}

async fn create_edge(ctx: &Ctx, want: &Want) -> Result<String, String> {
    let id = ctx.docker.create(&names.edge, &body).await.map_err(|e| e.to_string())?;
    if let Err(e) = async { ctx.docker.start(&id).await }.await {
        // ok: a-supervisor-removal-not-from-its-plan
        let _ = ctx.docker.remove(&id, Duration::ZERO).await;
        return Err(e.to_string());
    }
    Ok(id)
}

async fn make_room(ctx: &Ctx, want: &Want) {
    let names = ctx.specs().names(&want.network);
    // A name something else holds, removed to make room: a namesake with no
    // label goes, and it was never this supervisor's.
    // ruleid: a-supervisor-removal-not-from-its-plan
    let _ = ctx.docker.remove(&names.edge, grace).await;
}

async fn sweep_by_listing(ctx: &Ctx) -> Result<(), Error> {
    // Every container the daemon's filter returns, removed with no plan: a
    // live network's edge goes with the dead ones.
    for c in ctx.docker.containers(MANAGED_BY, me).await? {
        // ruleid: a-supervisor-removal-not-from-its-plan
        ctx.docker.remove(&c.id, grace).await?;
    }
    Ok(())
}

async fn create_then_other(ctx: &Ctx) -> Result<String, String> {
    let id = ctx.docker.create(&names.edge, &body).await.map_err(|e| e.to_string())?;
    // After a create, a removal of something other than what was made.
    // ruleid: a-supervisor-removal-not-from-its-plan
    let _ = ctx.docker.stop(&names.relay, grace).await;
    Ok(id)
}

// --- a-secret-reaching-a-log --------------------------------------------------

async fn logged(ctx: &Ctx, want: &Want, key: &RelayKey, token: Hidden, row: String) {
    // ok: a-secret-reaching-a-log
    tracing::info!(network = %want.network, token_row = %row, secrets = %secrets_hash, "tenant edge created");
    // ok: a-secret-reaching-a-log
    tracing::info!(network = %want.network, peer = %key.hostname, relay_key = %key.id, "relay peer created");
    // ok: a-secret-reaching-a-log
    tracing::info!(network = %network, token_row = %id, "tenant edge token issued to the edge supervisor");
    // ruleid: a-secret-reaching-a-log
    tracing::info!(network = %want.network, token = %token.expose(), "tenant edge created");
    // ruleid: a-secret-reaching-a-log
    tracing::debug!(network = %want.network, key = ?key.setup_key, "relay peer created");
    // ruleid: a-secret-reaching-a-log
    tracing::warn!("minted {token} for {}", want.network);
    // ruleid: a-secret-reaching-a-log
    anyhow::bail!("Core refused the key {}", key.setup_key.expose());
}

fn relay_env(key: &RelayKey) -> Vec<String> {
    // The environment is where the key belongs: not a log.
    // ok: a-secret-reaching-a-log
    vec![format!("NB_SETUP_KEY={}", key.setup_key.expose())]
}

fn refused(token: &str) -> Result<(), String> {
    // ruleid: a-secret-reaching-a-log
    Err(format!("the token {} was refused", token))
}

// --- an-unbounded-value-in-a-docker-path ---------------------------------------

async fn paths(ctx: &Ctx, want: &Want, key: &RelayKey, row: String) {
    // ok: an-unbounded-value-in-a-docker-path
    let taken = ctx.docker.started_at(&names.edge).await;
    // ok: an-unbounded-value-in-a-docker-path
    let id = ctx.docker.create(&names.relay, &body).await;
    // ok: an-unbounded-value-in-a-docker-path
    let v = ctx.docker.volume(&names.volume).await;
    // A value Core answered with, as a name: nothing bounds it.
    // ruleid: an-unbounded-value-in-a-docker-path
    let v = ctx.docker.volume(&key.hostname).await;
    // ruleid: an-unbounded-value-in-a-docker-path
    let t = ctx.docker.started_at(&row).await;
}

impl Docker {
    pub async fn restart(&self, id: &str, grace: Duration) -> Result<(), Error> {
        // ok: an-unbounded-value-in-a-docker-path
        let (s, b) = self.call(Method::POST, &format!("/containers/{}/restart?t={}", percent(id), grace.as_secs()), None).await?;
        Ok(())
    }
    pub async fn containers(&self, key: &str, value: &str) -> Result<Vec<Summary>, Error> {
        // ok: an-unbounded-value-in-a-docker-path
        let (s, b) = self.call(Method::GET, &format!("/containers/json?all=true&filters={}", label_filter(key, value)), None).await?;
        Self::json(s, &b)
    }
    pub async fn start_unencoded(&self, id: &str) -> Result<(), Error> {
        // ruleid: an-unbounded-value-in-a-docker-path
        let (s, b) = self.call(Method::POST, &format!("/containers/{}/start", id), None).await?;
        Ok(())
    }
    pub async fn start_inline(&self, id: &str) -> Result<(), Error> {
        // ruleid: an-unbounded-value-in-a-docker-path
        let (s, b) = self.call(Method::POST, &format!("/containers/{id}/start"), None).await?;
        Ok(())
    }
}

// an-error-printed-without-its-causes: the agent's print, as it shipped and fixed.
fn printed(e: anyhow::Error) {
    // ruleid: an-error-printed-without-its-causes
    eprintln!("could not tell Core: {e}");
    // ok: an-error-printed-without-its-causes
    eprintln!("could not tell Core: {e:#}");
    // ok: an-error-printed-without-its-causes
    eprintln!("an entry: {entry}");
}
