//! Runtime-local JSON Invoke boundary for Apple and Android hosts.
//!
//! `VCoreInvoke` is the only public business entry point. A runtime-local
//! per-request size limit bounds parsing memory. One public lifecycle
//! controller may exist at a time and its mutations are serialized by its
//! command lock. Every returned string is allocated by Rust and must be
//! released with `VCoreFree`.

#![cfg_attr(target_os = "android", allow(clippy::missing_const_for_thread_local))]

use std::{
    cell::Cell,
    ffi::{CString, c_char},
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    slice, str,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, TryLockError,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::SyncSender,
    },
    thread,
    time::Duration,
};

use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::oneshot;

use crate::{
    BUILD_IDENTITY, CONFIG_VERSION, ENGINE, INVOKE_API_VERSION, Lifecycle, LifecycleState,
    ResourceLimits, TunFraming, VCoreError,
    config::Config,
    data_dir::DataDirectory,
    dialer::{Dialer, SocketProtector, SystemResolver},
    geodata::{GeoDataManager, GeoDataStatus, GeoResourceState},
    runtime::PreparedCore,
};

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
use crate::platform::{TunFd, TunIo};

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
type InvokeTun = (TunFd, TunFraming);
#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "macos")))]
type InvokeTun = ();

#[cfg(target_os = "android")]
mod android;
mod measure_delay;

// A measureDelay request may inline five independently valid 256 KiB YAML
// documents. JSON escaping can double common YAML bytes such as backslashes,
// quotes, and newlines, so the wire envelope needs a larger aggregate bound.
const MAX_INVOKE_BYTES: usize = 3 * 1024 * 1024;
const MAX_ERROR_BYTES: usize = 4096;
static REGISTRY: OnceLock<RuntimeRegistry> = OnceLock::new();

thread_local! {
    static IS_RUNTIME_THREAD: Cell<bool> = const { Cell::new(false) };
}

#[derive(Default)]
struct RegistryInner {
    instance: Option<Arc<CoreController>>,
}

#[derive(Default)]
struct PlatformState {
    tun_owner: Option<u64>,
    #[cfg(target_os = "android")]
    android_protector: Option<Arc<dyn SocketProtector>>,
}

struct RuntimeRegistry {
    inner: Mutex<RegistryInner>,
    platform: Mutex<PlatformState>,
    runtime_data: Mutex<Option<RuntimeData>>,
    next_id: AtomicU64,
}

struct RuntimeData {
    directory: Arc<DataDirectory>,
    geodata: Arc<GeoDataManager>,
}

impl Default for RuntimeRegistry {
    fn default() -> Self {
        Self {
            inner: Mutex::new(RegistryInner::default()),
            platform: Mutex::new(PlatformState::default()),
            runtime_data: Mutex::new(None),
            next_id: AtomicU64::new(1),
        }
    }
}

struct CoreController {
    id: u64,
    tombstoned: AtomicBool,
    /// Held for the complete duration of every instance method. Contending
    /// calls fail fast rather than waiting behind a lifecycle operation.
    command: Mutex<()>,
    inner: Mutex<CoreInner>,
}

impl CoreController {
    fn new(id: u64) -> Self {
        Self {
            id,
            tombstoned: AtomicBool::new(false),
            command: Mutex::new(()),
            inner: Mutex::new(CoreInner::default()),
        }
    }
}

#[derive(Default)]
struct CoreInner {
    lifecycle: Lifecycle,
    prepared: Option<PreparedState>,
    engine: Option<Engine>,
    last_error: String,
    tun_lease: Option<TunLease>,
    ios_tun_allocator_relief: Option<IosTunAllocatorRelief>,
}

struct PreparedState {
    core: PreparedCore,
    protector: Option<Arc<dyn SocketProtector>>,
}

struct Engine {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<io::Result<()>>>,
}

struct PlatformAcquisition {
    tun_lease: Option<TunLease>,
    protector: Option<Arc<dyn SocketProtector>>,
}

struct TunLease {
    owner: u64,
}

impl Drop for TunLease {
    fn drop(&mut self) {
        registry().release_tun(self.owner);
    }
}

#[derive(Clone)]
struct IosTunAllocatorRelief {
    state: Arc<IosTunAllocatorReliefState>,
}

struct IosTunAllocatorReliefState {
    relieved: AtomicBool,
}

impl IosTunAllocatorRelief {
    fn new(has_tun: bool) -> Option<Self> {
        #[cfg(target_os = "ios")]
        if has_tun {
            return Some(Self {
                state: Arc::new(IosTunAllocatorReliefState {
                    relieved: AtomicBool::new(false),
                }),
            });
        }
        let _ = has_tun;
        None
    }

    fn relieve(&self) {
        if !self.state.relieved.swap(true, Ordering::AcqRel) {
            relieve_ios_tun_allocator();
        }
    }
}

impl Drop for IosTunAllocatorReliefState {
    fn drop(&mut self) {
        if !self.relieved.swap(true, Ordering::AcqRel) {
            relieve_ios_tun_allocator();
        }
    }
}

/// Makes an admitted destroy request a terminal registry barrier even when
/// synchronous stop reports an error or unwinds. Per-instance busy rejection
/// happens before this guard is created and therefore keeps the instance live.
struct InstanceRemovalGuard<'a> {
    controller: &'a Arc<CoreController>,
}

impl Drop for InstanceRemovalGuard<'_> {
    fn drop(&mut self) {
        self.controller.tombstoned.store(true, Ordering::Release);
        registry().remove_instance(self.controller);
    }
}

struct RuntimeThreadGuard;

impl RuntimeThreadGuard {
    fn enter() -> Self {
        IS_RUNTIME_THREAD.with(|marker| {
            debug_assert!(!marker.replace(true));
        });
        Self
    }
}

impl Drop for RuntimeThreadGuard {
    fn drop(&mut self) {
        IS_RUNTIME_THREAD.with(|marker| marker.set(false));
    }
}

impl Engine {
    fn stop(&mut self) -> Result<(), InvokeFailure> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        match thread.join() {
            Ok(result) => result.map_err(InvokeFailure::from),
            Err(_) => Err(InvokeFailure::internal("VCore runtime thread panicked")),
        }
    }

    fn is_finished(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(thread::JoinHandle::is_finished)
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // This is also the unwind safety net for a panic after the runtime was
        // spawned but before it was committed into its instance.
        let _ = self.stop();
    }
}

#[derive(Debug)]
struct InvokeFailure {
    message: String,
}

impl InvokeFailure {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: bounded_error(message.into()),
        }
    }

    fn invalid_request(message: impl std::fmt::Display) -> Self {
        Self::new(format!("invalid request: {message}"))
    }

    fn invalid_state(message: impl std::fmt::Display) -> Self {
        Self::new(format!("invalid state: {message}"))
    }

    fn internal(message: impl std::fmt::Display) -> Self {
        Self::new(format!("internal error: {message}"))
    }
}

impl From<VCoreError> for InvokeFailure {
    fn from(value: VCoreError) -> Self {
        Self::new(value.to_string())
    }
}

impl From<io::Error> for InvokeFailure {
    fn from(value: io::Error) -> Self {
        Self::new(value.to_string())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelope {
    #[serde(rename = "apiVersion")]
    api_version: u32,
    method: String,
    payload: Value,
    #[serde(
        rename = "instanceId",
        default,
        deserialize_with = "deserialize_present_instance_id"
    )]
    instance_id: Option<String>,
}

fn deserialize_present_instance_id<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ConfigYamlPayload {
    config_yaml: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InitializePayload {
    data_dir: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StartPayload {
    #[serde(default)]
    tun_fd: Option<i32>,
    #[serde(default)]
    tun_framing: Option<InvokeTunFraming>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum InvokeTunFraming {
    RawIp,
    Utun,
}

impl From<InvokeTunFraming> for TunFraming {
    fn from(value: InvokeTunFraming) -> Self {
        match value {
            InvokeTunFraming::RawIp => Self::RawIp,
            InvokeTunFraming::Utun => Self::Utun,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyPayload {}

#[derive(Debug, serde::Serialize)]
struct InvokeResponse {
    success: bool,
    data: Value,
    error: String,
}

impl InvokeResponse {
    fn success(data: Value) -> Self {
        Self {
            success: true,
            data,
            error: String::new(),
        }
    }

    fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            data: Value::Null,
            error: bounded_error(error.into()),
        }
    }
}

fn registry() -> &'static RuntimeRegistry {
    REGISTRY.get_or_init(RuntimeRegistry::default)
}

impl RuntimeRegistry {
    fn initialize_data_directory(
        &self,
        raw_path: &str,
    ) -> Result<Arc<DataDirectory>, InvokeFailure> {
        if raw_path.is_empty() {
            return Err(InvokeFailure::invalid_request("dataDir is empty"));
        }
        let initialized = Arc::new(DataDirectory::initialize(Path::new(raw_path)).map_err(
            |error| InvokeFailure::new(format!("failed to initialize dataDir: {error}")),
        )?);
        let geodata =
            GeoDataManager::open(initialized.geodata(), Duration::from_secs(24 * 60 * 60))
                .map_err(|error| {
                    InvokeFailure::new(format!("failed to initialize GeoData storage: {error}"))
                })?;
        let mut current = lock(&self.runtime_data);
        if let Some(current) = current.as_ref() {
            if current.directory.root() == initialized.root() {
                return Ok(current.directory.clone());
            }
            return Err(InvokeFailure::invalid_state(
                "VCore dataDir is already initialized to a different path",
            ));
        }
        *current = Some(RuntimeData {
            directory: initialized.clone(),
            geodata,
        });
        Ok(initialized)
    }

    fn data_directory(&self) -> Result<Arc<DataDirectory>, InvokeFailure> {
        lock(&self.runtime_data)
            .as_ref()
            .map(|data| data.directory.clone())
            .ok_or_else(|| {
                InvokeFailure::invalid_state(
                    "VCore dataDir is not initialized; call initialize before configuration methods",
                )
            })
    }

    fn geodata_manager(&self) -> Result<Arc<GeoDataManager>, InvokeFailure> {
        lock(&self.runtime_data)
            .as_ref()
            .map(|data| data.geodata.clone())
            .ok_or_else(|| {
                InvokeFailure::invalid_state(
                    "VCore dataDir is not initialized; call initialize before configuration methods",
                )
            })
    }

    fn create_instance(&self) -> Result<Arc<CoreController>, InvokeFailure> {
        let mut inner = lock(&self.inner);
        if inner.instance.is_some() {
            return Err(InvokeFailure::invalid_state(
                "a public lifecycle instance already exists; destroy it before creating another",
            ));
        }
        let id = self
            .next_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| InvokeFailure::internal("instance ID space is exhausted"))?;
        debug_assert_ne!(id, 0);
        let controller = Arc::new(CoreController::new(id));
        inner.instance = Some(controller.clone());
        Ok(controller)
    }

    fn instance(&self, raw_id: &str) -> Result<Arc<CoreController>, InvokeFailure> {
        let id = parse_instance_id(raw_id)?;
        let inner = lock(&self.inner);
        let controller = inner
            .instance
            .as_ref()
            .filter(|controller| controller.id == id)
            .ok_or_else(|| InvokeFailure::invalid_request("unknown instanceId"))?;
        if controller.tombstoned.load(Ordering::Acquire) {
            return Err(InvokeFailure::invalid_request("unknown instanceId"));
        }
        Ok(controller.clone())
    }

    fn remove_instance(&self, controller: &Arc<CoreController>) {
        let mut inner = lock(&self.inner);
        if inner
            .instance
            .as_ref()
            .is_some_and(|registered| Arc::ptr_eq(registered, controller))
        {
            inner.instance = None;
        }
    }

    fn acquire_platform_resources(
        &self,
        owner: u64,
        has_tun: bool,
    ) -> Result<PlatformAcquisition, InvokeFailure> {
        let mut platform = lock(&self.platform);
        if has_tun && platform.tun_owner.is_some() {
            return Err(InvokeFailure::invalid_state(
                "the public TUN lifecycle is already prepared or running",
            ));
        }
        #[cfg(target_os = "android")]
        let protector = select_android_protector(has_tun, platform.android_protector.as_ref())?;
        #[cfg(not(target_os = "android"))]
        let protector = None;
        let tun_lease = has_tun.then(|| {
            platform.tun_owner = Some(owner);
            TunLease { owner }
        });
        Ok(PlatformAcquisition {
            tun_lease,
            protector,
        })
    }

    fn release_tun(&self, owner: u64) {
        let mut platform = lock(&self.platform);
        if platform.tun_owner == Some(owner) {
            platform.tun_owner = None;
        }
    }

    #[cfg(target_os = "android")]
    fn replace_android_socket_protector(
        &self,
        protector: Option<Arc<dyn SocketProtector>>,
    ) -> Result<(), String> {
        let mut platform = lock(&self.platform);
        ensure_android_protector_replaceable(platform.tun_owner)?;
        platform.android_protector = protector;
        Ok(())
    }
}

#[cfg(any(target_os = "android", test))]
fn ensure_android_protector_replaceable(tun_owner: Option<u64>) -> Result<(), String> {
    if tun_owner.is_some() {
        return Err(
            "Android protector can only be replaced while the public TUN lifecycle is inactive"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(any(target_os = "android", test))]
fn select_android_protector(
    has_tun: bool,
    registered: Option<&Arc<dyn SocketProtector>>,
) -> Result<Option<Arc<dyn SocketProtector>>, InvokeFailure> {
    if !has_tun {
        return Ok(None);
    }
    registered.cloned().map(Some).ok_or_else(|| {
        InvokeFailure::new(
            "platform operation failed: Android protector is required for a TUN configuration",
        )
    })
}

fn parse_instance_id(raw_id: &str) -> Result<u64, InvokeFailure> {
    let id = raw_id
        .parse::<u64>()
        .map_err(|_| InvokeFailure::invalid_request("instanceId must be a decimal u64 string"))?;
    if id == 0 || id.to_string() != raw_id {
        return Err(InvokeFailure::invalid_request(
            "instanceId must be a canonical non-zero decimal u64 string",
        ));
    }
    Ok(id)
}

/// Executes one VCore request and returns an independently allocated UTF-8 JSON
/// response. The caller must release the returned pointer with `VCoreFree`.
///
/// # Safety
/// `request_json` must be either null or point to readable storage containing a
/// NUL terminator within `MAX_INVOKE_BYTES + 1` bytes.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn VCoreInvoke(request_json: *const c_char) -> *mut c_char {
    if is_runtime_thread() {
        return allocate_response(runtime_thread_response());
    }
    let response = match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the caller contract is documented above; this function adds
        // a bounded scan before constructing the byte slice.
        unsafe { read_request(request_json) }
    })) {
        Ok(Ok(request)) => invoke_bytes_admitted(request),
        Ok(Err(error)) => serialize_response(InvokeResponse::failure(error.message)),
        Err(_) => serialize_response(InvokeResponse::failure(
            "internal error: panic caught at the VCore Invoke boundary",
        )),
    };
    allocate_response(response)
}

/// Releases a response returned by `VCoreInvoke` or `VCoreWindowsVpnInvoke`.
/// A null pointer is ignored.
///
/// # Safety
/// A non-null pointer must have been returned by one of those functions, must not have
/// been freed already, and must not be used after this call.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn VCoreFree(response: *mut c_char) {
    if !response.is_null() {
        // SAFETY: ownership is returned by the caller under the contract above.
        drop(unsafe { CString::from_raw(response) });
    }
}

/// Test-facing entry that exercises the same dispatcher used by native hosts.
#[cfg(test)]
pub(super) fn invoke_bytes(request: &[u8]) -> Vec<u8> {
    if is_runtime_thread() {
        return runtime_thread_response();
    }
    invoke_bytes_admitted(request)
}

/// Shared byte-oriented dispatcher used by C and Android JNI.
/// It intentionally returns bytes so JNI never routes arbitrary JSON through
/// Modified UTF-8 strings.
pub(super) fn invoke_bytes_admitted(request: &[u8]) -> Vec<u8> {
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    let _logging = crate::platform::apple_logging::enter();
    invoke_guarded(|| dispatch_bytes(request))
}

pub(super) fn is_runtime_thread() -> bool {
    IS_RUNTIME_THREAD.with(Cell::get)
}

pub(super) fn runtime_thread_response() -> Vec<u8> {
    br#"{"success":false,"data":null,"error":"Invoke cannot be called from the VCore runtime thread"}"#
        .to_vec()
}

fn invoke_guarded(operation: impl FnOnce() -> Result<InvokeResponse, InvokeFailure>) -> Vec<u8> {
    let response = match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => InvokeResponse::failure(error.message),
        Err(_) => {
            InvokeResponse::failure("internal error: panic caught at the VCore Invoke boundary")
        }
    };
    serialize_response(response)
}

fn invoke_instance_guarded<T>(
    controller: &Arc<CoreController>,
    operation: impl FnOnce() -> Result<T, InvokeFailure>,
) -> Result<T, InvokeFailure> {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(_) => {
            if controller.tombstoned.load(Ordering::Acquire) {
                registry().remove_instance(controller);
            } else {
                controller.recover_after_panic()?;
            }
            Err(InvokeFailure::internal(
                "panic caught at the VCore Invoke boundary",
            ))
        }
    }
}

fn dispatch_bytes(request: &[u8]) -> Result<InvokeResponse, InvokeFailure> {
    if request.len() > MAX_INVOKE_BYTES {
        return Err(InvokeFailure::invalid_request(format!(
            "Invoke envelope exceeds the {MAX_INVOKE_BYTES}-byte limit"
        )));
    }
    let request = str::from_utf8(request)
        .map_err(|_| InvokeFailure::invalid_request("request is not valid UTF-8"))?;
    let envelope: RequestEnvelope =
        serde_json::from_str(request).map_err(InvokeFailure::invalid_request)?;
    if envelope.api_version != INVOKE_API_VERSION {
        return Err(InvokeFailure::invalid_request(format!(
            "unsupported apiVersion {}; expected {INVOKE_API_VERSION}",
            envelope.api_version
        )));
    }
    if !envelope.payload.is_object() {
        return Err(InvokeFailure::invalid_request("payload must be an object"));
    }

    let data = match envelope.method.as_str() {
        "initialize" => {
            require_instance_omitted(&envelope)?;
            let payload: InitializePayload = decode_payload(envelope.payload)?;
            let directory = registry().initialize_data_directory(&payload.data_dir)?;
            json!({"dataDir": directory.root().to_string_lossy()})
        }
        "createInstance" => {
            require_instance_omitted(&envelope)?;
            let _: EmptyPayload = decode_payload(envelope.payload)?;
            let controller = registry().create_instance()?;
            json!({"instanceId": controller.id.to_string()})
        }
        "getGeoDataState" => {
            require_instance_omitted(&envelope)?;
            let _: EmptyPayload = decode_payload(envelope.payload)?;
            geodata_status_data(registry().geodata_manager()?.status().map_err(|error| {
                InvokeFailure::new(format!("failed to read GeoData state: {error}"))
            })?)
        }
        "validateConfig" => {
            require_instance_omitted(&envelope)?;
            let payload: ConfigYamlPayload = decode_payload(envelope.payload)?;
            validate_config(payload.config_yaml)?;
            json!({})
        }
        "measureDelay" => {
            require_instance_omitted(&envelope)?;
            let payload: measure_delay::MeasureDelayPayload = decode_payload(envelope.payload)?;
            let results = measure_delay::measure_delay(payload)?;
            json!({"results": results})
        }
        "prepare" => {
            let controller = require_instance(&envelope)?;
            let payload: ConfigYamlPayload = decode_payload(envelope.payload)?;
            invoke_instance_guarded(&controller, || {
                controller.prepare(payload.config_yaml)?;
                Ok(json!({}))
            })?
        }
        "start" => {
            let controller = require_instance(&envelope)?;
            let field_presence = start_field_presence(&envelope.payload)?;
            let payload: StartPayload = decode_payload(envelope.payload)?;
            invoke_instance_guarded(&controller, || {
                controller.start(payload, field_presence)?;
                Ok(json!({}))
            })?
        }
        "stop" => {
            let controller = require_instance(&envelope)?;
            let _: EmptyPayload = decode_payload(envelope.payload)?;
            invoke_instance_guarded(&controller, || {
                controller.stop()?;
                Ok(json!({}))
            })?
        }
        "getState" => {
            let controller = require_instance(&envelope)?;
            let _: EmptyPayload = decode_payload(envelope.payload)?;
            invoke_instance_guarded(&controller, || controller.state_data())?
        }
        "destroyInstance" => {
            let controller = require_instance(&envelope)?;
            let _: EmptyPayload = decode_payload(envelope.payload)?;
            invoke_instance_guarded(&controller, || {
                controller.destroy()?;
                Ok(json!({}))
            })?
        }
        "version" => {
            require_instance_omitted(&envelope)?;
            let _: EmptyPayload = decode_payload(envelope.payload)?;
            json!({
                "apiVersion": INVOKE_API_VERSION,
                "buildIdentity": BUILD_IDENTITY,
                "configVersion": CONFIG_VERSION,
                "engine": ENGINE,
                "version": env!("CARGO_PKG_VERSION"),
            })
        }
        method => {
            return Err(InvokeFailure::invalid_request(format!(
                "unknown method `{method}`"
            )));
        }
    };
    Ok(InvokeResponse::success(data))
}

fn require_instance(envelope: &RequestEnvelope) -> Result<Arc<CoreController>, InvokeFailure> {
    let raw_id = envelope.instance_id.as_deref().ok_or_else(|| {
        InvokeFailure::invalid_request(format!(
            "instanceId is required for method `{}`",
            envelope.method
        ))
    })?;
    registry().instance(raw_id)
}

fn require_instance_omitted(envelope: &RequestEnvelope) -> Result<(), InvokeFailure> {
    if envelope.instance_id.is_some() {
        return Err(InvokeFailure::invalid_request(format!(
            "instanceId must be omitted for method `{}`",
            envelope.method
        )));
    }
    Ok(())
}

fn decode_payload<T: for<'de> Deserialize<'de>>(payload: Value) -> Result<T, InvokeFailure> {
    serde_json::from_value(payload).map_err(InvokeFailure::invalid_request)
}

#[derive(Debug, Clone, Copy)]
struct StartFieldPresence {
    tun_fd: bool,
    tun_framing: bool,
}

fn start_field_presence(payload: &Value) -> Result<StartFieldPresence, InvokeFailure> {
    let object = payload
        .as_object()
        .ok_or_else(|| InvokeFailure::invalid_request("payload must be an object"))?;
    Ok(StartFieldPresence {
        tun_fd: object.contains_key("tunFd"),
        tun_framing: object.contains_key("tunFraming"),
    })
}

impl CoreController {
    fn try_command(&self) -> Result<MutexGuard<'_, ()>, InvokeFailure> {
        let guard = match self.command.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(InvokeFailure::invalid_state(format!(
                    "instance {} is busy",
                    self.id
                )));
            }
        };
        self.ensure_live()?;
        Ok(guard)
    }

    fn ensure_live(&self) -> Result<(), InvokeFailure> {
        if self.tombstoned.load(Ordering::Acquire) {
            return Err(InvokeFailure::invalid_request("unknown instanceId"));
        }
        Ok(())
    }

    fn prepare(&self, config_yaml: String) -> Result<(), InvokeFailure> {
        let _command = self.try_command()?;
        {
            let mut inner = lock(&self.inner);
            refresh_runtime_status(&mut inner);
            if inner.lifecycle.state() != LifecycleState::Stopped {
                return Err(InvokeFailure::invalid_state(
                    "instance must be stopped before prepare",
                ));
            }
        }

        // Parse before claiming runtime-local resources. Android only needs a
        // protect controller for a configuration that actually contains TUN;
        // non-TUN configurations do not depend on controller registration.
        let _data_directory = registry().data_directory()?;
        let config = parse_config_yaml(&config_yaml)?;
        drop(config_yaml);
        let has_tun = config
            .inbounds
            .iter()
            .any(|inbound| matches!(inbound, crate::config::InboundConfig::Tun(_)));
        // The unique TUN lease and, on Android, the registered protector are
        // captured in one critical section so the protector cannot be replaced
        // during the prepared/running TUN lifecycle.
        let acquisition = registry().acquire_platform_resources(self.id, has_tun)?;
        let PlatformAcquisition {
            tun_lease,
            protector,
        } = acquisition;
        let allocator_relief = IosTunAllocatorRelief::new(has_tun);
        {
            let mut inner = lock(&self.inner);
            inner.last_error.clear();
            inner
                .lifecycle
                .transition(LifecycleState::Preparing)
                .map_err(InvokeFailure::from)?;
            inner.tun_lease = tun_lease;
            inner.ios_tun_allocator_relief = allocator_relief;
        }

        let prepared = (|| {
            let limits = ResourceLimits::default();
            let geodata_manager = registry().geodata_manager()?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(InvokeFailure::from)?;
            let prepared = runtime
                .block_on(PreparedCore::prepare_config(
                    config,
                    geodata_manager,
                    &SystemResolver,
                    limits,
                ))
                .map_err(InvokeFailure::from);
            // Bootstrap DNS runs on the runtime-shared bounded worker. Keep a
            // finite shutdown boundary so future prepare-only tasks cannot
            // turn Runtime::drop into an unbounded synchronous wait.
            runtime.shutdown_timeout(Duration::from_millis(100));
            prepared
        })();

        let mut inner = lock(&self.inner);
        match prepared {
            Ok(prepared) => {
                inner.prepared = Some(PreparedState {
                    core: prepared,
                    protector,
                });
                match inner
                    .lifecycle
                    .transition(LifecycleState::Prepared)
                    .map_err(InvokeFailure::from)
                {
                    Ok(()) => {
                        observe_ios_tun_memory(has_tun, "prepare-complete");
                        Ok(())
                    }
                    Err(error) => reset_failed_operation(&mut inner, "prepare-transition-failed")
                        .and(Err(error)),
                }
            }
            Err(error) => reset_failed_operation(&mut inner, "prepare-failed").and(Err(error)),
        }
    }

    fn start(
        &self,
        payload: StartPayload,
        presence: StartFieldPresence,
    ) -> Result<(), InvokeFailure> {
        if cfg!(target_os = "linux") {
            return Err(InvokeFailure::new(
                "VCore runtime startup is unsupported on Linux",
            ));
        }
        let _command = self.try_command()?;
        let (prepared, tun, has_tun, allocator_relief) = {
            let mut inner = lock(&self.inner);
            refresh_runtime_status(&mut inner);
            if inner.lifecycle.state() != LifecycleState::Prepared {
                return Err(InvokeFailure::invalid_state(
                    "instance must be prepared before start",
                ));
            }
            let has_tun = inner
                .prepared
                .as_ref()
                .ok_or_else(|| InvokeFailure::internal("prepared core is missing"))?
                .core
                .has_tun();
            let tun = validate_start_tun(has_tun, payload, presence)?;
            // Duplicate before consuming prepared state. If duplication fails,
            // the caller can correct the fd and retry from prepared.
            let tun = duplicate_start_tun(tun)?;
            let prepared = inner
                .prepared
                .take()
                .ok_or_else(|| InvokeFailure::internal("prepared core is missing"))?;
            inner.last_error.clear();
            inner
                .lifecycle
                .transition(LifecycleState::Starting)
                .map_err(InvokeFailure::from)?;
            let allocator_relief = inner.ios_tun_allocator_relief.clone();
            (prepared, tun, has_tun, allocator_relief)
        };

        let dialer = prepared
            .protector
            .clone()
            .map_or_else(Dialer::default, |protector| {
                Dialer::default().with_protector(protector)
            });
        let (stop_tx, stop_rx) = oneshot::channel();
        let (startup_tx, startup_rx) = std::sync::mpsc::sync_channel(1);
        let instance_id = self.id;
        let context = EngineContext {
            instance_id,
            has_tun,
            allocator_relief,
        };
        let spawned = thread::Builder::new()
            .name(format!("vcore-runtime-{instance_id}"))
            .stack_size(1024 * 1024)
            .spawn(move || {
                let _runtime_thread = RuntimeThreadGuard::enter();
                run_engine(context, prepared.core, tun, dialer, stop_rx, startup_tx)
            });
        let runtime_thread = match spawned {
            Ok(thread) => thread,
            Err(error) => {
                let mut inner = lock(&self.inner);
                return reset_failed_operation(&mut inner, "start-spawn-failed")
                    .and(Err(InvokeFailure::from(error)));
            }
        };
        let mut engine = Engine {
            stop: Some(stop_tx),
            thread: Some(runtime_thread),
        };

        match startup_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => {
                let mut inner = lock(&self.inner);
                if let Err(error) = inner
                    .lifecycle
                    .transition(LifecycleState::Running)
                    .map_err(InvokeFailure::from)
                {
                    drop(inner);
                    let _ = engine.stop();
                    let mut inner = lock(&self.inner);
                    return reset_failed_operation(&mut inner, "start-transition-failed")
                        .and(Err(error));
                }
                inner.engine = Some(engine);
                observe_ios_tun_memory(has_tun, "start-complete");
                Ok(())
            }
            Ok(Err(error)) => {
                let _ = engine.stop();
                let mut inner = lock(&self.inner);
                reset_failed_operation(&mut inner, "start-runtime-failed").and(Err(error))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let stopped = engine.stop();
                let mut inner = lock(&self.inner);
                let outcome = stopped.and_then(|()| {
                    Err(InvokeFailure::internal(
                        "VCore runtime exited before reporting startup",
                    ))
                });
                reset_failed_operation(&mut inner, "start-disconnected").and(outcome)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let _ = engine.stop();
                let mut inner = lock(&self.inner);
                reset_failed_operation(&mut inner, "start-timeout")
                    .and(Err(InvokeFailure::new("VCore runtime startup timed out")))
            }
        }
    }

    fn stop(&self) -> Result<(), InvokeFailure> {
        let _command = self.try_command()?;
        self.stop_locked()
    }

    fn stop_locked(&self) -> Result<(), InvokeFailure> {
        let (mut engine, had_tun) = {
            let mut inner = lock(&self.inner);
            refresh_runtime_status(&mut inner);
            match inner.lifecycle.state() {
                LifecycleState::Stopped => {
                    let had_tun = inner.tun_lease.is_some();
                    inner.last_error.clear();
                    observe_ios_tun_memory(had_tun, "stop-complete");
                    clear_instance_leases(&mut inner);
                    return Ok(());
                }
                LifecycleState::Prepared => {
                    let had_tun = inner.tun_lease.is_some();
                    inner.prepared = None;
                    inner.last_error.clear();
                    let transitioned = inner
                        .lifecycle
                        .transition(LifecycleState::Stopped)
                        .map_err(InvokeFailure::from);
                    observe_ios_tun_memory(had_tun, "stop-complete");
                    clear_instance_leases(&mut inner);
                    return transitioned;
                }
                LifecycleState::Running | LifecycleState::Failed => {
                    let had_tun = inner.tun_lease.is_some();
                    inner
                        .lifecycle
                        .transition(LifecycleState::Stopping)
                        .map_err(InvokeFailure::from)?;
                    (inner.engine.take(), had_tun)
                }
                LifecycleState::Preparing | LifecycleState::Starting | LifecycleState::Stopping => {
                    return Err(InvokeFailure::invalid_state(
                        "core cannot stop during a lifecycle transition",
                    ));
                }
            }
        };

        let stopped = engine.as_mut().map_or(Ok(()), Engine::stop);
        drop(engine);
        let mut inner = lock(&self.inner);
        inner.prepared = None;
        inner.engine = None;
        let transitioned = inner
            .lifecycle
            .transition(LifecycleState::Stopped)
            .map_err(InvokeFailure::from);
        match &stopped {
            Ok(()) => inner.last_error.clear(),
            Err(error) => inner.last_error = error.message.clone(),
        }
        clear_instance_leases(&mut inner);
        let _ = had_tun;
        transitioned.and(stopped)
    }

    fn state_data(&self) -> Result<Value, InvokeFailure> {
        // Reads participate in the same per-instance admission as lifecycle
        // mutations. Besides making the public fail-fast contract uniform,
        // this prevents a state read that already resolved the controller from
        // completing after destroyInstance's synchronous removal barrier.
        let _command = self.try_command()?;
        let mut inner = lock(&self.inner);
        refresh_runtime_status(&mut inner);
        Ok(json!({
            "state": inner.lifecycle.state().as_str(),
            "lastError": inner.last_error,
        }))
    }

    fn destroy(self: &Arc<Self>) -> Result<(), InvokeFailure> {
        self.destroy_with(|| self.stop_locked())
    }

    fn destroy_with(
        self: &Arc<Self>,
        operation: impl FnOnce() -> Result<(), InvokeFailure>,
    ) -> Result<(), InvokeFailure> {
        let _command = self.try_command()?;
        let _removal = InstanceRemovalGuard { controller: self };
        operation()
    }

    fn recover_after_panic(&self) -> Result<(), InvokeFailure> {
        let _command = lock(&self.command);
        if self.tombstoned.load(Ordering::Acquire) {
            return Ok(());
        }
        let (mut engine, had_tun) = {
            let mut inner = lock(&self.inner);
            let had_tun = inner.tun_lease.is_some();
            inner.prepared = None;
            inner.last_error =
                "internal error: panic caught at the VCore Invoke boundary".to_owned();
            match inner.lifecycle.state() {
                LifecycleState::Running | LifecycleState::Failed => {
                    let _ = inner.lifecycle.transition(LifecycleState::Stopping);
                }
                LifecycleState::Preparing | LifecycleState::Starting => {
                    let _ = inner.lifecycle.transition(LifecycleState::Failed);
                }
                LifecycleState::Prepared => {
                    let _ = inner.lifecycle.transition(LifecycleState::Stopped);
                }
                LifecycleState::Stopped | LifecycleState::Stopping => {}
            }
            (inner.engine.take(), had_tun)
        };
        if let Some(engine) = engine.as_mut() {
            let _ = engine.stop();
        }
        drop(engine);
        let mut inner = lock(&self.inner);
        inner.lifecycle = Lifecycle::default();
        inner.engine = None;
        observe_ios_tun_memory(had_tun, "panic-recovery");
        clear_instance_leases(&mut inner);
        Ok(())
    }
}

fn clear_instance_leases(inner: &mut CoreInner) {
    // Prepared-only paths own the final allocator-relief handle here. Running
    // paths share it with the engine, whose completion performs relief first.
    inner.ios_tun_allocator_relief = None;
    inner.tun_lease = None;
}

fn observe_ios_tun_memory(has_tun: bool, stage: &'static str) {
    #[cfg(target_os = "ios")]
    if has_tun {
        crate::platform::process_memory::observe(stage);
    }
    let _ = (has_tun, stage);
}

fn relieve_ios_tun_allocator() {
    #[cfg(target_os = "ios")]
    crate::platform::process_memory::relieve_allocator_pressure();
}

#[cfg(target_os = "android")]
pub(super) fn replace_android_socket_protector(
    protector: Option<Arc<dyn SocketProtector>>,
) -> Result<(), String> {
    registry().replace_android_socket_protector(protector)
}

fn validate_config(config_yaml: String) -> Result<(), InvokeFailure> {
    let _data_directory = registry().data_directory()?;
    let config = parse_config_yaml(&config_yaml)?;
    drop(config_yaml);
    PreparedCore::validate_config(config).map_err(InvokeFailure::from)
}

fn parse_config_yaml(config_yaml: &str) -> Result<Config, InvokeFailure> {
    if config_yaml.is_empty() {
        return Err(InvokeFailure::invalid_request("configYaml is empty"));
    }
    Config::parse_yaml(config_yaml.as_bytes()).map_err(InvokeFailure::from)
}

fn geodata_status_data(status: GeoDataStatus) -> Value {
    json!({
        "geosite": geodata_resource_data(status.geosite),
        "geoip": geodata_resource_data(status.geoip),
    })
}

fn geodata_resource_data(state: GeoResourceState) -> Value {
    json!({
        "required": state.required,
        "available": state.available,
        "updating": state.updating,
        "lastSuccess": state.last_success,
        "nextCheck": state.next_check,
        "lastError": state.last_error,
        "etag": state.etag,
        "hash": state.hash,
    })
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
fn duplicate_start_tun(tun: Option<(i32, TunFraming)>) -> Result<Option<InvokeTun>, InvokeFailure> {
    tun.map(|(fd, framing)| TunFd::duplicate(fd).map(|fd| (fd, framing)))
        .transpose()
        .map_err(InvokeFailure::from)
}

#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "macos")))]
fn duplicate_start_tun(tun: Option<(i32, TunFraming)>) -> Result<Option<InvokeTun>, InvokeFailure> {
    if tun.is_some() {
        return Err(InvokeFailure::invalid_request(
            "TUN fd is unsupported on this target; only iOS, macOS, and Android are supported",
        ));
    }
    Ok(None)
}

fn validate_start_tun(
    has_tun: bool,
    payload: StartPayload,
    presence: StartFieldPresence,
) -> Result<Option<(i32, TunFraming)>, InvokeFailure> {
    if has_tun {
        if !presence.tun_fd || !presence.tun_framing {
            return Err(InvokeFailure::invalid_request(
                "tunFd and tunFraming are required for a TUN configuration",
            ));
        }
        let fd = payload
            .tun_fd
            .ok_or_else(|| InvokeFailure::invalid_request("tunFd must be an integer"))?;
        if fd < 0 {
            return Err(InvokeFailure::invalid_request(
                "tunFd must be a non-negative descriptor",
            ));
        }
        let framing = payload
            .tun_framing
            .ok_or_else(|| InvokeFailure::invalid_request("tunFraming must be a string"))?;
        let framing = TunFraming::from(framing);
        validate_platform_tun_framing(framing)?;
        Ok(Some((fd, framing)))
    } else {
        if presence.tun_fd || presence.tun_framing {
            return Err(InvokeFailure::invalid_request(
                "tunFd and tunFraming must be omitted when tun.enable is not true",
            ));
        }
        Ok(None)
    }
}

#[cfg(target_os = "android")]
fn validate_platform_tun_framing(framing: TunFraming) -> Result<(), InvokeFailure> {
    if framing != TunFraming::RawIp {
        return Err(InvokeFailure::invalid_request(
            "Android TUN requires rawIp framing",
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn validate_platform_tun_framing(framing: TunFraming) -> Result<(), InvokeFailure> {
    if framing != TunFraming::Utun {
        return Err(InvokeFailure::invalid_request(
            "Apple TUN requires utun framing",
        ));
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "macos")))]
fn validate_platform_tun_framing(framing: TunFraming) -> Result<(), InvokeFailure> {
    let _ = framing;
    Err(InvokeFailure::invalid_request(
        "TUN fd is unsupported on this target; only iOS, macOS, and Android are supported",
    ))
}

struct EngineContext {
    instance_id: u64,
    has_tun: bool,
    allocator_relief: Option<IosTunAllocatorRelief>,
}

fn run_engine(
    context: EngineContext,
    prepared: PreparedCore,
    tun: Option<InvokeTun>,
    dialer: Dialer,
    stop: oneshot::Receiver<()>,
    startup: SyncSender<Result<(), InvokeFailure>>,
) -> io::Result<()> {
    let EngineContext {
        instance_id,
        has_tun,
        allocator_relief,
    } = context;
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    let _logging = crate::platform::apple_logging::enter();
    tracing::info!(instance_id, has_tun, "VCore runtime engine starting");
    let result = run_engine_inner(instance_id, has_tun, prepared, tun, dialer, stop, startup);
    observe_ios_tun_memory(has_tun, "stop-complete");
    if let Some(relief) = allocator_relief {
        relief.relieve();
    }
    match &result {
        Ok(()) => tracing::info!(instance_id, "VCore runtime engine stopped"),
        Err(error) => {
            tracing::error!(
                instance_id,
                error_kind = ?error.kind(),
                "VCore runtime engine failed"
            );
        }
    }
    result
}

fn run_engine_inner(
    instance_id: u64,
    has_tun: bool,
    prepared: PreparedCore,
    tun: Option<InvokeTun>,
    dialer: Dialer,
    stop: oneshot::Receiver<()>,
    startup: SyncSender<Result<(), InvokeFailure>>,
) -> io::Result<()> {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let message = error.to_string();
            let _ = startup.send(Err(InvokeFailure::internal(&message)));
            return Err(io::Error::new(error.kind(), message));
        }
    };
    runtime.block_on(async move {
        #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
        let started = match tun {
            Some((duplicate, framing)) => {
                tracing::info!(instance_id, ?framing, "VCore attaching TUN descriptor");
                let tun = TunIo::new(duplicate, framing).map_err(vcore_to_io)?;
                prepared.start_tun(tun, dialer).await
            }
            None => prepared.start_local(dialer).await,
        };
        #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "macos")))]
        let started = {
            debug_assert!(tun.is_none());
            prepared.start_local(dialer).await
        };
        let running = match started {
            Ok(running) => running,
            Err(error) => {
                let kind = error.kind();
                let message = error.to_string();
                let _ = startup.send(Err(InvokeFailure::from(error)));
                return Err(io::Error::new(kind, message));
            }
        };
        tracing::info!(instance_id, has_tun, "VCore runtime engine started");
        if startup.send(Ok(())).is_err() {
            return running.stop().await;
        }
        running
            .run_until_shutdown(wait_for_engine_shutdown(stop, has_tun))
            .await
    })
}

async fn wait_for_engine_shutdown(stop: oneshot::Receiver<()>, has_tun: bool) -> io::Result<()> {
    #[cfg(target_os = "ios")]
    let mut stop = stop;
    #[cfg(target_os = "ios")]
    if has_tun {
        let interval = crate::platform::process_memory::TELEMETRY_INTERVAL;
        let first_tick = tokio::time::Instant::now() + interval;
        let mut telemetry = tokio::time::interval_at(first_tick, interval);
        telemetry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = &mut stop => return Ok(()),
                _ = telemetry.tick() => observe_ios_tun_memory(true, "running"),
            }
        }
    }
    let _ = has_tun;
    let _ = stop.await;
    Ok(())
}

fn refresh_runtime_status(inner: &mut CoreInner) {
    if inner.lifecycle.state() != LifecycleState::Running
        || !inner.engine.as_ref().is_some_and(Engine::is_finished)
    {
        return;
    }
    let result = inner.engine.as_mut().map_or_else(
        || {
            Err(InvokeFailure::internal(
                "VCore runtime disappeared unexpectedly",
            ))
        },
        Engine::stop,
    );
    inner.engine = None;
    inner.last_error = match result {
        Ok(()) => "VCore runtime stopped unexpectedly".to_owned(),
        Err(error) => error.message,
    };
    let _ = inner.lifecycle.transition(LifecycleState::Failed);
}

fn reset_failed_operation(
    inner: &mut CoreInner,
    telemetry_stage: &'static str,
) -> Result<(), InvokeFailure> {
    let had_tun = inner.tun_lease.is_some();
    inner.prepared = None;
    inner.engine = None;
    match inner.lifecycle.state() {
        LifecycleState::Preparing | LifecycleState::Starting => {
            let _ = inner.lifecycle.transition(LifecycleState::Failed);
            let _ = inner.lifecycle.transition(LifecycleState::Stopped);
        }
        LifecycleState::Prepared => {
            let _ = inner.lifecycle.transition(LifecycleState::Stopped);
        }
        LifecycleState::Failed | LifecycleState::Stopping => {
            let _ = inner.lifecycle.transition(LifecycleState::Stopped);
        }
        LifecycleState::Running => {
            let _ = inner.lifecycle.transition(LifecycleState::Stopping);
            let _ = inner.lifecycle.transition(LifecycleState::Stopped);
        }
        LifecycleState::Stopped => {}
    }
    observe_ios_tun_memory(had_tun, telemetry_stage);
    clear_instance_leases(inner);
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
fn vcore_to_io(error: VCoreError) -> io::Error {
    match error {
        VCoreError::Io(error) => error,
        error => io::Error::other(error),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

unsafe fn read_request<'a>(request_json: *const c_char) -> Result<&'a [u8], InvokeFailure> {
    if request_json.is_null() {
        return Err(InvokeFailure::invalid_request("request_json is null"));
    }
    // SAFETY: the caller promises readable storage through the first NUL or
    // MAX_INVOKE_BYTES + 1 bytes, whichever comes first.
    let len = unsafe { libc::strnlen(request_json, MAX_INVOKE_BYTES + 1) };
    if len > MAX_INVOKE_BYTES {
        return Err(InvokeFailure::invalid_request(format!(
            "Invoke envelope exceeds the {MAX_INVOKE_BYTES}-byte limit or is not NUL-terminated"
        )));
    }
    // SAFETY: strnlen established that these bytes are readable and precede a
    // NUL terminator within the documented bound.
    Ok(unsafe { slice::from_raw_parts(request_json.cast::<u8>(), len) })
}

fn serialize_response(response: InvokeResponse) -> Vec<u8> {
    serde_json::to_vec(&response).unwrap_or_else(|_| {
        b"{\"success\":false,\"data\":null,\"error\":\"internal error: response serialization failed\"}"
            .to_vec()
    })
}

fn allocate_response(json: Vec<u8>) -> *mut c_char {
    // JSON escapes control characters, so serialization cannot introduce an
    // interior NUL. Keep a defensive fallback to preserve the C contract.
    CString::new(json).unwrap_or_else(|_| {
        CString::new(
            "{\"success\":false,\"data\":null,\"error\":\"internal error: invalid response string\"}",
        )
        .expect("static response has no NUL")
    })
    .into_raw()
}

fn bounded_error(mut message: String) -> String {
    if message.len() <= MAX_ERROR_BYTES {
        return message;
    }
    let mut end = MAX_ERROR_BYTES.saturating_sub(3);
    while !message.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    message.truncate(end);
    message.push_str("...");
    message
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::{CStr, CString},
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        ptr,
        sync::{Arc, Barrier, Mutex},
    };

    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    use std::os::{fd::AsRawFd, unix::net::UnixDatagram};

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct TestDataDirectory {
        _temporary: tempfile::TempDir,
    }

    struct AcceptingProtector;

    impl SocketProtector for AcceptingProtector {
        fn protect(&self, _socket: i32) -> io::Result<()> {
            Ok(())
        }
    }

    fn invoke(request: &str) -> Value {
        let request = CString::new(request).unwrap();
        // SAFETY: request is NUL-terminated and the response is freed exactly
        // once after copying it into an owned Rust string.
        let response = unsafe { VCoreInvoke(request.as_ptr()) };
        assert!(!response.is_null());
        // SAFETY: VCoreInvoke returns a live NUL-terminated string.
        let json = unsafe { CStr::from_ptr(response) }
            .to_str()
            .unwrap()
            .to_owned();
        // SAFETY: response came from VCoreInvoke and has not been freed.
        unsafe { VCoreFree(response) };
        serde_json::from_str(&json).unwrap()
    }

    fn assert_failure(response: &Value) {
        assert_eq!(response["success"], false);
        assert!(response["data"].is_null());
        assert!(
            response["error"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
        assert_eq!(response.as_object().unwrap().len(), 3);
    }

    fn request(method: &str, instance_id: Option<&str>, payload: Value) -> Value {
        let mut envelope = json!({
            "apiVersion": INVOKE_API_VERSION,
            "method": method,
            "payload": payload,
        });
        if let Some(instance_id) = instance_id {
            envelope["instanceId"] = Value::String(instance_id.to_owned());
        }
        invoke(&envelope.to_string())
    }

    fn create_instance() -> String {
        let response = request("createInstance", None, json!({}));
        assert_eq!(response["success"], true, "{response}");
        response["data"]["instanceId"].as_str().unwrap().to_owned()
    }

    fn destroy_instance(instance_id: &str) {
        let response = request("destroyInstance", Some(instance_id), json!({}));
        assert_eq!(response["success"], true, "{response}");
    }

    fn state(instance_id: &str) -> Value {
        request("getState", Some(instance_id), json!({}))
    }

    fn reset_registry() {
        let controller = lock(&registry().inner).instance.clone();
        if let Some(controller) = controller {
            let _ = controller.destroy();
        }
        let inner = lock(&registry().inner);
        assert!(inner.instance.is_none());
        drop(inner);
        let platform = lock(&registry().platform);
        assert_eq!(platform.tun_owner, None);
        drop(platform);
        *lock(&registry().runtime_data) = None;
    }

    fn initialize_test_data_directory() -> TestDataDirectory {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("vcore");
        let response = request(
            "initialize",
            None,
            json!({"dataDir": root.to_str().unwrap()}),
        );
        assert_eq!(response["success"], true, "{response}");
        TestDataDirectory {
            _temporary: temporary,
        }
    }

    fn config_with_outbound(http_port: Option<u16>, tun: bool, outbound_port: u16) -> String {
        let listener = match (http_port, tun) {
            (Some(port), false) => format!(
                "port: {port}
authentication:
  - measure:secret\n"
            ),
            (None, true) => "tun:\n  enable: true\n  mtu: 1500\n".to_owned(),
            _ => panic!("test configuration must select exactly one listener"),
        };
        format!(
            r#"{listener}proxies:
  - name: proxy
    type: vless
    server: 127.0.0.1
    port: {outbound_port}
    uuid: 00000000-0000-4000-8000-000000000001
    udp: true
    tls: true
    network: xhttp
    encryption: none
    servername: example.com
    alpn: [h2]
    xhttp-opts:
      host: example.com
      path: /vcore
      mode: packet-up
rules:
  - MATCH,proxy
"#
        )
    }

    fn tun_config() -> String {
        config_with_outbound(None, true, 443)
    }

    fn http_config(port: u16) -> String {
        config_with_outbound(Some(port), false, 443)
    }

    fn current_config(http_port: u16, rules: &str) -> String {
        format!(
            r#"port: {http_port}
authentication:
  - measure:secret
proxies:
  - name: proxy
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    udp: true
    tls: true
    network: xhttp
    encryption: none
    servername: example.com
    alpn: [h2]
    xhttp-opts:
      host: example.com
      path: /vcore
      mode: packet-up
rules:
{rules}
"#
        )
    }

    fn free_ports(count: usize) -> Vec<u16> {
        let listeners: Vec<_> = (0..count)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap().port())
            .collect()
    }

    fn probe_http_listener(port: u16) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .write_all(
                b"GET / HTTP/1.1\r\n\
                  Host: example.com\r\n\
                  Proxy-Authorization: Basic bWVhc3VyZTpzZWNyZXQ=\r\n\r\n",
            )
            .unwrap();
        let mut response = [0_u8; 128];
        let length = stream.read(&mut response).unwrap();
        assert!(
            response[..length].starts_with(b"HTTP/1.1 400")
                || response[..length].starts_with(b"HTTP/1.1 501"),
            "unexpected response: {}",
            String::from_utf8_lossy(&response[..length])
        );
    }

    #[test]
    fn version_and_state_use_the_fixed_response_envelope() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let version = request("version", None, json!({}));
        assert_eq!(version["success"], true);
        assert_eq!(version["error"], "");
        assert_eq!(version["data"]["apiVersion"], INVOKE_API_VERSION);
        assert_eq!(version["data"]["buildIdentity"], BUILD_IDENTITY);
        assert_eq!(version["data"]["configVersion"], CONFIG_VERSION);
        assert_eq!(version["data"]["engine"], ENGINE);
        assert_eq!(version["data"]["version"], env!("CARGO_PKG_VERSION"));

        let instance_id = create_instance();
        let instance_state = state(&instance_id);
        assert_eq!(instance_state["data"]["state"], "stopped");
        assert_eq!(instance_state["data"]["lastError"], "");
        destroy_instance(&instance_id);
    }

    #[test]
    fn initialize_is_idempotent_only_for_the_same_data_directory() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        assert_failure(&request("initialize", None, json!({"dataDir": "relative"})));
        assert_failure(&request("getGeoDataState", None, json!({})));

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("vcore");
        let first = request(
            "initialize",
            None,
            json!({"dataDir": root.to_str().unwrap()}),
        );
        assert_eq!(first["success"], true, "{first}");
        assert!(root.join(crate::data_dir::CONFIGS_DIR_NAME).is_dir());
        assert!(root.join(crate::data_dir::GEODATA_DIR_NAME).is_dir());

        let same = request(
            "initialize",
            None,
            json!({"dataDir": root.to_str().unwrap()}),
        );
        assert_eq!(same["success"], true, "{same}");

        let geodata = request("getGeoDataState", None, json!({}));
        assert_eq!(geodata["success"], true, "{geodata}");
        for kind in ["geosite", "geoip"] {
            assert_eq!(geodata["data"][kind]["required"], false);
            assert_eq!(geodata["data"][kind]["available"], false);
            assert_eq!(geodata["data"][kind]["updating"], false);
            assert!(geodata["data"][kind]["lastSuccess"].is_null());
            assert!(geodata["data"][kind]["nextCheck"].is_null());
            assert!(geodata["data"][kind]["lastError"].is_null());
            assert!(geodata["data"][kind]["etag"].is_null());
            assert!(geodata["data"][kind]["hash"].is_null());
        }

        let different = temporary.path().join("other");
        let rejected = request(
            "initialize",
            None,
            json!({"dataDir": different.to_str().unwrap()}),
        );
        assert_failure(&rejected);
        assert!(
            rejected["error"]
                .as_str()
                .unwrap()
                .contains("already initialized")
        );
        reset_registry();
    }

    #[test]
    fn envelope_and_payload_are_strict() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        for request in [
            r#"{"method":"version","payload":{}}"#,
            r#"{"apiVersion":0,"method":"version","payload":{}}"#,
            r#"{"apiVersion":2,"method":"version","payload":{}}"#,
            r#"{"apiVersion":3,"method":"version","payload":{}}"#,
            r#"{"apiVersion":4,"method":"version","payload":{}}"#,
            r#"{"apiVersion":5,"method":"version","payload":{},"extra":true}"#,
            r#"{"apiVersion":5,"method":"version","payload":{"extra":true}}"#,
            r#"{"apiVersion":5,"method":"version","payload":null}"#,
            r#"{"apiVersion":5,"method":"version","payload":{},"instanceId":"1"}"#,
            r#"{"apiVersion":5,"method":"createInstance","payload":{},"instanceId":"1"}"#,
            r#"{"apiVersion":5,"method":"getGeoDataState","payload":{},"instanceId":"1"}"#,
            r#"{"apiVersion":5,"method":"validateConfig","payload":{"configYaml":"x"},"instanceId":"1"}"#,
            r#"{"apiVersion":5,"method":"validateConfig","payload":{"configPath":"x"}}"#,
            r#"{"apiVersion":5,"method":"measureDelay","payload":{"configYamls":["x"],"timeout":5,"url":"https://example.com/"},"instanceId":"1"}"#,
            r#"{"apiVersion":5,"method":"measureDelay","payload":{"configYamls":["x"],"timeout":5,"url":"https://example.com/","extra":true}}"#,
            r#"{"apiVersion":5,"method":"measureDelay","payload":{"configYamls":[],"timeout":5,"url":"https://example.com/"}}"#,
            r#"{"apiVersion":5,"method":"measureDelay","payload":{"configYamls":[""],"timeout":5,"url":"https://example.com/"}}"#,
            r#"{"apiVersion":5,"method":"measureDelay","payload":{"configYamls":["x"],"timeout":0,"url":"https://example.com/"}}"#,
            r#"{"apiVersion":5,"method":"measureDelay","payload":{"configYamls":["x"],"timeout":31,"url":"https://example.com/"}}"#,
            r#"{"apiVersion":5,"method":"measureDelay","payload":{"configYamls":["x"],"timeout":5,"url":"ftp://example.com/"}}"#,
            r#"{"apiVersion":5,"method":"measureDelay","payload":{"configYaml":"x","timeout":5,"url":"https://example.com/","proxy":"http://127.0.0.1:18080"}}"#,
            r#"{"apiVersion":5,"method":"getState","payload":{}}"#,
            r#"{"apiVersion":5,"method":"getState","payload":{},"instanceId":null}"#,
            r#"{"apiVersion":5,"method":"getState","payload":{},"instanceId":1}"#,
            r#"{"apiVersion":5,"method":"getState","payload":{},"instanceId":"0"}"#,
            r#"{"apiVersion":5,"method":"getState","payload":{},"instanceId":"01"}"#,
            r#"{"apiVersion":5,"method":"getState","payload":{},"instanceId":"999999"}"#,
            r#"{"apiVersion":5,"method":"missing","payload":{}}"#,
        ] {
            assert_failure(&invoke(request));
        }
        let legacy_concurrency = invoke(
            r#"{"apiVersion":5,"method":"measureDelay","payload":{"configYamls":["x"],"timeout":5,"url":"https://example.com/","concurrency":1}}"#,
        );
        assert_failure(&legacy_concurrency);
        assert!(
            legacy_concurrency["error"]
                .as_str()
                .unwrap()
                .contains("concurrency")
        );
        let oversized_measure = request(
            "measureDelay",
            None,
            json!({
                "configYamls": vec!["x"; 6],
                "timeout": 5,
                "url": "https://example.com/",
            }),
        );
        assert_failure(&oversized_measure);
        assert!(
            oversized_measure["error"]
                .as_str()
                .unwrap()
                .contains("configYamls")
        );
        for method in ["prepare", "start", "stop", "getState", "destroyInstance"] {
            let response = request(method, None, json!({}));
            assert_failure(&response);
            assert!(
                response["error"]
                    .as_str()
                    .unwrap()
                    .contains("instanceId is required")
            );
        }
    }

    #[test]
    fn byte_dispatch_preserves_utf8_for_chinese_and_emoji_requests() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let response = invoke_bytes(
            r#"{"apiVersion":5,"method":"version","payload":{"备注":"你好😀"}}"#.as_bytes(),
        );
        let text = str::from_utf8(&response).unwrap();
        let json: Value = serde_json::from_str(text).unwrap();
        assert_failure(&json);
    }

    #[test]
    fn runtime_thread_cannot_reenter_invoke() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let response = thread::Builder::new()
            .name("arbitrary-runtime-name".to_owned())
            .spawn(|| {
                let _runtime_thread = RuntimeThreadGuard::enter();
                invoke_bytes(r#"{"apiVersion":5,"method":"version","payload":{}}"#.as_bytes())
            })
            .unwrap()
            .join()
            .unwrap();
        let json: Value = serde_json::from_slice(&response).unwrap();
        assert_failure(&json);
        assert!(json["error"].as_str().unwrap().contains("runtime thread"));
    }

    #[test]
    fn null_invalid_utf8_and_oversized_input_return_json_failures() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        // SAFETY: null is explicitly accepted as an error case.
        let null_response = unsafe { VCoreInvoke(ptr::null()) };
        assert!(!null_response.is_null());
        // SAFETY: response is a live VCore allocation.
        let null_json: Value =
            serde_json::from_str(unsafe { CStr::from_ptr(null_response) }.to_str().unwrap())
                .unwrap();
        unsafe { VCoreFree(null_response) };
        assert_failure(&null_json);

        let invalid = [0xff_u8, 0];
        // SAFETY: invalid has a NUL terminator and readable bounded storage.
        let invalid_response = unsafe { VCoreInvoke(invalid.as_ptr().cast()) };
        let invalid_json: Value = serde_json::from_str(
            unsafe { CStr::from_ptr(invalid_response) }
                .to_str()
                .unwrap(),
        )
        .unwrap();
        unsafe { VCoreFree(invalid_response) };
        assert_failure(&invalid_json);

        let mut oversized = vec![b' '; MAX_INVOKE_BYTES + 2];
        *oversized.last_mut().unwrap() = 0;
        // SAFETY: oversized is NUL-terminated and readable for the bounded scan.
        let oversized_response = unsafe { VCoreInvoke(oversized.as_ptr().cast()) };
        let oversized_json: Value = serde_json::from_str(
            unsafe { CStr::from_ptr(oversized_response) }
                .to_str()
                .unwrap(),
        )
        .unwrap();
        unsafe { VCoreFree(oversized_response) };
        assert_failure(&oversized_json);
    }

    #[test]
    fn start_payload_distinguishes_omitted_fields_from_null() {
        let empty: StartPayload = decode_payload(json!({})).unwrap();
        let empty_presence = start_field_presence(&json!({})).unwrap();
        assert!(
            validate_start_tun(false, empty, empty_presence)
                .unwrap()
                .is_none()
        );

        let null_value = json!({"tunFd": null, "tunFraming": null});
        let null: StartPayload = decode_payload(null_value.clone()).unwrap();
        let presence = start_field_presence(&null_value).unwrap();
        assert!(validate_start_tun(false, null, presence).is_err());

        let tun_framing = if cfg!(any(target_os = "ios", target_os = "macos")) {
            "utun"
        } else {
            "rawIp"
        };
        let tun_value = json!({"tunFd": 7, "tunFraming": tun_framing});
        let tun: StartPayload = decode_payload(tun_value.clone()).unwrap();
        let presence = start_field_presence(&tun_value).unwrap();
        #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
        assert_eq!(
            validate_start_tun(true, tun, presence).unwrap(),
            Some((
                7,
                if cfg!(any(target_os = "ios", target_os = "macos")) {
                    TunFraming::Utun
                } else {
                    TunFraming::RawIp
                }
            ))
        );
        #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "macos")))]
        assert!(validate_start_tun(true, tun, presence).is_err());

        #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
        {
            let wrong_framing = if cfg!(target_os = "android") {
                "utun"
            } else {
                "rawIp"
            };
            let wrong_value = json!({"tunFd": 7, "tunFraming": wrong_framing});
            let wrong: StartPayload = decode_payload(wrong_value.clone()).unwrap();
            let presence = start_field_presence(&wrong_value).unwrap();
            assert!(validate_start_tun(true, wrong, presence).is_err());
        }
    }

    #[test]
    fn config_yaml_input_is_strict_bounded_and_never_loaded_as_a_path() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();

        let uninitialized = request(
            "validateConfig",
            None,
            json!({"configYaml": http_config(free_ports(1)[0])}),
        );
        assert_failure(&uninitialized);
        assert!(
            uninitialized["error"]
                .as_str()
                .unwrap()
                .contains("not initialized")
        );
        let uninitialized_measure = request(
            "measureDelay",
            None,
            json!({
                "configYamls": ["proxies: []"],
                "timeout": 5,
                "url": "https://example.com/",
            }),
        );
        assert_failure(&uninitialized_measure);
        assert!(
            uninitialized_measure["error"]
                .as_str()
                .unwrap()
                .contains("not initialized")
        );

        let _directory = initialize_test_data_directory();
        let legacy_path = request(
            "validateConfig",
            None,
            json!({"configPath": "/tmp/config-that-must-not-be-read.yaml"}),
        );
        assert_failure(&legacy_path);
        assert!(
            legacy_path["error"]
                .as_str()
                .unwrap()
                .contains("configPath")
        );

        let empty = request("validateConfig", None, json!({"configYaml": ""}));
        assert_failure(&empty);
        assert!(
            empty["error"]
                .as_str()
                .unwrap()
                .contains("configYaml is empty")
        );

        let path_like_yaml = request(
            "validateConfig",
            None,
            json!({"configYaml": "/tmp/config-that-must-not-be-read.yaml"}),
        );
        assert_failure(&path_like_yaml);
        assert!(!path_like_yaml["error"].as_str().unwrap().contains("open"));

        let oversized = request(
            "validateConfig",
            None,
            json!({"configYaml": "x".repeat(crate::config::MAX_CONFIG_BYTES + 1)}),
        );
        assert_failure(&oversized);
        assert!(oversized["error"].as_str().unwrap().contains("byte limit"));
        reset_registry();
    }

    #[test]
    fn invoke_accepts_five_max_sized_inline_yaml_documents() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let config_yaml = "\\".repeat(crate::config::MAX_CONFIG_BYTES);
        let request = serde_json::to_vec(&json!({
            "apiVersion": INVOKE_API_VERSION,
            "method": "measureDelay",
            "payload": {
                "configYamls": vec![config_yaml; measure_delay::MAX_MEASURE_CONFIGS],
                "timeout": 5,
                "url": "https://example.com/",
            },
        }))
        .unwrap();
        assert!(request.len() > 1024 * 1024);
        assert!(request.len() <= MAX_INVOKE_BYTES);

        let response: Value = serde_json::from_slice(&invoke_bytes(&request)).unwrap();
        assert_eq!(response["success"], true, "{response}");
        let results = response["data"]["results"].as_array().unwrap();
        assert_eq!(results.len(), measure_delay::MAX_MEASURE_CONFIGS);
        assert!(results.iter().all(|result| result["success"] == false));
        reset_registry();
    }

    #[test]
    fn validate_config_does_not_change_instance_state() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let instance_id = create_instance();
        let _directory = initialize_test_data_directory();
        let request = json!({
            "apiVersion": INVOKE_API_VERSION,
            "method": "validateConfig",
            "payload": {"configYaml": "not: [valid"},
        });
        assert_failure(&invoke(&request.to_string()));
        assert_eq!(state(&instance_id)["data"]["state"], "stopped");
        destroy_instance(&instance_id);
    }

    #[test]
    fn validate_config_allows_referenced_geodata_assets_to_be_missing() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let config_yaml =
            current_config(free_ports(1)[0], "  - GEOSITE,cn,DIRECT\n  - MATCH,proxy");

        let response = request("validateConfig", None, json!({"configYaml": config_yaml}));
        assert_eq!(response["success"], true, "{response}");
        assert_registry_is_idle();
    }

    #[test]
    fn concurrent_validate_config_calls_return_the_same_result() {
        const CONCURRENT: usize = 12;

        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let config_yaml = http_config(free_ports(1)[0]);
        let request = Arc::new(
            json!({
                "apiVersion": INVOKE_API_VERSION,
                "method": "validateConfig",
                "payload": {"configYaml": config_yaml},
            })
            .to_string(),
        );
        let barrier = Arc::new(Barrier::new(CONCURRENT + 1));
        let threads: Vec<_> = (0..CONCURRENT)
            .map(|_| {
                let request = request.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    invoke(&request)
                })
            })
            .collect();
        barrier.wait();
        for thread in threads {
            let response = thread.join().unwrap();
            assert_eq!(response["success"], true, "{response}");
        }
        assert_registry_is_idle();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn prepare_keeps_missing_geodata_rules_dormant_and_reports_state() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let config_yaml = current_config(
            free_ports(1)[0],
            "  - GEOSITE,cn,DIRECT\n  - GEOIP,private,DIRECT,no-resolve\n  - MATCH,proxy",
        );
        let instance_id = create_instance();

        let prepared = request(
            "prepare",
            Some(&instance_id),
            json!({"configYaml": config_yaml}),
        );
        assert_eq!(prepared["success"], true, "{prepared}");
        let geodata = request("getGeoDataState", None, json!({}));
        assert_eq!(geodata["success"], true, "{geodata}");
        for kind in ["geosite", "geoip"] {
            assert_eq!(geodata["data"][kind]["required"], true);
            assert_eq!(geodata["data"][kind]["available"], false);
            assert!(
                geodata["data"][kind]["lastError"]
                    .as_str()
                    .is_some_and(|error| error.contains(".dat")),
                "{geodata}"
            );
        }

        let started = request("start", Some(&instance_id), json!({}));
        assert_eq!(started["success"], true, "{started}");
        assert_eq!(state(&instance_id)["data"]["state"], "running");
        assert_eq!(
            request("stop", Some(&instance_id), json!({}))["success"],
            true
        );
        let stopped = request("getGeoDataState", None, json!({}));
        assert_eq!(stopped["data"]["geosite"]["required"], false);
        assert_eq!(stopped["data"]["geoip"]["required"], false);
        destroy_instance(&instance_id);
        assert_registry_is_idle();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_runtime_start_fails_closed() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let instance_id = create_instance();
        let prepared = request(
            "prepare",
            Some(&instance_id),
            json!({"configYaml": http_config(free_ports(1)[0])}),
        );
        assert_eq!(prepared["success"], true, "{prepared}");

        let started = request("start", Some(&instance_id), json!({}));
        assert_failure(&started);
        assert!(
            started["error"]
                .as_str()
                .unwrap()
                .contains("unsupported on Linux")
        );
        assert_eq!(state(&instance_id)["data"]["state"], "prepared");

        assert_eq!(
            request("stop", Some(&instance_id), json!({}))["success"],
            true
        );
        destroy_instance(&instance_id);
        assert_registry_is_idle();
    }

    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    #[test]
    fn prepare_start_stop_is_instance_scoped_and_borrows_tun_fd() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let instance_id = create_instance();
        let _directory = initialize_test_data_directory();
        let config_yaml = tun_config();
        let validate = json!({
            "apiVersion": INVOKE_API_VERSION,
            "method": "validateConfig",
            "payload": {"configYaml": &config_yaml},
        });
        let response = invoke(&validate.to_string());
        assert_eq!(response["success"], true, "{response}");
        assert_eq!(state(&instance_id)["data"]["state"], "stopped");
        let prepare = json!({
            "apiVersion": INVOKE_API_VERSION,
            "method": "prepare",
            "instanceId": instance_id,
            "payload": {"configYaml": &config_yaml},
        });
        let response = invoke(&prepare.to_string());
        assert_eq!(response["success"], true, "{response}");
        assert_eq!(state(&instance_id)["data"]["state"], "prepared");

        let missing_tun = request("start", Some(&instance_id), json!({}));
        assert_failure(&missing_tun);
        assert_eq!(state(&instance_id)["data"]["state"], "prepared");

        let (original, peer) = UnixDatagram::pair().unwrap();
        original.set_nonblocking(true).unwrap();
        let tun_framing = if cfg!(any(target_os = "ios", target_os = "macos")) {
            "utun"
        } else {
            "rawIp"
        };
        let start = json!({
            "apiVersion": INVOKE_API_VERSION,
            "method": "start",
            "instanceId": instance_id,
            "payload": {
                "tunFd": original.as_raw_fd(),
                "tunFraming": tun_framing,
            },
        });
        for cycle in 0_u8..20 {
            if cycle != 0 {
                let response = invoke(&prepare.to_string());
                assert_eq!(response["success"], true, "cycle {cycle}: {response}");
            }
            let response = invoke(&start.to_string());
            assert_eq!(response["success"], true, "cycle {cycle}: {response}");
            assert_eq!(state(&instance_id)["data"]["state"], "running");

            let stopped = request("stop", Some(&instance_id), json!({}));
            assert_eq!(stopped["success"], true, "cycle {cycle}: {stopped}");
            original.send(&[cycle]).unwrap();
            let mut received = [0_u8; 1];
            assert_eq!(peer.recv(&mut received).unwrap(), 1);
            assert_eq!(received, [cycle]);
            let instance_state = state(&instance_id);
            assert_eq!(instance_state["data"]["state"], "stopped");
            assert_eq!(instance_state["data"]["lastError"], "");
            let controller = registry().instance(&instance_id).unwrap();
            let inner = lock(&controller.inner);
            assert!(inner.prepared.is_none());
            assert!(inner.engine.is_none());
            assert!(inner.tun_lease.is_none());
        }
        destroy_instance(&instance_id);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn repeated_create_run_stop_destroy_leaves_registry_idle() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let config_yaml = http_config(free_ports(1)[0]);

        for cycle in 0..20 {
            let instance_id = create_instance();
            let prepared = request(
                "prepare",
                Some(&instance_id),
                json!({"configYaml": &config_yaml}),
            );
            assert_eq!(prepared["success"], true, "cycle {cycle}: {prepared}");
            let started = request("start", Some(&instance_id), json!({}));
            assert_eq!(started["success"], true, "cycle {cycle}: {started}");
            let stopped = request("stop", Some(&instance_id), json!({}));
            assert_eq!(stopped["success"], true, "cycle {cycle}: {stopped}");
            destroy_instance(&instance_id);
            assert_failure(&state(&instance_id));
            assert!(lock(&registry().inner).instance.is_none());
            let platform = lock(&registry().platform);
            assert_eq!(platform.tun_owner, None);
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn public_lifecycle_is_singleton_until_destroyed() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let port = free_ports(1)[0];
        let config_yaml = http_config(port);
        let first = create_instance();

        let rejected = request("createInstance", None, json!({}));
        assert_failure(&rejected);
        assert!(
            rejected["error"]
                .as_str()
                .unwrap()
                .contains("public lifecycle instance already exists")
        );

        let prepared = request("prepare", Some(&first), json!({"configYaml": config_yaml}));
        assert_eq!(prepared["success"], true, "{prepared}");
        let started = request("start", Some(&first), json!({}));
        assert_eq!(started["success"], true, "{started}");
        probe_http_listener(port);
        assert_eq!(request("stop", Some(&first), json!({}))["success"], true);

        assert_failure(&request("createInstance", None, json!({})));
        destroy_instance(&first);
        let replacement = create_instance();
        assert!(parse_instance_id(&replacement).unwrap() > parse_instance_id(&first).unwrap());
        destroy_instance(&replacement);
    }

    #[test]
    fn same_instance_command_is_fail_fast() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let instance_id = create_instance();
        let controller = registry().instance(&instance_id).unwrap();
        let command = lock(&controller.command);
        let response = request("stop", Some(&instance_id), json!({}));
        assert_failure(&response);
        assert!(response["error"].as_str().unwrap().contains("is busy"));
        drop(command);
        destroy_instance(&instance_id);
    }

    #[test]
    fn android_protector_is_required_only_for_tun() {
        assert!(select_android_protector(false, None).unwrap().is_none());

        let missing = match select_android_protector(true, None) {
            Ok(_) => panic!("TUN must reject a missing Android protector"),
            Err(error) => error,
        };
        assert!(missing.message.contains("required for a TUN configuration"));

        let registered: Arc<dyn SocketProtector> = Arc::new(AcceptingProtector);
        let selected = select_android_protector(true, Some(&registered)).unwrap();
        assert!(selected.is_some());
        assert!(Arc::ptr_eq(&selected.unwrap(), &registered));

        assert!(ensure_android_protector_replaceable(None).is_ok());
        assert!(ensure_android_protector_replaceable(Some(7)).is_err());
    }

    #[test]
    fn tun_lease_is_held_from_prepare_until_stop_or_destroy() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let instance_id = create_instance();
        let payload = json!({"configYaml": tun_config()});

        assert_eq!(
            request("prepare", Some(&instance_id), payload.clone())["success"],
            true
        );
        assert_eq!(
            lock(&registry().platform).tun_owner,
            Some(parse_instance_id(&instance_id).unwrap())
        );

        assert_eq!(
            request("stop", Some(&instance_id), json!({}))["success"],
            true
        );
        assert_eq!(lock(&registry().platform).tun_owner, None);
        assert_eq!(
            request("prepare", Some(&instance_id), payload)["success"],
            true
        );
        destroy_instance(&instance_id);
        assert_eq!(lock(&registry().platform).tun_owner, None);
    }

    #[test]
    fn panic_recovery_releases_the_public_tun_lease() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let instance_id = create_instance();
        let payload = json!({"configYaml": tun_config()});

        assert_eq!(
            request("prepare", Some(&instance_id), payload.clone())["success"],
            true
        );
        let controller = registry().instance(&instance_id).unwrap();
        let result = invoke_instance_guarded(&controller, || -> Result<(), InvokeFailure> {
            panic!("test panic while holding a TUN lease")
        });
        assert!(result.unwrap_err().message.contains("panic caught"));
        assert_eq!(state(&instance_id)["data"]["state"], "stopped");
        assert_eq!(lock(&registry().platform).tun_owner, None);
        assert_eq!(
            request("prepare", Some(&instance_id), payload)["success"],
            true
        );
        assert_eq!(
            request("stop", Some(&instance_id), json!({}))["success"],
            true
        );
        destroy_instance(&instance_id);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn panic_recovery_preserves_the_public_generation_until_destroy() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let config_yaml = http_config(free_ports(1)[0]);
        let first = create_instance();
        assert_eq!(
            request("prepare", Some(&first), json!({"configYaml": config_yaml}),)["success"],
            true
        );
        assert_eq!(request("start", Some(&first), json!({}))["success"], true);
        assert_eq!(state(&first)["data"]["state"], "running");

        let first_controller = registry().instance(&first).unwrap();
        let result = invoke_instance_guarded(&first_controller, || -> Result<(), InvokeFailure> {
            panic!("test panic")
        });
        assert!(result.unwrap_err().message.contains("panic caught"));
        let first_state = state(&first);
        assert_eq!(first_state["data"]["state"], "stopped");
        assert!(
            first_state["data"]["lastError"]
                .as_str()
                .unwrap()
                .contains("panic caught")
        );
        let first_inner = lock(&first_controller.inner);
        assert!(first_inner.engine.is_none());
        drop(first_inner);
        assert_failure(&request("createInstance", None, json!({})));

        destroy_instance(&first);
        assert!(first_controller.tombstoned.load(Ordering::Acquire));
        assert!(first_controller.stop().is_err());
        assert!(registry().instance(&first).is_err());
        let replacement = create_instance();
        assert!(parse_instance_id(&replacement).unwrap() > parse_instance_id(&first).unwrap());
        destroy_instance(&replacement);
    }

    #[test]
    fn admitted_destroy_panic_is_still_a_terminal_registry_barrier() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let instance_id = create_instance();
        let controller = registry().instance(&instance_id).unwrap();

        let result = invoke_instance_guarded(&controller, || {
            controller.destroy_with(|| -> Result<(), InvokeFailure> {
                panic!("test panic during destroy cleanup")
            })
        });

        assert!(result.unwrap_err().message.contains("panic caught"));
        assert!(controller.tombstoned.load(Ordering::Acquire));
        assert!(registry().instance(&instance_id).is_err());
        reset_registry();
    }

    #[test]
    fn concurrent_create_allows_exactly_one_public_instance() {
        const CONCURRENT: usize = 12;

        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let barrier = Arc::new(Barrier::new(CONCURRENT + 1));
        let threads: Vec<_> = (0..CONCURRENT)
            .map(|_| {
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    request("createInstance", None, json!({}))
                })
            })
            .collect();
        barrier.wait();
        let responses: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        let successes: Vec<_> = responses
            .iter()
            .filter(|response| response["success"] == true)
            .collect();
        assert_eq!(successes.len(), 1, "{responses:?}");
        for response in responses
            .iter()
            .filter(|response| response["success"] == false)
        {
            assert!(
                response["error"]
                    .as_str()
                    .unwrap()
                    .contains("public lifecycle instance already exists"),
                "{response}"
            );
        }
        let first = successes[0]["data"]["instanceId"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(parse_instance_id(&first).unwrap(), 0);
        destroy_instance(&first);

        let replacement = create_instance();
        assert!(parse_instance_id(&replacement).unwrap() > parse_instance_id(&first).unwrap());
        destroy_instance(&replacement);
    }

    #[test]
    fn error_text_is_bounded_without_breaking_utf8() {
        let error = bounded_error("界".repeat(MAX_ERROR_BYTES));
        assert!(error.len() <= MAX_ERROR_BYTES);
        assert!(error.ends_with("..."));
    }

    fn assert_registry_is_idle() {
        assert!(lock(&registry().inner).instance.is_none());
        let platform = lock(&registry().platform);
        assert_eq!(platform.tun_owner, None);
    }
}
