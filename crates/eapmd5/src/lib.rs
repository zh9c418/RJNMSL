//! EapHost EAP-MD5 (RFC 3748 Type 4) peer method.
//!
//! Windows removed Microsoft's own EAP-MD5 implementation after Vista, but the
//! EapHost peer-method framework still allows third-party Type-4 methods. This
//! DLL plugs into Windows' native 802.1X supplicant (`dot3svc` / OneX), so the
//! EAPOL frames are handled entirely by Windows — no packet-capture driver
//! (Npcap/WinPcap/WinDivert) is involved.
//!
//! Registration (see register.bat):
//!   HKLM\SYSTEM\CurrentControlSet\Services\EapHost\Methods\<AuthorId>\4
//!
//! Only the MD5 math and a tiny state machine live here; everything else is
//! EapHost glue.

#![allow(non_snake_case, non_camel_case_types, clippy::missing_safety_doc)]

use std::ffi::c_void;
use std::ptr;

type BYTE = u8;
type DWORD = u32;
type BOOL = i32;
type LPWSTR = *mut u16;
type HANDLE = *mut c_void;
type EAP_SESSION_HANDLE = *mut c_void;

const ERROR_SUCCESS: DWORD = 0;
const ERROR_INVALID_PARAMETER: DWORD = 87;
const ERROR_INSUFFICIENT_BUFFER: DWORD = 122;

const EAP_TYPE_MD5: u8 = 4;

/// Our method author id (must match the registry path and the profile XML).
pub const AUTHOR_ID: DWORD = 0xC0DE;

// EapCode
const EAP_CODE_REQUEST: u8 = 1;
const EAP_CODE_RESPONSE: u8 = 2;

// EapPeerMethodResponseAction
const ACTION_DISCARD: u32 = 0;
const ACTION_SEND: u32 = 1;
const ACTION_NONE: u32 = 5;

// EapPeerMethodResultReason
const RESULT_REASON_SUCCESS: u32 = 2;

// ---------------------------------------------------------------------------
// Win32 heap (the returned buffers are freed by EapHost via EapPeerFreeMemory)
// ---------------------------------------------------------------------------

#[link(name = "kernel32")]
extern "system" {
    fn GetProcessHeap() -> HANDLE;
    fn HeapAlloc(h_heap: HANDLE, flags: DWORD, bytes: usize) -> *mut c_void;
    fn HeapFree(h_heap: HANDLE, flags: DWORD, mem: *mut c_void) -> BOOL;
}

unsafe fn heap_alloc(bytes: usize) -> *mut c_void {
    HeapAlloc(GetProcessHeap(), 0, bytes)
}

// ---------------------------------------------------------------------------
// EapHost types (from eapmethodpeerapis.h / eaptypes.h / eapmethodtypes.h)
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct EapType {
    pub type_: BYTE,
    pub dw_vendor_id: DWORD,
    pub dw_vendor_type: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Guid {
    d1: u32,
    d2: u16,
    d3: u16,
    d4: [u8; 8],
}

#[repr(C)]
pub struct EapMethodType {
    eap_type: EapType,
    dw_author_id: DWORD,
}

#[repr(C)]
pub struct EapError {
    dw_win_error: DWORD,
    type_: EapMethodType,
    dw_reason_code: DWORD,
    root_cause_guid: Guid,
    repair_guid: Guid,
    help_link_guid: Guid,
    p_root_cause_string: LPWSTR,
    p_repair_string: LPWSTR,
}

#[repr(C)]
pub struct EapAttribute {
    ea_type: DWORD,
    dw_length: DWORD,
    p_value: *mut BYTE,
}

#[repr(C)]
pub struct EapAttributes {
    dw_number_of_attributes: DWORD,
    p_attribs: *mut EapAttribute,
}

/// Variable-length on the wire: Code, Id, Length[2], Data[].
#[repr(C)]
pub struct EapPacket {
    pub code: BYTE,
    pub id: BYTE,
    pub length: [BYTE; 2],
    pub data: [BYTE; 1],
}

#[repr(C)]
pub struct EapPeerMethodOutput {
    action: u32,
    f_allow_notifications: BOOL,
}

#[repr(C)]
pub struct NgcTicketContext {
    wsz_ticket: [u16; 45],
    h_key: usize,
}

#[repr(C)]
pub struct EapPeerMethodResult {
    f_is_success: BOOL,
    dw_failure_reason_code: DWORD,
    f_save_connection_data: BOOL,
    dw_sizeof_connection_data: DWORD,
    p_connection_data: *mut BYTE,
    f_save_user_data: BOOL,
    dw_sizeof_user_data: DWORD,
    p_user_data: *mut BYTE,
    p_attrib_array: *mut EapAttributes,
    p_eap_error: *mut EapError,
    p_ngc_kerb_ticket: *mut NgcTicketContext,
    f_save_to_cred_man: BOOL,
}

// function-pointer aliases
type FnInitialize = unsafe extern "system" fn(*mut *mut EapError) -> DWORD;
type FnGetIdentity = unsafe extern "system" fn(
    DWORD,
    DWORD,
    *const BYTE,
    DWORD,
    *const BYTE,
    HANDLE,
    *mut BOOL,
    *mut DWORD,
    *mut *mut BYTE,
    *mut LPWSTR,
    *mut *mut EapError,
) -> DWORD;
type FnBeginSession = unsafe extern "system" fn(
    DWORD,
    *const EapAttributes,
    HANDLE,
    DWORD,
    *mut BYTE,
    DWORD,
    *mut BYTE,
    DWORD,
    *mut EAP_SESSION_HANDLE,
    *mut *mut EapError,
) -> DWORD;
type FnSetCredentials =
    unsafe extern "system" fn(EAP_SESSION_HANDLE, *mut u16, *mut u16, *mut *mut EapError) -> DWORD;
type FnProcessRequest = unsafe extern "system" fn(
    EAP_SESSION_HANDLE,
    DWORD,
    *mut EapPacket,
    *mut EapPeerMethodOutput,
    *mut *mut EapError,
) -> DWORD;
type FnGetResponse =
    unsafe extern "system" fn(EAP_SESSION_HANDLE, *mut DWORD, *mut EapPacket, *mut *mut EapError) -> DWORD;
type FnGetResult =
    unsafe extern "system" fn(EAP_SESSION_HANDLE, u32, *mut EapPeerMethodResult, *mut *mut EapError) -> DWORD;
type FnGetUIContext =
    unsafe extern "system" fn(EAP_SESSION_HANDLE, *mut DWORD, *mut *mut BYTE, *mut *mut EapError) -> DWORD;
type FnSetUIContext = unsafe extern "system" fn(
    EAP_SESSION_HANDLE,
    DWORD,
    *const BYTE,
    *mut EapPeerMethodOutput,
    *mut *mut EapError,
) -> DWORD;
type FnGetRespAttrs =
    unsafe extern "system" fn(EAP_SESSION_HANDLE, *mut EapAttributes, *mut *mut EapError) -> DWORD;
type FnSetRespAttrs = unsafe extern "system" fn(
    EAP_SESSION_HANDLE,
    *mut EapAttributes,
    *mut EapPeerMethodOutput,
    *mut *mut EapError,
) -> DWORD;
type FnEndSession = unsafe extern "system" fn(EAP_SESSION_HANDLE, *mut *mut EapError) -> DWORD;
type FnShutdown = unsafe extern "system" fn(*mut *mut EapError) -> DWORD;

#[repr(C)]
pub struct EapPeerMethodRoutines {
    dw_version: DWORD,
    p_eap_type: *mut EapType,
    eap_peer_initialize: Option<FnInitialize>,
    eap_peer_get_identity: Option<FnGetIdentity>,
    eap_peer_begin_session: Option<FnBeginSession>,
    eap_peer_set_credentials: Option<FnSetCredentials>,
    eap_peer_process_request_packet: Option<FnProcessRequest>,
    eap_peer_get_response_packet: Option<FnGetResponse>,
    eap_peer_get_result: Option<FnGetResult>,
    eap_peer_get_ui_context: Option<FnGetUIContext>,
    eap_peer_set_ui_context: Option<FnSetUIContext>,
    eap_peer_get_response_attributes: Option<FnGetRespAttrs>,
    eap_peer_set_response_attributes: Option<FnSetRespAttrs>,
    eap_peer_end_session: Option<FnEndSession>,
    eap_peer_shutdown: Option<FnShutdown>,
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

struct Session {
    identity: String,
    password: String,
    response: Vec<u8>,
}

impl Session {
    fn new() -> Session {
        Session {
            identity: String::new(),
            password: String::new(),
            response: Vec::new(),
        }
    }
}

unsafe fn session<'a>(h: EAP_SESSION_HANDLE) -> Option<&'a mut Session> {
    if h.is_null() {
        None
    } else {
        Some(&mut *(h as *mut Session))
    }
}

/// Allocate a NUL-terminated UTF-16 copy on the Win32 heap.
unsafe fn alloc_wide(s: &str) -> LPWSTR {
    let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = wide.len() * 2;
    let p = heap_alloc(bytes) as *mut u16;
    if p.is_null() {
        return ptr::null_mut();
    }
    ptr::copy_nonoverlapping(wide.as_ptr(), p, wide.len());
    p
}

unsafe fn clear_error(pp: *mut *mut EapError) {
    if !pp.is_null() {
        *pp = ptr::null_mut();
    }
}

unsafe fn wide_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *p.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(p, len);
    String::from_utf16_lossy(slice)
}

/// Build the EAP-Response/MD5 digest: MD5(Id | password | challenge).
fn md5_digest(id: u8, password: &[u8], challenge: &[u8]) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update([id]);
    h.update(password);
    h.update(challenge);
    let d = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d);
    out
}

// ---------------------------------------------------------------------------
// Exported EapHost peer-method functions
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "system" fn EapPeerGetInfo(
    p_eap_type: *mut EapType,
    p_eap_info: *mut EapPeerMethodRoutines,
    pp_eap_error: *mut *mut EapError,
) -> DWORD {
    clear_error(pp_eap_error);
    if p_eap_type.is_null() || p_eap_info.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    log_line(&format!("GetInfo type={}", (*p_eap_type).type_));
    if (*p_eap_type).type_ != EAP_TYPE_MD5 {
        return ERROR_INVALID_PARAMETER;
    }

    let info = &mut *p_eap_info;
    // Mirror the official SDK sample exactly: zero the struct, version 1,
    // pEapType NULL, and only ONE of GetIdentity / SetCredentials set.
    ptr::write_bytes(
        info as *mut EapPeerMethodRoutines as *mut u8,
        0,
        std::mem::size_of::<EapPeerMethodRoutines>(),
    );
    info.dw_version = 1;
    info.p_eap_type = ptr::null_mut();
    info.eap_peer_initialize = Some(EapPeerInitialize);
    info.eap_peer_get_identity = Some(EapPeerGetIdentity);
    info.eap_peer_begin_session = Some(EapPeerBeginSession);
    info.eap_peer_set_credentials = None; // GetIdentity XOR SetCredentials
    info.eap_peer_process_request_packet = Some(EapPeerProcessRequestPacket);
    info.eap_peer_get_response_packet = Some(EapPeerGetResponsePacket);
    info.eap_peer_get_result = Some(EapPeerGetResult);
    info.eap_peer_get_ui_context = Some(EapPeerGetUIContext);
    info.eap_peer_set_ui_context = Some(EapPeerSetUIContext);
    info.eap_peer_get_response_attributes = Some(EapPeerGetResponseAttributes);
    info.eap_peer_set_response_attributes = Some(EapPeerSetResponseAttributes);
    info.eap_peer_end_session = Some(EapPeerEndSession);
    info.eap_peer_shutdown = Some(EapPeerShutdown);
    log_line(&format!(
        "GetInfo filled: size={} init={:p} ident={:p} begin={:p} setcred=null",
        std::mem::size_of::<EapPeerMethodRoutines>(),
        EapPeerInitialize as *const (),
        EapPeerGetIdentity as *const (),
        EapPeerBeginSession as *const (),
    ));
    ERROR_SUCCESS
}


#[no_mangle]
pub unsafe extern "system" fn EapPeerInitialize(pp_eap_error: *mut *mut EapError) -> DWORD {
    clear_error(pp_eap_error);
    log_line("Initialize");
    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn EapPeerGetIdentity(
    _flags: DWORD,
    _dw_sizeof_connection_data: DWORD,
    _p_connection_data: *const BYTE,
    _dw_sizeof_user_data: DWORD,
    _p_user_data: *const BYTE,
    _h_token: HANDLE,
    pf_invoke_ui: *mut BOOL,
    pdw_size_of_user_data_out: *mut DWORD,
    pp_user_data_out: *mut *mut BYTE,
    ppwsz_identity: *mut LPWSTR,
    pp_eap_error: *mut *mut EapError,
) -> DWORD {
    clear_error(pp_eap_error);
    log_line("GetIdentity");
    // Prefer credentials from the local file so that no interactive UI (which is
    // unavailable in the service context) is required.
    let (identity, invoke_ui) = match load_cred() {
        Some((u, _)) => (Some(u), 0),
        None => (None, 1),
    };
    if !pf_invoke_ui.is_null() {
        *pf_invoke_ui = invoke_ui;
    }
    if !pdw_size_of_user_data_out.is_null() {
        *pdw_size_of_user_data_out = 0;
    }
    if !pp_user_data_out.is_null() {
        *pp_user_data_out = ptr::null_mut();
    }
    if !ppwsz_identity.is_null() {
        *ppwsz_identity = match identity {
            Some(u) => alloc_wide(&u),
            None => ptr::null_mut(),
        };
    }
    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn EapPeerBeginSession(
    _dw_flags: DWORD,
    _p_attribute_array: *const EapAttributes,
    _h_token: HANDLE,
    _dw_sizeof_connection_data: DWORD,
    _p_connection_data: *mut BYTE,
    _dw_sizeof_user_data: DWORD,
    _p_user_data: *mut BYTE,
    _dw_max_send_packet_size: DWORD,
    p_session_handle: *mut EAP_SESSION_HANDLE,
    pp_eap_error: *mut *mut EapError,
) -> DWORD {
    clear_error(pp_eap_error);
    if p_session_handle.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let mut s = Session::new();
    if let Some((u, p)) = load_cred() {
        s.identity = u;
        s.password = p;
    }
    log_line(&format!(
        "BeginSession identity={:?} has_pass={}",
        s.identity,
        !s.password.is_empty()
    ));
    let boxed = Box::into_raw(Box::new(s));
    *p_session_handle = boxed as EAP_SESSION_HANDLE;
    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn EapPeerSetCredentials(
    session_handle: EAP_SESSION_HANDLE,
    pwsz_identity: *mut u16,
    pwsz_password: *mut u16,
    pp_eap_error: *mut *mut EapError,
) -> DWORD {
    clear_error(pp_eap_error);
    let Some(s) = session(session_handle) else {
        return ERROR_INVALID_PARAMETER;
    };
    s.identity = wide_to_string(pwsz_identity);
    s.password = wide_to_string(pwsz_password);
    log_line(&format!(
        "SetCredentials identity={:?} password_len={}",
        s.identity,
        s.password.len()
    ));
    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn EapPeerProcessRequestPacket(
    session_handle: EAP_SESSION_HANDLE,
    cb_receive_packet: DWORD,
    p_receive_packet: *mut EapPacket,
    p_eap_output: *mut EapPeerMethodOutput,
    pp_eap_error: *mut *mut EapError,
) -> DWORD {
    clear_error(pp_eap_error);
    let Some(s) = session(session_handle) else {
        return ERROR_INVALID_PARAMETER;
    };
    if p_receive_packet.is_null() || p_eap_output.is_null() || cb_receive_packet < 5 {
        return ERROR_INVALID_PARAMETER;
    }

    let pkt = &*p_receive_packet;
    let out = &mut *p_eap_output;
    out.f_allow_notifications = 0;
    out.action = ACTION_DISCARD;

    if pkt.code != EAP_CODE_REQUEST {
        return ERROR_SUCCESS;
    }

    // Length field is big-endian and tells the true packet size.
    let eap_len = u16::from_be_bytes(pkt.length) as usize;
    let avail = (cb_receive_packet as usize).min(eap_len).max(5);
    let raw = std::slice::from_raw_parts(p_receive_packet as *const u8, avail);
    let eap_type = raw[4];
    let body = &raw[5..];

    log_line(&format!(
        "ProcessRequest id={} type={} body_len={}",
        pkt.id,
        eap_type,
        body.len()
    ));


    match eap_type {
        1 => {
            // EAP-Request/Identity
            let ident = s.identity.as_bytes();
            let mut resp = Vec::with_capacity(5 + ident.len());
            resp.push(EAP_CODE_RESPONSE);
            resp.push(pkt.id);
            let total = 5 + ident.len();
            resp.extend_from_slice(&(total as u16).to_be_bytes());
            resp.push(1); // Identity
            resp.extend_from_slice(ident);
            s.response = resp;
            out.action = ACTION_SEND;
        }
        4 => {
            // EAP-Request/MD5-Challenge: body = [value-size][challenge...][name]
            if body.is_empty() {
                return ERROR_SUCCESS;
            }
            let value_size = body[0] as usize;
            let challenge = &body[1..(1 + value_size).min(body.len())];
            let digest = md5_digest(pkt.id, s.password.as_bytes(), challenge);
            let mut resp = Vec::with_capacity(5 + 1 + 16);
            resp.push(EAP_CODE_RESPONSE);
            resp.push(pkt.id);
            let total = 5 + 1 + 16;
            resp.extend_from_slice(&(total as u16).to_be_bytes());
            resp.push(4); // MD5
            resp.push(16); // value-size
            resp.extend_from_slice(&digest);
            s.response = resp;
            out.action = ACTION_SEND;
        }
        _ => {
            out.action = ACTION_DISCARD;
        }
    }
    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn EapPeerGetResponsePacket(
    session_handle: EAP_SESSION_HANDLE,
    pcb_send_packet: *mut DWORD,
    p_send_packet: *mut EapPacket,
    pp_eap_error: *mut *mut EapError,
) -> DWORD {
    clear_error(pp_eap_error);
    let Some(s) = session(session_handle) else {
        return ERROR_INVALID_PARAMETER;
    };
    if pcb_send_packet.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let need = s.response.len();
    if need == 0 {
        *pcb_send_packet = 0;
        return ERROR_INVALID_PARAMETER;
    }
    if (*pcb_send_packet as usize) < need || p_send_packet.is_null() {
        *pcb_send_packet = need as DWORD;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    ptr::copy_nonoverlapping(s.response.as_ptr(), p_send_packet as *mut u8, need);
    *pcb_send_packet = need as DWORD;
    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn EapPeerGetResult(
    _session_handle: EAP_SESSION_HANDLE,
    reason: u32,
    p_result: *mut EapPeerMethodResult,
    pp_eap_error: *mut *mut EapError,
) -> DWORD {
    clear_error(pp_eap_error);
    if p_result.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let r = &mut *p_result;
    log_line(&format!("GetResult reason={reason}"));
    r.f_is_success = if reason == RESULT_REASON_SUCCESS { 1 } else { 0 };
    r.dw_failure_reason_code = 0;
    r.f_save_connection_data = 0;
    r.dw_sizeof_connection_data = 0;
    r.p_connection_data = ptr::null_mut();
    r.f_save_user_data = 0;
    r.dw_sizeof_user_data = 0;
    r.p_user_data = ptr::null_mut();
    r.p_attrib_array = ptr::null_mut();
    r.p_eap_error = ptr::null_mut();
    r.p_ngc_kerb_ticket = ptr::null_mut();
    r.f_save_to_cred_man = 0;
    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn EapPeerGetUIContext(
    _session_handle: EAP_SESSION_HANDLE,
    pdw_size_of_ui_context_data: *mut DWORD,
    pp_ui_context_data: *mut *mut BYTE,
    pp_eap_error: *mut *mut EapError,
) -> DWORD {
    clear_error(pp_eap_error);
    if !pdw_size_of_ui_context_data.is_null() {
        *pdw_size_of_ui_context_data = 0;
    }
    if !pp_ui_context_data.is_null() {
        *pp_ui_context_data = ptr::null_mut();
    }
    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn EapPeerSetUIContext(
    _session_handle: EAP_SESSION_HANDLE,
    _dw_size_of_ui_context_data: DWORD,
    _p_ui_context_data: *const BYTE,
    p_eap_output: *mut EapPeerMethodOutput,
    pp_eap_error: *mut *mut EapError,
) -> DWORD {
    clear_error(pp_eap_error);
    if !p_eap_output.is_null() {
        (*p_eap_output).action = ACTION_NONE;
        (*p_eap_output).f_allow_notifications = 0;
    }
    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn EapPeerGetResponseAttributes(
    _session_handle: EAP_SESSION_HANDLE,
    p_attribs: *mut EapAttributes,
    pp_eap_error: *mut *mut EapError,
) -> DWORD {
    clear_error(pp_eap_error);
    if !p_attribs.is_null() {
        (*p_attribs).dw_number_of_attributes = 0;
        (*p_attribs).p_attribs = ptr::null_mut();
    }
    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn EapPeerSetResponseAttributes(
    _session_handle: EAP_SESSION_HANDLE,
    _p_attribs: *mut EapAttributes,
    p_eap_output: *mut EapPeerMethodOutput,
    pp_eap_error: *mut *mut EapError,
) -> DWORD {
    clear_error(pp_eap_error);
    if !p_eap_output.is_null() {
        (*p_eap_output).action = ACTION_NONE;
        (*p_eap_output).f_allow_notifications = 0;
    }
    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn EapPeerEndSession(
    session_handle: EAP_SESSION_HANDLE,
    pp_eap_error: *mut *mut EapError,
) -> DWORD {
    clear_error(pp_eap_error);
    if !session_handle.is_null() {
        log_line("EndSession");
        drop(Box::from_raw(session_handle as *mut Session));
    }
    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn EapPeerShutdown(pp_eap_error: *mut *mut EapError) -> DWORD {
    clear_error(pp_eap_error);
    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn EapPeerFreeMemory(p: *mut c_void) {
    if !p.is_null() {
        HeapFree(GetProcessHeap(), 0, p);
    }
}

#[no_mangle]
pub unsafe extern "system" fn EapPeerFreeErrorMemory(_p: *mut EapError) {
    // We never allocate EAP_ERROR.
}

/// Copy `data` into a Win32-heap buffer that EapHost will free via EapPeerFreeMemory.
unsafe fn return_blob(data: &[u8], pp: *mut *mut BYTE, pdw: *mut DWORD) -> DWORD {
    let len = data.len().max(1);
    let p = heap_alloc(len) as *mut BYTE;
    if p.is_null() {
        return 8; // ERROR_NOT_ENOUGH_MEMORY
    }
    if !data.is_empty() {
        ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());
    }
    if !pp.is_null() {
        *pp = p;
    }
    if !pdw.is_null() {
        *pdw = data.len() as DWORD;
    }
    ERROR_SUCCESS
}

/// Convert the profile's configuration XML into a (dummy) config blob.
/// EAP-MD5 needs no configuration, so the content is irrelevant.
#[no_mangle]
pub unsafe extern "system" fn EapPeerConfigXml2Blob(
    _dw_flags: DWORD,
    _eap_method_type: EapMethodType,
    _p_config_doc: *mut c_void,
    pp_config_out: *mut *mut BYTE,
    pdw_size_of_config_out: *mut DWORD,
    pp_eap_error: *mut *mut EapError,
) -> DWORD {
    clear_error(pp_eap_error);
    log_line("ConfigXml2Blob");
    return_blob(b"md5cfg", pp_config_out, pdw_size_of_config_out)
}

/// Convert the credential XML into a (dummy) credential blob. This is what makes
/// `netsh lan set eapuserdata` succeed and OneX report "Credentials Configured: Yes".
/// The real username/password are read from [`CONF_PATH`].
#[no_mangle]
pub unsafe extern "system" fn EapPeerCredentialsXml2Blob(
    _dw_flags: DWORD,
    _eap_method_type: EapMethodType,
    _p_credentials_doc: *mut c_void,
    _p_config_in: *const BYTE,
    _dw_size_of_config_in: DWORD,
    pp_credentials_out: *mut *mut BYTE,
    pdw_size_of_credentials_out: *mut DWORD,
    pp_eap_error: *mut *mut EapError,
) -> DWORD {
    clear_error(pp_eap_error);
    log_line("CredentialsXml2Blob");
    return_blob(b"md5cred", pp_credentials_out, pdw_size_of_credentials_out)
}

// ---------------------------------------------------------------------------
// Credential loading + debug logging
// ---------------------------------------------------------------------------

/// Where the username/password live. Kept out of the repository; written by the
/// installer. Format:
/// ```text
/// username=<your 802.1X account>
/// password=<your password>
/// ```
pub const CONF_PATH: &str = "C:\\ProgramData\\RJNMSL\\eapmd5.ini";
const LOG_PATH: &str = "C:\\ProgramData\\RJNMSL\\eapmd5.log";
const CONF_DIR: &str = "C:\\ProgramData\\RJNMSL";

fn log_line(msg: &str) {
    use std::io::Write;
    let _ = std::fs::create_dir_all(CONF_DIR);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_PATH)
    {
        let _ = writeln!(f, "{msg}");
    }
}

/// Read `username=` / `password=` from [`CONF_PATH`].
fn load_cred() -> Option<(String, String)> {
    let text = std::fs::read_to_string(CONF_PATH).ok()?;
    let mut user = None;
    let mut pass = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            match k.trim().to_ascii_lowercase().as_str() {
                "username" | "identity" | "user" => user = Some(v.trim().to_string()),
                "password" | "pass" => pass = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }
    match (user, pass) {
        (Some(u), Some(p)) if !u.is_empty() => Some((u, p)),
        _ => None,
    }
}