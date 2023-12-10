use pam::Conversation;
use pam_bindings::{
    constants::{
        PamFlag, PamResultCode, PAM_ERROR_MSG, PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON,
        PAM_TEXT_INFO,
    },
    conv::Conv,
    items::AuthTok,
    module::{PamHandle, PamHooks},
};
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::unix::thread::JoinHandleExt;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{RecvError, SendError, Sender},
    Arc, Mutex,
};
use std::thread::{JoinHandle, ThreadId};
use std::{
    collections::{HashMap, HashSet},
    ffi::IntoStringError,
};
mod conv;

struct PamHttp;
pam_bindings::pam_hooks!(PamHttp);

struct PomConversation {
    layer: String,
    tx_result: Sender<CrossMessage>,
}

type PromptCallback = Sender<CString>;

#[derive(Debug)]
enum CrossMessage {
    PamResult(String, PamResultCode),
    Prompt(String, CString, PromptCallback),
    PromptBlind(String, CString, PromptCallback),
    Info(String, CString),
    Error(String, CString),
}

struct ConvWrapper<'a>(Conv<'a>);

unsafe impl<'a> Send for ConvWrapper<'a> {}

impl Conversation for PomConversation {
    fn prompt_echo(&mut self, msg: &CStr) -> Result<CString, ()> {
        let (tx, rx) = std::sync::mpsc::channel();
        // println!("Prompt echo {}", self.layer);
        self.tx_result
            .send(CrossMessage::Prompt(self.layer.clone(), msg.into(), tx))
            .unwrap();
        rx.recv().map_err(|_| ())
    }
    fn prompt_blind(&mut self, msg: &CStr) -> Result<CString, ()> {
        let (tx, rx) = std::sync::mpsc::channel();
        // println!("Prompt blind {}", self.layer);
        self.tx_result
            .send(CrossMessage::PromptBlind(
                self.layer.clone(),
                msg.into(),
                tx,
            ))
            .unwrap();
        rx.recv().map_err(|_| ())
    }
    fn info(&mut self, msg: &CStr) {
        // println!("info {}", self.layer);
        self.tx_result
            .send(CrossMessage::Info(self.layer.clone(), msg.into()))
            .unwrap();
    }
    fn error(&mut self, msg: &CStr) {
        // println!("error {}", self.layer);
        self.tx_result
            .send(CrossMessage::Error(self.layer.clone(), msg.into()))
            .unwrap();
    }
}

struct JoinWrapper(JoinHandle<()>);
impl Drop for JoinWrapper {
    fn drop(&mut self) {
        // eprintln!("Trying to cancel!");
        let rc = unsafe { libc::pthread_kill(self.0.as_pthread_t(), libc::SIGUSR1) };
        if rc != 0 {
            eprintln!("PamPom failed to cancel a layer: {rc}");
            panic!("PamPom failed to cancel a layer: {rc}");
        }
        // std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

extern "C" fn sigusr_handler(_sig: libc::c_int) {
    if MAIN_THREADS
        .lock()
        .unwrap()
        .contains(&std::thread::current().id())
    {
        eprintln!("\n\n\nIgnoring a SIGUSR on main thread... How'd this get installed on here anyways?\n\n\n");
        return;
    }
    // eprintln!("Please stop!");
    // panic!("trying to kill this thread forcefully!");
    std::panic::resume_unwind(Box::new(0));
}

#[derive(Debug)]
enum IoThreadError {
    RecvError(RecvError),
    SendError,
    IntoStringError(IntoStringError),
    PamResultCode(PamResultCode),
}

impl fmt::Display for IoThreadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IoThreadError")
    }
}
impl std::error::Error for IoThreadError {}

impl From<RecvError> for IoThreadError {
    fn from(recv_error: RecvError) -> Self {
        IoThreadError::RecvError(recv_error)
    }
}

impl<T> From<SendError<T>> for IoThreadError {
    fn from(_: SendError<T>) -> Self {
        IoThreadError::SendError
    }
}

impl From<IntoStringError> for IoThreadError {
    fn from(error: IntoStringError) -> Self {
        IoThreadError::IntoStringError(error)
    }
}

impl From<PamResultCode> for IoThreadError {
    fn from(error: PamResultCode) -> Self {
        IoThreadError::PamResultCode(error)
    }
}

lazy_static::lazy_static! {
    static ref MAIN_THREADS: Arc<Mutex<HashSet<ThreadId>>> = Arc::new(Mutex::new(HashSet::new()));
}

struct MainThreadDropper;
impl Drop for MainThreadDropper {
    fn drop(&mut self) {
        // println!("Dropping the main thread!");
        MAIN_THREADS
            .lock()
            .unwrap()
            .remove(&std::thread::current().id());
    }
}

struct NewlineDropper {
    is_prompting: AtomicBool,
}

impl Drop for NewlineDropper {
    fn drop(&mut self) {
        if self.is_prompting.load(Ordering::Relaxed) {
            println!();
        }
    }
}

impl PamHooks for PamHttp {
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        MAIN_THREADS
            .lock()
            .unwrap()
            .insert(std::thread::current().id());
        let _main_thread_dropper = MainThreadDropper;
        let is_prompting = NewlineDropper {
            is_prompting: AtomicBool::new(false),
        };
        let username = match pamh.get_user(None) {
            Ok(username) => username,
            Err(err) => return err,
        };
        let (tx_result, rx_result) = std::sync::mpsc::channel();
        let mut map: HashMap<String, JoinWrapper> = HashMap::new();

        let auth_tok = pamh
            .get_item::<AuthTok>()
            .unwrap()
            .map(|s| CString::new(s.0.to_bytes()).unwrap());
        let old_auth_tok = pamh
            .get_item::<pam_bindings::items::OldAuthTok>()
            .unwrap()
            .map(|s| CString::new(s.0.to_bytes()).unwrap());
        let rhost = pamh
            .get_item::<pam_bindings::items::RHost>()
            .unwrap()
            .map(|s| CString::new(s.0.to_bytes()).unwrap());
        let ruser = pamh
            .get_item::<pam_bindings::items::RUser>()
            .unwrap()
            .map(|s| CString::new(s.0.to_bytes()).unwrap());
        // let service = pamh
        //     .get_item::<pam_bindings::items::Service>()
        //     .unwrap()
        //     .map(|s| CString::new(s.0.to_bytes()).unwrap());
        let tty = pamh
            .get_item::<pam_bindings::items::Tty>()
            .unwrap()
            .map(|s| CString::new(s.0.to_bytes()).unwrap());
        let user = pamh
            .get_item::<pam_bindings::items::User>()
            .unwrap()
            .map(|s| CString::new(s.0.to_bytes()).unwrap());
        let user_prompt = pamh
            .get_item::<pam_bindings::items::UserPrompt>()
            .unwrap()
            .map(|s| CString::new(s.0.to_bytes()).unwrap());

        for layer in args
            .iter()
            .map(|s| s.to_string_lossy())
            .filter_map(|s| s.strip_prefix("layer=").map(|s| s.to_string()))
            .collect::<Vec<_>>()
        {
            let tx_result = tx_result.clone();
            let username = username.clone();
            let join_handle = {
                let auth_tok = auth_tok.clone();
                let old_auth_tok = old_auth_tok.clone();
                let rhost = rhost.clone();
                let ruser = ruser.clone();
                // let service = service.clone();
                let tty = tty.clone();
                let user = user.clone();
                let user_prompt = user_prompt.clone();

                let layer = layer.clone();
                std::thread::Builder::new()
                    .name(format!("pampom_layer_{layer}"))
                    .spawn(move || {
                        unsafe {
                            libc::signal(libc::SIGUSR1, sigusr_handler as libc::sighandler_t);
                        }

                        let mut conversation = PomConversation {
                            layer: layer.clone(),
                            tx_result: tx_result.clone(),
                        };
                        let conv = conv::into_pam_conv(&mut conversation);
                        let pam_handle = pam::start(&layer, Some(&username), &conv).unwrap();

                        if let Some(auth_tok) = auth_tok {
                            pam::set_item(pam_handle, pam::PamItemType::AuthTok, unsafe {
                                &*(auth_tok.as_ptr() as *const libc::c_void)
                            })
                            .unwrap();
                        }
                        if let Some(old_auth_tok) = old_auth_tok {
                            pam::set_item(pam_handle, pam::PamItemType::OldAuthTok, unsafe {
                                &*(old_auth_tok.as_ptr() as *const libc::c_void)
                            })
                            .unwrap();
                        }
                        if let Some(rhost) = rhost {
                            pam::set_item(pam_handle, pam::PamItemType::RHost, unsafe {
                                &*(rhost.as_ptr() as *const libc::c_void)
                            })
                            .unwrap();
                        }
                        if let Some(ruser) = ruser {
                            pam::set_item(pam_handle, pam::PamItemType::RUser, unsafe {
                                &*(ruser.as_ptr() as *const libc::c_void)
                            })
                            .unwrap();
                        }
                        // if let Some(service) = service {
                        //     pam::set_item(pam_handle, pam::PamItemType::Service, unsafe {
                        //         &*(service.as_ptr() as *const libc::c_void)
                        //     })
                        //     .unwrap();
                        // }
                        if let Some(tty) = tty {
                            pam::set_item(pam_handle, pam::PamItemType::TTY, unsafe {
                                &*(tty.as_ptr() as *const libc::c_void)
                            })
                            .unwrap();
                        }
                        if let Some(user) = user {
                            pam::set_item(pam_handle, pam::PamItemType::User, unsafe {
                                &*(user.as_ptr() as *const libc::c_void)
                            })
                            .unwrap();
                        }
                        if let Some(user_prompt) = user_prompt {
                            pam::set_item(pam_handle, pam::PamItemType::User_Prompt, unsafe {
                                &*(user_prompt.as_ptr() as *const libc::c_void)
                            })
                            .unwrap();
                        }

                        let return_code = pam::authenticate(pam_handle, (flags as i32).into());
                        let return_code = convert_return_code(return_code);
                        tx_result
                            .send(CrossMessage::PamResult(layer.clone(), return_code))
                            .ok();
                    })
                    .unwrap()
            };
            map.insert(layer.clone(), JoinWrapper(join_handle));
        }
        std::mem::drop(tx_result);

        let (tx_new, rx_new) = std::sync::mpsc::channel();
        let conv = pamh.get_item::<Conv>().unwrap().expect("No conv available");
        let conv = Arc::new(Mutex::new(ConvWrapper(conv)));

        let _io_join = JoinWrapper(
            std::thread::Builder::new()
                .name("pampom_io".to_string())
                .spawn(move || {
                    unsafe {
                        libc::signal(libc::SIGUSR1, sigusr_handler as libc::sighandler_t);
                    }
                    let conv = &conv.lock().unwrap().0;
                    let message_handler = move |conv: &Conv<'_>| {
                        let message = rx_new.recv()?;

                        match message {
                            CrossMessage::Info(layer, msg) => {
                                let msg = msg.into_string()?;
                                conv.send(PAM_TEXT_INFO, &format!("[{layer}] {msg}"))?;
                            }
                            CrossMessage::Error(layer, msg) => {
                                let msg = msg.into_string()?;
                                conv.send(PAM_ERROR_MSG, &format!("[{layer}] {msg}"))?;
                            }
                            CrossMessage::Prompt(layer, prompt, cb) => {
                                let prompt = prompt.into_string()?;
                                is_prompting.is_prompting.store(true, Ordering::Relaxed);
                                match conv.send(PAM_PROMPT_ECHO_ON, &format!("[{layer}] {prompt}"))
                                {
                                    Ok(Some(response)) => {
                                        is_prompting.is_prompting.store(false, Ordering::Relaxed);
                                        cb.send(response.into())?
                                    }
                                    Ok(None) | Err(PamResultCode::PAM_CONV_ERR) => {}
                                    Err(err) => {
                                        eprintln!("Got error: {err:?}");
                                    }
                                }
                            }
                            CrossMessage::PromptBlind(layer, prompt, cb) => {
                                let prompt = prompt.into_string().unwrap();
                                is_prompting.is_prompting.store(true, Ordering::Relaxed);
                                match conv.send(PAM_PROMPT_ECHO_OFF, &format!("[{layer}] {prompt}"))
                                {
                                    Ok(Some(response)) => {
                                        is_prompting.is_prompting.store(false, Ordering::Relaxed);
                                        cb.send(response.into())?
                                    }
                                    Ok(None) | Err(PamResultCode::PAM_CONV_ERR) => {}
                                    Err(err) => {
                                        eprintln!("Got error: {err:?}");
                                    }
                                }
                            }
                            CrossMessage::PamResult(_, _) => unreachable!(),
                        };
                        Ok(()) as Result<(), IoThreadError>
                    };
                    loop {
                        if message_handler(conv).is_err() {
                            break;
                        }
                    }
                })
                .unwrap(),
        );

        let mut highest_priority_error = PamResultCode::PAM_IGNORE;
        loop {
            let message = match rx_result.recv() {
                Ok(message) => message,
                Err(_) => {
                    // println!("All our senders dropped, bailing!");
                    return highest_priority_error;
                }
            };
            // println!("Got this message: {message:?}");

            match message {
                CrossMessage::PamResult(_layer, result_code) => {
                    // println!("Got a return code from {layer}! {result_code:?}");
                    if result_code == PamResultCode::PAM_SUCCESS {
                        std::mem::drop(map);
                        std::mem::drop(_io_join);
                        return result_code;
                    }
                    highest_priority_error = result_code;
                }

                message => tx_new.send(message).unwrap(),
            }
        }
    }
}

fn convert_return_code(old: pam::PamReturnCode) -> pam_bindings::constants::PamResultCode {
    use pam::PamReturnCode::*;
    use pam_bindings::constants::PamResultCode::*;
    match old {
        System_Err => PAM_SYSTEM_ERR,
        Success => PAM_SUCCESS,
        Open_Err => PAM_OPEN_ERR,
        Symbol_Err => PAM_SYMBOL_ERR,
        Service_Err => PAM_SERVICE_ERR,
        Buf_Err => PAM_BUF_ERR,
        Perm_Denied => PAM_PERM_DENIED,
        Auth_Err => PAM_AUTH_ERR,
        Cred_Insufficient => PAM_CRED_INSUFFICIENT,
        Authinfo_Unavail => PAM_AUTHINFO_UNAVAIL,
        User_Unknown => PAM_USER_UNKNOWN,
        MaxTries => PAM_MAXTRIES,
        New_Authtok_Reqd => PAM_NEW_AUTHTOK_REQD,
        Acct_Expired => PAM_ACCT_EXPIRED,
        Session_Err => PAM_SESSION_ERR,
        Cred_Unavail => PAM_CRED_UNAVAIL,
        Cred_Expired => PAM_CRED_EXPIRED,
        Cred_Err => PAM_CRED_ERR,
        No_Module_Data => PAM_NO_MODULE_DATA,
        Conv_Err => PAM_CONV_ERR,
        AuthTok_Err => PAM_AUTHTOK_ERR,
        AuthTok_Recovery_Err => PAM_AUTHTOK_RECOVERY_ERR,
        AuthTok_Lock_Busy => PAM_AUTHTOK_LOCK_BUSY,
        AuthTok_Disable_Aging => PAM_AUTHTOK_DISABLE_AGING,
        Try_Again => PAM_TRY_AGAIN,
        Ignore => PAM_IGNORE,
        AuthTok_Expired => PAM_AUTHTOK_EXPIRED,
        Abort => PAM_ABORT,
        Module_Unknown => PAM_MODULE_UNKNOWN,
        Bad_Item => PAM_BAD_ITEM,
        Conv_Again => PAM_CONV_AGAIN,
        Incomplete => PAM_INCOMPLETE,
    }
}
