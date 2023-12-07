use pam::Conversation;

use libc::{c_int, c_void, calloc, free, size_t, strdup};

use std::ffi::CStr;
use std::mem;

use pam::{ffi::pam_conv, PamMessage, PamMessageStyle, PamResponse, PamReturnCode};

pub(crate) fn into_pam_conv<C: Conversation>(conv: &mut C) -> pam_conv {
    pam_conv {
        conv: Some(converse::<C>),
        appdata_ptr: conv as *mut C as *mut c_void,
    }
}

// FIXME: verify this
pub(crate) unsafe extern "C" fn converse<C: Conversation>(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    out_resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int {
    // allocate space for responses
    let resp =
        calloc(num_msg as usize, mem::size_of::<PamResponse>() as size_t) as *mut PamResponse;
    if resp.is_null() {
        return PamReturnCode::Buf_Err as c_int;
    }

    let handler = &mut *(appdata_ptr as *mut C);

    let mut result: PamReturnCode = PamReturnCode::Success;
    for i in 0..num_msg as isize {
        // get indexed values
        // FIXME: check this
        let m: &mut PamMessage = &mut *(*(msg.offset(i)) as *mut PamMessage);
        let r: &mut PamResponse = &mut *(resp.offset(i));

        let msg = CStr::from_ptr(m.msg);
        // match on msg_style
        match PamMessageStyle::from(m.msg_style) {
            PamMessageStyle::Prompt_Echo_On => {
                if let Ok(handler_response) = handler.prompt_echo(msg) {
                    r.resp = strdup(handler_response.as_ptr());
                } else {
                    result = PamReturnCode::Conv_Err;
                }
            }
            PamMessageStyle::Prompt_Echo_Off => {
                if let Ok(handler_response) = handler.prompt_blind(msg) {
                    r.resp = strdup(handler_response.as_ptr());
                } else {
                    result = PamReturnCode::Conv_Err;
                }
            }
            PamMessageStyle::Text_Info => {
                handler.info(msg);
            }
            PamMessageStyle::Error_Msg => {
                handler.error(msg);
                result = PamReturnCode::Conv_Err;
            }
        }
        if result != PamReturnCode::Success {
            break;
        }
    }

    // free allocated memory if an error occured
    if result != PamReturnCode::Success {
        free(resp as *mut c_void);
    } else {
        *out_resp = resp;
    }

    result as c_int
}
