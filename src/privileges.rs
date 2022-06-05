use windows::Win32::{
    Foundation::{GetLastError, ERROR_SUCCESS, HANDLE, LUID},
    Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueA, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    },
    System::{
        SystemServices::{SE_BACKUP_NAME, SE_RESTORE_NAME},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

use crate::err::Error;

use std::{mem, ptr};

fn lookup_priv_id(name: &'static str) -> Result<LUID, Error> {
    let mut priv_id = LUID::default();
    unsafe { LookupPrivilegeValueA(None, name, &mut priv_id).ok() }
        .map(|_| priv_id)
        .map_err(|err| Error::LookupPrivilegeValueFailed(err.code()))
}

pub fn has_sufficient_privileges() -> Result<bool, Error> {
    let my_token = {
        let my_process = unsafe { GetCurrentProcess() };
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(my_process, TOKEN_ADJUST_PRIVILEGES, &mut token).ok() }
            .map_err(|err| Error::GetSelfProcessTokenFailed(err.code()))?;

        token
    };

    let backup_token_privs = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: lookup_priv_id(SE_BACKUP_NAME)?,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    let restore_token_privs = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: lookup_priv_id(SE_RESTORE_NAME)?,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    // We call adjust twice since it's easier than hacking together memory
    // to form a C-style array.

    for privilege in [backup_token_privs, restore_token_privs] {
        let result = unsafe {
            AdjustTokenPrivileges(
                my_token,
                false,
                &privilege,
                mem::size_of::<TOKEN_PRIVILEGES>().try_into().unwrap(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };

        // AdjustTokenPrivileges is weird. Even if it indicates success, we need
        // to GetLastError to determine if it *really* succeeded.
        let err_code = unsafe { GetLastError() };
        if result.as_bool() {
            if err_code != ERROR_SUCCESS {
                return Ok(false);
            }
        } else {
            return Err(Error::AdjustTokenPrivilegesFailed(err_code.into()));
        }
    }

    Ok(true)
}
