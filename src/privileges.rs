use crate::err::Error;

use winapi::{
    shared::{minwindef::FALSE, ntdef::LUID, winerror},
    um::{
        errhandlingapi as ehapi,
        processthreadsapi::{GetCurrentProcess, OpenProcessToken},
        securitybaseapi::AdjustTokenPrivileges,
        winbase::LookupPrivilegeValueA,
        winnt,
    },
};

use std::{convert::TryInto as _, ffi::CString, mem, ptr};

fn lookup_priv_id(name: &'static str) -> Result<LUID, Error> {
    let priv_name = CString::new(name)?;
    let mut priv_id = LUID::default();
    let success = unsafe { LookupPrivilegeValueA(ptr::null(), priv_name.as_ptr(), &mut priv_id) };

    if success == 0 {
        let err = unsafe { ehapi::GetLastError() };
        return Err(Error::LookupPrivilegeValueFailed(err));
    }

    Ok(priv_id)
}

pub fn has_sufficient_privileges() -> Result<bool, Error> {
    let my_token = {
        let my_process = unsafe { GetCurrentProcess() };
        let mut token = ptr::null_mut();
        let success =
            unsafe { OpenProcessToken(my_process, winnt::TOKEN_ADJUST_PRIVILEGES, &mut token) };

        if success == 0 {
            let err = unsafe { ehapi::GetLastError() };
            return Err(Error::GetSelfProcessTokenFailed(err));
        }

        token
    };

    let mut backup_token_privs = winnt::TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [winnt::LUID_AND_ATTRIBUTES {
            Luid: lookup_priv_id(winnt::SE_BACKUP_NAME)?,
            Attributes: winnt::SE_PRIVILEGE_ENABLED,
        }],
    };
    let mut restore_token_privs = winnt::TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [winnt::LUID_AND_ATTRIBUTES {
            Luid: lookup_priv_id(winnt::SE_RESTORE_NAME)?,
            Attributes: winnt::SE_PRIVILEGE_ENABLED,
        }],
    };

    // We call adjust twice since it's easier than hacking together memory
    // to form a C-style array.

    let success = unsafe {
        AdjustTokenPrivileges(
            my_token,
            FALSE,
            &mut backup_token_privs,
            mem::size_of::<winnt::TOKEN_PRIVILEGES>()
                .try_into()
                .unwrap(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    let errcode = unsafe { ehapi::GetLastError() };
    if success == 0 {
        return Err(Error::AdjustTokenPrivilegesFailed(errcode));
    } else if errcode != winerror::ERROR_SUCCESS {
        // If we don't have permissions, the function returns success
        // and sets the last error to ERROR_NOT_ALL_ASSIGNED. Let's be
        // more defensive and assume any non-ERROR_SUCCESS means no permissions.
        return Ok(false);
    }

    let success = unsafe {
        AdjustTokenPrivileges(
            my_token,
            FALSE,
            &mut restore_token_privs,
            mem::size_of::<winnt::TOKEN_PRIVILEGES>()
                .try_into()
                .unwrap(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    let errcode = unsafe { ehapi::GetLastError() };
    if success == 0 {
        return Err(Error::AdjustTokenPrivilegesFailed(errcode));
    } else if errcode != winerror::ERROR_SUCCESS {
        return Ok(false);
    }

    Ok(true)
}
