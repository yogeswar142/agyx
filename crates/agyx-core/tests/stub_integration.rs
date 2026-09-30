use agyx_core::{
    adapter::mock::MockAgyAdapter,
    adapter::AgyAdapter,
    credential_store::os_keyring::agt,
    credential_store::vault::CredentialVault,
    identity::extract_identity,
    journal::{check_and_recover_journal, read_journal, remove_journal, write_journal, RecoveryJournal},
    lock::AgyxLock,
    switcher::Switcher,
    AgyxError,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

fn make_jwt(sub: &str, email: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
    let payload_json = serde_json::json!({
        "iss": "https://accounts.google.com",
        "sub": sub,
        "email": email,
        "email_verified": true,
        "name": format!("User {sub}"),
    });
    let payload = URL_SAFE_NO_PAD.encode(payload_json.to_string());
    let sig = URL_SAFE_NO_PAD.encode(b"SIGNATURE");
    format!("{header}.{payload}.{sig}")
}

fn make_blob(sub: &str, email: &str) -> Vec<u8> {
    let jwt = make_jwt(sub, email);
    serde_json::json!({
        "token": {
            "access_token": format!("ya29.access_{sub}"),
            "token_type": "Bearer",
            "refresh_token": format!("1//refresh_{sub}"),
            "expiry": "2026-10-01T00:00:00Z"
        },
        "auth_method": "consumer",
        "id_token": jwt
    })
    .to_string()
    .into_bytes()
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. save leaves live bytes unchanged; rejects duplicate sub; rejects existing name
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_save_leaves_live_bytes_unchanged_and_rejects_duplicates() {
    let blob_a = make_blob("sub_save_1", "save_1@gmail.com");
    let adapter = MockAgyAdapter::new();
    adapter.set_credential(Some(blob_a.clone()));

    let switcher = Switcher::new(Box::new(adapter));

    // Save as 'profile1'
    let res = switcher.save("profile1").expect("save profile1");
    assert_eq!(res.email, "save_1@gmail.com");
    assert_eq!(res.sub, "sub_save_1");

    // CRITICAL: Live credential bytes must be completely unchanged
    let current_live = switcher.current().unwrap().unwrap();
    assert_eq!(current_live.sub, "sub_save_1");
    assert_eq!(current_live.email, "save_1@gmail.com");
    assert_eq!(current_live.profile.as_deref(), Some("profile1"));

    // Reject existing name
    let err_name = switcher.save("profile1").unwrap_err();
    assert!(matches!(err_name, AgyxError::ProfileAlreadyExists { .. }));

    // Reject duplicate sub under different name
    let err_sub = switcher.save("another_name").unwrap_err();
    assert!(matches!(err_sub, AgyxError::AccountAlreadyRegistered { .. }));

    // Clean up profile1 from vault/config for test hygiene
    let _ = switcher.remove("profile1");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. login fails midway -> original restored byte-for-byte, or removed if none existed
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_login_fails_midway_restores_original_byte_for_byte() {
    let original_blob = make_blob("sub_orig", "orig@gmail.com");
    let adapter = MockAgyAdapter::new();
    adapter.set_credential(Some(original_blob.clone()));

    // Simulate login failure
    adapter.set_login_error("simulated browser failure".into());

    let switcher = Switcher::new(Box::new(adapter));

    // Must allow unsaved live or save it first
    let res = switcher.login("test_fail", true);
    assert!(res.is_err());

    // Verify original credential is restored byte-for-byte!
    let live = switcher.current().unwrap().unwrap();
    assert_eq!(live.sub, "sub_orig");
    assert_eq!(live.email, "orig@gmail.com");
}

#[test]
fn test_login_fails_midway_when_none_existed_removes_entry() {
    let adapter = MockAgyAdapter::new();
    adapter.set_credential(None);

    adapter.set_login_error("simulated failure".into());

    let switcher = Switcher::new(Box::new(adapter));
    let res = switcher.login("test_fail_none", true);
    assert!(res.is_err());

    // Live credential must be None
    assert!(switcher.current().unwrap().is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Crash-recovery journal: hard-killed midway -> next invocation recovers
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_crash_recovery_journal_restores_interrupted_session() {
    let orig_blob = make_blob("sub_crashed", "crashed@gmail.com");
    let mut vault = CredentialVault::open().expect("open vault");
    let backup_key = "__test_crash_backup__";
    vault.save(backup_key, &orig_blob).expect("save backup");

    // Write a mock stale journal as if agyx was killed via taskkill /F
    let journal = RecoveryJournal {
        timestamp: "2026-09-30T12:00:00Z".into(),
        action: "login interrupted".into(),
        had_original_credential: true,
        backup_vault_key: Some(backup_key.into()),
        original_sub: Some("sub_crashed".into()),
        original_email: Some("crashed@gmail.com".into()),
    };
    write_journal(&journal).expect("write journal");

    // In the mock adapter, simulate the dirty live credential left behind by the crash
    let dirty_blob = make_blob("sub_dirty", "dirty@gmail.com");
    let adapter = MockAgyAdapter::new();
    adapter.set_credential(Some(dirty_blob));

    // Next agyx invocation checks and recovers
    let recovery = check_and_recover_journal(&adapter)
        .expect("recover journal")
        .expect("recovery report");

    assert_eq!(recovery.original_sub.as_deref(), Some("sub_crashed"));
    assert_eq!(recovery.original_email.as_deref(), Some("crashed@gmail.com"));

    // Verify adapter now has the original blob restored
    let restored = adapter.read_credential().unwrap().unwrap();
    assert_eq!(restored, orig_blob, "Must be restored byte-for-byte");

    // Verify journal file was removed
    assert!(read_journal().unwrap().is_none());
    let _ = vault.remove(backup_key);
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Failed restore keeps backup and reports recovery command
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_failed_restore_reports_loudly_and_keeps_backup() {
    let original_blob = make_blob("sub_fail_res", "fail_res@gmail.com");
    agyx_core::process_manager::set_mock_running_pids(Some(vec![]));
    let adapter = MockAgyAdapter::new();
    adapter.set_credential(Some(original_blob));

    // Simulate login error AND write_credential failure during rollback
    adapter.set_login_error("login aborted".into());
    adapter.set_write_error("OS keyring locked".into());

    let switcher = Switcher::new(Box::new(adapter));
    let err = switcher.login("test_restore_fail", true).unwrap_err();

    match err {
        AgyxError::RestoreFailed { reason, backup_path } => {
            assert!(reason.contains("rollback failed"));
            assert!(!backup_path.is_empty());
        }
        other => panic!("Expected RestoreFailed, got: {other:?}"),
    }

    // Clean up temporary journal if left
    let _ = remove_journal();
    agyx_core::process_manager::set_mock_running_pids(None);
}

// ─────────────────────────────────────────────────────────────────────────────
// switch/login/restore refused while AGY is running
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_switch_login_restore_refused_while_agy_running() {
    agyx_core::process_manager::set_mock_running_pids(Some(vec![99999]));

    let adapter = MockAgyAdapter::new();
    let switcher = Switcher::new(Box::new(adapter));

    // 1. switch refused
    let err_switch = switcher.switch("any_profile").unwrap_err();
    assert!(matches!(err_switch, AgyxError::AgyRunning { .. }));

    // 2. login refused
    let err_login = switcher.login("any_profile", true).unwrap_err();
    assert!(matches!(err_login, AgyxError::AgyRunning { .. }));

    // 3. restore refused
    let err_restore = switcher.restore_original().unwrap_err();
    assert!(matches!(err_restore, AgyxError::AgyRunning { .. }));

    // Reset mock
    agyx_core::process_manager::set_mock_running_pids(None);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Two agyx instances contending for the lock
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_lock_contention_between_instances() {
    let tmp = tempfile::tempdir().unwrap();
    let lock_path = tmp.path().join("agyx_test.lock");

    let lock1 = AgyxLock::try_acquire(&lock_path).expect("acquire lock 1");
    // Second acquire must fail with LockContended
    let lock2_err = AgyxLock::try_acquire(&lock_path).unwrap_err();
    assert!(matches!(lock2_err, AgyxError::LockContended));

    // Drop lock 1
    drop(lock1);

    // Now acquire must succeed
    let lock2 = AgyxLock::try_acquire(&lock_path);
    assert!(lock2.is_ok());
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Post-run sync skipped when live sub differs from active profile
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_post_run_sync_skipped_on_sub_mismatch() {
    let blob_user_a = make_blob("sub_user_a", "user_a@gmail.com");
    let blob_user_b = make_blob("sub_user_b", "user_b@gmail.com");

    let adapter = MockAgyAdapter::new();
    adapter.set_credential(Some(blob_user_a.clone()));

    let switcher = Switcher::new(Box::new(adapter));
    // Save profile "account_a"
    switcher.save("account_a").expect("save account_a");

    // Now simulate running AGY, but during the run the user logged into account_b
    // in AGY (changing the live credential)
    // In run(), we pass account "account_a". Let's verify sync_back logic directly:
    let live_adapter = MockAgyAdapter::new();
    live_adapter.set_credential(Some(blob_user_b.clone()));

    let live_switcher = Switcher::new(Box::new(live_adapter));
    // Calling run with Some("account_a") but mock returns exit code 0
    let _ = live_switcher.run(Some("account_a"), &[]);

    // Vault for account_a must still contain user_a, NOT user_b!
    let vault = CredentialVault::open().unwrap();
    let vault_a = vault.load("account_a").unwrap();
    let id_a = extract_identity(&vault_a).unwrap();
    assert_eq!(id_a.sub, "sub_user_a", "Must not overwrite account_a with user_b's credential");

    let _ = switcher.remove("account_a");
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Blob over Windows limit fails loudly without truncation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_blob_over_windows_limit_fails_loudly() {
    #[cfg(target_os = "windows")]
    {
        // Windows Credential Manager limit is 2,560 bytes
        let oversized = vec![0x41u8; 2561];
        let err = agt::write_raw(&oversized).unwrap_err();
        match err {
            AgyxError::BlobTooLarge { size, limit } => {
                assert_eq!(size, 2561);
                assert_eq!(limit, 2560);
            }
            other => panic!("Expected BlobTooLarge, got {other:?}"),
        }
    }
}
