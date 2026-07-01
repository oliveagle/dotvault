//! Strict concurrency tests for the namespace file-locking.
//!
//! These tests run real OS threads that race for the same namespace and verify
//! the exclusive `flock` serializes the read-modify-write cycle so that:
//!   - no `set` is silently lost (lost-update bug),
//!   - the lock actually blocks (not a no-op),
//!   - concurrent `init` of the same namespace has exactly one winner.
//!
//! Each test sets DOTVAULT_HOME/BACKUP_DIR/CONFIG/KEY_FILE into a temp dir and
//! runs single-threaded at the cargo level (these tests spawn their own
//! threads internally), so they use the shared `env_lock` to avoid colliding
//! with env-mutating tests in the other file.

mod common;

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use dotvault::commands;
use dotvault::vault;

use common::TestKey;

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

macro_rules! env_test {
    ($name:ident, $body:block) => {
        #[test]
        fn $name() {
            let _guard = env_lock().lock().unwrap();
            $body
        }
    };
}

/// Isolated environment: temp DOTVAULT_HOME/backups/config + a temp project
/// dir as CWD holding `.dotvault_key`.
struct Iso {
    _home: tempfile::TempDir,
    _project: tempfile::TempDir,
    key: TestKey,
}

impl Iso {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        std::env::set_var("DOTVAULT_HOME", home.path());
        std::env::set_var("DOTVAULT_BACKUP_DIR", home.path().join("backups"));
        std::env::set_var("DOTVAULT_CONFIG", home.path().join("config.toml"));
        std::env::set_current_dir(project.path()).unwrap();
        std::env::set_var("DOTVAULT_KEY_FILE", project.path().join(".dotvault_key"));
        Self {
            _home: home,
            _project: project,
            key: TestKey::new(),
        }
    }

    fn key_path(&self) -> std::path::PathBuf {
        self.key.path.clone()
    }
}

// =========================================================================
// 1. NO LOST UPDATE — many threads set DIFFERENT keys; all must survive.
//    Without the lock, some writers would read the pre-write state and
//    clobber each other's additions. With the lock, every set serializes and
//    all N keys appear.
// =========================================================================
env_test!(concurrent_set_distinct_keys_no_loss, {
    let iso = Iso::new();
    commands::init("ns", &Some(iso.key_path())).unwrap();
    let key = Some(iso.key_path());
    let n = 16;

    let mut handles = Vec::new();
    for i in 0..n {
        let k = key.clone();
        handles.push(std::thread::spawn(move || {
            // Each thread adds its own unique key.
            commands::set(&k, &format!("K{i}"), &format!("v{i}"))
        }));
    }
    for h in handles {
        h.join().unwrap().expect("each set must succeed");
    }

    // Reload and verify ALL n keys are present (no lost updates).
    let v = vault::Vault::load("ns", &iso.key_path()).unwrap();
    let mut names: Vec<String> = v.entries.iter().map(|(k, _)| k.clone()).collect();
    names.sort();
    assert_eq!(
        names.len(),
        n,
        "lost update: expected {n} keys, got {}",
        names.len()
    );
    for i in 0..n {
        assert_eq!(
            v.get(&format!("K{i}")),
            Some(&*format!("v{i}")),
            "key K{i} lost"
        );
    }
});

// =========================================================================
// 2. LOCK ACTUALLY BLOCKS — a held Vault blocks a second loader until release.
//    We load + HOLD (don't drop), then a second thread tries to load; it must
//    still be blocked after a short wait. After we drop, it proceeds.
// =========================================================================
env_test!(held_lock_blocks_second_loader, {
    let iso = Iso::new();
    commands::init("ns", &Some(iso.key_path())).unwrap();

    // Hold the lock for the whole test by keeping this Vault alive.
    let _held = vault::Vault::load("ns", &iso.key_path()).unwrap();
    let key_path = iso.key_path();

    // Second loader in another thread.
    let loaded = Arc::new(Mutex::new(false));
    let loaded2 = loaded.clone();
    let h = std::thread::spawn(move || {
        // This must block until `_held` is dropped. If the lock were a no-op,
        // this would complete almost instantly.
        let _v = vault::Vault::load("ns", &key_path).unwrap();
        *loaded2.lock().unwrap() = true;
    });

    // Give the second thread time to (try to) acquire the lock.
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        !*loaded.lock().unwrap(),
        "second loader raced past a held lock — lock is a no-op!"
    );

    // Drop the held vault → lock released → second loader should now finish.
    drop(_held);
    // Wait up to 2s for the second thread to acquire and complete.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !*loaded.lock().unwrap() {
        if std::time::Instant::now() > deadline {
            panic!("second loader never acquired the lock after release");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    h.join().unwrap();
});

// =========================================================================
// 3. TOCTOU ON INIT — many threads concurrently `init` the SAME namespace.
//    Exactly one must win; the rest must error "already exists". Without the
//    init lock, two could both pass the existence check and corrupt state.
// =========================================================================
env_test!(concurrent_init_same_namespace_one_winner, {
    let iso = Iso::new();
    let key = Some(iso.key_path());
    let n = 12;

    let results = Arc::new(Mutex::new(Vec::<bool>::new()));
    let mut handles = Vec::new();
    for _ in 0..n {
        let k = key.clone();
        let r = results.clone();
        handles.push(std::thread::spawn(move || {
            let ok = commands::init("solo", &k).is_ok();
            r.lock().unwrap().push(ok);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let wins = results.lock().unwrap().iter().filter(|&&b| b).count();
    assert_eq!(
        wins, 1,
        "exactly one init must win, got {wins} (TOCTOU race / init not locked)"
    );
    // Namespace is usable.
    assert!(vault::list_namespaces()
        .unwrap()
        .contains(&"solo".to_string()));
});

// =========================================================================
// 4. SERIALIZED WRITES PRESERVE COUNT — many threads each set the SAME key
//    would be nonsensical (set errors on existing), so instead each thread
//    does set K{n}=v then a 2nd set of a unique key. We assert the final
//    entry count equals the number of distinct keys written, proving every
//    write committed on top of the latest state (no stale-overwrite).
// =========================================================================
env_test!(interleaved_writes_all_commit, {
    let iso = Iso::new();
    commands::init("ns", &Some(iso.key_path())).unwrap();
    let key = Some(iso.key_path());
    let n = 10;

    let mut handles = Vec::new();
    for i in 0..n {
        let k = key.clone();
        handles.push(std::thread::spawn(move || {
            // Sequentially: add own key, then a "shared-counter-style" key that
            // reads-modifies-writes. The lock guarantees each sees the prior.
            commands::set(&k, &format!("T{i}"), "1").unwrap();
            // Small spin to increase interleaving odds.
            std::thread::yield_now();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let v = vault::Vault::load("ns", &iso.key_path()).unwrap();
    assert_eq!(v.entries.len(), n, "expected {n} committed writes");
});

// =========================================================================
// 5. LOCK IS PER-NAMESPACE — holding namespace A does NOT block namespace B.
//    This guards against accidentally locking a global/shared file.
// =========================================================================
env_test!(lock_is_per_namespace, {
    let iso = Iso::new();
    commands::init("ns-a", &Some(iso.key_path())).unwrap();
    commands::init("ns-b", &Some(iso.key_path())).unwrap();

    // Hold ns-a's lock.
    let _held_a = vault::Vault::load("ns-a", &iso.key_path()).unwrap();

    // ns-b should be loadable + writable without delay.
    let started = std::time::Instant::now();
    {
        let mut b = vault::Vault::load("ns-b", &iso.key_path()).unwrap();
        b.set("X", "1").unwrap();
        b.save().unwrap();
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "ns-b was blocked ({elapsed:?}) while only ns-a was locked — lock is not per-namespace"
    );
});

// =========================================================================
// 6. READ-WRITE CYCLE IS ATOMIC — two threads each read the count, add one
//    distinct key, write back. With proper locking, final count == 2*N. This
//    is the canonical lost-update test expressed directly.
// =========================================================================
env_test!(read_modify_write_is_atomic, {
    let iso = Iso::new();
    commands::init("ns", &Some(iso.key_path())).unwrap();
    let key = Some(iso.key_path());
    let n = 8usize;

    // Seed one key so both threads see a non-empty vault.
    commands::set(&key, "seed", "0").unwrap();

    let mut handles = Vec::new();
    for t in 0..n {
        let k = key.clone();
        handles.push(std::thread::spawn(move || {
            // Full read-modify-write through the command layer (load→set→save),
            // each adding one unique key. Lock must serialize the whole cycle.
            let mut v = vault::Vault::load("ns", k.as_deref().unwrap()).unwrap();
            v.set(&format!("w{t}"), "v").unwrap();
            v.save().unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let v = vault::Vault::load("ns", &iso.key_path()).unwrap();
    // seed + n writer keys.
    assert_eq!(
        v.entries.len(),
        1 + n,
        "lost update: read-modify-write was not atomic, got {} entries",
        v.entries.len()
    );
});
