import CryptoKit
import Foundation
import Security
#if !os(tvOS)
import LocalAuthentication
#endif
#if os(iOS)
import UIKit
#endif

let ENCRYPTEDUSERDEFAULTSKEYNAME = "EncryptedUserDefaultsKey"

/// Durable, *unprotected* evidence that an encryption key has been created for
/// this install. Lives in a file with no data protection, so it is readable in
/// every launch window — including background/prewarm launches before first
/// unlock, where both the keychain and UserDefaults read as empty/missing.
/// This is the only signal that safely distinguishes "fresh install" from
/// "existing install whose protected stores are temporarily unreadable":
/// keychain error codes cannot (locked keychains have been observed returning
/// errSecItemNotFound, not just errSecInteractionNotAllowed), and
/// `isProtectedDataAvailable` has documented false negatives. The file is
/// removed on app uninstall along with the rest of the container, so a true
/// reinstall correctly presents as fresh.
enum EncryptionKeyEvidence {
    static var overrideForTesting: Bool?

    private static var markerURL: URL? {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { return nil }
        return base
            .appendingPathComponent("StytchCore", isDirectory: true)
            .appendingPathComponent("encryption_key_evidence")
    }

    static var exists: Bool {
        if let overrideForTesting { return overrideForTesting }
        guard let url = markerURL else { return false }
        return FileManager.default.fileExists(atPath: url.path)
    }

    static func record() {
        guard overrideForTesting == nil, let url = markerURL else { return }
        guard !FileManager.default.fileExists(atPath: url.path) else { return }
        let directory = url.deletingLastPathComponent()
        #if os(macOS)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: url.path, contents: Data())
        #else
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.none])
        FileManager.default.createFile(atPath: url.path, contents: Data(), attributes: [.protectionKey: FileProtectionType.none])
        #endif
    }

    static func clear() {
        guard overrideForTesting == nil, let url = markerURL else { return }
        try? FileManager.default.removeItem(at: url)
    }
}

#if os(iOS)
/// Thread-safe, notification-backed view of `UIApplication.shared.isProtectedDataAvailable`.
/// The keychain client consults this from its own serial queue; reading the
/// `UIApplication` property there directly is a main-actor violation and can
/// return stale values at exactly the moments (prewarm, early launch) where the
/// answer matters most. Until the first main-queue read lands the value is
/// unknown and treated as available — a wrong optimistic answer is harmless
/// because a locked keychain read fails with `errSecInteractionNotAllowed`,
/// which is handled non-destructively (no key regeneration).
final class ProtectedDataAvailability {
    static let shared = ProtectedDataAvailability()
    static var overrideForTesting: Bool?
    private let lock = NSLock()
    private var cachedAvailable: Bool?

    private init() {
        NotificationCenter.default.addObserver(
            forName: UIApplication.protectedDataDidBecomeAvailableNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.update(true) }
        NotificationCenter.default.addObserver(
            forName: UIApplication.protectedDataWillBecomeUnavailableNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.update(false) }
        // Re-read on foreground activation as well: the availability property
        // has documented false negatives right after launch where the
        // did-become-available notification then never fires (it only signals
        // transitions) — an activation re-check heals a stale cached value.
        NotificationCenter.default.addObserver(
            forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.update(UIApplication.shared.isProtectedDataAvailable) }
        DispatchQueue.main.async { [weak self] in
            self?.update(UIApplication.shared.isProtectedDataAvailable)
        }
    }

    private func update(_ value: Bool) {
        lock.lock()
        cachedAvailable = value
        lock.unlock()
    }

    /// Cached value, seeded synchronously when the caller is already on the
    /// main thread (where the UIApplication property is legal to read). This
    /// matters at configure time: SDK configuration runs on the main thread
    /// before the async warm-up has landed, and destructive decisions gated on
    /// "affirmatively available" must not be deferred forever by an unknown.
    private func currentValue() -> Bool? {
        lock.lock()
        if let cachedAvailable {
            lock.unlock()
            return cachedAvailable
        }
        lock.unlock()
        guard Thread.isMainThread else { return nil }
        let value = UIApplication.shared.isProtectedDataAvailable
        update(value)
        return value
    }

    /// Optimistic view for read attempts: unknown counts as available, because
    /// a failed read on a locked keychain is handled non-destructively.
    var isAvailable: Bool {
        if let value = Self.overrideForTesting { return value }
        return currentValue() ?? true
    }

    /// Conservative view for destructive decisions (minting/reset/strikes):
    /// unknown does NOT count as available.
    var isAffirmativelyAvailable: Bool {
        if let value = Self.overrideForTesting { return value }
        return currentValue() == true
    }
}
#endif

final class KeychainClientImplementation: KeychainClient {
    static let shared = KeychainClientImplementation()
    private let queue: DispatchQueue
    private let queueKey = DispatchSpecificKey<Void>()
    private var cachedEncryptionKey: SymmetricKey?
    var didInitializeKeychainData = false
    var encryptionKey: SymmetricKey? {
        (try? safelyEnqueue {
            if let cachedEncryptionKey {
                return cachedEncryptionKey
            }
            #if os(iOS)
            // NOTE: consulted via a thread-safe cache — reading
            // `UIApplication.shared.isProtectedDataAvailable` directly from this
            // queue is a main-actor violation and can misreport during launch.
            if ProtectedDataAvailability.shared.isAvailable {
                try? getEncryptionKey()
                didInitializeKeychainData = true
            } else {
                // For some reason, we are trying to read the encryption key before protected data became available
                // Log that this happened (which it hopefully won't?), but leave the behavior up to the caller (EncryptedUserDefaultsClient) to handle a missing key (throw an error)
                StytchConsoleLogger.error(message: "Attempted to read encryption key before protected data became available")
            }
            #else
            try? getEncryptionKey()
            #endif
            return cachedEncryptionKey
        })
    }

    private var isOnQueue: Bool {
        DispatchQueue.getSpecific(key: queueKey) != nil
    }

    #if !os(tvOS) && !os(watchOS)
    // Shared reusable private context for the keychain client,
    // always configured with interactionNotAllowed = true
    private let contextWithoutUI = LAContext()
    #endif

    private init() {
        queue = DispatchQueue(label: "StytchKeychainClientQueue")
        queue.setSpecific(key: queueKey, value: ())
        #if !os(tvOS) && !os(watchOS)
        contextWithoutUI.interactionNotAllowed = true
        #endif
    }

    func safelyEnqueue<T>(_ block: () throws -> T) throws -> T {
        if isOnQueue {
            return try block()
        } else {
            return try queue.sync { try block() }
        }
    }

    // MARK: Missing-key recovery policy
    //
    // A nil keychain read for the encryption key is ambiguous: on a fresh
    // install the key truly doesn't exist, but when encrypted payloads are
    // still sitting in the UserDefaults suite the key SHOULD exist — the nil
    // is either a transient keychain glitch or a genuine key loss. The old
    // behavior minted a replacement key immediately in both cases, which
    // permanently orphaned every persisted payload (and, when the nil was
    // transient, destroyed a perfectly good key by overwriting it). Instead:
    // give a possible glitch `keyMissingStrikeLimit` consecutive launches to
    // heal (treating the store as unavailable in the meantime), and only then
    // declare the loss permanent — clearing the orphaned ciphertext so the
    // reset is explicit and consistent rather than silent and partial.

    static let keyMissingStrikeLimit = 2
    private static let keyMissingStrikesKey = "stytch_encryption_key_missing_strikes"
    /// A strike counts at most once per process so repeated key accesses
    /// within a single launch cannot exhaust the allowance.
    private var recordedKeyMissingStrikeThisLaunch = false

    enum MissingKeyDecision: Equatable {
        /// No evidence of an existing install — fresh state; mint as before.
        /// (If this is actually a locked-window misread, the mint's keychain
        /// write fails with errSecInteractionNotAllowed and nothing is lost.)
        case mintFresh
        /// Evidence of an existing install — treat the store as unavailable
        /// this launch. `strike` is nil when protected data was not confirmed
        /// available (locked-window launches must not burn the allowance).
        case storeUnavailable(strike: Int?)
        /// The key has been missing across the full allowance of confirmed
        /// unlocked launches — the data is undecryptable; reset explicitly.
        case resetOrphanedStoreAndMint
    }

    static func decideOnMissingKey(evidenceOfExistingInstall: Bool, protectedDataAvailable: Bool, priorStrikes: Int, strikeAlreadyRecordedThisLaunch: Bool) -> MissingKeyDecision {
        guard evidenceOfExistingInstall else { return .mintFresh }
        guard protectedDataAvailable else { return .storeUnavailable(strike: nil) }
        let strikes = strikeAlreadyRecordedThisLaunch ? priorStrikes : priorStrikes + 1
        return strikes >= keyMissingStrikeLimit ? .resetOrphanedStoreAndMint : .storeUnavailable(strike: strikes)
    }

    private var loggedLockedWindowUnavailability = false

    func getEncryptionKey() throws {
        try safelyEnqueue {
            let result = try getFirstQueryResult(KeychainItem.encryptionKey)
            guard let result else {
                let protectedDataAvailable: Bool
                #if os(iOS)
                protectedDataAvailable = ProtectedDataAvailability.shared.isAffirmativelyAvailable
                #else
                protectedDataAvailable = true
                #endif
                switch Self.decideOnMissingKey(
                    // The evidence marker is readable in every launch window;
                    // the ciphertext check backstops installs that predate it.
                    evidenceOfExistingInstall: EncryptionKeyEvidence.exists || encryptedPayloadsExist(),
                    protectedDataAvailable: protectedDataAvailable,
                    priorStrikes: persistedKeyMissingStrikes(),
                    strikeAlreadyRecordedThisLaunch: recordedKeyMissingStrikeThisLaunch
                ) {
                case .mintFresh:
                    try mintAndStoreFreshKey()
                case let .storeUnavailable(strike):
                    // Log once per launch — this getter runs on every
                    // encrypted read/write, and an unavailable launch would
                    // otherwise emit hundreds of identical lines.
                    if let strike {
                        if !recordedKeyMissingStrikeThisLaunch {
                            StytchConsoleLogger.error(message: "Encryption key missing while evidence of an existing install exists (strike \(strike)/\(Self.keyMissingStrikeLimit)). Treating the store as unavailable instead of regenerating — a replacement key would permanently orphan the persisted session. Will retry.")
                        }
                        recordKeyMissingStrike(strike)
                    } else if !loggedLockedWindowUnavailability {
                        loggedLockedWindowUnavailability = true
                        StytchConsoleLogger.error(message: "Encryption key unreadable before protected data was confirmed available (likely a background/prewarm launch on a locked device). Treating the store as unavailable; not counting toward the reset allowance.")
                    }
                    throw KeychainError.encryptionKeyUnavailable
                case .resetOrphanedStoreAndMint:
                    StytchConsoleLogger.error(message: "Encryption key missing for \(Self.keyMissingStrikeLimit) consecutive unlocked launches with evidence of an existing install. Declaring the key lost: clearing the orphaned (undecryptable) store and generating a fresh key.")
                    clearEncryptedPayloads()
                    try mintAndStoreFreshKey()
                }
                return
            }
            clearKeyMissingStrikes()
            EncryptionKeyEvidence.record()
            upgradeKeyItemProtectionIfNeeded()
            cachedEncryptionKey = SymmetricKey(data: result.data)
        }
    }

    private func mintAndStoreFreshKey() throws {
        let data = SymmetricKey(size: .bits256).withUnsafeBytes {
            Data(Array($0))
        }
        try setValueForItem(value: .init(data: data, account: ENCRYPTEDUSERDEFAULTSKEYNAME, label: nil, generic: nil, accessPolicy: nil), item: .encryptionKey)
        cachedEncryptionKey = SymmetricKey(data: data)
        clearKeyMissingStrikes()
        EncryptionKeyEvidence.record()
    }

    /// Whether the encrypted UserDefaults suite still holds payloads that were
    /// sealed with the (now missing) key. Bookkeeping keys are excluded.
    private func encryptedPayloadsExist() -> Bool {
        guard let domain = UserDefaults(suiteName: STYTCHENCRYPTEDUSERDEFAULTSSUITENAME)?
            .persistentDomain(forName: STYTCHENCRYPTEDUSERDEFAULTSSUITENAME) else { return false }
        return domain.contains { key, value in
            key != Self.keyMissingStrikesKey && value is Data
        }
    }

    private func clearEncryptedPayloads() {
        guard let defaults = UserDefaults(suiteName: STYTCHENCRYPTEDUSERDEFAULTSSUITENAME),
              let domain = defaults.persistentDomain(forName: STYTCHENCRYPTEDUSERDEFAULTSSUITENAME) else { return }
        for (key, value) in domain where key != Self.keyMissingStrikesKey && value is Data {
            defaults.removeObject(forKey: key)
        }
    }

    private func persistedKeyMissingStrikes() -> Int {
        UserDefaults(suiteName: STYTCHENCRYPTEDUSERDEFAULTSSUITENAME)?.integer(forKey: Self.keyMissingStrikesKey) ?? 0
    }

    private func recordKeyMissingStrike(_ strikes: Int) {
        guard !recordedKeyMissingStrikeThisLaunch else { return }
        recordedKeyMissingStrikeThisLaunch = true
        UserDefaults(suiteName: STYTCHENCRYPTEDUSERDEFAULTSSUITENAME)?.set(strikes, forKey: Self.keyMissingStrikesKey)
    }

    private func clearKeyMissingStrikes() {
        recordedKeyMissingStrikeThisLaunch = false
        guard let defaults = UserDefaults(suiteName: STYTCHENCRYPTEDUSERDEFAULTSSUITENAME),
              defaults.object(forKey: Self.keyMissingStrikesKey) != nil else { return }
        defaults.removeObject(forKey: Self.keyMissingStrikesKey)
    }

    /// One-time, best-effort in-place upgrade of the key item's protection
    /// class to AfterFirstUnlockThisDeviceOnly / non-synchronizable (the data
    /// is preserved). A session encryption key must not ride device backups to
    /// other devices; ThisDeviceOnly also removes a whole class of external
    /// deletions (iCloud Keychain sync) from the key's threat model.
    private var attemptedKeyItemProtectionUpgrade = false
    private func upgradeKeyItemProtectionIfNeeded() {
        guard !attemptedKeyItemProtectionUpgrade else { return }
        attemptedKeyItemProtectionUpgrade = true
        var query = KeychainItem.encryptionKey.baseQuery
        query[kSecAttrAccount] = ENCRYPTEDUSERDEFAULTSKEYNAME
        query[kSecAttrSynchronizable] = kSecAttrSynchronizableAny
        let attributes: [CFString: Any] = [
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrSynchronizable: false,
        ]
        _ = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    }

    // swiftlint:disable:next function_body_length
    func getQueryResults(item: KeychainItem) throws -> [KeychainQueryResult] {
        try safelyEnqueue {
            var result: CFTypeRef?
            var query = item.getQuery
            #if !os(tvOS) && !os(watchOS)
            query[kSecUseAuthenticationContext] = LocalAuthenticationContextManager.laContext
            #endif
            var status: OSStatus?
            if item.kind == .privateKey {
                // recursively check each potential type of access control flag
                var potentialFlags: [SecAccessControlCreateFlags] = [
                    [.userPresence],
                    [.biometryCurrentSet],
                ]

                #if os(macOS)
                potentialFlags.append([.biometryCurrentSet, .or, .watch])
                #endif

                for flags in potentialFlags {
                    var error: Unmanaged<CFError>?
                    defer {
                        error?.release()
                    }
                    let accessControl = SecAccessControlCreateWithFlags(
                        nil,
                        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                        flags,
                        &error
                    )
                    var newQuery = query
                    newQuery[kSecAttrAccessControl] = accessControl
                    status = SecItemCopyMatching(newQuery as CFDictionary, &result)
                    if status == errSecSuccess {
                        break
                    }
                }
            } else if item.kind == .encryptionKey {
                var newQuery = query
                newQuery[kSecAttrAccount] = ENCRYPTEDUSERDEFAULTSKEYNAME
                status = SecItemCopyMatching(newQuery as CFDictionary, &result)
            } else {
                status = SecItemCopyMatching(query as CFDictionary, &result)
            }

            if let status = status, ![errSecSuccess, errSecItemNotFound].contains(status) {
                throw KeychainError.unhandledError(status: status)
            }
            guard case errSecSuccess = status else {
                return []
            }
            guard let results = result as? [[CFString: Any]] else {
                throw KeychainError.resultNotArray
            }
            return try results.compactMap { dict in
                guard let data = dict[kSecValueData] as? Data else {
                    throw KeychainError.resultNotData
                }
                guard let account = dict[kSecAttrAccount] as? String else {
                    throw KeychainError.resultMissingAccount
                }
                guard let createdAt = dict[kSecAttrCreationDate] as? Date, let modifiedAt = dict[kSecAttrModificationDate] as? Date else {
                    throw KeychainError.resultMissingDates
                }
                let label = dict[kSecAttrLabel] as? String
                let generic = dict[kSecAttrGeneric] as? Data
                return KeychainQueryResult(
                    data: data,
                    createdAt: createdAt,
                    modifiedAt: modifiedAt,
                    label: label,
                    account: account,
                    generic: generic
                )
            }
        }
    }

    func valueExistsForItem(item: KeychainItem) -> Bool {
        let exists = try? safelyEnqueue {
            var result: CFTypeRef?
            var query = item.getQuery
            #if !os(tvOS) && !os(watchOS)
            query[kSecUseAuthenticationContext] = contextWithoutUI
            #endif
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            return [errSecSuccess, errSecInteractionNotAllowed].contains(status)
        }
        return exists == true
    }

    func setValueForItem(value: KeychainItem.Value, item: KeychainItem) throws {
        try safelyEnqueue {
            let status: OSStatus
            var query = item.baseQuery
            #if !os(tvOS) && !os(watchOS)
            query[kSecUseAuthenticationContext] = LocalAuthenticationContextManager.laContext
            #endif
            if valueExistsForItem(item: item) {
                let queryDict = query as CFDictionary
                let attributesToUpdate = item.updateQuerySegment(for: value) as CFDictionary
                status = SecItemUpdate(queryDict, attributesToUpdate)
            } else {
                status = SecItemAdd(item.insertQuery(value: value), nil)
            }
            if status != errSecSuccess {
                throw KeychainError.unhandledError(status: status)
            }
        }
    }

    func removeItem(item: KeychainItem) throws {
        try safelyEnqueue {
            let tryRemovingItem: (CFDictionary) throws -> Void = { query in
                let status = SecItemDelete(query)
                guard [errSecSuccess, errSecItemNotFound].contains(status) else {
                    throw KeychainError.unhandledError(status: status)
                }
            }
            var parameters: [CFString: AnyObject] = [kSecAttrSynchronizable: kSecAttrSynchronizableAny]
            if item.kind == .encryptionKey {
                // No kSecAttrAccessible filter here: it would silently fail to
                // match items whose protection class has been upgraded (or was
                // created by a different SDK version).
                try tryRemovingItem(item.baseQuery.merging(parameters))
                // A deliberate deletion clears the existing-install evidence so
                // the next key access mints fresh instead of treating the
                // absence as a loss event.
                EncryptionKeyEvidence.clear()
            } else {
                // recursively check each potential type of access control flag
                var potentialFlags: [SecAccessControlCreateFlags] = [
                    [.userPresence],
                    [.biometryCurrentSet],
                ]
                #if os(macOS)
                potentialFlags.append([.biometryCurrentSet, .or, .watch])
                #endif
                try potentialFlags.forEach { flags in
                    var newParameters = parameters
                    var error: Unmanaged<CFError>?
                    defer {
                        error?.release()
                    }
                    let accessControl = SecAccessControlCreateWithFlags(
                        nil,
                        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                        flags,
                        &error
                    )
                    newParameters[kSecAttrAccessControl] = accessControl
                    try tryRemovingItem(item.baseQuery.merging(newParameters))
                }
            }
        }
    }
}
