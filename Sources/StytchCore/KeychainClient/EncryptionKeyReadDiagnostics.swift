import Foundation

/// What happened on the most recent uncached attempt to load the session encryption key. Diagnostics only.
public struct EncryptionKeyReadSnapshot: Equatable, Sendable {
    public enum Outcome: String, Sendable {
        /// The read was not attempted because protected data was reported unavailable.
        case skippedProtectedDataUnavailable
        /// The keychain returned the key.
        case keyFound
        /// The keychain returned no key.
        case keyMissing
        /// The keychain query or its result parsing threw.
        case readFailed
    }

    /// Where the cached protected-data flag came from.
    public enum ProtectedDataSource: String, Sendable {
        case unknown
        case mainThreadRead
        case launchAsyncRead
        case didBecomeAvailableNotification
        case willBecomeUnavailableNotification
        case didBecomeActiveNotification
        case testOverride
        case notApplicable
    }

    public var date: Date
    public var outcome: Outcome
    public var protectedDataCached: Bool?
    public var protectedDataSource: ProtectedDataSource
    public var secItemStatus: Int32?
    public var matchCount: Int?
    public var parseError: String?
    public var ciphertextPresent: Bool
    public var evidencePresent: Bool
    public var strikes: Int
    public var missingKeyDecision: String?
    public var activePrewarm: String?
    public var appState: String

    /// Flat, log-friendly attributes with a `stytch.key_read.` prefix.
    public var attributes: [String: Any] {
        var out: [String: Any] = [
            "stytch.key_read.outcome": outcome.rawValue,
            "stytch.key_read.age_s": max(0, Date().timeIntervalSince(date)),
            "stytch.key_read.protected_data_source": protectedDataSource.rawValue,
            "stytch.key_read.ciphertext_present": ciphertextPresent,
            "stytch.key_read.evidence_present": evidencePresent,
            "stytch.key_read.strikes": strikes,
            "stytch.key_read.app_state": appState,
            "stytch.key_read.active_prewarm": activePrewarm ?? "unset",
        ]
        out["stytch.key_read.protected_data_cached"] = protectedDataCached.map { $0 ? "true" : "false" } ?? "unknown"
        if let secItemStatus { out["stytch.key_read.sec_item_status"] = Int(secItemStatus) }
        if let matchCount { out["stytch.key_read.match_count"] = matchCount }
        if let parseError { out["stytch.key_read.parse_error"] = parseError }
        if let missingKeyDecision { out["stytch.key_read.missing_key_decision"] = missingKeyDecision }
        return out
    }
}

/// Read-only access to the fork's key-read diagnostics.
public enum StytchKeyReadDiagnostics {
    private static let lock = NSLock()
    private static var last: EncryptionKeyReadSnapshot?

    /// The most recent uncached encryption-key read in this process, if any.
    public static var lastEncryptionKeyRead: EncryptionKeyReadSnapshot? {
        lock.lock()
        defer { lock.unlock() }
        return last
    }

    static func record(_ snapshot: EncryptionKeyReadSnapshot) {
        lock.lock()
        last = snapshot
        lock.unlock()
    }

    static func resetForTesting() {
        lock.lock()
        last = nil
        lock.unlock()
    }
}
