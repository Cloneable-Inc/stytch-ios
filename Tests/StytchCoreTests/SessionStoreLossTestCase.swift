import XCTest
@testable import StytchCore

/// Regression tests for silent session-store loss (issue #601 class).
///
/// Two invariants:
/// 1. A nil keychain read for the encryption key while encrypted payloads
///    still exist must never silently regenerate the key over the (then
///    undecryptable) data. It is either a transient glitch — which gets a
///    strike allowance to heal across launches — or a permanent loss, which
///    is resolved by an explicit, consistent reset.
/// 2. A live session handed to the SDK must remain usable for the rest of the
///    process even when the encrypted store cannot persist it: the server,
///    not a local storage failure, is the arbiter of session validity.
final class SessionStoreLossTestCase: BaseTestCase {
    // MARK: - Missing-key decision policy

    func testFreshInstallMintsImmediately() {
        XCTAssertEqual(
            KeychainClientImplementation.decideOnMissingKey(evidenceOfExistingInstall: false, protectedDataAvailable: true, priorStrikes: 0, strikeAlreadyRecordedThisLaunch: false),
            .mintFresh
        )
    }

    func testMissingKeyWithEvidenceIsUnavailableNotRegenerated() {
        // The pre-fix behavior for this exact case was `.mintFresh`, which
        // permanently orphaned every persisted payload.
        XCTAssertEqual(
            KeychainClientImplementation.decideOnMissingKey(evidenceOfExistingInstall: true, protectedDataAvailable: true, priorStrikes: 0, strikeAlreadyRecordedThisLaunch: false),
            .storeUnavailable(strike: 1)
        )
    }

    func testLockedWindowLaunchDoesNotBurnStrikes() {
        // Background/prewarm launches before first unlock read the keychain as
        // missing; they must neither mint nor count toward the reset
        // allowance — regardless of how many strikes are already recorded.
        XCTAssertEqual(
            KeychainClientImplementation.decideOnMissingKey(evidenceOfExistingInstall: true, protectedDataAvailable: false, priorStrikes: 0, strikeAlreadyRecordedThisLaunch: false),
            .storeUnavailable(strike: nil)
        )
        XCTAssertEqual(
            KeychainClientImplementation.decideOnMissingKey(evidenceOfExistingInstall: true, protectedDataAvailable: false, priorStrikes: 5, strikeAlreadyRecordedThisLaunch: false),
            .storeUnavailable(strike: nil)
        )
    }

    func testRepeatedAccessesWithinOneLaunchDoNotBurnStrikes() {
        XCTAssertEqual(
            KeychainClientImplementation.decideOnMissingKey(evidenceOfExistingInstall: true, protectedDataAvailable: true, priorStrikes: 1, strikeAlreadyRecordedThisLaunch: true),
            .storeUnavailable(strike: 1)
        )
    }

    func testStrikeLimitDeclaresPermanentLossAndResetsExplicitly() {
        XCTAssertEqual(
            KeychainClientImplementation.decideOnMissingKey(evidenceOfExistingInstall: true, protectedDataAvailable: true, priorStrikes: 1, strikeAlreadyRecordedThisLaunch: false),
            .resetOrphanedStoreAndMint
        )
    }

    func testStrikesBeyondLimitStillReset() {
        XCTAssertEqual(
            KeychainClientImplementation.decideOnMissingKey(evidenceOfExistingInstall: true, protectedDataAvailable: true, priorStrikes: 5, strikeAlreadyRecordedThisLaunch: false),
            .resetOrphanedStoreAndMint
        )
    }

    // MARK: - In-memory survival on a broken store

    func testSessionTokensSurviveWhenStoreCannotPersist() {
        Current.userDefaultsClient = BrokenEncryptedUserDefaultsClientMock()
        Current.sessionManager.updatePersistentStorage(tokens: SessionTokens(jwt: "jwt_value", opaque: "opaque_value"))
        XCTAssertEqual(Current.sessionManager.sessionToken, "opaque_value")
        XCTAssertEqual(Current.sessionManager.sessionJwt, "jwt_value")
    }

    func testResetSessionClearsInMemoryTokens() {
        Current.userDefaultsClient = BrokenEncryptedUserDefaultsClientMock()
        Current.sessionManager.updatePersistentStorage(tokens: SessionTokens(jwt: "jwt_value", opaque: "opaque_value"))
        Current.sessionManager.resetSession()
        XCTAssertNil(Current.sessionManager.sessionToken)
        XCTAssertNil(Current.sessionManager.sessionJwt)
    }

    func testPersistedTokenWinsOverInMemoryFallback() {
        // RAM is a fallback for the broken-store launch only — once the store
        // is readable again its contents are authoritative.
        Current.userDefaultsClient = BrokenEncryptedUserDefaultsClientMock()
        Current.sessionManager.updatePersistentStorage(tokens: SessionTokens(jwt: "ram_jwt", opaque: "ram_opaque"))
        let workingStore = EncryptedUserDefaultsClientMock()
        Current.userDefaultsClient = workingStore
        try? workingStore.setStringValue("persisted_opaque", for: .sessionToken)
        XCTAssertEqual(Current.sessionManager.sessionToken, "persisted_opaque")
    }

    func testMemberSessionVisibleWhenStoreCannotPersist() {
        Current.userDefaultsClient = BrokenEncryptedUserDefaultsClientMock()
        let wrapper = MemberSessionStorageWrapper()
        wrapper.setObject(object: .mock)
        XCTAssertEqual(try? wrapper.getObject()?.memberSessionId, MemberSession.mock.memberSessionId)
        XCTAssertNotNil(wrapper.lastValidatedAtDate)
    }

    func testExpiredMemberSessionFromMemoryFallbackIsNotReturned() {
        Current.userDefaultsClient = BrokenEncryptedUserDefaultsClientMock()
        let wrapper = MemberSessionStorageWrapper()
        wrapper.setObject(object: .mockWithExpiredMemberSession)
        XCTAssertNil(try? wrapper.getObject())
    }

    // MARK: - Fresh-install keychain reset must not fire on unreadable state

    func testFreshInstallResetSkippedWhenKeyEvidenceExists() throws {
        // A nil install id with existing-install evidence means the defaults
        // are missing/poisoned, not that this is a fresh install — the wipe
        // (which used to delete the live encryption key) must not run.
        EncryptionKeyEvidence.overrideForTesting = true
        let installIdKey = "stytch_install_id_defaults_key"
        Current.defaults.removeObject(forKey: installIdKey)
        try Current.keychainClient.setValueForItem(value: .init(data: "encryption key".data(using: .utf8)!, account: nil, label: nil, generic: nil, accessPolicy: nil), item: .encryptionKey)
        StytchClient.configure(configuration: .init(publicToken: "evidence-token", defaultSessionDuration: 5))
        XCTAssertEqual(try Current.keychainClient.getFirstQueryResult(.encryptionKey)?.stringValue, "encryption key")
        XCTAssertNotNil(Current.defaults.string(forKey: installIdKey))
    }

    func testFreshInstallResetDeferredWhileProtectedDataUnavailable() throws {
        // Before first unlock, standard UserDefaults reads every key as nil —
        // a launch in that window must defer the fresh-install decision
        // entirely (no wipe, no install-id write) rather than delete the key.
        ProtectedDataAvailability.overrideForTesting = false
        let installIdKey = "stytch_install_id_defaults_key"
        Current.defaults.removeObject(forKey: installIdKey)
        try Current.keychainClient.setValueForItem(value: .init(data: "encryption key".data(using: .utf8)!, account: nil, label: nil, generic: nil, accessPolicy: nil), item: .encryptionKey)
        StytchClient.configure(configuration: .init(publicToken: "locked-window-token", defaultSessionDuration: 5))
        XCTAssertEqual(try Current.keychainClient.getFirstQueryResult(.encryptionKey)?.stringValue, "encryption key")
        XCTAssertNil(Current.defaults.string(forKey: installIdKey))
    }
}

/// Models the launch where the encryption key is unavailable: every encrypted
/// read/write fails exactly as `EncryptedUserDefaultsClientImplementation`
/// fails when `keychainClient.encryptionKey` is nil.
private final class BrokenEncryptedUserDefaultsClientMock: EncryptedUserDefaultsClient {
    func getItem(item _: EncryptedUserDefaultsItem) throws -> EncryptedUserDefaultsItemResult? {
        throw EncryptedUserDefaultsError.encryptionKeyNotAvailable
    }

    func itemExists(item _: EncryptedUserDefaultsItem) -> Bool {
        false
    }

    func setValueForItem(value _: String?, item _: EncryptedUserDefaultsItem) throws {
        throw EncryptedUserDefaultsError.encryptionKeyNotAvailable
    }

    func removeItem(item _: EncryptedUserDefaultsItem) throws {
        throw EncryptedUserDefaultsError.encryptionKeyNotAvailable
    }
}
