import XCTest
@testable import StytchCore

final class EncryptionKeyReadDiagnosticsTestCase: XCTestCase {
    override func tearDown() {
        StytchKeyReadDiagnostics.resetForTesting()
        super.tearDown()
    }

    private func snapshot(_ outcome: EncryptionKeyReadSnapshot.Outcome) -> EncryptionKeyReadSnapshot {
        EncryptionKeyReadSnapshot(
            date: Date(), outcome: outcome, protectedDataCached: false, protectedDataSource: .launchAsyncRead,
            secItemStatus: -25300, matchCount: 0, parseError: nil, ciphertextPresent: true, evidencePresent: true,
            strikes: 1, missingKeyDecision: "storeUnavailable(strike 1)", activePrewarm: "1", appState: "background"
        )
    }

    func testEveryFieldAppearsInTheAttributes() {
        let attributes = snapshot(.keyMissing).attributes
        XCTAssertEqual(attributes["stytch.key_read.outcome"] as? String, "keyMissing")
        XCTAssertEqual(attributes["stytch.key_read.protected_data_cached"] as? String, "false")
        XCTAssertEqual(attributes["stytch.key_read.protected_data_source"] as? String, "launchAsyncRead")
        XCTAssertEqual(attributes["stytch.key_read.sec_item_status"] as? Int, -25300)
        XCTAssertEqual(attributes["stytch.key_read.match_count"] as? Int, 0)
        XCTAssertEqual(attributes["stytch.key_read.ciphertext_present"] as? Bool, true)
        XCTAssertEqual(attributes["stytch.key_read.evidence_present"] as? Bool, true)
        XCTAssertEqual(attributes["stytch.key_read.strikes"] as? Int, 1)
        XCTAssertEqual(attributes["stytch.key_read.missing_key_decision"] as? String, "storeUnavailable(strike 1)")
        XCTAssertEqual(attributes["stytch.key_read.active_prewarm"] as? String, "1")
        XCTAssertEqual(attributes["stytch.key_read.app_state"] as? String, "background")
        XCTAssertNotNil(attributes["stytch.key_read.age_s"] as? Double)
        XCTAssertNil(attributes["stytch.key_read.parse_error"])
    }

    func testSkippedReadCarriesNoQueryResultAndUnknownFlagsAreExplicit() {
        var skipped = snapshot(.skippedProtectedDataUnavailable)
        skipped.secItemStatus = nil
        skipped.matchCount = nil
        skipped.protectedDataCached = nil
        skipped.activePrewarm = nil
        let attributes = skipped.attributes
        XCTAssertNil(attributes["stytch.key_read.sec_item_status"])
        XCTAssertNil(attributes["stytch.key_read.match_count"])
        XCTAssertEqual(attributes["stytch.key_read.protected_data_cached"] as? String, "unknown")
        XCTAssertEqual(attributes["stytch.key_read.active_prewarm"] as? String, "unset")
    }

    func testLatestRecordedSnapshotIsReturned() {
        XCTAssertNil(StytchKeyReadDiagnostics.lastEncryptionKeyRead)
        StytchKeyReadDiagnostics.record(snapshot(.keyMissing))
        StytchKeyReadDiagnostics.record(snapshot(.keyFound))
        XCTAssertEqual(StytchKeyReadDiagnostics.lastEncryptionKeyRead?.outcome, .keyFound)
    }

    func testMissingKeyDecisionsAreDescribed() {
        XCTAssertEqual(KeychainClientImplementation.describe(.mintFresh), "mintFresh")
        XCTAssertEqual(KeychainClientImplementation.describe(.storeUnavailable(strike: 2)), "storeUnavailable(strike 2)")
        XCTAssertEqual(KeychainClientImplementation.describe(.storeUnavailable(strike: nil)), "storeUnavailable(locked window)")
        XCTAssertEqual(KeychainClientImplementation.describe(.resetOrphanedStoreAndMint), "resetOrphanedStoreAndMint")
    }
}
