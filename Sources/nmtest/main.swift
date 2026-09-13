import Foundation
import NMTestKit

runByteReaderTests()
runIPAddressTests()
runPktapDecoderTests()
runPcapRoundTripTests()
runFlowTests()
runDNSParserTests()
runDNSAnalyzerTests()
runHostnameCacheTests()
runStreamBufferTests()
runTLSTests()
await runRetentionTests()
await runIPCTests()
await runStoreReaderTests()
runFilterParserTests()
await runCheckpointTests()

exit(NMTest.finish())
