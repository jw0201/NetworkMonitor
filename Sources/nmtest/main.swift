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

exit(NMTest.finish())
