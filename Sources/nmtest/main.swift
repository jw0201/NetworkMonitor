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

exit(NMTest.finish())
