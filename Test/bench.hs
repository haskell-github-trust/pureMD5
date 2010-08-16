import Data.Digest.Pure.MD5
import Benchmark.Crypto
import Criterion.Main

main = defaultMain [benchmarkHash (undefined :: MD5Digest) "pureMD5"]
