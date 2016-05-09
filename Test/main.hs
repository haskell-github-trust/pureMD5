module Main where

import Test.Framework
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.MD5
import Data.Digest.Pure.MD5
import Data.Char (isSpace)
import Data.ByteString.Lazy (toStrict, ByteString)
import qualified Data.Binary as B
import qualified Data.Serialize as S
import Hexdump

main :: IO ()
main = defaultMain
  [ testGroup "MD5 functional correctness tests" base_tests
  , testGroup "Serialization order correctness tests" serialization_tests
  ]

-- | Use the crypto-api-tests, piddly as they are, to give evidence of
-- functional correctness.
base_tests :: [Test]
base_tests = makeMD5Tests (undefined :: MD5Digest)

-- | Ensure the output of `show`, `Serialize`, `Binary`, and `md5DigestBytes`
-- are all consistent.
serialization_tests :: [Test]
serialization_tests =
  [ testProperty "show == simple_hex . Serialize.encode"
      (\bs -> let d = hsh bs in show d == filter (not . isSpace) (simpleHex (S.encode d)))
  , testProperty "Serialize.encode == toStrict . Binary.encode"
      (\bs -> let d = hsh bs in toStrict (B.encode d) == S.encode d)
  , testProperty "Serialize.encode == md5DigestBytes"
      (\bs -> let d = hsh bs in S.encode d == md5DigestBytes d)
  ]
 where
 hsh = hash :: ByteString -> MD5Digest
