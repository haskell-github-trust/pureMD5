{-# LANGUAGE ExistentialQuantification #-}
module Test.MD5 where

import Test.QuickCheck
import Test.Crypto
import Data.Digest.Pure.MD5
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as S
import Control.Monad (forM)
import Data.Word (Word8)
import Data.Binary

test = runTests (makeMD5Tests (undefined :: MD5Digest))

{-

instance Arbitrary Word8 where
    arbitrary = (arbitrary :: Gen Int) >>= return . fromIntegral

instance Arbitrary S.ByteString where
    arbitrary = do
        len <- choose (0,4096) :: Gen Int
        words <- forM [0..len] (\_ -> arbitrary)
        return $ S.pack words

instance Arbitrary L.ByteString where
    arbitrary = do
        len <- choose (0,10) :: Gen Int
        chunks <- vector len
        return $ L.fromChunks chunks

prop_PartsEqWhole lps =
    let lpsChunks   = map (L.fromChunks . (:[])) (L.toChunks lps)
        incremental = foldl md5Update md5InitialContext lpsChunks
        final = md5Finalize incremental
    in md5 lps == final

prop_ShowLen bs = 32 == (length $ show (md5 bs))

prop_BinaryLen bs = 16 == (L.length $ encode (md5 bs))

prop_GetPut bs =
    let dg = md5 bs
    in decode (encode dg) == dg

prop_ShowElem bs =
    let digest = md5 bs
        valids = \c -> (c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')
    in [] == filter (not . valids) (show digest)

prop_KnownAnswers =
  let mds = show . md5 . pk
      pk  = L.pack . (map (fromIntegral . fromEnum))
  in mds ("") == "d41d8cd98f00b204e9800998ecf8427e" &&
     mds ("a") == "0cc175b9c0f1b6a831c399e269772661" &&
     mds ("abc") == "900150983cd24fb0d6963f7d28e17f72" &&
     mds ("message digest") == "f96b697d7cb7938d525a2f31aaf161d0" &&
     mds ("abcdefghijklmnopqrstuvwxyz") == "c3fcd3d76192e4007dfb496cca67e13b" &&
     mds ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") ==
       "d174ab98d277d9f5a5611c2c9f419d9f" &&
     mds ("12345678901234567890123456789012345678901234567890123456789012345678901234567890") == "57edf4a22be3c955ac49da2e2107b67a"

tests = [ T prop_PartsEqWhole "PartsEqWhole"
        , T prop_ShowLen "ShowLen"
        , T prop_BinaryLen "BinaryLen"
        , T prop_GetPut "GetPut"
        , T prop_ShowElem "ShowElem"
        , T prop_KnownAnswers "KnownAnswers"]

data Test = forall a. Testable a => T a String
runTest (T a s) = do
    putStr ("prop_" ++ s ++ ": ")
    quickCheck a

runTests = mapM_ runTest tests
-}
