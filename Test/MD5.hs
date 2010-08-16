{-# LANGUAGE ExistentialQuantification #-}
module Test.MD5 where

import Test.QuickCheck
import Test.Crypto
import Data.Digest.Pure.MD5

test = runTests (makeMD5Tests (undefined :: MD5Digest))
