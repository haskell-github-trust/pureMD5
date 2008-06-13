import Control.Arrow
import Data.ByteString.Lazy.Char8
import Data.Digest.Pure.MD5
import Test.QuickCheck

instance Arbitrary Char where
  arbitrary = choose ('A', 'Z')

md5parts =
  (uncurry ((md5Finalize .) . md5Update . md5Update md5InitialContext) .)
  . curry (pack *** pack)

prop_md5 xs ys = show (md5 (pack (xs ++ ys))) == show (md5parts xs ys)

