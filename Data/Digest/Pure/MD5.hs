{-# LANGUAGE BangPatterns, ForeignFunctionInterface, MultiParamTypeClasses #-}
-----------------------------------------------------------------------------
--
-- Module      : Data.Digest.Pure.MD5
-- License     : BSD3
-- Maintainer  : Thomas.DuBuisson@gmail.com
-- Stability   : experimental
-- Portability : portable, requires bang patterns and ByteString
-- Tested with : GHC-6.8.1
--
-- |To get an MD5 digest of a lazy ByteString (you probably want this):
--   hash = md5 lazyByteString
--
-- Alternativly, for a context that can be further updated/finalized:
--   partialCtx = md5Update md5InitialContext partOfFile
--
-- And you finialize the context with:
--   hash = md5Finalize partialCtx
-----------------------------------------------------------------------------

module Data.Digest.Pure.MD5
	(
        -- * Types
          MD5Context
        , MD5Digest
        -- * Static data
        , md5InitialContext
        , blockSize
        -- * Functions
        , md5
        , md5Update
        , md5Finalize
        ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.ByteString.Internal
import Data.Bits
import Data.List
import Data.Int (Int64)
import Data.Word
import Foreign.Storable
import Foreign.Ptr
import Foreign.ForeignPtr
import System.IO
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import qualified Data.Serialize.Get as G
import qualified Data.Serialize.Put as P
import qualified Data.Serialize as S
import Data.Crypto.Classes
import Data.Tagged
import Numeric

-- | Block size in bits
md5BlockSize :: Int
md5BlockSize = 512

blockSizeBytes = md5BlockSize `div` 8
blockSizeBytesI64 = (fromIntegral blockSizeBytes) :: Int64
blockSizeBits = (fromIntegral md5BlockSize) :: Word64

-- | The type for intermediate results (from md5Update)
data MD5Partial = MD5Par !Word32 !Word32 !Word32 !Word32
    deriving (Ord, Eq)

-- | The type for final results.
data MD5Context = MD5Ctx { mdPartial  :: !MD5Partial,
                           mdLeftOver :: !ByteString,
                           mdTotalLen :: !Word64 }

-- |After finalizing a context, using md5Finalize, a new type
-- is returned to prevent 're-finalizing' the structure.
data MD5Digest = MD5Digest MD5Partial deriving (Eq, Ord)

-- | The initial context to use when calling md5Update for the first time
md5InitialContext :: MD5Context
md5InitialContext = MD5Ctx (MD5Par h0 h1 h2 h3) B.empty 0
h0 = 0x67452301
h1 = 0xEFCDAB89
h2 = 0x98BADCFE
h3 = 0x10325476

-- | Processes a lazy ByteString and returns the md5 digest.
--   This is probably what you want.
md5 :: L.ByteString -> MD5Digest
md5 = flip md5Finalize B.empty . foldl' md5Update md5InitialContext . L.toChunks -- hash

-- | Closes an MD5 context, thus producing the digest.
md5Finalize :: MD5Context -> B.ByteString -> MD5Digest
md5Finalize !ctx@(MD5Ctx (MD5Par a b c d) remPrev !totLen) end =
        let totLen' = (totLen + 8*fromIntegral l) :: Word64
            padBS = L.toChunks $ runPut ( do
                        putWord8 0x80
                        mapM_ putWord8 (replicate lenZeroPad 0)
                        putWord64le totLen' )
        in MD5Digest $ mdPartial $ md5Update ctx' (B.concat padBS)
    where
    ctx' = md5Update ctx rem
    rem = B.append remPrev end
    l = B.length rem
    lenZeroPad = if (l + 1) <= blockSizeBytes - 8
                     then (blockSizeBytes - 8) - (l + 1)
                     else (2 * blockSizeBytes - 8) - (l + 1)

-- | Alters the MD5Context with a partial digest of the data.
md5Update :: MD5Context -> B.ByteString -> MD5Context
md5Update !ctx@(MD5Ctx _ !leftover _) bs = blockAndDo ctx (B.append leftover bs)

blockAndDo :: MD5Context -> B.ByteString -> MD5Context
blockAndDo !ctx bs =
    if B.length blk == blockSizeBytes
        then let !newCtx = performMD5Update ctx blk
             in blockAndDo newCtx rest
        else ctx { mdLeftOver = blk }
  where
  blk = if isAligned top then top else B.copy top
  (top,rest) = B.splitAt blockSizeBytes bs
{-# INLINE blockAndDo #-}

-- Assumes ByteString length == blockSizeBytes, will fold the 
-- context across calls to applyMD5Rounds.
performMD5Update :: MD5Context -> B.ByteString -> MD5Context
performMD5Update !ctx@(MD5Ctx !par@(MD5Par !a !b !c !d) _ !len) !bs = {-# SCC "performMD5Update" #-}
        let MD5Par a' b' c' d' = applyMD5Rounds par bs
        in MD5Ctx {
                        mdPartial = MD5Par (a' + a) (b' + b) (c' + c) (d' + d),
                        mdLeftOver = B.empty,
                        mdTotalLen = len + blockSizeBits
                        }
{-# INLINE performMD5Update #-}

isAligned (PS _ off _) = off `rem` 4 == 0

applyMD5Rounds :: MD5Partial -> ByteString -> MD5Partial
applyMD5Rounds par@(MD5Par a b c d) w = {-# SCC "applyMD5Rounds" #-}
        let -- Round 1
            !r0  = ff  a  b  c  d   (w!!0)  7  3614090360
            !r1  = ff  d r0  b  c   (w!!1)  12 3905402710
            !r2  = ff  c r1 r0  b   (w!!2)  17 606105819
            !r3  = ff  b r2 r1 r0   (w!!3)  22 3250441966
            !r4  = ff r0 r3 r2 r1   (w!!4)  7  4118548399
            !r5  = ff r1 r4 r3 r2   (w!!5)  12 1200080426
            !r6  = ff r2 r5 r4 r3   (w!!6)  17 2821735955
            !r7  = ff r3 r6 r5 r4   (w!!7)  22 4249261313
            !r8  = ff r4 r7 r6 r5   (w!!8)  7  1770035416
            !r9  = ff r5 r8 r7 r6   (w!!9)  12 2336552879
            !r10 = ff r6 r9 r8 r7  (w!!10) 17 4294925233
            !r11 = ff r7 r10 r9 r8 (w!!11) 22 2304563134
            !r12 = ff r8 r11 r10 r9 (w!!12) 7  1804603682
            !r13 = ff r9 r12 r11 r10 (w!!13) 12 4254626195
            !r14 = ff r10 r13 r12 r11 (w!!14) 17 2792965006
            !r15 = ff r11 r14 r13 r12 (w!!15) 22 1236535329
            -- Round 2
            !r16 = gg r12 r15 r14 r13 (w!!1)  5  4129170786
            !r17 = gg r13 r16 r15 r14 (w!!6)  9  3225465664
            !r18 = gg r14 r17 r16 r15 (w!!11) 14 643717713
            !r19 = gg r15 r18 r17 r16 (w!!0)  20 3921069994
            !r20 = gg r16 r19 r18 r17 (w!!5)  5  3593408605
            !r21 = gg r17 r20 r19 r18 (w!!10) 9  38016083
            !r22 = gg r18 r21 r20 r19 (w!!15) 14 3634488961
            !r23 = gg r19 r22 r21 r20 (w!!4)  20 3889429448
            !r24 = gg r20 r23 r22 r21 (w!!9)  5  568446438
            !r25 = gg r21 r24 r23 r22 (w!!14) 9  3275163606
            !r26 = gg r22 r25 r24 r23 (w!!3)  14 4107603335
            !r27 = gg r23 r26 r25 r24 (w!!8)  20 1163531501
            !r28 = gg r24 r27 r26 r25 (w!!13) 5  2850285829
            !r29 = gg r25 r28 r27 r26 (w!!2)  9  4243563512
            !r30 = gg r26 r29 r28 r27 (w!!7)  14 1735328473
            !r31 = gg r27 r30 r29 r28 (w!!12) 20 2368359562
            -- Round 3
            !r32 = hh r28 r31 r30 r29 (w!!5)  4  4294588738
            !r33 = hh r29 r32 r31 r30 (w!!8)  11 2272392833
            !r34 = hh r30 r33 r32 r31 (w!!11) 16 1839030562
            !r35 = hh r31 r34 r33 r32 (w!!14) 23 4259657740
            !r36 = hh r32 r35 r34 r33 (w!!1)  4  2763975236
            !r37 = hh r33 r36 r35 r34 (w!!4)  11 1272893353
            !r38 = hh r34 r37 r36 r35 (w!!7)  16 4139469664
            !r39 = hh r35 r38 r37 r36 (w!!10) 23 3200236656
            !r40 = hh r36 r39 r38 r37 (w!!13) 4  681279174
            !r41 = hh r37 r40 r39 r38 (w!!0)  11 3936430074
            !r42 = hh r38 r41 r40 r39 (w!!3)  16 3572445317
            !r43 = hh r39 r42 r41 r40 (w!!6)  23 76029189
            !r44 = hh r40 r43 r42 r41 (w!!9)  4  3654602809
            !r45 = hh r41 r44 r43 r42 (w!!12) 11 3873151461
            !r46 = hh r42 r45 r44 r43 (w!!15) 16 530742520
            !r47 = hh r43 r46 r45 r44 (w!!2)  23 3299628645
            -- Round 4
            !r48 = ii r44 r47 r46 r45 (w!!0)  6  4096336452
            !r49 = ii r45 r48 r47 r46 (w!!7)  10 1126891415
            !r50 = ii r46 r49 r48 r47 (w!!14) 15 2878612391
            !r51 = ii r47 r50 r49 r48 (w!!5)  21 4237533241
            !r52 = ii r48 r51 r50 r49 (w!!12) 6  1700485571
            !r53 = ii r49 r52 r51 r50 (w!!3)  10 2399980690
            !r54 = ii r50 r53 r52 r51 (w!!10) 15 4293915773
            !r55 = ii r51 r54 r53 r52 (w!!1)  21 2240044497
            !r56 = ii r52 r55 r54 r53 (w!!8)  6  1873313359
            !r57 = ii r53 r56 r55 r54 (w!!15) 10 4264355552
            !r58 = ii r54 r57 r56 r55 (w!!6)  15 2734768916
            !r59 = ii r55 r58 r57 r56 (w!!13) 21 1309151649
            !r60 = ii r56 r59 r58 r57 (w!!4)  6  4149444226
            !r61 = ii r57 r60 r59 r58 (w!!11) 10 3174756917
            !r62 = ii r58 r61 r60 r59 (w!!2)  15 718787259
            !r63 = ii r59 r62 r61 r60 (w!!9)  21 3951481745
        in MD5Par r60 r63 r62 r61
        where
        f !x !y !z = (x .&. y) .|. ((complement x) .&. z)
        {-# INLINE f #-}
        g !x !y !z = (x .&. z) .|. (y .&. (complement z))
        {-# INLINE g #-}
        h !x !y !z = (x `xor` y `xor` z)
        {-# INLINE h #-}
        i !x !y !z = y `xor` (x .|. (complement z))
        {-# INLINE i #-}
        ff a b c d !x s ac = {-# SCC "ff" #-}
                let !a' = f b c d + x + ac + a
                    !a'' = rotateL a' s
                in a'' + b
        {-# INLINE ff #-}
        gg a b c d !x s ac = {-# SCC "gg" #-}
                let !a' = g b c d + x + ac + a
                    !a'' = rotateL a' s
                in a'' + b
        {-# INLINE gg #-}
        hh a b c d !x s ac = {-# SCC "hh" #-}
                let !a' = h b c d + x + ac + a
                    !a'' = rotateL a' s
                    in a'' + b
        {-# INLINE hh #-}
        ii a b c d  !x s ac = {-# SCC "ii" #-}
                let !a' = i b c d + x + ac + a
                    !a'' = rotateL a' s
                in a'' + b
        {-# INLINE ii #-}
        (!!) word32s pos = getNthWord pos word32s
        {-# INLINE (!!) #-}
{-# INLINE applyMD5Rounds #-}

getNthWord :: Int -> B.ByteString -> Word32
getNthWord n = right . G.runGet (do
                G.uncheckedSkip (n * sizeOf (undefined :: Word32))
                G.getWord32le)
  where
  right x = case x of Right y -> y
{-# INLINE getNthWord #-}

infix 9 .<.
(.<.) :: Word8 -> Int -> Word32
(.<.) w i = (fromIntegral w) `shiftL` i

----- Some quick and dirty instances follow -----

instance Show MD5Digest where
    show (MD5Digest h) = show h

instance Show MD5Partial where
  show (MD5Par a b c d) = 
    let bs = runPut $ putWord32be d >> putWord32be c >> putWord32be b >> putWord32be a
    in foldl' (\str w -> let c = showHex w str
                         in if length c < length str + 2
                                 then '0':c
                                else c) "" (L.unpack bs)

instance Binary MD5Digest where
    put (MD5Digest p) = put p
    get = do
        p <- get
        return $ MD5Digest p

instance Binary MD5Context where
        put (MD5Ctx p r l) = put p >> putWord8 (fromIntegral (B.length r)) >> 
                             putByteString r >> putWord64be l
        get = do p <- get
                 s <- getWord8
                 r <- getByteString (fromIntegral s)
                 l <- getWord64be
                 return $ MD5Ctx p r l

instance Binary MD5Partial where
        put (MD5Par a b c d) = putWord32le a >> putWord32le b >> putWord32le c >> putWord32le d
        get = do a <- getWord32le
                 b <- getWord32le
                 c <- getWord32le
                 d <- getWord32le
                 return $ MD5Par a b c d

instance S.Serialize MD5Digest where
    put (MD5Digest p) = S.put p
    get = do
        p <- S.get
        return $ MD5Digest p

instance S.Serialize MD5Context where
        put (MD5Ctx p r l) = S.put p >> P.putWord8 (fromIntegral (B.length r)) >>
                             P.putByteString r >> P.putWord64be l
        get = do p <- S.get
                 s <- G.getWord8
                 r <- G.getByteString (fromIntegral s)
                 l <- G.getWord64be
                 return $ MD5Ctx p r l

instance S.Serialize MD5Partial where
	put (MD5Par a b c d) = P.putWord32le a >> P.putWord32le b >> P.putWord32le c >> P.putWord32le d
	get = do a <- G.getWord32le
		 b <- G.getWord32le
		 c <- G.getWord32le
		 d <- G.getWord32le
		 return $ MD5Par a b c d

instance Hash MD5Context MD5Digest where
	outputLength = Tagged 128
	blockLength  = Tagged 512
	initialCtx   = md5InitialContext
	updateCtx    = md5Update
	finalize     = md5Finalize
