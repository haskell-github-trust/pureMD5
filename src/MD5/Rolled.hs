{-# OPTIONS_GHC -fbang-patterns -funbox-strict-fields -fvia-c -optc-funroll-all-loops -optc-O3 #-}
--
-- Module      : Crypto.MD5
-- License     : BSD3
-- Maintainer  : Thomas.DuBuisson@gmail.com
-- Stability   : experimental
-- Portability : portable, requires bang patterns and ByteString
-- Tested with : GHC-6.8.0
--

module MD5.Rolled
	(md5
	,md5InitialContext
	,md5Update
	,md5Finalize
	,MD5Context
	,applyMD5Rounds
	) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.ByteString.Internal
import Data.Bits
import Data.List as T
import Data.Int (Int64)
import Data.Word
import Foreign.Storable
import Foreign.Ptr
import Foreign.ForeignPtr
import Numeric
import System.Environment
import System.IO
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put

blockSize = 512		-- Block size in bits
blockSizeBytes = blockSize `div` 8
blockSizeBytesW64 = fromIntegral blockSizeBytes
blockSizeBits = (fromIntegral blockSize) :: Word64

sinConst :: [Word32]
sinConst = [floor(abs(sin(i + 1)) * (2 ^ 32)) | i <- [0..63]]

roundShift :: [Int]
roundShift = [7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	      5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	      4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	      6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21 ]

data MD5Partial = MD5Par !Word32 !Word32 !Word32 !Word32
data MD5Context = MD5Ctx { mdPartial  :: MD5Partial,
			   mdLeftOver :: ByteString,
			   mdTotalLen :: Word64
			}

md5InitialContext = MD5Ctx (MD5Par h0 h1 h2 h3) B.empty 0
h0 = 0x67452301
h1 = 0xEFCDAB89
h2 = 0x98BADCFE
h3 = 0x10325476

-- | Will read the lazy ByteString and return the md5 digest.
--   Some application might want to wrap this function for type safty.
md5 :: L.ByteString -> L.ByteString
md5 bs = md5Finalize $ md5Update md5InitialContext bs

md5Finalize :: MD5Context -> L.ByteString
md5Finalize !ctx@(MD5Ctx (MD5Par a b c d) rem !totLen) =
	let totLen' = (totLen + 8*fromIntegral l) :: Word64
	    padBS = L.toChunks $ runPut ( do
			putWord8 0x80
			mapM_ putWord8 (replicate lenZeroPad 0)
			putWord64le totLen' )
	    (MD5Ctx (MD5Par a' b' c' d') _ _) = md5Update ctx (L.fromChunks (rem:padBS))
	in runPut ( do
		putWord32le a'
		putWord32le b'
		putWord32le c'
		putWord32le d' )

	where
	l = B.length rem
	lenZeroPad = if (l+1) <= blockSizeBytes - 8
			then (blockSizeBytes - 8) - (l+1)
			else (2*blockSizeBytes - 8) - (l+1)

md5Update :: MD5Context -> L.ByteString -> MD5Context
md5Update ctx bsLazy =
	let blks = block bsLazy
	in foldl' performMD5Update ctx blks

block :: L.ByteString -> [ByteString]
block bs =
	case L.toChunks bs of
		[] 		-> []
		otherwise	-> (B.concat . L.toChunks) top : block rest
	where
	(top,rest) = L.splitAt blockSizeBytesW64 bs
{-# INLINE block #-}

-- Assumes ByteString length == blockSizeBytes, will fold the 
-- context across calls to applyMD5Rounds.
performMD5Update :: MD5Context -> ByteString -> MD5Context
performMD5Update !ctx@(MD5Ctx !par@(MD5Par !a !b !c !d) _ !len) bs =
	let MD5Par a' b' c' d' = applyMD5Rounds par bs
	in if B.length bs == blockSizeBytes
		then MD5Ctx {
			mdPartial = MD5Par (a' + a) (b' + b) (c' + c) (d' + d),
			mdLeftOver = B.empty,
			mdTotalLen = len + blockSizeBits
			}
		else ctx { mdLeftOver = bs }

applyMD5Rounds :: MD5Partial -> ByteString -> MD5Partial
applyMD5Rounds par@(MD5Par a b c d) w =
	foldl' (md5Round w) par [0..63]

md5Round :: ByteString -> MD5Partial -> Int -> MD5Partial
md5Round w par@(MD5Par a b c d) !r
	| r <= 15 = let j  = r
			b' = ff a b c d (w!!j) rs sc
		    in MD5Par d b' b c
	| r <= 31 = let j  = (5*r + 1) `mod` 16
			b' = gg a b c d (w!!j) rs sc
		    in MD5Par d b' b c
	| r <= 47 = let j  = (3*r + 5) `mod` 16
			b' = hh a b c d (w!!j) rs sc
		    in MD5Par d b' b c
	| otherwise = let j  = (7*r) `mod` 16
			  b' = ii a b c d (w!!j) rs sc
		      in MD5Par d b' b c
	where
	rs = roundShift T.!! r
	sc = sinConst T.!! r
	f !x !y !z = (x .&. y) .|. ((complement x) .&. z)
	{-# INLINE f #-}
	g !x !y !z = (x .&. z) .|. (y .&. (complement z))
	{-# INLINE g #-}
	h !x !y !z = (x `xor` y `xor` z)
	{-# INLINE h #-}
	i !x !y !z = y `xor` (x .|. (complement z))
	{-# INLINE i #-}
	ff a b c d x s ac = {-# SCC "ff" #-}
		let !a' = f b c d + x + ac + a
		    !a'' = rotateL a' s
		in a'' + b
	{-# INLINE ff #-}
	gg a b c d x s ac = {-# SCC "gg" #-}
		let !a' = g b c d + x + ac + a
		    !a'' = rotateL a' s
		in a'' + b
	{-# INLINE gg #-}
	hh a b c d x s ac = {-# SCC "hh" #-}
		let !a' = h b c d + x + ac + a
		    !a'' = rotateL a' s
		    in a'' + b
	{-# INLINE hh #-}
	ii a b c d  x s ac = {-# SCC "ii" #-}
		let !a' = i b c d + x + ac + a
		    !a'' = rotateL a' s
		in a'' + b
	{-# INLINE ii #-}
	(!!) word32s pos = getNthWord pos word32s
	{-# INLINE (!!) #-}
--	getNthWord n bs = runGet (skip (n*4) >> getWord32le) (L.fromChunks [bs])
	getNthWord n bs@(PS ptr off len) =
		inlinePerformIO $ withForeignPtr ptr $ \ptr' -> do
		let p = castPtr $ plusPtr ptr' off
		peekElemOff p n
	{-# INLINE getNthWord #-}
{-# INLINE applyMD5Rounds #-}
