package hotp

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
)

// GenerateHOTP generates a HMAC-Based One-Time Password Algorithm
func GenerateHOTP(hash func() hash.Hash, secret []byte, counter uint64, length uint) string {
	countBytes := make([]byte, 8)
	/*
		Step 1: Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)  // HS is a 20-byte string
	*/
	h := hmac.New(hash, secret)
	binary.BigEndian.PutUint64(countBytes, counter)
	h.Write(countBytes)
	bytes := h.Sum(nil)
	/*
			Step 2: Generate a 4-byte string (Dynamic Truncation)
			Let Sbits = DT(HS)   //  DT, defined below,
		                        //  returns a 31-bit string
			DT(String) // String = String[0]...String[19]
		     Let OffsetBits be the low-order 4 bits of String[19]
		     Offset = StToNum(OffsetBits) // 0 <= OffSet <= 15
		     Let P = String[OffSet]...String[OffSet+3]
		     Return the Last 31 bits of P
	*/

	offsetBits := bytes[len(bytes)-1] & 0xf
	Snum := (int(bytes[offsetBits])&0x7f)<<24 |
		(int(bytes[offsetBits+1]&0xff))<<16 |
		(int(bytes[offsetBits+2]&0xff))<<8 |
		int(bytes[offsetBits+3])&0xff

	/*
			Step 3: Compute an HOTP value
		   	Let Snum  = StToNum(Sbits)   // Convert S to a number in
		                                    0...2^{31}-1
		   	Return D = Snum mod 10^Digit //  D is a number in the range
		                                    0...10^{Digit}-1
	*/
	// thanks https://stackoverflow.com/a/51546906 did not know about *
	return fmt.Sprintf("%0*d", int(length), int64(Snum)%int64(math.Pow10(int(length))))
}
