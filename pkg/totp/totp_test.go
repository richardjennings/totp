package totp

import (
	"testing"
)

/*
RFC 6238                      HOTPTimeBased                     May 2011


   The test token shared secret uses the ASCII string value
   "12345678901234567890".  With Time Step X = 30, and the Unix epoch as
   the initial value to count time steps, where T0 = 0, the TOTP
   algorithm will display the following values for specified modes and
   timestamps.

  +-------------+--------------+------------------+----------+--------+
  |  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
  +-------------+--------------+------------------+----------+--------+
  |      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
  |             |   00:00:59   |                  |          |        |
  |      59     |  1970-01-01  | 0000000000000001 | 46119246 | SHA256 |
  |             |   00:00:59   |                  |          |        |
  |      59     |  1970-01-01  | 0000000000000001 | 90693936 | SHA512 |
  |             |   00:00:59   |                  |          |        |
  |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
  |             |   01:58:29   |                  |          |        |
  |  1111111109 |  2005-03-18  | 00000000023523EC | 68084774 | SHA256 |
  |             |   01:58:29   |                  |          |        |
  |  1111111109 |  2005-03-18  | 00000000023523EC | 25091201 | SHA512 |
  |             |   01:58:29   |                  |          |        |
  |  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
  |             |   01:58:31   |                  |          |        |
  |  1111111111 |  2005-03-18  | 00000000023523ED | 67062674 | SHA256 |
  |             |   01:58:31   |                  |          |        |
  |  1111111111 |  2005-03-18  | 00000000023523ED | 99943326 | SHA512 |
  |             |   01:58:31   |                  |          |        |
  |  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
  |             |   23:31:30   |                  |          |        |
  |  1234567890 |  2009-02-13  | 000000000273EF07 | 91819424 | SHA256 |
  |             |   23:31:30   |                  |          |        |
  |  1234567890 |  2009-02-13  | 000000000273EF07 | 93441116 | SHA512 |
  |             |   23:31:30   |                  |          |        |
  |  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
  |             |   03:33:20   |                  |          |        |
  |  2000000000 |  2033-05-18  | 0000000003F940AA | 90698825 | SHA256 |
  |             |   03:33:20   |                  |          |        |
  |  2000000000 |  2033-05-18  | 0000000003F940AA | 38618901 | SHA512 |
  |             |   03:33:20   |                  |          |        |
  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
  |             |   11:33:20   |                  |          |        |
  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 77737706 | SHA256 |
  |             |   11:33:20   |                  |          |        |
  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 47863826 | SHA512 |
  |             |   11:33:20   |                  |          |        |
  +-------------+--------------+------------------+----------+--------+
*/

func TestGenerateTOTP(t *testing.T) {
	// https://www.rfc-editor.org/errata_search.php?rfc=6238
	sha1Secret := []byte("12345678901234567890")
	sha256Secret := []byte("12345678901234567890123456789012")
	sha512Secret := []byte("1234567890123456789012345678901234567890123456789012345678901234")
	opts := Opts{
		Timestep:        30,
		Secret:          sha1Secret,
		Digits:          8,
		Algorithm:       SHA1,
		CurrentUnixTime: 59,
	}
	for _, tcase := range []struct {
		mode   Algo
		secret []byte
		time   uint64
		totp   string
	}{
		{SHA1, sha1Secret, 59, "94287082"},
		{SHA256, sha256Secret, 59, "46119246"},
		{SHA512, sha512Secret, 59, "90693936"},
		{SHA1, sha1Secret, 1111111109, "07081804"},
		{SHA256, sha256Secret, 1111111109, "68084774"},
		{SHA512, sha512Secret, 1111111109, "25091201"},
		{SHA1, sha1Secret, 1111111111, "14050471"},
		{SHA256, sha256Secret, 1111111111, "67062674"},
		{SHA512, sha512Secret, 1111111111, "99943326"},
		{SHA1, sha1Secret, 1234567890, "89005924"},
		{SHA256, sha256Secret, 1234567890, "91819424"},
		{SHA512, sha512Secret, 1234567890, "93441116"},
		{SHA1, sha1Secret, 2000000000, "69279037"},
		{SHA256, sha256Secret, 2000000000, "90698825"},
		{SHA512, sha512Secret, 2000000000, "38618901"},
		{SHA1, sha1Secret, 20000000000, "65353130"},
		{SHA256, sha256Secret, 20000000000, "77737706"},
		{SHA512, sha512Secret, 20000000000, "47863826"},
	} {
		opts.Algorithm = tcase.mode
		opts.Secret = tcase.secret
		opts.CurrentUnixTime = tcase.time
		totp := GenerateTOTP(opts)
		if totp != tcase.totp {
			t.Errorf("expected %s got %s", tcase.totp, totp)
		}
	}
}
