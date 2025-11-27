package main

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/bits"
	"sort"
)

/* -----------------------------------------------------
   S-box / P-box
----------------------------------------------------- */

var (
	S = [16]uint8{
		0xC, 0x5, 0x6, 0xB,
		0x9, 0x0, 0xA, 0xD,
		0x3, 0xE, 0xF, 0x8,
		0x4, 0x7, 0x1, 0x2,
	}

	InvS [16]uint8

	P = [16]uint8{
		0x0, 0x4, 0x8, 0xC,
		0x1, 0x5, 0x9, 0xD,
		0x2, 0x6, 0xA, 0xE,
		0x3, 0x7, 0xB, 0xF,
	}

	InvP [16]uint8

	rounds = 4
)

/* -----------------------------------------------------
   Utility
----------------------------------------------------- */

func dotParity16(mask uint16, v uint16) uint8 {
	return uint8(bits.OnesCount16(mask&v) & 1)
}

func makeLAT(sbox [16]uint8) [16][16]int {
	var lat [16][16]int
	for a := 0; a < 16; a++ {
		for b := 0; b < 16; b++ {
			cnt := 0
			for x := 0; x < 16; x++ {
				l := bits.OnesCount8(uint8(x)&uint8(a)) & 1
				r := bits.OnesCount8(sbox[x]&uint8(b)) & 1
				if (l ^ r) == 0 {
					cnt++
				}
			}
			lat[a][b] = cnt - 8
		}
	}
	return lat
}

/* -----------------------------------------------------
   SPN Components
----------------------------------------------------- */

func SubBytes(x uint16, s [16]uint8) uint16 {
	return (uint16(s[(x>>12)&0xF]) << 12) |
		(uint16(s[(x>>8)&0xF]) << 8) |
		(uint16(s[(x>>4)&0xF]) << 4) |
		uint16(s[x&0xF])
}

func InvSubBytes(x uint16, s [16]uint8) uint16 {
	return (uint16(s[(x>>12)&0xF]) << 12) |
		(uint16(s[(x>>8)&0xF]) << 8) |
		(uint16(s[(x>>4)&0xF]) << 4) |
		uint16(s[x&0xF])
}

func PermuteBits(x uint16, p [16]uint8) uint16 {
	var r uint16 = 0
	for i := 0; i < 16; i++ {
		b := (x >> i) & 1
		r |= b << p[i]
	}
	return r
}

/* -----------------------------------------------------
   SPN Encrypt/Decrypt
----------------------------------------------------- */

func EncryptBlock(x uint16, keys []uint16) uint16 {
	for r := 0; r < rounds-1; r++ {
		x ^= keys[r]
		x = SubBytes(x, S)
		x = PermuteBits(x, P)
	}
	x ^= keys[rounds-1]
	x = SubBytes(x, S)
	x ^= keys[rounds]
	return x
}

func DecryptBlock(x uint16, keys []uint16) uint16 {
	x ^= keys[rounds]
	x = InvSubBytes(x, InvS)
	x ^= keys[rounds-1]

	for r := rounds - 2; r >= 0; r-- {
		x = PermuteBits(x, InvP)
		x = InvSubBytes(x, InvS)
		x ^= keys[r]
	}
	return x
}

func EncryptSPN(arr []uint16, keys []uint16) []uint16 {
	out := make([]uint16, len(arr))
	for i := range arr {
		out[i] = EncryptBlock(arr[i], keys)
	}
	return out
}

/* -----------------------------------------------------
   Key schedule
----------------------------------------------------- */

func GenerateKeys16(rounds int) ([]uint16, error) {
	var kb [2]byte
	_, err := rand.Read(kb[:])
	if err != nil {
		return nil, err
	}
	k := uint16(kb[0])<<8 | uint16(kb[1])

	keys := make([]uint16, rounds+1)
	for i := 0; i <= rounds; i++ {
		keys[i] = k
		k = bits.RotateLeft16(k, 4)
	}
	return keys, nil
}

/* -----------------------------------------------------
   Linear cryptanalysis: partial key guess
----------------------------------------------------- */

// gamma = mask on U4 (input to last S-box layer)
// guess = 8 bits:
//   high nibble => nibble 3
//   low nibble  => nibble 1

func partialDecryptU4(C uint16, guess uint8) uint16 {
	var k uint16
	k |= uint16((guess>>4)&0xF) << 12 // nibble 3
	k |= uint16((guess)&0xF) << 4     // nibble 1

	tmp := C ^ k
	U4 := InvSubBytes(tmp, InvS)
	return U4
}

func AttackRecoverPartialKey(PT, CT []uint16, alpha, gamma uint16) (uint8, []int) {
	N := len(PT)
	counts := make([]int, 256)

	for g := 0; g < 256; g++ {
		c := 0
		for i := 0; i < N; i++ {
			left := dotParity16(alpha, PT[i])

			U4 := partialDecryptU4(CT[i], uint8(g))
			right := dotParity16(gamma, U4)

			if left^right == 0 {
				c++
			}
		}
		counts[g] = c
	}

	bestG := 0
	bestDev := 0.0
	half := float64(N) * 0.5

	for g := 0; g < 256; g++ {
		dev := math.Abs(float64(counts[g]) - half)
		if dev > bestDev {
			bestDev = dev
			bestG = g
		}
	}

	return uint8(bestG), counts
}

/* -----------------------------------------------------
   Full key recovery from partial candidates
----------------------------------------------------- */

func RecoverFullKey(PT, CT []uint16, partial []int) []uint16 {
	N := len(PT)
	var found []uint16
	checkPairs := 30 // проверяем только первые 30 пар

	if N < checkPairs {
		checkPairs = N
	}

	for _, p := range partial {
		n3 := uint16((p >> 4) & 0xF)
		n1 := uint16(p & 0xF)

		for n2 := 0; n2 < 16; n2++ {
			for n0 := 0; n0 < 16; n0++ {
				k := uint16(n3)<<12 | uint16(n2)<<8 | uint16(n1)<<4 | uint16(n0)

				keys := make([]uint16, rounds+1)
				cur := k
				for i := range keys {
					keys[i] = cur
					cur = bits.RotateLeft16(cur, 4)
				}

				ok := true
				for i := 0; i < checkPairs; i++ {
					if DecryptBlock(CT[i], keys) != PT[i] {
						ok = false
						break
					}
				}
				if ok {
					found = append(found, k)
				}
			}
		}
	}

	return found
}

/* -----------------------------------------------------
   Helper: top K
----------------------------------------------------- */

type pair struct {
	g, c int
}

func topK(counts []int, K int) []pair {
	arr := make([]pair, 256)
	for g := 0; g < 256; g++ {
		arr[g] = pair{g, counts[g]}
	}
	sort.Slice(arr, func(i, j int) bool {
		return arr[i].c > arr[j].c
	})
	if K > len(arr) {
		K = len(arr)
	}
	return arr[:K]
}

// Convert text string into []uint16 blocks
func TextToBlocks(text string) []uint16 {
	b := []byte(text)
	if len(b)%2 != 0 {
		b = append(b, 0) // дополняем нулём, если нечётное число символов
	}
	blocks := make([]uint16, len(b)/2)
	for i := 0; i < len(b)/2; i++ {
		blocks[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}
	return blocks
}

// Convert []uint16 blocks back into string
func BlocksToText(blocks []uint16) string {
	b := make([]byte, len(blocks)*2)
	for i, bl := range blocks {
		b[2*i] = byte(bl >> 8)
		b[2*i+1] = byte(bl & 0xFF)
	}
	// удаляем нули в конце (если были добавлены для выравнивания)
	return string(b)
}

/* -----------------------------------------------------
   MAIN
----------------------------------------------------- */

func main() {
	// Prepare inverses
	for i := 0; i < 16; i++ {
		InvS[S[i]] = uint8(i)
		InvP[P[i]] = uint8(i)
	}

	// LAT print
	lat := makeLAT(S)
	fmt.Println("LAT:")
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			fmt.Printf("%4d", lat[i][j])
		}
		fmt.Println()
	}

	keys, err := GenerateKeys16(rounds)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\nREAL last key = 0x%04X\n", keys[rounds])

	N := 10000
	PT := make([]uint16, N)
	for i := 0; i < N; i++ {
		var b [2]byte
		rand.Read(b[:])
		PT[i] = uint16(b[0])<<8 | uint16(b[1])
	}
	CT := EncryptSPN(PT, keys)

	alpha := uint16(0x1010)
	gamma := uint16(0x2020)

	guess, counts := AttackRecoverPartialKey(PT, CT, alpha, gamma)
	fmt.Printf("Best guess = 0x%02X\n", guess)

	trueNib3 := (keys[rounds] >> 12) & 0xF
	trueNib1 := (keys[rounds] >> 4) & 0xF
	fmt.Printf("True value = 0x%02X\n", trueNib3<<4|trueNib1)

	top := topK(counts, 10)
	fmt.Println("Top candidates:")
	for _, t := range top {
		fmt.Printf("0x%02X : %d\n", t.g, t.c)
	}

	pars := make([]int, 0, 10)
	for _, t := range top {
		pars = append(pars, t.g)
	}

	found := RecoverFullKey(PT, CT, pars)
	fmt.Println("\nRecovered full keys:", found)
	if len(found) > 0 {
		fmt.Println("\n--- Demo decryption with text ---")

		testPTText := "Piska popka i zalupk" // текстовый формат
		testPT := TextToBlocks(testPTText)

		// 1) Шифруем настоящими ключами
		testCT := EncryptSPN(testPT, keys)

		// 2) Восстанавливаем round keys из найденного основного ключа
		keysRecovered := make([]uint16, rounds+1)
		cur := found[0]
		for i := range keysRecovered {
			keysRecovered[i] = cur
			cur = bits.RotateLeft16(cur, 4)
		}

		// 3) Расшифровываем найденными ключами
		decrypted := make([]uint16, len(testCT))
		for i := range testCT {
			decrypted[i] = DecryptBlock(testCT[i], keysRecovered)
		}

		decryptedText := BlocksToText(decrypted)

		fmt.Printf("Test PT = %q\n", testPTText)
		fmt.Printf("Encrypted blocks = %v\n", testCT)
		fmt.Printf("Decrypted text = %q\n", decryptedText)
	}

}
