package main

import (
	"crypto/rand"
	"fmt"
	"math/bits"
)

var (
	S = [16]uint8{
		0xC, 0x5, 0x6, 0xB,
		0x9, 0x0, 0xA, 0xD,
		0x3, 0xE, 0xF, 0x8,
		0x4, 0x7, 0x1, 0x2,
	}

	P = [16]uint8{
		0x0, 0x4, 0x8, 0xC,
		0x1, 0x5, 0x9, 0xD,
		0x2, 0x6, 0xA, 0xE,
		0x3, 0x7, 0xB, 0xF,
	}

	rounds = 4
)


func SubBytes(block uint16, sbox [16]uint8) uint16 {
	return uint16(sbox[(block >> 12)])
}
func main() {
	plainText := "secret"
	data := []byte(plainText)

	var blocks []uint16

	for i := 0; i < len(data); i += 2 {
		var block uint16
		block = uint16(data[i]) << 8
		if i+1 < len(data) {
			block |= uint16(data[i+1])
		} else {
			block |= 0x00
		}
		blocks = append(blocks, block)
	}

	for _, b := range blocks {
		fmt.Printf("%04X ", b)

	}
	fmt.Println()

	var keyBytes [2]byte
	_, err := rand.Read(keyBytes[:])
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	key := uint16(keyBytes[0])<<8 | uint16(keyBytes[1])

	fmt.Printf("%02X\n", keyBytes)

	for r := 0; r < rounds; r++ {
		for _, b := range blocks {
			b ^= key
			
		}
		key = bits.RotateLeft16(key, 4)
	}

}
