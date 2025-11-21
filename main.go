package main

import (
	"bytes"
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

	InvS [16]uint8
	InvP [16]uint8

	rounds = 4
)

func SubBytes(block uint16, sbox [16]uint8) uint16 {
	return uint16(sbox[(block>>12)&0xF])<<12 |
		uint16(sbox[(block>>8)&0xF])<<8 |
		uint16(sbox[(block>>4)&0xF])<<4 |
		uint16(sbox[(block&0xF)])
}

func PermuteBytes(block uint16, pbox [16]uint8) uint16 {
	var res uint16 = 0
	for i := 0; i < 16; i++ {
		bit := (block >> i) & 1
		res |= bit << pbox[i]
	}
	return res
}

func SplitIntoBlocks16(s string) []uint16 {
	data := PKCS7Pad([]byte(s), 2)

	var blocks []uint16

	for i := 0; i < len(data); i += 2 {
		var block uint16
		block = uint16(data[i])<<8 | uint16(data[i+1])

		blocks = append(blocks, block)
	}

	return blocks
}

func GenerateKeys16(rounds int) ([]uint16, error) {
	var keyBytes [2]byte
	_, err := rand.Read(keyBytes[:])
	if err != nil {
		return nil, err
	}

	key := uint16(keyBytes[0])<<8 | uint16(keyBytes[1])

	keys := make([]uint16, rounds+1)
	for i := range rounds + 1 {
		keys[i] = key
		key = bits.RotateLeft16(key, 4)
	}

	return keys, nil
}

func EncryptSPN(blocks []uint16, keys []uint16, rounds int) []uint16 {
	for r := 0; r < rounds-1; r++ {
		for i := range blocks {
			blocks[i] = SPNRound(blocks[i], keys[r], S, P)
		}
	}

	for i := range blocks {
		blocks[i] ^= keys[rounds-1]
		blocks[i] = SubBytes(blocks[i], S)
	}

	for i := range blocks {
		blocks[i] ^= keys[rounds]
	}

	return blocks
}

func DecryptSPN(blocks []uint16, keys []uint16, rounds int) []uint16 {
	// Последний раунд
	for i := range blocks {
		blocks[i] ^= keys[rounds]
		blocks[i] = SubBytes(blocks[i], InvS) // обратный S-блок
		blocks[i] ^= keys[rounds-1]
	}

	// Основные раунды в обратном порядке
	for r := rounds - 2; r >= 0; r-- {
		for i := range blocks {
			blocks[i] = PermuteBytes(blocks[i], InvP) // обратная перестановка
			blocks[i] = SubBytes(blocks[i], InvS)     // обратный S-блок
			blocks[i] ^= keys[r]
		}
	}

	return blocks
}

func SPNRound(block uint16, roundKey uint16, sbox [16]uint8, pbox [16]uint8) uint16 {
	block ^= roundKey
	block = SubBytes(block, sbox)
	block = PermuteBytes(block, pbox)
	return block
}

func JoinIntoBytes(blocks []uint16) (out []byte) {
	for _, b := range blocks {
		out = append(out, byte(b>>8))
		out = append(out, byte(b))
	}

	return out
}

func PKCS7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	if padLen == 0 {
		padLen = blockSize
	}
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, pad...)
}

func PKCS7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padLen], nil
}

func main() {
	for i, v := range S {
		InvS[v] = uint8(i)
	}
	for i, v := range P {
		InvP[v] = uint8(i)
	}
	plainText := "secret"
	fmt.Printf("Полученные блоки байт: %v\n", []byte(plainText))
	blocks := SplitIntoBlocks16(plainText)

	keys, err := GenerateKeys16(rounds)
	if err != nil {
		fmt.Printf("Ошибка генервции ключа: %v\n", err)
		return
	}

	encryptedBlocks := EncryptSPN(blocks, keys, rounds)
	decryptedBlocks := DecryptSPN(encryptedBlocks, keys, rounds)
	decryptedBytes := JoinIntoBytes(decryptedBlocks)
	decryptedBytesUnpad, err := PKCS7Unpad(decryptedBytes)
	if err != nil {
		fmt.Printf("Ошибка Unpad: %v", err)
	}
	fmt.Println(string(decryptedBytesUnpad))
}
