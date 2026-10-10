package disk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// A shard file is a sequence of records, one per erasure block:
//
//	[HashSize bytes: SHA-256 of the shard bytes][shard bytes]
//
// Every block but the last of a part has the full shard length.

// HashSize is the size of a block hash.
const HashSize = sha256.Size

// ShardLen is the size of one shard of a block of blockLen bytes when the
// block is split over dataBlocks data shards.
func ShardLen(blockLen int64, dataBlocks int) int64 {
	return (blockLen + int64(dataBlocks) - 1) / int64(dataBlocks)
}

// BlockCount is the number of erasure blocks of a part.
func BlockCount(partSize, blockSize int64) int64 {
	return (partSize + blockSize - 1) / blockSize
}

// ShardFileSize is the size of one drive's shard file for a part.
func ShardFileSize(partSize, blockSize int64, dataBlocks int) int64 {
	if partSize <= 0 {
		return 0
	}
	size := (partSize / blockSize) * (HashSize + ShardLen(blockSize, dataBlocks))
	if rem := partSize % blockSize; rem > 0 {
		size += HashSize + ShardLen(rem, dataBlocks)
	}
	return size
}

// VerifyStream reads a whole shard file, checking every block's hash, and
// returns the checksum root: the SHA-256 over the block hashes.
func VerifyStream(r io.ReaderAt, partSize, blockSize int64, dataBlocks int) (string, error) {
	root := sha256.New()
	for b := int64(0); b < BlockCount(partSize, blockSize); b++ {
		blockLen := min(blockSize, partSize-b*blockSize)
		buf := make([]byte, HashSize+ShardLen(blockLen, dataBlocks))
		if _, err := r.ReadAt(buf, b*(HashSize+ShardLen(blockSize, dataBlocks))); err != nil {
			return "", err
		}
		sum := sha256.Sum256(buf[HashSize:])
		if string(sum[:]) != string(buf[:HashSize]) {
			return "", fmt.Errorf("block %d fails its hash", b)
		}
		root.Write(sum[:])
	}
	return hex.EncodeToString(root.Sum(nil)), nil
}
