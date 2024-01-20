package utils

import "bytes"

type ByteBuffer struct {
	Buf []byte
}

func (b *ByteBuffer) Append(data []byte) {
	b.Buf = append(b.Buf, data...)
}

func (b *ByteBuffer) Len() int {
	return len(b.Buf)
}

func (b *ByteBuffer) Index(sep []byte) int {
	return bytes.Index(b.Buf, sep)
}

func (b *ByteBuffer) Get(length int, consume bool) (data []byte, ok bool) {
	if len(b.Buf) < length {
		return nil, false
	}
	data = b.Buf[:length]
	if consume {
		b.Buf = b.Buf[length:]
	}
	return data, true
}

func (b *ByteBuffer) GetString(length int, consume bool) (string, bool) {
	data, ok := b.Get(length, consume)
	if !ok {
		return "", false
	}
	return string(data), true
}

func (b *ByteBuffer) GetByte(consume bool) (byte, bool) {
	data, ok := b.Get(1, consume)
	if !ok {
		return 0, false
	}
	return data[0], true
}

func (b *ByteBuffer) GetUint16(littleEndian, consume bool) (uint16, bool) {
	data, ok := b.Get(2, consume)
	if !ok {
		return 0, false
	}
	if littleEndian {
		return uint16(data[0]) | uint16(data[1])<<8, true
	}
	return uint16(data[1]) | uint16(data[0])<<8, true
}

func (b *ByteBuffer) GetUint32(littleEndian, consume bool) (uint32, bool) {
	data, ok := b.Get(4, consume)
	if !ok {
		return 0, false
	}
	if littleEndian {
		return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24, true
	}
	return uint32(data[3]) | uint32(data[2])<<8 | uint32(data[1])<<16 | uint32(data[0])<<24, true
}

func (b *ByteBuffer) GetUntil(sep []byte, includeSep, consume bool) (data []byte, ok bool) {
	index := b.Index(sep)
	if index == -1 {
		return nil, false
	}
	if includeSep {
		index += len(sep)
	}
	return b.Get(index, consume)
}

func (b *ByteBuffer) GetSubBuffer(length int, consume bool) (sub *ByteBuffer, ok bool) {
	data, ok := b.Get(length, consume)
	if !ok {
		return nil, false
	}
	return &ByteBuffer{Buf: data}, true
}

func (b *ByteBuffer) Skip(length int) bool {
	if len(b.Buf) < length {
		return false
	}
	b.Buf = b.Buf[length:]
	return true
}

func (b *ByteBuffer) Reset() {
	b.Buf = nil
}
