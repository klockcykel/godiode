package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type DirRecord struct {
	path  string
	modts uint32
}

type FileRecord struct {
	DirRecord
	size int64
}

type Manifest struct {
	dirs  []DirRecord
	files []FileRecord
}

/**
 * Manifest format
 * <number of dirs> | <dir-records> | <file records> | <signature>
 * number of dirs - uint32 - number of directory records
 * number of files - uint32 - number of file records
 * dir-records:
 *		len uint16 - path string length
 *      path string - path of the dir
 *      modts uint32 - the modification ts of the folder (unix epoch seconds)
 * file-records:
 *		len uint16 - path string length
 *      path string - path of the file
 *      modts uint32 - the modification ts of the folder (unix epoch seconds)
 *      size uint64 - size of the file in bytes
 * signature byte[64] - hmac512 of this packet
 */
func deserializeManifest(data []byte, hmacSecret string) (*Manifest, error) {
	l := len(data)
	if l < 64+4+4 {
		return nil, errors.New("Truncated manifest")
	}
	h512 := sha512.New()
	io.WriteString(h512, hmacSecret)
	mac := hmac.New(sha512.New, h512.Sum(nil))
	mac.Write(data[:l-64])
	sign := mac.Sum(nil)
	if !bytes.Equal(sign, data[l-64:]) {
		return nil, errors.New("Invalid manifest signature")
	}

	manifest := Manifest{}
	dl := int(binary.BigEndian.Uint32(data[0:]))
	fl := int(binary.BigEndian.Uint32(data[4:]))

	offset := 8
	//TODO: check lengths
	manifest.dirs = make([]DirRecord, dl)
	manifest.files = make([]FileRecord, fl)
	for i := 0; i < dl; i++ {
		plen := int(binary.BigEndian.Uint16(data[offset:]) & 0xFFFF)
		offset += 2
		//TODO: check lengths
		p := string(data[offset : offset+plen])
		offset += plen
		modts := binary.BigEndian.Uint32(data[offset:])
		offset += 4
		manifest.dirs[i] = DirRecord{p, modts}
	}
	for i := 0; i < fl; i++ {
		plen := int(binary.BigEndian.Uint16(data[offset:]) & 0xFFFF)
		offset += 2
		//TODO: check lengths
		p := string(data[offset : offset+plen])
		offset += plen
		modts := binary.BigEndian.Uint32(data[offset:])
		offset += 4
		s := binary.BigEndian.Uint64(data[offset:])
		offset += 8
		manifest.files[i] = FileRecord{DirRecord{p, modts}, int64(s)}
	}
	return &manifest, nil
}

func (m *Manifest) serializeManifest(hmacSecret string) ([]byte, error) {
	dirsSize := 0
	filesSize := 0
	for i := range m.dirs {
		dirsSize += 2 + len(m.dirs[i].path) + 4
	}
	for i := range m.files {
		filesSize += 2 + len(m.files[i].path) + 4 + 8
	}
	manifest := make([]byte, 4+4+dirsSize+filesSize+64)
	binary.BigEndian.PutUint32(manifest, uint32(len(m.dirs)))
	binary.BigEndian.PutUint32(manifest[4:], uint32(len(m.files)))
	offset := 8

	for i := range m.dirs {
		d := m.dirs[i]
		binary.BigEndian.PutUint16(manifest[offset:], uint16(len(d.path)))
		offset += 2
		copy(manifest[offset:], d.path)
		offset += len(d.path)
		binary.BigEndian.PutUint32(manifest[offset:], d.modts)
		offset += 4
	}
	for i := range m.files {
		f := m.files[i]
		binary.BigEndian.PutUint16(manifest[offset:], uint16(len(f.path)))
		offset += 2
		copy(manifest[offset:], f.path)
		offset += len(f.path)
		binary.BigEndian.PutUint32(manifest[offset:], f.modts)
		offset += 4
		binary.BigEndian.PutUint64(manifest[offset:], uint64(f.size))
		offset += 8
	}

	h512 := sha512.New()
	io.WriteString(h512, hmacSecret)
	mac := hmac.New(sha512.New, h512.Sum(nil))
	mac.Write(manifest[:offset])
	sign := mac.Sum(nil)
	copy(manifest[offset:], sign)
	return manifest, nil
}

func generateManifest(dir string) (*Manifest, error) {
	manifest := Manifest{make([]DirRecord, 0), make([]FileRecord, 0)}
	dir = path.Clean(dir)
	finfo, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}

	if finfo.IsDir() {
		dir = dir + "/"
		filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if p == dir {
				return nil
			}
			p = strings.Replace(p, dir, "", 1)
			if d.IsDir() {
				info, err := d.Info()
				if err != nil {
					return nil
				}
				manifest.dirs = append(manifest.dirs, DirRecord{p, uint32(info.ModTime().Unix())})
			} else {
				info, err := d.Info()
				if err != nil {
					return nil
				}
				manifest.files = append(manifest.files, FileRecord{DirRecord{p, uint32(info.ModTime().Unix())}, info.Size()})
			}
			return nil
		})
	} else {
		manifest.files = append(manifest.files, FileRecord{DirRecord{finfo.Name(), uint32(finfo.ModTime().Unix())}, finfo.Size()})
	}

	return &manifest, nil
}
