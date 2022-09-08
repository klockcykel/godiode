package main

import (
	"bytes"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	//	"flag"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"log"
	"math"
	"net"
	"os"
	"path"
	"strconv"
	"time"
)

type PendingManifestTransfer struct {
	buff   []byte
	offset int
	index  int
}

type PendingFileTransfer struct {
	size          uint64
	offset        uint64
	index         uint8
	rawSize       uint64
	hash          hash.Hash
	file          *os.File
	transferStart time.Time
	err           *error
	filename      string
	fileIndex     int
	modts         uint32
}

type Receiver struct {
	conf                    *Config
	dir                     string
	tmpDir                  string
	manifest                *Manifest
	manifestId              int
	pendingFileTransfer     *PendingFileTransfer
	pendingManifestTransfer *PendingManifestTransfer
}

func (r *Receiver) onFileTransferData(buff []byte, read int) error {
	pt := r.pendingFileTransfer
	if pt == nil || read < 1 || pt.err != nil {
		return nil
	}

	idx := buff[0] & 0x7F
	if idx == pt.index {
		//check out of order packets
		if pt.offset+uint64(read-1) > pt.size {
			err := errors.New("Received too much data on file")
			pt.err = &err
			pt.file.Close()
			os.Remove(pt.filename)
			return err
		}
		pt.hash.Write(buff[1:read])
		pt.file.Write(buff[1:read])
		pt.index = (pt.index + 1) & 0x7F
		pt.offset += uint64(read - 1)
		pt.rawSize += uint64(HEADER_OVERHEAD + read)
		if pt.offset == uint64(read-1) && r.conf.Verbose {
			//			fmt.Println("Received first byte of data of " + pt.filename)
		}
		if pt.offset == pt.size {
			//done, wait for file complete packet
		}
	} else {
		//log.Fatal("Received out of order packet ", ptype&0x7F, pt.index, pt.offset)
		err := errors.New("Received out of order packet for file transfer")
		pt.err = &err
		return err
	}
	return nil
}

/*
 * file transfer start packet
 *
 * type - uint8 - 0x02
 * filetype - uint8 - (regular file)
 * manifestSessionId - uint32 - manifest session id
 * fileIndex - uint32 - file index in the manifest
 * size - uint64 - size of file in bytes
 * mtime - int64 - unix millis
 * sign - byte[64] - hmac512 of this header
 */
func (r *Receiver) onFileTransferStart(buff []byte, read int) error {
	if read < 1+1+4+4+8+8+64 {
		return errors.New("Received truncated file transfer start packet")
	}
	if r.pendingFileTransfer != nil {
		//TODO: check if same file
		fmt.Fprintf(os.Stderr, "Received new file transfer with previous still pending\n")
		r.pendingFileTransfer.file.Close()
		r.pendingFileTransfer = nil
	}

	if r.manifest == nil {
		return errors.New("Received file transfer start packet without pending manifest")
	}

	if buff[1] != 0 {
		return errors.New("Ignoring file transfer start with unknown file type " + strconv.Itoa(int(buff[2])))
	}

	manifestId := int(binary.BigEndian.Uint32(buff[2:]))
	if manifestId != r.manifestId {
		return errors.New("Ignoring file transfer start for another manifest " + strconv.Itoa(manifestId) + " " + strconv.Itoa(manifestId))
	}

	fileIndex := int(binary.BigEndian.Uint32(buff[6:]))
	if fileIndex < 0 || fileIndex >= len(r.manifest.files) {
		return errors.New("Ignoring file transfer start for invalid file index")
	}

	mf := r.manifest.files[fileIndex]

	//sanitize path
	fp := path.Clean(r.dir + mf.path)
	if fp == "." {
		return errors.New("Invalid file path name")
	}

	size := binary.BigEndian.Uint64(buff[10:])

	h512 := sha512.New()
	io.WriteString(h512, r.conf.HMACSecret)
	mac := hmac.New(sha512.New, h512.Sum(nil))
	mac.Write(buff[:26])
	if !bytes.Equal(mac.Sum(nil), buff[26:26+64]) {
		return errors.New("Invalid signature in file start packet for " + fp)
	}

	tmpFile := path.Join(r.tmpDir, "godiodetmp."+strconv.FormatUint(uint64(manifestId), 16)+"."+strconv.Itoa(fileIndex))
	file, err := os.OpenFile(tmpFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, r.conf.Receiver.FilePermission)
	if err != nil {
		return errors.New("Failed to create file " + fp + ": " + err.Error())
	}
	r.pendingFileTransfer = &PendingFileTransfer{
		size:          size,
		hash:          sha256.New(),
		file:          file,
		transferStart: time.Now(),
		filename:      fp,
		fileIndex:     fileIndex,
		modts:         mf.modts,
	}
	return nil
}

func (r *Receiver) moveTmpFile(pft *PendingFileTransfer, tmpFile string) {
	timeTaken := float64(time.Duration.Seconds(time.Since(pft.transferStart)))
	err := os.Rename(tmpFile, pft.filename)
	if err != nil {
		//TODO: fallback to copy+rm (file may be located on another fs)
		fmt.Fprintf(os.Stderr, "Failed to move tmp file "+pft.filename+" "+err.Error()+"\n")
		return
	}
	err = os.Chtimes(pft.filename, time.Unix(int64(pft.modts), 0), time.Unix(int64(pft.modts), 0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to set mtime on "+pft.filename+"\n")
	}
	if r.conf.Verbose {
		var speed int = 0
		if timeTaken > 0 {
			speed = int(math.Round(float64((8*pft.size)/1000) / timeTaken))
		}
		h := pft.hash.Sum(nil)
		fmt.Println("Successfully received " + pft.filename + ", checksum=" + hex.EncodeToString(h) + " size=" + strconv.FormatInt(int64(pft.size), 10) + " " + strconv.Itoa(speed) + "kbit/s")
	}
	return
}

/*
 * file transfer complete packet
 *
 * type - uint8 - 0x03
 * manifestSessionId - uint32 - manifest session id
 * fileIndex - uint32 - file index in the manifest
 * hash - byte[32] - sha256 of file content
 * sign - byte[64] - hmac512 of this packet
 */
func (r *Receiver) onFileTransferComplete(buff []byte, read int) error {
	if read < 1+4+4+32+64 {
		return errors.New("Received truncated file transfer complete packet")
	}

	pft := r.pendingFileTransfer
	if pft == nil {
		return errors.New("Received file transfer complete packet without pending transfer")
	}

	offset := 1
	manifestId := int(binary.BigEndian.Uint32(buff[offset:]))
	offset += 4
	if manifestId != r.manifestId {
		return errors.New("Ignoring file transfer complete for another manifest " + strconv.Itoa(manifestId) + " " + strconv.Itoa(manifestId))
	}

	fileIndex := int(binary.BigEndian.Uint32(buff[offset:]))
	offset += 4
	if fileIndex != pft.fileIndex {
		return errors.New("Ignoring file transfer complete for other file than the current pending")
	}

	h := buff[offset : offset+32]
	offset += 32

	h512 := sha512.New()
	io.WriteString(h512, r.conf.HMACSecret)
	mac := hmac.New(sha512.New, h512.Sum(nil))
	mac.Write(buff[:offset])
	if !bytes.Equal(mac.Sum(nil), buff[offset:offset+64]) {
		return errors.New("Invalid signature in file complete packet for file " + pft.filename)
	}

	pft.file.Close()
	r.pendingFileTransfer = nil
	if !bytes.Equal(h, pft.hash.Sum(nil)) {
		os.Remove(pft.filename)
		return errors.New("Data checksum error for received file " + pft.filename)
	}
	tmpFile := path.Join(r.tmpDir, "godiodetmp."+strconv.FormatUint(uint64(manifestId), 16)+"."+strconv.Itoa(fileIndex))
	go r.moveTmpFile(pft, tmpFile)
	return nil
}

func (r *Receiver) createFolders() error {
	if r.manifest == nil {
		return errors.New("No manifest")
	}
	for d := range r.manifest.dirs {
		p := r.dir + path.Clean(r.manifest.dirs[d].path)
		err := os.MkdirAll(p, r.conf.Receiver.FolderPermission)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating dir "+p+"\n")
		} else {
			err = os.Chtimes(p, time.Unix(int64(r.manifest.dirs[d].modts), 0), time.Unix(int64(r.manifest.dirs[d].modts), 0))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to set mtime on "+p+"\n")
			}
		}
	}
	return nil
}

func (r *Receiver) handleManifestReceived() error {
	if r.conf.Verbose {
		fmt.Println("Received valid manifest with " + strconv.Itoa(len(r.manifest.dirs)) + " dirs, " + strconv.Itoa(len(r.manifest.files)) + " files")
	}
	if r.conf.Receiver.Delete {
		var dm map[string]bool
		var fm map[string]FileRecord
		filepath.WalkDir(r.dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if p == r.dir {
				return nil
			}
			if d.IsDir() {
				dm[p] = true
			} else {
				finfo, err := os.Stat(p)
				if err != nil {
					return nil
				}
				fm[p] = FileRecord{DirRecord{p, uint32(finfo.ModTime().Unix())}, finfo.Size()}
			}
			return nil
		})
		for i := range r.manifest.files {
			f, exists := fm[r.manifest.files[i].path]
			if exists && f.size == r.manifest.files[i].size && f.modts == r.manifest.files[i].modts {
				//keep this file
				delete(fm, r.manifest.files[i].path)
			}
		}
		for f, _ := range fm {
			err := os.Remove(f)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to delete file "+f+"\n")
			} else if r.conf.Verbose {
				fmt.Println("Removed file " + f)
			}
		}

		for i := range r.manifest.dirs {
			_, exists := dm[r.manifest.dirs[i].path]
			if exists {
				//keep this dir
				delete(dm, r.manifest.dirs[i].path)
			}
		}
		for d, _ := range dm {
			if d != r.tmpDir {
				err := os.Remove(d)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to delete dir "+d+"\n")
				} else if r.conf.Verbose {
					fmt.Println("Removed dir " + d)
				}
			}
		}
	}
	err := r.createFolders()
	return err
}

/**
 * manifest record
 * | type | id | part | [size] | payload
 * type - uint8 - 0x01
 * id - uint32 - manifest session id
 * part - uint16 - manifest session part index
 * size - uint32 - total manifest size, only sent in part 0
 * payload | manifest chunk
 *
 */
func (r *Receiver) onManifestPacket(buff []byte, read int) error {
	if read < 10 {
		return nil
	}
	manifestId := int(binary.BigEndian.Uint32(buff[1:]))
	part := int(binary.BigEndian.Uint16(buff[5:]))
	pmt := r.pendingManifestTransfer
	if pmt != nil {
		if manifestId != r.manifestId {
			fmt.Fprintf(os.Stderr, "Replacing pending manifest before completed\n")
			r.pendingManifestTransfer = nil
			pmt = nil
		} else {
			if part != pmt.index {
				r.pendingManifestTransfer = nil
				return errors.New("Received out of order manifest packet")
			}
			read = copy(pmt.buff[pmt.offset:], buff[7:read])
			pmt.offset += read
			if pmt.offset == len(pmt.buff) {
				manifest, err := deserializeManifest(pmt.buff, r.conf.HMACSecret)
				if err != nil {
					return err
				}
				r.manifest = manifest
				r.handleManifestReceived()
				return nil
			}
			pmt.index++
		}
	}
	if pmt == nil {
		if part != 0 {
			return errors.New("Unexpected manifest part received")
		}
		size := int(binary.BigEndian.Uint32(buff[7:]))
		if size > 5*1024*1024 || size < 1 {
			return errors.New("Too large manifest")
		}
		r.manifestId = manifestId
		manifestData := make([]byte, size)
		read = copy(manifestData, buff[11:])
		if read == size {
			manifest, err := deserializeManifest(manifestData, r.conf.HMACSecret)
			if err != nil {
				return err
			}
			r.manifest = manifest
			r.handleManifestReceived()
			return nil
		}
		r.pendingManifestTransfer = &PendingManifestTransfer{manifestData, read, 1}
		return nil
	}
	return nil
}

/**
 * Protocol format
 *
 * | type | payload... |
 * type - uint8
 *   0x00 - heartbeat
 *   0x01 - manifest
 *   0x02 - file transfer start
 *   0x80-0xFF - file transfer data
 *
 * manifest
 * | type | id | part | [size] | payload
 * type - uint8 - 0x01
 * id - uint16 - manifest session id
 * part - uint16 - manifest session part index
 * size - uint32 - total manifest size (including signature), only sent in part 0
 * payload | <utf8-json> + \n + hmac signature asciihex
 *
 * file transfer start
 * | filename | type | size | mtime | sign |
 * type - uint8 - 0x02 (regular file)
 * size - uint64 - size of file in bytes
 * mtime - uint64 - unix millis
 * sign - byte[64] - hmac512 of this header
 */

func receive(conf *Config, dir string) error {

	dir = path.Clean(dir) + "/"
	finfo, err := os.Stat(dir)
	if err != nil {
		return errors.New("Failed to stat receive dir " + err.Error())
	}
	if !finfo.IsDir() {
		return errors.New("Receive dir is not a directory")
	}

	tmpDir := conf.Receiver.TmpDir
	if tmpDir == "" {
		tmpDir = path.Join(dir, ".tmp")
	}
	err = os.Mkdir(tmpDir, 0700)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return errors.New("Could not create tmp dir")
	}
	finfo, err = os.Stat(tmpDir)
	if err != nil {
		return errors.New("Failed to stat tmp dir " + err.Error())
	}
	if !finfo.IsDir() {
		return errors.New("Tmp dir is not a directory")
	}
	tmpFiles, err := os.ReadDir(tmpDir)
	if err != nil {
		return errors.New("Failed to read tmp dir " + err.Error())
	}
	for i := range tmpFiles {
		if strings.HasPrefix(tmpFiles[i].Name(), "godiodetmp.") {
			err = os.Remove(path.Join(tmpDir, tmpFiles[i].Name()))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to remove tmp file: "+tmpFiles[i].Name()+" "+err.Error()+"\n")
			}
		}
	}

	maddr, err := net.ResolveUDPAddr("udp", conf.MulticastAddr)
	if err != nil {
		return errors.New("Failed to resolve multicast address: " + err.Error())
	}
	var nic *net.Interface
	if conf.NIC != "" {
		nic, err = net.InterfaceByName(conf.NIC)
		if err != nil {
			return errors.New("Failed to resolve nic: " + err.Error())
		}
	}
	c, err := net.ListenMulticastUDP("udp", nic, maddr)
	if err != nil {
		return errors.New("Failed to join multicast address: " + err.Error())
	}

	err = c.SetReadBuffer(300 * conf.MaxPacketSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to set read buffer: "+err.Error()+"\n")
	}

	buff := make([]byte, conf.MaxPacketSize)
	receiver := Receiver{
		conf:   conf,
		dir:    dir,
		tmpDir: tmpDir,
	}

	for {
		read, err := c.Read(buff)
		if err != nil {
			log.Fatal("Failed to recv data: " + err.Error())
		}
		if read < 1 {
			continue
		}
		ptype := buff[0] & 0xFF
		if (ptype & 0x80) != 0 { // file transfer data
			err = receiver.onFileTransferData(buff, read)
		} else if ptype == 0x02 { // start file transfer
			err = receiver.onFileTransferStart(buff, read)
		} else if ptype == 0x03 { // start file transfer
			err = receiver.onFileTransferComplete(buff, read)
		} else if ptype == 0x01 { // manifest
			err = receiver.onManifestPacket(buff, read)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error()+"\n")
		}
	}

	return nil
}
