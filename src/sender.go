package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"os"
	"path"
	"time"
)

const HEADER_OVERHEAD = 6 + 6 + 2 + 4 + 20 + 8

var THROTTLE = struct {
	enabled    bool
	tokens     int64
	capacity   int64
	last       time.Time
	nsPerToken float64
}{}

/**
 * Protocol format
 *
 * | type | payload... |
 * type - uint8
 *   0x01 - manifest
 *   0x02 - file transfer start
 *   0x03 - file transfer complete
 *   0x80-0xFF - file transfer data
 *
 * manifest
 * | type | id | part | [size] | payload
 * type - uint8 - 0x01
 * id - uint32 - manifest session id
 * part - uint16 - manifest session part index
 * size - uint32 - total manifest size, only sent in part 0
 * payload | manifest chunk
 *
 */

func sendManifest(conf *Config, c *net.UDPConn, manifest *Manifest, manifestId uint32) error {
	if conf.Verbose {
		fmt.Println("Sending manifest")
	}

	if conf.MaxPacketSize < 14 {
		return errors.New("Too small packet max size for sending manifest")
	}
	manifestData, err := manifest.serializeManifest(conf.HMACSecret)
	if err != nil {
		return err
	}
	buff := make([]byte, conf.MaxPacketSize)
	buff[0] = 0x01
	binary.BigEndian.PutUint32(buff[1:], manifestId)

	offset := 0
	for i := 0; offset < len(manifestData); i++ {
		binary.BigEndian.PutUint16(buff[5:], uint16(i))
		l := 7
		if i == 0 {
			binary.BigEndian.PutUint32(buff[l:], uint32(len(manifestData)))
			l += 4
			copied := copy(buff[l:], manifestData[offset:])
			l += copied
			offset += copied
		} else {
			copied := copy(buff[l:], manifestData[offset:])
			l += copied
			offset += copied
		}
		c.Write(buff[:l])
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

/*
 * file transfer start packet
 *
 * type - uint8 - 0x02
 * filetype - uint8 - 0x00 (regular file)
 * manifestSessionId - uint32 - manifest session id
 * fileIndex - uint32 - file index in the manifest
 * size - uint64 - size of file in bytes
 * mtime - int64 - unix millis
 * sign - byte[64] - hmac512 of this packet
 *
 *
 *
 * file transfer complete packet
 *
 * type - uint8 - 0x03
 * manifestSessionId - uint32 - manifest session id
 * fileIndex - uint32 - file index in the manifest
 * hash - byte[32] - sha256 of file content
 * sign - byte[64] - hmac512 of this packet
 */
func sendFile(conf *Config, c *net.UDPConn, manifestId uint32, fIndex uint32, f string) error {
	finfo, err := os.Stat(f)
	if err != nil {
		return err
	}

	file, err := os.Open(f)
	if err != nil {
		return err
	}
	defer file.Close()

	if conf.Verbose {
		fmt.Println("Sending file " + f)
	}

	buff := make([]byte, conf.MaxPacketSize)
	buff[0] = 0x02
	buff[1] = 0x00
	binary.BigEndian.PutUint32(buff[2:], manifestId)
	binary.BigEndian.PutUint32(buff[6:], fIndex)
	binary.BigEndian.PutUint64(buff[10:], uint64(finfo.Size()))
	binary.BigEndian.PutUint64(buff[18:], uint64(finfo.ModTime().Unix()))
	h512 := sha512.New()
	io.WriteString(h512, conf.HMACSecret)
	mac := hmac.New(sha512.New, h512.Sum(nil))
	mac.Write(buff[:26])
	copy(buff[26:], mac.Sum(nil))
	c.Write(buff[:26+64])

	h := sha256.New()

	time.Sleep(50 * time.Millisecond)

	//buffOut := make([]byte, MAX_PACKET_SIZE)
	buff[0] = 0x7F
	//	pos := 0
	for {
		read, err := file.Read(buff[1:])
		//		fmt.Println("read=%d", read, err)
		if read == 0 {
			break
		}
		if err != nil {
			return errors.New("Failed to read file: " + err.Error())
		}
		//		fmt.Println("xread=%d", read, err)
		buff[0]++
		if buff[0] == 0 {
			buff[0] = 0x80
		}

		//		c.WriteMsgUDP(buff[:(read+1)], nil, maddr)
		if THROTTLE.enabled {
			plen := read + 1 + HEADER_OVERHEAD
			for {
				if THROTTLE.tokens >= int64(plen) {
					THROTTLE.tokens -= int64(plen)
					break
				}
				now := time.Now()
				ns := time.Duration.Nanoseconds(now.Sub(THROTTLE.last))
				//log.Println(ns, ns/THROTTLE.nsPerToken, THROTTLE.tokens)
				newValue := THROTTLE.tokens + int64(math.Round(float64(ns)/THROTTLE.nsPerToken))
				if newValue >= int64(plen) {
					THROTTLE.tokens = newValue
					if THROTTLE.tokens > THROTTLE.capacity {
						THROTTLE.tokens = THROTTLE.capacity
					}
					THROTTLE.last = now
				} else {
					sleepTime := math.Ceil(float64(int64(plen)-newValue) * THROTTLE.nsPerToken)
					//log.Println(sleepTime, THROTTLE.tokens)
					time.Sleep(time.Duration(sleepTime))
				}
			}
		}
		c.Write(buff[:(read + 1)])
		h.Write(buff[1:(read + 1)])
	}

	hs := h.Sum(nil)

	buff[0] = 0x03
	binary.BigEndian.PutUint32(buff[1:], manifestId)
	binary.BigEndian.PutUint32(buff[5:], fIndex)
	copy(buff[9:], hs)
	h512 = sha512.New()
	io.WriteString(h512, conf.HMACSecret)
	mac = hmac.New(sha512.New, h512.Sum(nil))
	mac.Write(buff[:9+32])
	copy(buff[9+32:], mac.Sum(nil))
	c.Write(buff[:9+32+64])

	if conf.Verbose {
		fmt.Println("Sent file " + f + ", checksum=" + hex.EncodeToString(hs))
	}

	time.Sleep(100 * time.Millisecond)

	return nil
}

func send(conf *Config, dir string) error {

	dir = path.Clean(dir)

	manifest, err := generateManifest(dir)
	if err != nil {
		return err
	}

	if len(manifest.files) == 0 && len(manifest.dirs) == 0 {
		return errors.New("No files to send")
	}

	maddr, err := net.ResolveUDPAddr("udp", conf.MulticastAddr)
	if err != nil {
		return err
	}
	var baddr *net.UDPAddr = nil
	if conf.BindAddr != "" {
		baddr, err = net.ResolveUDPAddr("udp", conf.BindAddr)
		if err != nil {
			return err
		}
	}
	c, err := net.DialUDP("udp", baddr, maddr)
	if err != nil {
		return err
	}
	defer c.Close()
	if err != nil {
		return err
	}
	err = c.SetWriteBuffer(10 * conf.MaxPacketSize)
	if err != nil {
		return err
	}

	manifestId := rand.Uint32()
	err = sendManifest(conf, c, manifest, manifestId)
	if err != nil {
		return err
	}

	if conf.Sender.Bw > 0 {
		THROTTLE.enabled = true
		bytesPerSecond := int64(1000000 * conf.Sender.Bw / 8)
		THROTTLE.nsPerToken = float64(1000000000) / float64(bytesPerSecond)
		THROTTLE.capacity = 13 * int64(conf.MaxPacketSize+HEADER_OVERHEAD)
		THROTTLE.tokens = THROTTLE.capacity
		THROTTLE.last = time.Now()
	}

	//	log.Println(THROTTLE.nsPerToken, THROTTLE.capacity, THROTTLE.tokens, THROTTLE.last)

	for rs := 0; rs < conf.ResendCount; rs++ {
		// wait some to let the receiver create dirs etc
		time.Sleep(1000 * time.Millisecond)

		finfo, err := os.Stat(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error sending : "+err.Error()+"\n")
			return err
		}

		if !finfo.IsDir() {
			err = sendFile(conf, c, manifestId, 0, dir)
			return err
		} else {
			dir = dir + "/"
			for i := 0; i < len(manifest.files); i++ {
				err = sendFile(conf, c, manifestId, uint32(i), dir+manifest.files[i].path)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error sending file: "+manifest.files[i].path+" "+err.Error()+"\n")
					continue
				}

				if conf.ResendManifest {
					err = sendManifest(conf, c, manifest, manifestId)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error sending manifest: "+err.Error()+"\n")
						return err
					}

				}
			}
		}

		if conf.Verbose {
			fmt.Printf("All files sent. Transmission %d of %d \n", rs+1, conf.ResendCount)
		}
	}
	return nil
}
