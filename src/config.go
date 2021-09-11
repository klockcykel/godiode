package main

import "io/fs"

type SenderConfig struct {
	Bw int `json:"bw"`
}

type ReceiverConfig struct {
	Delete           bool        `json:"delete"`
	FilePermission   fs.FileMode `json:"filePermission"`
	FolderPermission fs.FileMode `json:"folderPermission"`
	TmpDir           string      `json:"tmpDir"`
}

type Config struct {
	MaxPacketSize int            `json:"maxPacketSize"`
	HMACSecret    string         `json:"hmacSecret"`
	MulticastAddr string         `json:"multicastAddr"`
	BindAddr      string         `json:"bindAddr"`
	NIC           string         `json:"nic"`
	Verbose       bool           `json:"verbose"`
	Sender        SenderConfig   `json:"sender"`
	Receiver      ReceiverConfig `json:"receiver"`
}

var config = Config{
	MaxPacketSize: 1500 - 8 - 20,
	HMACSecret:    "",
	MulticastAddr: "239.252.28.12:5432",
	BindAddr:      "",
	NIC:           "",
	Sender:        SenderConfig{Bw: 0},
	Receiver: ReceiverConfig{
		Delete:           false,
		FilePermission:   0600,
		FolderPermission: 0700,
		TmpDir:           "",
	},
}
