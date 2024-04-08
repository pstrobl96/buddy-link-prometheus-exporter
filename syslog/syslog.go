package syslog

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"gopkg.in/mcuadros/go-syslog.v2"
)

type patterns struct {
	pattern string
	fields  []string
}

var (
	// syslogMetrics is a map of mac addresses and their metrics
	macList = []string{"1b:c2:36:9c:8e:0e",
		"34:9a:b3:ef:a7:31",
		"a3:fb:9f:5b:aa:c3",
		"25:04:35:c5:b5:a5",
		"ec:e7:c0:ad:c7:dd",
		"e2:3d:e0:55:bc:81",
		"ee:3d:e2:53:9d:e5",
		"de:d1:e6:f7:46:ba",
		"46:1e:a1:c9:95:35",
		"b1:ee:ca:47:f9:36",
		"69:f9:54:60:af:ca",
		"b7:e6:b2:4a:ef:48",
		"6b:eb:6f:bf:e5:d1",
		"42:87:3c:8c:b7:67",
		"de:fb:57:64:92:26",
		"08:7d:9e:5e:fa:c2",
		"f8:c2:57:75:b1:bb",
		"37:69:66:d0:9f:50",
		"2b:51:3f:16:a2:14",
		"92:b4:2f:c6:12:91",
		"1e:b5:df:61:2c:a1",
		"d0:3d:16:91:86:40",
		"f5:ac:f7:1f:72:50",
		"ba:be:9d:d1:8a:f9",
		"8e:63:84:81:5a:83",
		"62:f8:0b:d7:a0:a1",
		"c7:a0:0b:f8:e3:50",
		"c3:8a:3b:c1:40:82",
		"67:35:1f:69:84:3f",
		"00:54:78:23:d1:61",
		"71:bd:1f:0d:83:fd",
		"e4:e3:c1:85:a0:90",
		"2c:d4:55:46:a0:80",
		"30:5d:67:1c:50:c4",
		"41:db:ec:08:e2:08",
		"f5:d6:9f:c1:88:23",
		"a5:27:03:b6:62:0f",
		"87:87:03:7f:01:c1",
		"ea:b6:73:aa:58:1e",
		"4a:9d:92:38:f8:19",
		"a7:04:6c:42:f3:38",
		"38:b4:ab:b1:ac:7b",
		"dd:cd:04:15:01:eb",
		"92:f7:d0:30:8c:ca",
		"82:a7:f3:ae:64:d9",
		"68:f4:68:72:2b:70",
		"a8:33:80:75:ed:3c",
		"9a:b6:0e:42:0b:9f",
		"a4:8f:db:93:31:ea",
		"e5:c9:03:24:10:44",
		"16:d5:c3:09:97:19",
		"01:2a:43:c8:a9:1b",
		"89:33:a3:63:4c:75",
		"b2:31:1b:bc:cd:51",
		"4b:bc:69:a9:c7:4e",
		"05:f6:51:7c:ea:d9",
		"14:30:44:f9:ca:59",
		"68:b8:35:35:d4:b6",
		"c7:a1:f2:b6:47:32",
		"ef:b6:0f:53:df:65",
		"e8:b2:f5:2b:eb:2f",
		"a3:26:49:1f:ec:44",
		"26:f6:44:b0:ef:e7",
		"72:a5:41:b3:2d:5c",
		"26:6d:53:b7:69:4b",
		"5e:6a:1c:4f:11:50",
		"6e:bf:00:a5:93:d2",
		"21:e7:29:55:47:9f",
		"57:1a:10:a9:0a:04",
		"f5:a2:2d:21:cc:84",
		"07:9d:f0:e1:59:e3",
		"5c:da:d1:93:16:93",
		"6e:a5:10:06:5d:eb",
		"22:ae:5d:7c:cd:0a",
		"e1:ae:2d:f6:cb:dd",
		"17:d2:a0:13:69:c4",
		"e8:f5:5a:ea:3e:ed",
		"d7:1e:f1:aa:c4:98",
		"d8:67:73:c5:99:cd",
		"59:e4:f3:37:bf:77",
		"32:4e:31:2a:d6:14",
		"2a:aa:b0:78:14:fc",
		"cc:a1:09:64:be:3c",
		"6f:82:77:50:9d:70",
		"67:07:0a:b0:37:55",
		"5a:50:6e:64:6e:26",
		"26:0b:41:1c:b3:4a",
		"76:83:a5:4e:d7:9a",
		"96:5e:17:48:ef:16",
		"70:b5:df:ec:3b:76",
		"64:c1:6f:d6:04:bf",
		"e0:28:87:e5:96:58",
		"dc:11:0d:06:96:3e",
		"a1:8a:7a:dd:d1:0f",
		"76:f4:0d:6d:38:04",
		"6d:a7:7d:36:39:72",
		"80:6c:09:83:77:da",
		"be:83:6b:88:e4:48",
		"6f:9d:88:37:60:75",
		"fc:bd:ae:6d:85:b4",
		"64:39:89:89:1e:83",
		"24:7e:fc:63:0d:d2",
		"38:d1:b0:5a:4f:48",
		"c1:c3:91:be:7d:9f",
		"f2:48:1f:01:2c:23",
		"be:7b:ab:95:ae:d9",
		"20:5d:b6:48:b6:6d",
		"a0:92:21:74:1b:7c",
		"18:39:1b:9b:28:cc",
		"3b:22:d7:c5:64:75",
		"72:49:da:fa:f4:61",
		"3f:dd:f0:92:6c:09",
		"40:ab:c4:b8:34:b5",
		"5b:ac:eb:eb:2c:a0",
		"0a:71:9e:17:b6:16",
		"30:bc:2a:ae:e5:4f",
		"2c:46:37:4f:46:30",
		"69:b4:06:53:5e:83",
		"05:14:3f:ed:55:0f",
		"f0:92:16:b2:d0:c4",
		"c5:1b:32:d1:ad:fe",
		"21:46:81:c8:4b:14",
		"c4:2b:e0:66:ab:8b",
		"99:45:5e:54:a0:f8",
		"8c:02:06:f4:5f:92",
		"48:f4:fe:d6:8c:74",
		"f6:12:86:f0:c6:65",
		"4e:f5:3b:45:b0:fe",
		"d6:bb:81:dd:a9:52",
		"6f:48:d8:2d:80:4a",
		"51:a8:b4:6d:8f:14",
		"1f:ec:a6:7e:9f:ae",
		"99:51:e7:0e:df:24",
		"b1:79:9e:d4:f7:6f",
		"e3:8a:fc:ba:83:8c",
		"15:c1:4f:10:e9:c3",
		"64:7b:73:a1:ed:cc",
		"14:82:8a:09:a6:86",
		"04:57:64:70:fb:a4",
		"f9:d0:28:e3:30:e4",
		"79:53:11:2e:71:88",
		"f4:b2:f5:80:3a:dc",
		"27:95:5b:34:45:a9",
		"c7:2b:54:5c:3a:9f",
		"7e:7e:1a:09:4b:46",
		"45:66:6c:44:c3:41",
		"08:ac:64:a9:b9:49",
		"21:d7:db:3b:2a:03",
		"f5:73:39:a8:f8:d1",
		"25:f2:66:c7:c8:09",
		"98:78:c9:e0:37:fd",
		"71:7a:75:80:de:0c",
		"5f:7b:72:d7:61:38",
		"0f:be:fd:b8:ae:2f",
		"10:c5:b3:9c:c3:2f",
		"42:9c:3c:18:2e:fb",
		"1a:ae:53:07:a5:94",
		"9f:d4:3b:f9:7e:b3",
		"d9:5c:3e:75:31:58",
		"1c:51:7b:6a:6e:07",
		"ac:ef:b6:f8:1c:9f",
		"31:ac:27:d8:c7:f1",
		"65:8d:fa:1e:0a:00",
		"dd:c6:75:27:3e:8c",
		"57:a1:1d:9c:45:7c",
		"55:8a:bc:da:44:98",
		"69:80:12:41:38:28",
		"da:b6:d6:8f:1f:94",
		"86:6b:f7:71:bd:b3",
		"e4:93:d0:f6:e3:b7",
		"87:58:d3:d1:b7:4c",
		"fb:a0:3f:9b:43:e2",
		"1a:13:aa:47:9f:cc",
		"3f:95:a4:6a:a6:8a",
		"c7:28:69:84:8d:f9",
		"c9:fb:57:8e:f5:b9",
		"15:2c:11:a3:30:84",
		"6a:c9:88:1f:d9:3a",
		"46:99:93:66:2b:43",
		"bf:36:63:26:1a:87",
		"a9:f3:02:77:5e:09",
		"e0:30:73:0c:bc:bb",
		"90:e1:6f:a9:dc:2a",
		"2b:24:e3:86:a4:0f",
		"7e:84:3d:65:12:3f",
		"a9:52:3d:4e:ec:76",
		"9b:ce:27:1b:fa:68",
		"31:e1:2d:ed:7c:2d",
		"48:38:ef:93:b5:42",
		"d2:71:75:1b:67:d8",
		"19:b9:b0:d7:c3:64",
		"da:28:4d:1c:b4:8c",
		"e8:7e:3e:b5:99:1d",
		"a8:22:c0:1f:b1:fe",
		"dd:bd:18:5b:20:dc",
		"f2:fc:2a:4f:5f:d3",
		"fc:c5:36:44:c4:6a",
		"37:0c:70:44:64:a4",
		"ad:e1:3b:7a:e4:95",
		"28:ef:cd:33:b1:58",
		"b4:80:de:fd:9f:f6",
		"97:c7:76:db:38:87",
		"1b:e9:7f:0d:02:66",
		"e4:c4:b8:c7:0b:a5",
		"93:6f:93:7f:14:9b",
		"b6:7d:ce:3e:43:1c",
		"91:59:fe:e0:4e:e8",
		"77:31:9e:36:fd:29",
		"99:71:b0:5b:70:ed",
		"8f:bf:c0:3d:9f:91",
		"be:12:dd:2c:29:9a",
		"b1:a0:f0:eb:e6:b2",
		"80:c8:a3:f1:4a:25",
		"37:34:23:1a:b3:56",
		"10:41:68:6c:20:85",
		"a8:d2:70:60:3a:7b",
		"ca:9a:70:2a:0b:6d",
		"e4:db:5c:54:19:2b",
		"93:5a:7d:30:e8:bd",
		"df:f6:91:50:08:7f",
		"7c:61:4c:0e:bc:3e",
		"e0:57:6c:e6:39:da",
		"b7:a4:d2:57:c1:c9",
		"7c:63:79:12:11:52",
		"a7:08:74:a6:2b:0c",
		"00:73:e1:7e:3e:0b",
		"f2:d5:83:c4:59:e0",
		"70:e0:ee:fd:53:43",
		"7f:5c:63:81:f5:44",
		"75:d1:ee:cf:4f:38",
		"84:b6:46:65:14:00",
		"40:f4:13:98:18:9b",
		"df:0d:62:05:95:d3",
		"cb:1f:f2:7f:36:ae",
		"6e:fa:ef:bf:00:64",
		"cf:2b:d8:6f:48:5e",
		"81:e6:f6:26:d2:7a",
		"7b:7d:cc:1e:19:a7",
		"93:9b:27:55:af:db",
		"8e:c0:6d:cd:91:b9",
		"4d:c7:ca:92:7a:72",
		"be:60:db:71:34:50",
		"da:99:e6:ea:a3:cd",
		"61:1a:c7:c1:d4:8a",
		"49:54:d3:42:16:4a",
		"4d:54:ad:e6:9f:1a",
		"68:57:24:26:2f:b7",
		"e4:2f:7f:6b:b3:05",
		"67:d3:fb:73:cd:77",
		"d9:3e:e5:03:04:bd",
		"92:b4:61:11:e8:2a",
		"bd:55:84:00:7d:17",
		"e7:78:94:9c:3e:60",
		"7d:56:67:f1:62:f4",
		"17:c8:c7:0a:f2:54",
		"de:75:18:af:a8:86",
		"91:72:a4:f4:a9:c0",
		"f4:ea:e9:70:ed:4d",
		"f9:ec:59:62:9a:3a",
		"11:c6:42:3e:2e:53",
		"58:6b:db:c9:53:a7",
		"fc:54:81:02:e3:a9",
		"53:da:1b:cf:6f:11",
		"e2:f6:12:75:51:59",
		"1e:c4:ee:7c:8c:80",
		"31:4e:41:17:8f:ae",
		"cc:0e:a8:f5:3f:1b",
		"6a:61:b7:78:0c:48",
		"91:c6:84:7f:a4:5a",
		"ec:41:c5:4b:8b:59",
		"ea:ee:e7:fd:d5:2d",
		"3c:89:2a:3f:e6:d3",
		"80:99:66:14:1a:b3",
		"3c:40:c0:9e:7c:28",
		"53:70:14:20:e3:22",
		"ba:ef:0b:1e:4a:b4",
		"d6:74:48:b7:24:54",
		"24:23:c3:99:d1:7e",
		"4d:08:1f:e7:60:e8",
		"c3:3c:5c:53:3e:0f",
		"4c:87:45:8e:b3:74",
		"fb:3d:c7:17:12:d9",
		"a5:b6:93:64:87:1b",
		"d3:b2:bf:49:77:84",
		"f8:b2:1d:55:7d:05",
		"1e:00:01:51:88:ce",
		"93:81:c1:f0:67:c8",
		"e2:1a:0e:8b:37:59",
		"b0:2c:ed:6d:83:90",
		"8c:86:fd:fa:61:fd",
		"6f:f5:06:08:4c:b6",
		"32:04:80:62:42:f9",
		"4d:4d:e8:7e:d5:cd",
		"79:68:50:91:ca:c9",
		"2a:e2:c7:25:6c:1c",
		"a3:4d:8b:ba:84:aa",
		"e7:4c:52:93:fd:ce",
		"8c:a7:92:12:9a:85",
		"5e:ac:ca:9b:63:d0",
		"44:a7:6f:88:51:28",
		"66:23:7a:b3:18:48",
		"57:4d:91:1b:53:1e",
		"bc:6f:c4:37:d3:d8",
		"3a:0c:bb:32:d5:3c",
		"cf:51:09:de:d7:d9",
		"ce:cc:6d:fb:4c:7e",
		"d5:b5:21:91:5f:47",
		"56:b3:88:2d:c3:06",
		"71:55:4d:71:9c:e9",
		"3d:b4:09:35:a6:32",
		"af:1b:a3:73:cb:04",
		"a0:49:7f:e0:6a:8f",
		"d2:c4:09:2a:ef:36",
		"ab:b2:be:54:2d:8c",
		"72:f5:a1:05:ac:51",
		"30:41:ef:80:d4:bb",
		"96:f4:eb:a0:76:42",
		"fc:78:c4:9a:9f:ae",
		"40:b5:86:82:a0:40",
		"ee:a8:7b:e7:c3:74",
		"22:82:6c:34:dd:93",
		"22:96:6d:f2:03:8f",
		"69:7e:1a:5b:a7:aa",
		"d0:86:73:3a:bb:f9",
		"81:6b:98:59:ad:a9",
		"4f:f2:70:cf:7f:7b",
		"4f:a3:6f:8e:94:15",
		"ef:82:2d:38:20:29",
		"9d:aa:3b:45:c3:1a",
		"60:78:bd:26:50:09",
		"39:92:2f:b5:65:97",
		"7b:f9:7e:74:d6:04",
		"f3:53:44:02:29:ac",
		"49:bb:a6:34:a4:5c",
		"c2:d2:49:9d:1f:02",
		"fa:cf:98:6d:0f:a9",
		"30:b6:88:9d:7b:65",
		"d2:f3:75:af:47:3a",
		"c9:0d:eb:6c:5b:11",
		"50:32:c0:64:73:7a",
		"02:78:4a:23:58:a8",
		"a3:8d:ed:07:b5:8e",
		"5d:4e:64:b1:bd:e5",
		"5e:93:37:17:10:50",
		"a5:28:c3:e7:8c:a3",
		"64:8e:08:db:5d:77",
		"99:ec:6d:c3:86:e2",
		"cc:c5:7a:94:be:da",
		"a6:19:18:b7:54:d5",
		"cb:20:ef:18:16:fa",
		"53:1c:3a:51:8a:e7",
		"eb:1f:f6:bf:72:5f",
		"35:87:7a:27:28:86",
		"4f:e8:25:96:b4:3a",
		"df:b2:29:d6:2d:f7",
		"a9:08:83:7e:5d:38",
		"94:92:e9:f3:52:43",
		"86:89:97:61:a2:5e",
		"87:54:da:1e:9f:01",
		"0c:f7:78:58:5d:9c",
		"3e:b7:e3:d3:26:53",
		"cd:51:73:9f:5f:41",
		"da:58:cb:1f:a4:1d",
		"67:ab:7a:39:34:3c",
		"09:09:c9:3c:02:dc",
		"40:3e:e5:e2:2f:5c",
		"68:ac:27:52:e6:82",
		"ba:ae:45:9b:e2:27",
		"f1:e6:20:8b:1d:6a",
		"5f:e9:df:aa:fb:1d",
		"a5:a0:9b:dc:1f:3b",
		"29:3e:80:08:a4:ba",
		"bf:fb:d4:d1:7c:bc",
		"81:96:9e:a3:50:d6",
		"c6:ca:68:86:41:44",
		"aa:b8:3b:50:c9:94",
		"67:ae:dc:38:51:72",
		"fe:e5:65:c8:78:c4",
		"d7:14:af:bc:8d:49",
		"cf:fd:e0:b2:aa:d0",
		"1f:c0:4c:45:94:14",
		"f5:90:6a:07:d9:dd",
		"3d:1c:e3:aa:5b:56",
		"b9:70:50:be:1b:03",
		"54:09:55:ce:ab:5e",
		"f4:5e:f5:8f:78:0c",
		"fe:2c:39:a8:e8:bb",
		"27:f9:62:37:48:b7",
		"88:3c:29:11:82:3d",
		"7d:1d:1e:75:e6:55",
		"15:61:da:85:b2:f9",
		"cc:b6:d1:41:b6:52",
		"82:d5:2f:0b:64:30",
		"89:7e:ea:7a:3d:3d",
		"c3:a3:5c:39:0d:e6",
		"cf:e6:cc:48:74:59",
		"22:f6:6e:57:8e:c9",
		"4a:a2:cf:d4:d6:c5",
		"48:51:8a:e6:60:89",
		"57:bc:d1:e2:33:ac",
		"57:1a:b7:2f:71:56",
		"eb:62:09:95:2f:d3",
		"55:ec:51:d0:3c:a7",
		"19:87:f9:de:68:28",
		"58:28:e9:36:df:d2",
		"32:58:05:34:dc:cf",
		"02:b7:ba:b9:f1:94",
		"4d:60:1f:61:35:e5",
		"39:18:c8:fe:3f:e9",
		"b1:ef:7e:39:93:4e",
		"8c:31:c4:55:ec:72",
		"5a:7b:51:7d:1e:88",
		"80:32:78:a8:f8:81",
		"f2:6c:7c:17:b2:f9",
		"1a:7b:08:41:57:9a",
		"8a:be:82:89:f0:8e",
		"0a:10:d0:dd:4d:2d",
		"48:08:ce:4c:c2:73",
		"ee:6a:66:1d:2d:8c",
		"31:f9:a6:50:d0:e3",
		"02:05:f6:f6:b8:42",
		"49:fd:81:3c:a3:de",
		"b3:3c:c0:bb:ee:45",
		"fc:66:98:66:36:5a",
		"80:fd:35:16:cf:5c",
		"c5:dc:3b:38:79:3f",
		"5b:93:11:a6:b2:b3",
		"91:f2:6c:e3:c4:10",
		"e6:b1:f8:14:2e:86",
		"b9:94:11:fa:3a:60",
		"04:b9:0f:64:3b:19",
		"c4:3f:86:e1:76:11",
		"2b:e2:ca:b2:ba:01",
		"5e:cb:60:43:20:84",
		"fa:ce:70:c3:66:87",
		"3e:3d:8c:aa:a3:f9",
		"4f:29:b5:b4:a0:8c",
		"d0:3b:7b:20:10:86",
		"f4:6e:60:16:b8:a4",
		"85:31:6d:6c:50:13",
		"96:e0:c5:25:bd:85",
		"d4:1d:b6:d5:a1:8f",
		"d8:de:36:32:ed:fb",
		"10:64:04:02:44:52",
		"29:79:7e:55:7e:5d",
		"d2:3b:9a:66:1c:ae",
		"3d:89:8a:14:6a:da",
		"07:91:89:ee:87:88",
		"cc:f7:82:b1:2e:cc",
		"5b:08:3b:d4:83:a9",
		"79:f4:51:40:cf:2e",
		"f8:71:78:ad:85:ac",
		"5f:51:fe:a5:fd:c6",
		"2b:52:c2:bb:c6:83",
		"7b:42:09:1b:ce:94",
		"46:42:d8:96:13:83",
		"1c:c6:98:fe:77:44",
		"b2:92:92:3e:a4:fd",
		"8d:85:bf:41:35:58",
		"06:4f:8b:ec:79:3b",
		"d8:0c:03:a2:24:4e",
		"35:aa:18:aa:e9:4b",
		"b1:54:ea:35:2f:7b",
		"27:34:0b:d7:8a:3b",
		"25:5e:e4:64:6b:be",
		"b8:5f:6f:e2:90:1c",
		"66:f8:10:4d:99:f0",
		"7e:60:13:4b:2d:e8",
		"3b:42:f0:fd:07:24",
		"13:f1:20:66:b5:35",
		"89:2d:b4:ba:50:d5",
		"61:25:03:6b:22:47",
		"0b:24:de:96:a4:a9",
		"ac:24:07:15:ab:4f",
		"c0:52:47:6f:b4:64",
		"88:d4:f5:c5:65:e0",
		"ab:2e:ea:85:15:9f",
		"b3:8d:4c:5f:2b:9e",
		"6d:19:46:88:99:66",
		"e4:41:e6:14:09:01",
		"86:b1:98:cd:32:b5",
		"b6:fe:fe:c9:a0:4f",
		"15:6f:64:ee:d9:44",
		"1c:0f:e7:8c:bb:19",
		"64:09:ea:99:d9:0c",
		"73:0a:48:43:90:e0",
		"fd:df:32:a9:2f:19",
		"5b:96:2b:18:01:73",
		"b1:35:9b:6f:41:a7",
		"34:40:83:e9:57:61",
		"68:e7:a2:f4:a3:6e",
		"6a:02:6d:c0:1f:9d",
		"ef:e6:21:c1:a4:8f",
		"fa:a5:0e:2b:0b:a9",
		"ef:95:c8:9c:b7:92",
		"1d:0b:7d:69:5f:65",
		"33:c8:e2:b2:8e:2e",
		"35:7d:df:b1:96:48",
		"a7:37:c8:2c:cc:13",
		"58:1d:19:66:54:c8",
		"05:1d:20:63:45:fb",
		"57:14:4e:8b:34:70",
		"97:bc:f9:9b:ea:62",
		"cd:0a:6a:86:f3:21",
		"0c:27:32:3f:44:4b",
		"0b:67:06:14:e9:fb",
		"c0:32:dc:92:af:2c",
		"1b:0d:2a:41:c9:a8",
		"04:4f:0b:63:99:25",
		"67:da:80:f7:a3:86",
		"83:9c:63:85:d8:fd",
		"10:94:d9:38:54:23",
		"91:43:f2:ab:16:ed",
		"80:2b:7c:16:e4:6a",
		"a4:82:69:67:a1:6d",
		"80:02:8d:b8:c1:6d",
		"87:9e:f8:89:20:c0",
		"4a:c4:3b:ee:45:5d",
		"57:15:1f:54:d1:1e",
		"33:7e:fd:97:1b:46",
		"fc:40:3f:49:94:04",
		"23:17:c1:11:e9:3f",
		"38:2a:34:cb:bf:5a",
		"fb:06:84:79:82:de",
		"d2:df:2f:da:cb:35",
		"37:96:47:86:43:1b",
		"ef:14:0b:12:dd:70",
		"fd:71:04:41:6b:b7",
		"bd:14:71:34:c5:d8",
		"c2:8d:e3:cc:88:53",
		"0a:3c:c2:f8:17:58",
		"55:b3:95:a4:9c:4d",
		"08:c1:a1:63:9c:e2",
		"6b:03:8d:a7:7f:6a",
		"0a:37:cc:52:da:02",
		"be:4a:80:76:4e:f8",
		"80:bd:f5:1a:8c:ce",
		"e1:36:1f:de:3b:15",
		"c5:a5:16:90:fb:00",
		"0b:5e:19:aa:de:de",
		"5e:6e:3a:0c:6d:b1",
		"30:52:d5:fc:e6:cf",
		"3e:df:89:e9:19:9a",
		"87:39:f0:c8:6a:83",
		"18:4d:f6:97:98:8d",
		"15:db:bc:e9:56:d2",
		"43:20:c7:c4:02:8b",
		"2e:ad:9b:6d:ef:5b",
		"54:50:a7:98:89:5d",
		"a6:0d:8d:83:14:c6",
		"3b:0c:97:51:43:79",
		"86:59:3f:12:a2:e5",
		"2f:6c:44:4c:b3:6e",
		"ec:51:72:d1:aa:b6",
		"6f:31:35:82:e2:d5",
		"1e:76:27:c7:36:b6",
		"17:90:27:2a:17:56",
		"24:fd:05:b6:81:5d",
		"c3:44:49:b7:11:8e",
		"a9:54:fa:89:6e:54",
		"d0:84:fb:bd:55:65",
		"f0:dc:9a:af:32:f2",
		"04:ae:79:1c:6f:a2",
		"5c:a6:b6:f2:68:00",
		"5e:5a:f1:26:b4:3e",
		"17:da:f6:4d:a5:ed",
		"d4:1a:ac:d6:00:03",
		"2b:26:d1:4c:cb:e2",
		"38:9f:36:57:7f:29",
		"a2:b0:c1:f7:ea:77",
		"7b:da:57:a9:37:9b",
		"0a:86:2e:f5:1e:3b",
		"34:f2:cc:c3:74:7b",
		"a1:86:bd:6b:e5:2c",
		"90:13:8b:d5:ab:07",
		"7d:0c:55:4a:95:dd",
		"96:7e:d2:ab:9c:58",
		"48:11:20:8f:c0:9d",
		"0d:8b:f4:16:f7:a5",
		"d3:21:18:d8:1d:d0",
		"1d:61:17:6d:db:12",
		"d3:3b:f3:23:e3:d6",
		"c5:4d:2d:a5:31:32",
		"c4:0f:a4:5d:71:db",
		"60:b8:b1:18:5f:51",
		"64:1b:8c:fb:34:f5",
		"0e:96:1d:c2:d1:01",
		"a7:a9:38:fa:ca:34",
		"cc:4e:f4:99:aa:04",
		"f2:a0:9e:ae:7f:b5",
		"8a:b8:82:83:15:d5",
		"8d:35:c2:a5:28:a8",
		"58:af:74:24:f0:ad",
		"79:df:12:17:22:5d",
		"b0:ca:37:5c:f3:fa",
		"df:5f:31:cc:5b:fa",
		"08:00:d1:69:d6:0b",
		"d9:9e:f0:e1:75:a5",
		"68:d1:72:ac:a0:a6",
		"c5:ba:cf:eb:01:c0",
		"9b:a0:ba:b5:b7:95",
		"d6:93:2b:d5:05:24",
		"ef:47:20:70:4b:fb",
		"4e:6a:b0:36:0a:ab",
		"fe:a5:46:fd:36:92",
		"9e:5a:b9:43:da:59",
		"6f:ee:92:72:98:e4",
		"2c:e6:3d:2a:4f:dc",
		"d3:cd:42:d0:7d:12",
		"8a:e9:6b:85:3b:b7",
		"14:60:d9:cd:75:56",
		"f8:ed:ec:28:b4:07",
		"12:01:d4:60:86:61",
		"6e:b3:73:09:01:17",
		"da:0f:e3:28:7b:64",
		"12:4c:2e:ac:62:1f",
		"a4:d6:8c:63:72:ee",
		"5e:03:19:2f:74:aa",
		"32:a4:71:0e:f9:8b",
		"c0:6a:d5:2d:90:bb",
		"a1:f5:fc:0b:ba:b6",
		"30:f5:92:c0:62:91",
		"aa:f3:07:c1:c1:1f",
		"8b:32:03:e4:96:ce",
		"c1:0b:e4:ea:60:ea",
		"ac:39:16:25:f5:0d",
		"55:36:c7:66:82:14",
		"21:89:bb:85:5f:b2",
		"4d:04:71:a5:b3:7d",
		"cd:d4:61:8f:e3:94",
		"b5:0b:43:91:1b:29",
		"9b:2e:f0:35:f7:75",
		"b9:5d:42:0b:97:1a",
		"90:c5:c3:02:83:43",
		"d7:c9:99:f7:c9:e3",
		"78:a1:8c:19:43:9c",
		"b6:5e:22:47:15:26",
		"ef:86:26:55:7a:84",
		"40:03:95:47:e8:71",
		"e4:e2:79:96:b3:4e",
		"1d:94:78:69:3b:e5",
		"c8:f0:14:7f:b8:6e",
		"bd:b9:cf:0f:d0:ac",
		"8d:56:c1:ac:78:88",
		"bb:c5:5e:2b:6d:40",
		"dd:18:e4:83:44:80",
		"8f:bc:f7:86:fa:37",
		"30:50:21:10:e3:36",
		"06:ad:92:55:8c:0c",
		"4f:72:c6:1d:fe:2f",
		"d6:e3:83:ab:76:cf",
		"49:5d:3c:30:04:81",
		"57:99:33:c7:f8:b4",
		"4c:42:c5:32:20:d3",
		"22:41:8b:16:90:fb",
		"be:52:3d:e7:4a:1d",
		"de:1f:65:f5:eb:77",
		"4c:37:25:f7:2d:6f",
		"2e:58:9b:9a:2f:59",
		"49:6d:74:76:f6:c1",
		"9f:75:35:2a:9c:e8",
		"c6:05:68:04:d2:7c",
		"36:f3:57:2b:2a:f2",
		"39:a9:49:1a:bd:bb",
		"45:31:ed:bd:e4:50",
		"b0:80:a5:ca:14:6b",
		"2f:2f:be:8c:d9:ae",
		"46:a8:a2:20:43:a7",
		"10:e0:f3:73:7c:19",
		"f0:2a:24:4b:5d:d3",
		"d5:63:99:34:2e:49",
		"5b:c5:f3:88:36:06",
		"77:d4:d4:03:8c:5f",
		"f6:de:60:d6:dd:d2",
		"42:27:e3:49:17:b8",
		"bc:d4:6e:03:40:d4",
		"09:33:7f:59:c9:f4",
		"99:a1:6d:b3:1f:d6",
		"e2:cf:f6:c6:be:98",
		"e5:d4:60:84:ae:f2",
		"52:c4:3b:2e:41:06",
		"f6:38:29:d7:53:25",
		"31:32:e0:43:9b:dd",
		"96:b9:19:a8:30:79",
		"fd:f0:7d:8d:24:cc",
		"b1:db:03:bc:2f:73",
		"92:f7:52:35:4a:d3",
		"73:f8:e1:19:24:f1",
		"ac:b8:77:09:45:cb",
		"c4:4a:ef:2c:23:e9",
		"c2:91:ab:99:e8:df",
		"e5:f8:e8:fa:34:27",
		"b5:5c:5b:5d:63:a6",
		"8b:7e:4a:18:2a:69",
		"34:ca:52:cf:b4:a7",
		"2e:3f:f5:45:2b:48",
		"17:a4:be:71:54:0d",
		"f5:03:0d:9e:e1:5a",
		"10:1a:03:74:45:59",
		"73:53:28:bd:49:be",
		"13:6f:20:a1:57:fd",
		"59:68:f5:35:18:07",
		"1e:db:f4:4a:c2:49",
		"22:ed:2d:7b:25:21",
		"15:8b:74:69:ba:0c",
		"9b:71:5d:cd:ee:43",
		"3c:16:f3:eb:a9:ee",
		"dd:b0:dc:bf:3b:54",
		"56:c8:e8:e8:30:37",
		"43:03:e6:49:e5:b8",
		"e5:03:43:ea:35:84",
		"a5:aa:ea:5f:68:e3",
		"df:20:57:ab:3e:83",
		"18:8f:c2:04:b8:0b",
		"e9:72:5d:98:2c:ef",
		"fa:d1:23:fe:b3:98",
		"08:9c:ae:56:b8:42",
		"f2:49:2a:1f:2a:29",
		"57:d0:22:cc:ac:1f",
		"04:87:77:a5:4f:03",
		"fb:20:e8:93:2a:66",
		"40:23:69:98:c0:c5",
		"1f:2d:d0:97:f7:43",
		"b3:20:94:a9:bc:c6",
		"8e:cd:49:17:29:c6",
		"64:f7:38:57:7a:0a",
		"f5:31:b4:0f:77:a4",
		"26:d1:0a:cb:9c:e5",
		"77:58:7f:fb:16:40",
		"b5:55:a1:96:5d:7d",
		"2b:3c:6c:60:a8:1e",
		"81:88:16:e5:0f:99",
		"bc:7b:81:ec:86:37",
		"7f:6a:ad:3d:b4:b9",
		"fa:d3:c8:32:ec:3c",
		"03:bd:ae:68:71:2e",
		"9d:fd:75:ea:a2:78",
		"4b:9e:69:e2:3f:8c",
		"1b:b4:e1:28:99:3c",
		"81:5b:f2:92:0e:73",
		"8f:ab:82:82:54:5e",
		"41:d3:43:c3:cc:2d",
		"57:bb:83:93:d9:bc",
		"72:90:99:83:32:55",
		"34:07:dc:24:c7:59",
		"02:1b:ec:f0:44:08",
		"61:86:24:99:a9:bc",
		"24:9c:17:40:bd:9f",
		"64:81:81:b9:2c:f6",
		"eb:06:de:87:57:1a",
		"b2:c5:c0:13:95:23",
		"9c:dc:ec:ab:2c:bd",
		"69:54:bc:de:5b:f3",
		"ab:13:b1:f4:84:ab",
		"3e:d2:26:1d:9c:54",
		"85:05:b8:fd:87:66",
		"22:65:98:a0:29:53",
		"53:72:ea:26:59:2c",
		"8a:03:a1:a4:3b:23",
		"21:6b:7a:85:28:1a",
		"bd:f1:c4:35:3b:a7",
		"44:cf:8d:40:5f:22",
		"66:f2:24:04:ba:7d",
		"d4:70:54:55:9a:6d",
		"59:47:e4:ee:c9:e3",
		"3d:62:1a:26:06:e8",
		"22:11:a2:4e:7f:a6",
		"fb:0f:33:69:0c:f1",
		"4c:a2:21:22:80:27",
		"33:0c:da:e9:b5:f6",
		"27:86:c6:76:c1:41",
		"1e:fb:4c:08:d5:db",
		"60:3c:6c:ba:48:b7",
		"3d:68:14:e8:17:d5",
		"45:c6:e7:e4:a3:71",
		"a7:4e:63:ca:84:3e",
		"08:0c:54:63:43:8d",
		"02:e5:68:58:85:4e",
		"ab:28:4e:af:f0:5e",
		"27:08:e1:99:db:20",
		"c5:68:f2:67:26:8e",
		"ed:e9:a5:b6:b7:75",
		"51:d9:59:ba:a5:0d",
		"1f:cf:82:ec:89:00",
		"fe:cf:44:16:f5:01",
		"22:7a:92:18:1f:a4",
		"7f:b2:90:61:8d:be",
		"8e:75:cd:10:8e:2e",
		"74:c9:82:84:c5:80",
		"d8:86:67:72:6a:9c",
		"c9:0e:a5:58:ab:3d",
		"1e:11:c3:0f:46:20",
		"df:83:da:9b:20:6e",
		"c5:f4:d3:b6:9c:d0",
		"36:d3:62:d1:a5:71",
		"82:a0:da:21:9a:27",
		"18:22:1c:24:22:ef",
		"c8:09:2b:e6:65:83",
		"59:cf:4d:31:cc:89",
		"3f:6a:8e:18:20:ef",
		"1f:87:46:ee:cd:37",
		"1d:05:66:e7:fe:0d",
		"47:c0:b9:bb:44:25",
		"b4:02:0a:ca:38:72",
		"5b:7a:7a:f7:04:b8",
		"ca:0b:0d:e6:fb:9f",
		"10:ed:aa:d7:06:1e",
		"c1:ba:8f:59:63:2f",
		"57:10:f8:c8:1a:8a",
		"69:24:ae:c5:5c:11",
		"55:bd:09:fb:ea:3a",
		"4a:f0:83:a8:fc:78",
		"6e:44:8b:04:9e:b6",
		"58:2a:0c:cc:f8:1b",
		"aa:bb:d0:8e:27:77",
		"04:72:56:ad:ce:f9",
		"d0:fe:3b:3b:59:3d",
		"eb:01:c4:5a:1d:ab",
		"b1:98:f9:3d:f9:39",
		"e3:17:6c:28:11:58",
		"bd:81:5b:b5:38:bc",
		"e7:c3:d2:24:59:9d",
		"43:aa:14:27:24:47",
		"8b:c7:05:ad:e2:76",
		"30:c6:74:f8:39:27",
		"82:04:b4:1f:48:63",
		"9d:59:3a:88:41:ed",
		"46:ee:bf:5e:e7:64",
		"bb:44:b9:86:4c:eb",
		"aa:de:d3:9e:dd:52",
		"5b:e9:36:12:ea:9a",
		"14:10:a6:e4:a4:ba",
		"61:2d:f0:30:d8:55",
		"3c:ac:79:eb:6d:a3",
		"b1:34:03:ce:d4:26",
		"46:ed:1a:6c:05:10",
		"61:cf:59:60:a0:84",
		"10:58:4c:90:37:5b",
		"8b:c4:44:de:f2:41",
		"1e:e6:1e:86:b3:27",
		"5f:b8:ea:ad:ad:d0",
		"e1:0d:88:81:b3:c4",
		"1f:60:3d:e1:16:87",
		"14:a8:b2:b9:3a:c3",
		"0b:cd:b0:1d:85:a1",
		"5e:fe:6c:a7:8c:41",
		"c8:33:aa:05:02:a0",
		"c0:23:19:3c:2f:4f",
		"0a:c8:e1:ed:21:06",
		"6c:1e:8f:cd:cf:e8",
		"21:ec:5d:07:db:8e",
		"f0:fa:54:d9:ef:f8",
		"79:18:7c:30:20:0e",
		"7c:a9:6f:78:07:1f",
		"65:fb:f1:b1:cc:aa",
		"1a:dc:f4:a1:ce:95",
		"be:cd:48:2f:8d:7b",
		"9a:a3:4c:87:c9:bf",
		"42:d5:8c:28:6d:2f",
		"b3:e2:5c:0b:52:eb",
		"21:33:0e:0f:01:60",
		"56:e5:55:b5:f9:03",
		"eb:29:df:c8:98:bb",
		"19:13:01:76:b9:5b",
		"95:a2:5b:50:b8:a3",
		"dc:fd:81:3a:14:54",
		"04:38:3e:21:0a:37",
		"1f:78:b5:7e:0d:fa",
		"1c:56:40:25:15:72",
		"e4:65:fb:8b:e1:a5",
		"f9:fd:4e:5b:e8:cb",
		"2c:94:1c:fb:c6:a9",
		"ee:83:eb:77:e2:33",
		"56:68:a7:34:3c:fb",
		"e0:7c:f1:a1:79:da",
		"65:f1:0a:e8:e8:6c",
		"96:63:e9:48:21:4a",
		"52:8f:cb:df:89:2e",
		"5e:03:13:e5:ef:c7",
		"ad:ba:a1:79:b6:9d",
		"10:2f:18:6a:fd:54",
		"ec:73:cc:c7:6c:fc",
		"a0:f1:a2:fb:89:9e",
		"8f:6d:62:7e:b4:8c",
		"35:e3:ad:91:a4:b4",
		"33:ea:8f:f8:70:f5",
		"b7:d3:c7:f1:a6:91",
		"f1:85:b0:fd:25:a0",
		"b3:98:b2:2e:df:47",
		"69:a7:12:b1:5b:fb",
		"8c:6c:9a:6d:21:62",
		"c1:74:a6:1f:51:df",
		"98:62:9e:90:19:a2",
		"49:73:6d:3f:6b:b0",
		"10:3a:cb:f7:0c:49",
		"67:8f:12:26:e2:3c",
		"33:9d:1c:61:0a:0c",
		"bf:98:95:d1:e3:40",
		"4e:08:87:d0:e9:bd",
		"57:77:2e:4a:10:2e",
		"cc:d7:89:38:6e:20",
		"50:a3:68:64:20:1d",
		"a8:a2:cf:b9:b6:5d",
		"21:16:b9:41:d9:5e",
		"b4:6b:d5:71:71:a9",
		"04:4e:99:ee:c4:fe",
		"6a:a6:f8:98:27:c3",
		"16:6d:ae:8e:59:c4",
		"53:e6:bb:20:c8:3e",
		"08:57:5e:c3:6d:48",
		"49:b7:fc:e5:f8:89",
		"d6:8f:20:02:6b:f5",
		"ac:83:18:aa:cc:a7",
		"98:ab:61:88:8a:64",
		"05:f4:69:b4:f3:b7",
		"f3:c0:d8:5d:75:e3",
		"42:b4:e9:3f:84:b6",
		"f4:3e:e3:54:7e:9b",
		"00:4c:5b:8c:a2:07",
		"a5:55:19:93:5d:71",
		"10:97:ed:73:e5:36",
		"82:fa:97:c2:88:1f",
		"5f:ce:be:e5:0e:f4",
		"08:db:4f:44:5d:b4",
		"c7:ee:09:b4:03:5c",
		"10:76:f0:e5:cd:af",
		"22:a3:4c:ab:11:b2",
		"d7:2b:30:3e:cb:e0",
		"ec:53:a5:f6:a4:bb",
		"51:b3:b9:f0:a3:05",
		"ba:71:db:e5:ac:a1",
		"14:da:5c:a1:91:4f",
		"94:04:2c:6d:02:55",
		"7b:d6:fc:06:b9:ea",
		"c4:24:18:b5:42:75",
		"be:34:91:4e:f3:d5",
		"16:2e:5d:95:0e:9a",
		"fa:56:c8:cf:e8:0b",
		"c5:9c:45:e6:0a:90",
		"08:6c:c8:db:1f:bb",
		"38:94:7a:02:e6:69",
		"e0:5a:02:d7:0c:eb",
		"80:a7:67:cd:92:b0",
		"32:14:74:96:3a:8c",
		"2d:07:44:82:9a:c9",
		"a1:9e:83:67:f7:8f",
		"19:b9:38:3d:43:60",
		"3b:2a:e4:ad:26:5f",
		"57:f5:88:7a:e3:59",
		"f6:18:dd:1b:75:2c",
		"f8:8e:10:ca:e7:9d",
		"cd:cb:52:c6:1b:13",
		"28:96:44:c7:1f:43",
		"c5:cc:6f:c6:13:71",
		"14:8a:7c:c1:2d:f4",
		"07:74:0a:bb:1f:91",
		"02:81:18:50:f3:b3",
		"0b:5b:d3:23:76:4a",
		"8f:c5:f7:20:37:27",
		"e2:c0:b2:9d:04:22",
		"f2:9f:06:2f:eb:e8",
		"d9:2a:6e:3c:32:45",
		"f2:76:62:92:75:02",
		"49:b2:3c:61:f8:6c",
		"a8:f2:b5:6a:e5:e1",
		"cd:31:c3:99:95:d5",
		"eb:db:66:98:9b:de",
		"4f:0a:7c:c1:8a:10",
		"60:0d:d8:0c:56:66",
		"1e:20:b7:1f:e7:f8",
		"cd:fe:22:04:35:e9",
		"d6:c3:0f:a5:7f:35",
		"e7:48:ae:e1:4e:0d",
		"63:8f:52:80:c5:9b",
		"b4:8e:18:37:7f:16",
		"46:51:0f:cc:d3:13",
		"51:b4:4e:06:e5:b2",
		"c1:46:59:82:52:2a",
		"69:45:41:7a:5c:88",
		"a7:e3:30:c5:13:e7",
		"bf:1b:a8:f4:cd:84",
		"d1:4d:08:97:60:1e",
		"e7:be:2d:2c:ad:64",
		"55:48:68:28:e4:38",
		"f9:68:4e:96:08:46",
		"d6:65:6c:f9:23:af",
		"3f:b2:de:1a:09:67",
		"63:85:c4:de:72:f0",
		"40:e9:06:ab:1e:3f",
		"08:ea:a0:b9:ae:1c",
		"73:30:e4:7a:26:8d",
		"62:9f:08:49:e7:35",
		"2a:00:92:75:49:41",
		"12:b9:2e:07:b6:ba",
		"02:ae:9d:5f:dc:28",
		"47:76:f1:7e:8c:5f",
		"3e:84:01:b8:45:83",
		"75:23:17:20:cc:db",
		"4e:80:b0:5f:c7:56",
		"4e:a3:b6:f8:37:b5"}
	mutex sync.RWMutex

	syslogMetrics = map[string]map[string]map[string]string{} // mac -> metric -> field -> value ; field can be value or label

	// regexpPatterns is a map that stores the regular expression patterns for different types of log messages.
	// Each pattern is associated with a set of named capture groups and corresponding field names.
	regexpPatterns = map[string]patterns{
		"v_integer":              {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) v=(?P<value>-?\d+)i`, fields: []string{"name", "value"}},
		"float":                  {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) v=(?P<value>[-\d\.]+)`, fields: []string{"name", "value"}},
		"integer":                {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) v=(?P<value>[-\d\.]+)i`, fields: []string{"name", "value"}},
		"string":                 {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) v="(?P<value>.*)"`, fields: []string{"name", "value"}},
		"xyv":                    {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) x=(?P<x>[-\d\.]+),y=(?P<y>[-\d\.]+),v=(?P<value>[-\d\.]+)`, fields: []string{"name", "x", "y", "value"}},
		"free_total":             {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) free=(?P<free>[-\d\.]+)i,total=(?P<total>[-\d\.]+)i`, fields: []string{"name", "free", "total"}},
		"axis_sens_period_speed": {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),axis=(?P<axis>[-\d\.]+) sens=(?P<sens>[-\d\.]+)i,period=(?P<period>[-\d\.]+)i,speed=(?P<speed>[-\d\.]+)`, fields: []string{"name", "axis", "sens", "period", "speed"}},
		"axis_last_total":        {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),axis=(?P<axis>[-\d\.]+) last=(?P<last>[-\d\.]+)i,total=(?P<total>[-\d\.]+)i`, fields: []string{"name", "axis", "last", "total"}},
		"xyz":                    {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) x=(?P<x>[-\d\.]+),y=(?P<y>[-\d\.]+),z=(?P<z>[-\d\.]+)`, fields: []string{"name", "x", "y", "z"}},
		"a_f_x_y_z":              {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) a=(?P<a>[-\d\.]+),f=(?P<f>[-\d\.]+),x=(?P<x>[-\d\.]+),y=(?P<y>[-\d\.]+),z=(?P<z>[-\d\.]+)`, fields: []string{"name", "a", "f", "x", "y", "z"}},
		"ax_ok_v_n":              {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),ax=(?P<ax>[-\d\.]+),ok=(?P<ok>[-\d\.]+) v=(?P<v>[-\d\.]+),n=(?P<n>[-\d\.]+)`, fields: []string{"name", "ax", "ok", "value", "n"}},
		"ok_desc":                {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) ok=(?P<ok>[-\d\.]+),desc="(?P<desc>[-\d\.]+)"`, fields: []string{"name", "ok", "desc"}},
		"sent":                   {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) sent=(?P<sent>[-\d\.]+)i`, fields: []string{"name", "sent"}},
		"recv":                   {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) recv=(?P<recv>[-\d\.]+)i`, fields: []string{"name", "recv"}},
		"n_t_m":                  {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+) t=(?P<t>[-\d\.]+),m=(?P<m>[-\d\.]+)`, fields: []string{"name", "n", "t", "m"}},
		"n_u":                    {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+) u=(?P<u>[-\d\.]+)`, fields: []string{"name", "n", "u"}},
		"n_a_value":              {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+),a=(?P<a>[-\d\.]+) value=(?P<value>[-\d\.]+)`, fields: []string{"name", "n", "a", "value"}},
		"n_a_value_integer":      {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+),a=(?P<a>[-\d\.]+) value=(?P<value>[-\d\.]+)i`, fields: []string{"name", "n", "a", "value"}},
		"n_st_f_r_ri_sp":         {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+) st=(?P<st>[-\d\.]+),f=(?P<f>[-\d\.]+),r=(?P<r>[-\d\.]+),ri=(?P<ri>[-\d\.]+),sp=(?P<sp>[-\d\.]+)`, fields: []string{"name", "n", "st", "f", "r", "ri", "sp"}},
		"n_v_integer":            {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+) v=(?P<v>[-\d\.]+)i`, fields: []string{"name", "n", "value"}},
		"xy":                     {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) x=(?P<x>[-\d\.]+),y=(?P<y>[-\d\.]+)`, fields: []string{"name", "x", "y"}},
		"as_fe_rs_ae":            {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) as=(?P<as>[-\d\.]+),fe=(?P<fe>[-\d\.]+),rs=(?P<rs>[-\d\.]+),ae=(?P<ae>[-\d\.]+)`, fields: []string{"name", "as", "fe", "rs", "ae"}},
		"ax_reg_regn_value":      {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),ax=(?P<ax>[-\d\.]+) reg=(?P<reg>[-\d\.]+),regn="(?P<regn>[-\d\.]+)",value=(?P<value>[-\d\.]+)i`, fields: []string{"name", "ax", "reg", "regn", "value"}},
		"fan_state_pwm_measured": {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),fan=(?P<fan>[-\d\.]+) state=(?P<state>[-\d\.]+),pwm=(?P<pwm>[-\d\.]+),measured=(?P<measured>[-\d\.]+)`, fields: []string{"name", "fan", "state", "pwm", "measured"}},
		"t_p_a_x_y":              {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),t=(?P<t>[-\d\.]+),p=(?P<p>[-\d\.]+),a=(?P<a>[-\d\.]+) x=(?P<x>[-\d\.]+),y=(?P<y>[-\d\.]+)`, fields: []string{"name", "t", "p", "a", "x", "y"}},
		"t_p_x_y_z":              {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),t=(?P<t>[-\d\.]+),p=(?P<p>[-\d\.]+) x=(?P<x>[-\d\.]+),y=(?P<y>[-\d\.]+),z=(?P<z>[-\d\.]+)`, fields: []string{"name", "t", "p", "x", "y", "z"}},
		"t_x_y_z":                {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),t=(?P<t>[-\d\.]+) x=(?P<x>[-\d\.]+),y=(?P<y>[-\d\.]+),z=(?P<z>[-\d\.]+)`, fields: []string{"name", "t", "x", "y", "z"}},
		"n_v":                    {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+) v=(?P<v>[-\d\.]+)`, fields: []string{"name", "n", "value"}},
		"n_v_e_integer":          {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+) v=(?P<v>[-\d\.]+)i,e=(?P<e>[-\d\.]+)i`, fields: []string{"name", "n", "value", "e"}},
		"n_p_i_d_tc":             {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+) p=(?P<p>[-\d\.]+),i=(?P<i>[-\d\.]+),d=(?P<d>[-\d\.]+),tc=(?P<tc>[-\d\.]+)`, fields: []string{"name", "n", "p", "i", "d", "tc"}},
		"n_v_e":                  {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+) v=(?P<v>[-\d\.]+),e=(?P<e>[-\d\.]+)`, fields: []string{"name", "n", "value", "e"}},
		"r_o_s":                  {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) r=(?P<r>[-\d\.]+)i,o=(?P<o>[-\d\.]+)i,s=(?P<s>[-\d\.]+)`, fields: []string{"name", "r", "o", "s"}},
	}
)

// startSyslogServer is a function that starts a syslog server and returns a channel to receive log parts and the server instance.
// The syslog server listens for UDP connections on the specified address.
// It uses the RFC5424 format for log messages.
// The log parts are sent to the provided channel for further processing.
func startSyslogServer(listenUDP string) (syslog.LogPartsChannel, *syslog.Server) {
	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.RFC5424)
	server.SetHandler(handler)
	server.ListenUDP(listenUDP)
	server.Boot()
	return channel, server
}

// HandleMetrics is function that listens for syslog messages and parses them into map
func HandleMetrics(listenUDP string) {
	channel, server := startSyslogServer(listenUDP)
	log.Debug().Msg("Syslog server started at: " + listenUDP)
	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			var timestamp time.Time
			var output []string
			timestamp = time.Now().UTC()
			timestampUnix := timestamp.UnixNano()
			mac := logParts["hostname"].(string)
			if mac == "" {
				continue
			}
			ip := logParts["client"].(string)
			facility := logParts["facility"].(int)
			severity := logParts["severity"].(int)
			appName := logParts["app_name"].(string)
			if appName == "" {
				appName = "unknown"
			}
			procID := logParts["proc_id"].(string)
			if procID == "" {
				procID = "unknown"
			}
			msgID := logParts["msg_id"].(string)
			if msgID == "" {
				msgID = "unknown"
			}
			message := logParts["message"].(string)
			if message == "" {
				message = "unknown"
			}
			priority := logParts["priority"].(int)
			structuredData := logParts["structured_data"].(string)
			if structuredData == "" {
				structuredData = "unknown"
			}
			version := logParts["version"].(int)
			tlsPeer := logParts["tls_peer"].(string)
			if tlsPeer == "" {
				tlsPeer = "unknown"
			}

			remoteWriteInflux = true
			if remoteWriteInflux {
				output = []string{}
				log.Info().Msg("Received message from: " + mac)
				var splittedMessage []string
				if strings.Contains(message, "\n") {
					splittedMessage = strings.Split(logParts["message"].(string), "\n")
				} else {
					splittedMessage = []string{logParts["message"].(string)}
				}

				for _, v := range macList {
					go func(splittedMessage []string, v string) {
						for _, message := range splittedMessage {
							line := strings.Split(message, " ")
							length := len(line)
							pos := 0
							if strings.Contains(line[pos], "msg") { // getting rid of msg metrics
								line[0] = ""
								pos = 1
							}

							line[pos] = strings.Join([]string{"prusa_" + line[0], "ip=" + ip, "facility=" + strconv.Itoa(facility), "severity=" + strconv.Itoa(severity),
								"app_name=" + appName, "proc_id=" + procID, "msg_id=" + msgID, "priority=" + strconv.Itoa(priority), "structured_data=" + structuredData,
								"version=" + strconv.Itoa(version), "tls_peer=" + tlsPeer, "mac=" + v}, ",")
							time, _ := strconv.ParseInt(line[length-1], 10, 64)
							line[length-1] = strconv.FormatInt(timestampUnix-(time*1000), 10)
							output = append(output, strings.Join(line, " "))
							//fmt.Println(line[length-1])
						}
						url := "http://influxproxy:8007/api/v1/push/influx/write"
						for _, line := range output {
							body := strings.NewReader(line)
							req, err := http.NewRequest("POST", url, body)
							if err != nil {
								log.Error().Msg("Error creating request: " + err.Error())
								continue
							}
							req.Header.Set("Content-Type", "application/json")

							resp, err := http.DefaultClient.Do(req)
							if err != nil {
								log.Error().Msg("Error sending request: " + err.Error())
								continue
							}

							//log.Debug().Msg("Sent message to InfluxProxy: " + line)
							defer resp.Body.Close()
						}
					}(splittedMessage, v)
				}

				/*}  else if !remoteWriteInflux {
					var splittedMessage []string
					if strings.Contains(message, "\n") {
						splittedMessage = strings.Split(logParts["message"].(string), "\n")
					} else {
						splittedMessage = []string{logParts["message"].(string)}
					}

					for _, message := range splittedMessage {
						line := strings.Split(message, " ")
						length := len(line)
						pos := 0
						if strings.Contains(line[pos], "msg") { // getting rid of msg metrics
							line[0] = ""
							pos = 1
						}

						line[pos] = "prusa_" + line[pos]
						timestamp, _ := strconv.ParseInt(line[length-1], 10, 64)
						line[length-1] = strconv.FormatInt(timestampUnix-(timestamp*1000), 10)
						//fmt.Println(strings.Join(line, " "))
						points, _ := models.ParsePointsString(strings.Join(line, " "))

						fmt.Printf("tags: %v\n", points[0].Tags())
						client := promwrite.NewClient("http://mimir:9009/api/v1/push")

						fields, err := points[0].Fields()

						if err != nil {
							fmt.Println("Error getting fields:", err)
							continue
						}
						for k, v := range fields {
							value := 0.0

							labels := []promwrite.Label{
								{
									Name:  "__name__",
									Value: "prusa_" + string(points[0].Name()) + "_" + k,
								},
							}

							for _, v := range points[0].Tags() {
								if v.Key != "v" {
									labels = append(labels, promwrite.Label{
										Name:  string(v.Key),
										Value: string(v.Value),
									})
								} else {
									value, _ = strconv.ParseFloat(string(v.Value), 64)
								}
							}

							_, err := client.Write(context.Background(), &promwrite.WriteRequest{
								TimeSeries: []promwrite.TimeSeries{
									{
										Labels: labels,
										Sample: promwrite.Sample{
											Time:  time.Unix(timestampUnix-(timestamp), 0),
											Value: value,
										},
									},
								},
							})
							if err != nil {
								fmt.Println("Error writing points:", err)
								continue
							}
							fmt.Println(k, v)
						}

					}
				} */
			} else {

				mac := logParts["hostname"].(string)
				if mac == "" { // Skip empty mac addresses
					continue
				} else {
					mutex.Lock()
					loadedPart := syslogMetrics[mac]

					if loadedPart == nil {
						loadedPart = make(map[string]map[string]string) // if found but empty, create a new map, at start it will be empty everytime
					}

					if loadedPart["ip"] == nil {
						loadedPart["ip"] = make(map[string]string)
					}

					if loadedPart["timestamp"] == nil {
						loadedPart["timestamp"] = make(map[string]string)
					}

					loadedPart["ip"]["value"] = logParts["client"].(string)
					loadedPart["timestamp"]["value"] = time.Now().Format(time.RFC3339Nano)

					log.Trace().Msg("Received message from: " + mac)

					message := logParts["message"].(string)

					var splittedMessage []string

					if strings.Contains(message, "\n") {
						splittedMessage = strings.Split(logParts["message"].(string), "\n")
					} else {
						splittedMessage = []string{logParts["message"].(string)}
					}

					for _, message := range splittedMessage {
						for name, pattern := range regexpPatterns {

							reg, err := regexp.Compile(pattern.pattern)
							if err != nil {
								log.Error().Msg("Error compiling regexp: " + err.Error())
								continue
							}

							log.Trace().Msg("Matching pattern: " + name + " for message: " + message)

							matches := reg.FindAllStringSubmatch(message, -1)
							if matches == nil {
								continue // No matches for this pattern
							}
							var metricName string

							for _, match := range matches {
								// Extract values based on named groups

								suffix := ""

								for i, field := range pattern.fields {
									if field == "n" {
										suffix = "_" + match[i+1]
									}
								}

								for i, field := range pattern.fields {
									if field == "name" {
										metricName = match[i+1] + suffix
									} else if match[i+1] != "" && field != "timestamp" { // todo - check if timestamp is needed
										if loadedPart[metricName] == nil {
											loadedPart[metricName] = make(map[string]string)
										}
										loadedPart[metricName][field] = match[i+1]
									}
								}
							}
						}
					}

					syslogMetrics[mac] = loadedPart

					mutex.Unlock()
				}
			}
		}
	}(channel)

	server.Wait()
}
