package bmp420

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"xvertile/akamai-bmp/dm"
)

func TestAzulSensorLayoutAndIntegrity(t *testing.T) {
	devices, err := dm.LoadDevicesFromFile("../../server/db/devices.json")
	if err != nil || len(devices) == 0 {
		t.Fatalf("load devices: %v", err)
	}
	profile := DeviceProfileFromDM(devices[0], "pt_BR")
	repeatedProfile := DeviceProfileFromDM(devices[0], "pt_BR")
	if profile.BuildTime != repeatedProfile.BuildTime ||
		profile.SecurityPatch != repeatedProfile.SecurityPatch ||
		time.UnixMilli(profile.BuildTime).Year() != 2019 {
		t.Fatal("build properties must remain stable and match the release era")
	}
	if buildCommonInfo(profile) != buildCommonInfo(profile) {
		t.Fatal("local device info must stay stable across sensor requests")
	}
	if profile.MemoryTotalKB != repeatedProfile.MemoryTotalKB ||
		profile.StorageTotalBytes != repeatedProfile.StorageTotalBytes {
		t.Fatal("memory and storage capacities must stay stable for a device")
	}
	profile.AppSignatureSHA1 = "bb40c0885cba78e617b4c484de534fc0b5dd3c59"
	g, err := NewGenerator(profile, "br.com.voeazul", "7.4.1", 4141,
		"https://b2c-api.voeazul.com.br")
	if err != nil {
		t.Fatal(err)
	}
	sensor := g.Generate(GenerateOpts{DeviceID: profile.AndroidID})
	parts := strings.Split(sensor, "$")
	if len(parts) != 7 || !strings.HasPrefix(parts[0], "6,a,") {
		t.Fatalf("unexpected header shape: %d parts", len(parts))
	}
	if !strings.HasSuffix(parts[6], "&&&4.2.0") {
		t.Fatal("metadata lacks sensor version 4.2.0")
	}
	packet, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(packet) < 16+32+16 {
		t.Fatal("invalid encrypted payload")
	}
	iv, ciphertext, tag := packet[:16], packet[16:len(packet)-32], packet[len(packet)-32:]
	mac := hmac.New(sha256.New, g.Ctx.HMACKey)
	mac.Write(iv)
	mac.Write(ciphertext)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		t.Fatal("payload HMAC mismatch")
	}
	block, err := aes.NewCipher(g.Ctx.AESKey)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > aes.BlockSize {
		t.Fatal("invalid padding")
	}
	plain = plain[:len(plain)-pad]
	s := string(plain)
	if !strings.HasPrefix(s, "4.2.0") || !strings.Contains(s, "br.com.voeazul") {
		t.Fatal("sensor version or app identity missing")
	}
	if !strings.Contains(s, "-90,buildId=") ||
		!strings.Contains(s, "#screenWidth=") ||
		!strings.Contains(s, "#cpuABI=") {
		t.Fatal("SDK JavaScript signal field names missing")
	}
	last := 0
	for _, field := range []string{
		"-90,", "-91,", "-70,", "-80,", "-121,", "-100,", "-101,",
		"-102,", "-103,", "-104,", "-108,", "-112,", "-115,", "-117,", "-120,",
		"-144,", "-160,", "-142,", "-145,", "-161,", "-143,", "-150,",
		"-163,", "-165,", "-166,", "-171,", "-240,", "-172,", "-180,",
	} {
		at := strings.Index(s[last:], Separator+field)
		if at < 0 {
			t.Fatalf("missing or out-of-order field %s", field)
		}
		last += at + len(Separator+field)
	}
}

func TestAndroidSDKFieldShapes(t *testing.T) {
	devices, err := dm.LoadDevicesFromFile("../../server/db/devices.json")
	if err != nil || len(devices) == 0 {
		t.Fatalf("load devices: %v", err)
	}
	profile := DeviceProfileFromDM(devices[0], "pt_BR")
	pairs := BuildSensorPairs(profile, "br.com.voeazul", "7.6.0", 4154,
		"https://b2c-api.voeazul.com.br/", "synthetic JS", "0", 3, 256)
	fields := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		fields[pair[0]] = pair[1]
	}
	for field, count := range map[string]int{"-112": 9, "-115": 19, "-163": 8} {
		if got := len(strings.Split(fields[field], ",")); got != count {
			t.Errorf("%s: got %d comma fields, Android SDK has %d", field, got, count)
		}
	}
	fingerprint := strings.Split(fields["-100"], ",")
	if len(fingerprint) != 40 || fingerprint[9] != profile.Release ||
		fingerprint[12] != profile.Bootloader ||
		fingerprint[23] != profile.Incremental ||
		fingerprint[29] != profile.BuildUser ||
		fingerprint[30] != profile.BuildDisplay ||
		fingerprint[34] != profile.Fingerprint {
		t.Fatal("-100 does not match Android SDK property positions")
	}
	androidInfo := strings.Split(fields["-166"], ",")
	if len(androidInfo) != 39 || androidInfo[20] != URLEncode(profile.BuildID) ||
		androidInfo[21] != URLEncode(profile.RadioVersion) ||
		androidInfo[23] != URLEncode(profile.ABI32) ||
		androidInfo[24] != URLEncode(profile.ABI64) ||
		androidInfo[29] != "false" || androidInfo[30] != "false" ||
		androidInfo[35] != "false" {
		t.Fatal("-166 does not match Android SDK property positions")
	}
	perf := strings.Split(fields["-112"], ",")
	sqrtHits, err := strconv.Atoi(perf[4])
	if err != nil {
		t.Fatal(err)
	}
	sqrtHundreds, err := strconv.Atoi(perf[5])
	if err != nil {
		t.Fatal(err)
	}
	if sqrtHits < 0 || sqrtHundreds < 1 || sqrtHits > sqrtHundreds*100 {
		t.Fatalf("impossible sqrt benchmark relationship: %d/%d", sqrtHits, sqrtHundreds)
	}
	if !strings.HasSuffix(fields["-163"], ",false,false") {
		t.Fatal("native device-info status fields missing")
	}
	if !strings.HasSuffix(fields["-171"], "/") {
		t.Fatal("SDK endpoint lost trailing slash")
	}
}

func TestNativeStaticFieldsStayStableAcrossSensorCalls(t *testing.T) {
	devices, err := dm.LoadDevicesFromFile("../../server/db/devices.json")
	if err != nil || len(devices) == 0 {
		t.Fatalf("load devices: %v", err)
	}
	profile := DeviceProfileFromDM(devices[0], "pt_BR")
	profile.AndroidID = "0123456789abcdef"
	profile.DeviceID = profile.AndroidID
	profile.AppStartTimestampMS = 1790000000000
	profile.InstallTimestampMS = 1780000000000
	makeFields := func() map[string]string {
		pairs := BuildSensorPairs(profile, "br.com.voeazul", "7.6.0", 4154,
			"https://b2c-api.voeazul.com.br/", "same JS signal", "0", 3, 32)
		fields := make(map[string]string, len(pairs))
		for _, pair := range pairs {
			fields[pair[0]] = pair[1]
		}
		return fields
	}
	first, second := makeFields(), makeFields()
	for _, field := range []string{"-90", "-163", "-165", "-166", "-171"} {
		if first[field] != second[field] {
			t.Errorf("%s changes despite stable device and app process", field)
		}
	}
	fp1, fp2 := strings.Split(first["-100"], ","), strings.Split(second["-100"], ",")
	if len(fp1) != 40 || len(fp2) != 40 ||
		strings.Join(fp1[:38], ",") != strings.Join(fp2[:38], ",") {
		t.Error("static -100 device properties change across sensor calls")
	}
}
