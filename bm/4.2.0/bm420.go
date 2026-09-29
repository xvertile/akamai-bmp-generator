// Package bmp420 implements an experimental Akamai BAP sensor 4.2.0 layout.
//
// The field identifiers and order were checked against the Java layer of an
// Android SDK 4.0.5 integration. Successful acceptance by Akamai has not been
// demonstrated; native encryption and device signals still need comparison
// with a sensor emitted by that SDK.
package bmp420

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math"
	mrand "math/rand"
	"strconv"
	"strings"
	"time"

	dm "xvertile/akamai-bmp/dm"

	"crypto/aes"
	"crypto/cipher"
)

const (
	Separator             = "-1,2,-94,"
	SDKVersion            = "4.2.0"
	DefaultAppPackage     = "com.example.app"
	DefaultAppVersion     = "1.0.0"
	DefaultAppVersionCode = 1
	DefaultServerURL      = "https://example.com/"
	DefaultSignatureSHA1  = "0000000000000000000000000000000000000000"
	rsaPEM                = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCy6MZCHFkCceIPw2AHHnSdTckX
aD2d7W4zMQEfDPil01O7avuUw+IFEY1ap6qrwScbeuKp/63sNEumI/bz5wtNdf6G
rCCPRQGB7brjE468euFFi2+zIYQWDlv3FH3kkfc9aZJAvuSyIQVv7YAVwSpFCM3c
cmD0GuxAIRckhuvqvQIDAQAB
-----END PUBLIC KEY-----`
)

var crcTable = [256]uint32{
	3523407757, 2768625435, 1007455905, 1259060791, 3580832660, 2724731650,
	996231864, 1281784366, 3705235391, 2883475241, 852952723, 1171273221,
	3686048678, 2897449776, 901431946, 1119744540, 3484811241, 3098726271,
	565944005, 1455205971, 3369614320, 3219065702, 651582172, 1372678730,
	3245242331, 3060352845, 794826487, 1483155041, 3322131394, 2969862996,
	671994606, 1594548856, 3916222277, 2657877971, 123907689, 1885708031,
	3993045852, 2567322570, 1010288, 1997036262, 3887548279, 2427484129,
	163128923, 2126386893, 3772416878, 2547889144, 248832578, 2043925204,
	4108050209, 2212294583, 450215437, 1842515611, 4088798008, 2226203566,
	498629140, 1790921346, 4194326291, 2366072709, 336475711, 1661535913,
	4251816714, 2322244508, 325317158, 1684325040, 2766056989, 3554254475,
	1255198513, 1037565863, 2746444292, 3568589458, 1304234792, 985283518,
	2852464175, 3707901625, 1141589763, 856455061, 2909332022, 3664761504,
	1130791706, 878818188, 3110715001, 3463352047, 1466425173, 543223747,
	3187964512, 3372436214, 1342839628, 655174618, 3081909835, 3233089245,
	1505515367, 784033777, 2967466578, 3352871620, 1590793086, 701932520,
	2679148245, 3904355907, 1908338681, 112844655, 2564639436, 4024072794,
	1993550816, 30677878, 2439710439, 3865851505, 2137352139, 140662621,
	2517025534, 3775001192, 2013832146, 252678980, 2181537457, 4110462503,
	1812594589, 453955339, 2238339752, 4067256894, 1801730948, 476252946,
	2363233923, 4225443349, 1657960367, 366298937, 2343686810, 4239843852,
	1707062198, 314082080, 1069182125, 1220369467, 3518238081, 2796764439,
	953657524, 1339070498, 3604597144, 2715744526, 828499103, 1181144073,
	3748627891, 2825434405, 906764422, 1091244048, 3624026538, 2936369468,
	571309257, 1426738271, 3422756325, 3137613171, 627095760, 1382516806,
	3413039612, 3161057642, 752284923, 1540473965, 3268974039, 3051332929,
	733688034, 1555824756, 3316994510, 2998034776, 81022053, 1943239923,
	3940166985, 2648514015, 62490748, 1958656234, 3988253008, 2595281350,
	168805463, 2097738945, 3825313147, 2466682349, 224526414, 2053451992,
	3815530850, 2490061300, 425942017, 1852075159, 4151131437, 2154433979,
	504272920, 1762240654, 4026595636, 2265434530, 397988915, 1623188645,
	4189500703, 2393998729, 282398762, 1741824188, 4275794182, 2312913296,
	1231433021, 1046551979, 2808630289, 3496967303, 1309403428, 957143474,
	2684717064, 3607279774, 1203610895, 817534361, 2847130659, 3736401077,
	1087398166, 936857984, 2933784634, 3654889644, 1422998873, 601230799,
	3135200373, 3453512931, 1404893504, 616286678, 3182598252, 3400902906,
	1510651243, 755860989, 3020215367, 3271812305, 1567060338, 710951396,
	3010007134, 3295551688, 1913130485, 84884835, 2617666777, 3942734927,
	1969605100, 40040826, 2607524032, 3966539862, 2094237127, 198489425,
	2464015595, 3856323709, 2076066270, 213479752, 2511347954, 3803648100,
	1874795921, 414723335, 2175892669, 4139142187, 1758648712, 534112542,
	2262612132, 4057696306, 1633981859, 375629109, 2406151311, 4167943193,
	1711886778, 286155052, 2282172566, 4278190080,
}

var mustEncode = map[byte]bool{34: true, 37: true, 39: true, 44: true, 92: true}

// ── Types ────────────────────────────────────────────────────────────────────

type DeviceProfile struct {
	Model               string      `json:"model"`
	Manufacturer        string      `json:"manufacturer"`
	Brand               string      `json:"brand"`
	Device              string      `json:"device"`
	Product             string      `json:"product"`
	Board               string      `json:"board"`
	Hardware            string      `json:"hardware"`
	Bootloader          string      `json:"bootloader"`
	Fingerprint         string      `json:"fingerprint"`
	BuildID             string      `json:"build_id"`
	BuildDisplay        string      `json:"build_display"`
	BuildTags           string      `json:"build_tags"`
	BuildType           string      `json:"build_type"`
	BuildUser           string      `json:"build_user"`
	Incremental         string      `json:"incremental"`
	Codename            string      `json:"codename"`
	Release             string      `json:"release"`
	SDKInt              int         `json:"sdk_int"`
	SecurityPatch       string      `json:"security_patch"`
	PreviewSDKInt       int         `json:"preview_sdk_int"`
	BaseOS              string      `json:"base_os"`
	ABI32               string      `json:"abi_32"`
	ABI64               string      `json:"abi_64"`
	CPUABI              string      `json:"cpu_abi"`
	ScreenHeight        int         `json:"screen_height"`
	ScreenWidth         int         `json:"screen_width"`
	ScreenCount         int         `json:"screen_count"`
	IsCharging          bool        `json:"is_charging"`
	BatteryPercent      int         `json:"battery_percent"`
	Orientation         int         `json:"orientation"`
	AutoRotate          int         `json:"auto_rotate"`
	PhysicalKeyboard    bool        `json:"physical_keyboard"`
	GlobalSettingFlag   int         `json:"global_setting_flag"`
	DensityDPI          string      `json:"density_dpi"`
	RefreshRate         float64     `json:"refresh_rate"`
	Host                string      `json:"host"`
	Serial              string      `json:"serial"`
	RadioVersion        string      `json:"radio_version"`
	BuildTime           int64       `json:"build_time"`
	UserAgent           string      `json:"user_agent"`
	UAHash              string      `json:"ua_hash"`
	InstalledApps       []string    `json:"installed_apps,omitempty"`
	LocaleLanguage      string      `json:"locale_language"`
	LocaleCountry       string      `json:"locale_country"`
	TimezoneOffset      int         `json:"timezone_offset_min"`
	BluetoothName       string      `json:"bluetooth_name"`
	LocalIP             string      `json:"local_ip,omitempty"`
	TelephonyStatus     int         `json:"telephony_status"`
	SIMStatus           int         `json:"sim_status"`
	NFCEnabled          int         `json:"nfc_enabled"`
	AirplaneMode        int         `json:"airplane_mode"`
	IsTablet            int         `json:"is_tablet"`
	MemoryTotalKB       int         `json:"memory_total_kb"`
	StorageTotalBytes   int64       `json:"storage_total_bytes"`
	AppSignatureSHA1    string      `json:"app_signature_sha1"`
	InstallTimestampMS  int64       `json:"install_timestamp_ms,omitempty"`
	AppStartTimestampMS int64       `json:"app_start_timestamp_ms,omitempty"`
	WebviewFPHash       string      `json:"webview_fp_hash"`
	SensorRates         SensorRates `json:"sensor_rates"`
	AndroidID           string      `json:"android_id,omitempty"`
	DeviceID            string      `json:"device_id,omitempty"`
}

type SensorRates struct {
	AccelUS    int `json:"accel_us"`
	GyroUS     int `json:"gyro_us"`
	AccelRange int `json:"accel_range"`
	GyroRange  int `json:"gyro_range"`
}

type CryptoContext struct {
	AESKey     []byte
	HMACKey    []byte
	RSAAesB64  string
	RSAHMACB64 string
	rsaKey     *rsa.PublicKey
}

type MersenneTwister struct {
	mt    [624]uint32
	index int
}

type Generator struct {
	Device         DeviceProfile
	AppPackage     string
	AppVersion     string
	AppVersionCode int
	ServerURL      string
	Ctx            *CryptoContext
}

type GenerateOpts struct {
	ServerSignal    string
	CPRSignal       string
	CPRToken        string
	DeviceID        string
	PoWResponse     string
	CCAToken        string
	JSSignals       string
	NumTouchTaps    int
	NumSensorEvents int
}

// ── CRC32 ────────────────────────────────────────────────────────────────────

func CRC32(s string) uint32 {
	var crc uint32
	for _, ch := range s {
		idx := (crc & 0xFF) ^ uint32(ch)
		crc = (crc >> 8) ^ crcTable[idx]
	}
	return crc
}

// ── RLE ──────────────────────────────────────────────────────────────────────

func RLEEncode(s string) string {
	if len(s) == 0 {
		return s
	}
	var b strings.Builder
	runes := []rune(s)
	i := 0
	for i < len(runes) {
		ch := runes[i]
		count := 1
		for i+count < len(runes) && runes[i+count] == ch {
			count++
		}
		if count > 1 {
			b.WriteString(strconv.Itoa(count))
		}
		b.WriteRune(ch)
		i += count
	}
	return b.String()
}

// ── Quantize ─────────────────────────────────────────────────────────────────

func swapDotBackslash(ch rune) rune {
	if ch == '\\' {
		return '.'
	}
	if ch == '.' {
		return '\\'
	}
	return ch
}

func Quantize(values []float64, minVal, maxVal float64) string {
	binWidth := (maxVal - minVal) / 60.0
	var b strings.Builder
	for _, v := range values {
		var idx int
		if v == maxVal {
			idx = 60 + 65
		} else {
			idx = int(math.Floor((v-minVal)/binWidth)) + 65
		}
		b.WriteRune(swapDotBackslash(rune(idx)))
	}
	return b.String()
}

// ── DCT-II ───────────────────────────────────────────────────────────────────

func dctFwd(data, temp []float64, off, length int) {
	if length == 1 {
		return
	}
	half := length / 2
	for i := 0; i < half; i++ {
		a := data[off+i]
		b := data[off+length-1-i]
		temp[off+i] = a + b
		cosVal := math.Cos((float64(i) + 0.5) * math.Pi / float64(length))
		temp[off+i+half] = (a - b) / (2.0 * cosVal)
	}
	dctFwd(temp, data, off, half)
	dctFwd(temp, data, off+half, half)
	for i := 0; i < half-1; i++ {
		data[off+2*i] = temp[off+i]
		data[off+2*i+1] = temp[off+i+half] + temp[off+i+half+1]
	}
	data[off+length-2] = temp[off+half-1]
	data[off+length-1] = temp[off+length-1]
}

func DCTForward(arr []float64) []float64 {
	n := len(arr)
	data := make([]float64, n)
	copy(data, arr)
	temp := make([]float64, n)
	dctFwd(data, temp, 0, n)
	return data
}

// ── Shrink ───────────────────────────────────────────────────────────────────

func ShrinkCoef(coeffs []float64, pct float64) {
	n := len(coeffs)
	sorted := make([]float64, n)
	for i, v := range coeffs {
		sorted[i] = math.Abs(v)
	}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	idx := int(math.Floor(float64(n-1) * pct))
	threshold := sorted[idx]
	for i := range coeffs {
		if math.Abs(coeffs[i]) < threshold {
			coeffs[i] = 0
		}
	}
}

// ── Axis Encoding ────────────────────────────────────────────────────────────

func round2(f float64) float64 {
	return math.Round(f*100) / 100.0
}

func prevPowerOfTwo(n int) int {
	if n <= 0 {
		return 0
	}
	v := uint32(n)
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	return int(v - (v >> 1))
}

func minMax(vals []float64) (float64, float64) {
	mn, mx := vals[0], vals[0]
	for _, v := range vals[1:] {
		if v < mn {
			mn = v
		}
		if v > mx {
			mx = v
		}
	}
	return mn, mx
}

func EncodeAxis(values []float64, shrinkPct float64) (string, int64) {
	if len(values) < 2 {
		return "0;", 0
	}

	mn1, mx1 := minMax(values)
	if mn1 == mx1 {
		mx1 = mn1 + 0.01
	}
	q1 := Quantize(values, mn1, mx1)
	rle1 := RLEEncode(q1)
	c1 := CRC32(rle1)
	mn1r, mx1r := round2(mn1), round2(mx1)
	s1 := fmt.Sprintf("2;%.2f;%.2f;%d;%s", mn1r, mx1r, c1, rle1)
	ck1 := int64(math.Round(mn1r*100+mx1r*100)) + int64(c1)

	n := len(values)
	if n&(n-1) != 0 {
		return s1, ck1
	}

	coeffs := DCTForward(values)
	ShrinkCoef(coeffs, shrinkPct)
	dc := coeffs[0]
	rem := coeffs[1:]
	if len(rem) < 1 {
		return s1, ck1
	}
	mn2, mx2 := minMax(rem)
	if mn2 == mx2 {
		mx2 = mn2 + 0.01
	}
	q2 := Quantize(rem, mn2, mx2)
	rle2 := RLEEncode(q2)
	c2 := CRC32(rle2)
	mn2r, mx2r, dcr := round2(mn2), round2(mx2), round2(dc)
	s2 := fmt.Sprintf("1;%.2f;%.2f;%.2f;%d;%s", mn2r, mx2r, dcr, c2, rle2)
	ck2 := int64(math.Round(mn2r*100+mx2r*100+dcr*100)) + int64(c2)

	if len(rle1)-len(rle2) >= 20 {
		return s2, ck2
	}
	return s1, ck1
}

// ── Feistel ──────────────────────────────────────────────────────────────────

func feistelRound(val, key uint32, r int) uint32 {
	r &= 31
	rotated := (key << r) | (key >> (32 - r))
	return val ^ rotated
}

func FeistelEncode(val uint64, key uint32) uint64 {
	lo := uint32(val)
	hi := uint32(val >> 32)
	for r := 0; r < 16; r++ {
		newHi := hi ^ feistelRound(lo, key, r)
		hi, lo = lo, newHi
	}
	return (uint64(hi) << 32) | uint64(lo)
}

func GQRJZH(a, b int, c int64) uint64 {
	packed := (uint64(uint32(a)) << 32) | uint64(uint32(b))
	return FeistelEncode(packed, uint32(c))
}

// ── StringToInt ──────────────────────────────────────────────────────────────

func StringToInt(s string) int {
	if len(strings.TrimSpace(s)) == 0 {
		return -1
	}
	total := 0
	for _, c := range s {
		if c < 128 {
			total += int(c)
		}
	}
	return total
}

// ── URL Encode ───────────────────────────────────────────────────────────────

func URLEncode(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, by := range []byte(s) {
		if by >= 33 && by <= 126 && !mustEncode[by] {
			b.WriteByte(by)
		} else {
			fmt.Fprintf(&b, "%%%02X", by)
		}
	}
	return b.String()
}

// ── Mersenne Twister ─────────────────────────────────────────────────────────

func NewMT(seed uint32) *MersenneTwister {
	mt := &MersenneTwister{index: 624}
	mt.mt[0] = seed
	for i := 1; i < 624; i++ {
		mt.mt[i] = uint32(i) + 1812433253*(mt.mt[i-1]^(mt.mt[i-1]>>30))
	}
	return mt
}

func (m *MersenneTwister) twist() {
	for i := 0; i < 624; i++ {
		y := (m.mt[i] & 0x80000000) | (m.mt[(i+1)%624] & 0x7FFFFFFF)
		m.mt[i] = m.mt[(i+397)%624] ^ (y >> 1)
		if y&1 != 0 {
			m.mt[i] ^= 0x9908B0DF
		}
	}
	m.index = 0
}

func (m *MersenneTwister) Extract() uint32 {
	if m.index >= 624 {
		m.twist()
	}
	y := m.mt[m.index]
	y ^= y >> 11
	y ^= (y << 7) & 0x9D2C5680
	y ^= (y << 15) & 0xEFC60000
	y ^= y >> 18
	m.index++
	return y
}

func (m *MersenneTwister) RandRange(lo, hi int) int {
	if lo == hi {
		return lo
	}
	rangeSize := uint32(hi - lo + 1)
	for {
		val := m.Extract()
		result := val % rangeSize
		if val-result+rangeSize-1 < 0xFFFFFFFF {
			return lo + int(result)
		}
	}
}

// ── Crypto Context ───────────────────────────────────────────────────────────

func NewCryptoContext() (*CryptoContext, error) {
	block, _ := pem.Decode([]byte(rsaPEM))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey := pub.(*rsa.PublicKey)

	aesKey := make([]byte, 16)
	rand.Read(aesKey)
	hmacKey := make([]byte, 32)
	rand.Read(hmacKey)

	enc1, _ := rsa.EncryptPKCS1v15(rand.Reader, rsaKey, aesKey)
	enc2, _ := rsa.EncryptPKCS1v15(rand.Reader, rsaKey, hmacKey)

	return &CryptoContext{
		AESKey:     aesKey,
		HMACKey:    hmacKey,
		RSAAesB64:  base64.StdEncoding.EncodeToString(enc1),
		RSAHMACB64: base64.StdEncoding.EncodeToString(enc2),
		rsaKey:     rsaKey,
	}, nil
}

func MTVerification(mt *MersenneTwister) string {
	v13 := mt.RandRange(1, 1000)
	v15 := mt.RandRange(1, 1000)
	v17 := mt.RandRange(1, 1000)
	v19 := mt.RandRange(1, 1000)

	val1 := uint32(7 * v13)
	val2 := uint32(8*v15) ^ val1
	val3 := uint32(9*v17) ^ val2
	val4 := uint32(5*v19) ^ val3

	s := func(v uint32) int32 { return int32(v) }
	return fmt.Sprintf("%d,%d,%d,%d", s(val1), s(val2), s(val3), s(val4))
}

func EncryptPayload(ctx *CryptoContext, plaintext string) (string, string) {
	pt := []byte(plaintext)
	padLen := aes.BlockSize - len(pt)%aes.BlockSize
	for i := 0; i < padLen; i++ {
		pt = append(pt, byte(padLen))
	}

	iv := make([]byte, 16)
	rand.Read(iv)

	t0 := time.Now()
	block, _ := aes.NewCipher(ctx.AESKey)
	cbc := cipher.NewCBCEncrypter(block, iv)
	ct := make([]byte, len(pt))
	cbc.CryptBlocks(ct, pt)
	t1 := time.Now()

	mac := hmac.New(sha256.New, ctx.HMACKey)
	mac.Write(iv)
	mac.Write(ct)
	tag := mac.Sum(nil)
	t2 := time.Now()

	final := append(append(iv, ct...), tag...)
	b64 := base64.StdEncoding.EncodeToString(final)
	t3 := time.Now()

	us := func(d time.Duration) int64 {
		v := d.Microseconds()
		if v < 1 {
			return 1
		}
		return v
	}
	timing := fmt.Sprintf("%d,%d,%d", us(t1.Sub(t0)), us(t2.Sub(t1)), us(t3.Sub(t2)))
	return b64, timing
}

// ── Sensor Generators ────────────────────────────────────────────────────────

func noise(n int, mean, std float64) []float64 {
	v := make([]float64, n)
	for i := range v {
		v[i] = mean + std*mrand.NormFloat64()
	}
	return v
}

func walk(n int, start, stepStd float64) []float64 {
	v := make([]float64, n)
	v[0] = start
	for i := 1; i < n; i++ {
		v[i] = v[i-1] + stepStd*mrand.NormFloat64()
	}
	return v
}

func timingDeltas(n int) []float64 {
	v := make([]float64, n)
	for i := range v {
		v[i] = 15 + mrand.Float64()*65
	}
	return v
}

func GenerateOrientation(numEvents int) (string, string, int64) {
	n := prevPowerOfTwo(numEvents)
	if n < 2 {
		n = 2
	}
	if n > 512 {
		n = 512
	}
	az := walk(n, mrand.Float64()*360-180, 2.0)
	pi := walk(n, mrand.Float64()*60-30, 1.5)
	ro := walk(n, mrand.Float64()*20-10, 1.0)
	tm := timingDeltas(n)

	azS, azC := EncodeAxis(az, 0.6)
	piS, piC := EncodeAxis(pi, 0.6)
	roS, roC := EncodeAxis(ro, 0.6)
	tmS, tmC := EncodeAxis(tm, 0.0)

	return azS + ":" + piS + ":" + roS, tmS, azC + piC + roC + tmC
}

func GenerateMotion(numEvents int) (string, string, int64) {
	n := prevPowerOfTwo(numEvents)
	if n < 2 {
		n = 2
	}
	if n > 512 {
		n = 512
	}
	axes := [][]float64{
		noise(n, 0.1, 0.3), noise(n, 0.2, 0.4), noise(n, 9.6, 0.3),
		noise(n, 0, 0.5), noise(n, 0, 0.5), noise(n, 0, 0.3),
		noise(n, 0, 0.1), noise(n, 0, 0.1), noise(n, 0, 0.05),
	}
	tm := timingDeltas(n)

	parts := make([]string, 9)
	var totalCk int64
	for i, a := range axes {
		s, ck := EncodeAxis(a, 0.6)
		parts[i] = s
		totalCk += ck
	}
	tmS, tmC := EncodeAxis(tm, 0.0)
	return strings.Join(parts, ":"), tmS, totalCk + tmC
}

func GenerateTouchEvents(taps, w, h int) (string, int) {
	var b strings.Builder
	total := 0
	t := mrand.Intn(6000) + 2000

	for i := 0; i < taps; i++ {
		x := mrand.Intn(w-100) + 50
		y := mrand.Intn(h-400) + 200
		fmt.Fprintf(&b, "2,%d,%d,%d,1,1,1,-1;", t, x, y)
		total++
		for j := 0; j < mrand.Intn(5)+1; j++ {
			dt := mrand.Intn(36) + 5
			fmt.Fprintf(&b, "1,%d,%d,%d,1,1,1,-1;", dt, x+mrand.Intn(11)-5, y+mrand.Intn(11)-5)
			total++
		}
		fmt.Fprintf(&b, "3,%d,%d,%d,1,1,1,-1;", mrand.Intn(26)+5, x, y)
		total++
		t = mrand.Intn(4500) + 500
	}
	return b.String(), total
}

func GenerateLifecycle(n int, baseTS int64) string {
	var b strings.Builder
	ts := baseTS
	for i := 0; i < n && i < 10; i++ {
		typ := 3
		if i%2 == 1 {
			typ = 2
		}
		fmt.Fprintf(&b, "%d,%d;", typ, ts)
		ts += int64(mrand.Intn(2500) + 500)
	}
	return b.String()
}

func GeneratePerformance() string {
	// Match the five short benchmarks in the Android SDK's V.b(). The
	// resulting counts are correlated; nine independent random numbers are
	// visibly unlike a native -112 field.
	limit := 3 * time.Millisecond
	start := time.Now()
	intHits, intIterations := 0, 0
	for i := 1; i < 1_000_000; i++ {
		if ((4508713 % i) * 11 % i) == 0 {
			intHits++
		}
		if i%100 == 0 && time.Since(start) > limit {
			break
		}
		intIterations++
	}
	start = time.Now()
	floatHits, floatIterations := 0, 0
	f := float32(33.34)
	for i := 1; i < 1_000_000; i++ {
		f += float32(i)
		if (float32(19.239)*f)/float32(3.56) < 10000 {
			floatHits++
		}
		if i%100 == 0 && time.Since(start) > limit {
			break
		}
		floatIterations++
	}
	start = time.Now()
	sqrtHits, sqrtIterations := 0, 0
	for i := 1; i < 1_000_000; i++ {
		if math.Sqrt(float64(i)) > 30 {
			sqrtHits++
		}
		if i%100 == 0 && time.Since(start) > limit {
			break
		}
		sqrtIterations++
	}
	start = time.Now()
	trigHits, trigIterations := 0, 0
	for i := 1; i < 1_000_000; i++ {
		// The SDK divides two ints before passing the result to Math.*.
		x := float64(i / 1_000_000)
		if math.Acos(x)+math.Asin(x)+math.Atan(x) > 1.5 {
			trigHits++
		}
		if i%100 == 0 && time.Since(start) > limit {
			break
		}
		trigIterations++
	}
	start = time.Now()
	spinIterations := 0
	for i := 1; i < 1_000_000 && time.Since(start) <= limit; i++ {
		spinIterations++
	}
	v := []int{intHits, intIterations / 100, floatHits,
		floatIterations / 100, sqrtHits, sqrtIterations / 100,
		trigHits, trigIterations / 100, spinIterations}
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = strconv.Itoa(x)
	}
	return strings.Join(s, ",")
}

// ── Serializer ───────────────────────────────────────────────────────────────

func buildDeviceFP(d DeviceProfile, pkg string) string {
	charging := 0
	if d.IsCharging {
		charging = 1
	}
	keyboard := 0
	if d.PhysicalKeyboard {
		keyboard = 1
	}
	fields := []string{
		"-1", "uaend", "-1",
		itoa(d.ScreenHeight), itoa(d.ScreenWidth), itoa(charging),
		itoa(d.BatteryPercent), itoa(d.Orientation), d.LocaleLanguage,
		d.Release, itoa(d.AutoRotate), d.Model,
		d.Bootloader, d.Hardware, "-1", pkg,
		"-1", "-1", d.AndroidID, "-1",
		itoa(keyboard), itoa(d.GlobalSettingFlag),
		d.Codename, d.Incremental, itoa(d.SDKInt),
		d.Manufacturer, d.Product, d.BuildTags,
		d.BuildType, d.BuildUser, d.BuildDisplay,
		d.Board, d.Brand, d.Device,
		d.Fingerprint, d.Host, d.BuildID,
	}
	fp := strings.Join(fields, ",")
	ck := StringToInt(fp)
	nonce := mrand.Int31()
	halfTS := time.Now().UnixMilli() / 2
	return fmt.Sprintf("%s,%d,%d,%d", fp, ck, nonce, halfTS)
}

func buildCommonInfo(d DeviceProfile) string {
	osVer := fmt.Sprintf("Android %s %s API %d", d.Codename, d.Release, d.SDKInt)
	locale := d.LocaleLanguage + d.LocaleCountry
	localIP := d.LocalIP
	if localIP == "" {
		ipSeed := sha256.Sum256([]byte(d.AndroidID))
		localIP = fmt.Sprintf("192.168.1.%d", 2+int(ipSeed[0])%253)
	}
	return strings.Join([]string{
		URLEncode(osVer), URLEncode(locale),
		URLEncode(itoa(d.TimezoneOffset)),
		URLEncode(d.BluetoothName),
		URLEncode(localIP),
	}, ",")
}

func buildAndroidInfo(d DeviceProfile, pkg string) string {
	neg := URLEncode("-1")
	apps := d.InstalledApps
	if len(apps) == 0 {
		apps = []string{pkg}
	}
	installedAppsHash := sha256Hex(strings.Join(apps, "#"))
	fields := make([]string, 0, 39)
	for i := 0; i < 20; i++ {
		fields = append(fields, neg)
	}
	fields = append(fields,
		URLEncode(d.BuildID),
		URLEncode(d.RadioVersion),
		URLEncode(d.Serial),
		URLEncode(d.ABI32),
		URLEncode(d.ABI64),
		URLEncode(fmt.Sprintf("%d", d.BuildTime)),
		URLEncode(itoa(d.PreviewSDKInt)),
		URLEncode(d.SecurityPatch),
		URLEncode("1.0"),
		URLEncode("false"), URLEncode("false"),
		URLEncode("1.0"),
		URLEncode("0"), URLEncode("0"),
		neg, URLEncode("false"), URLEncode("0"),
		URLEncode(installedAppsHash),
		URLEncode(d.UserAgent),
	)
	return strings.Join(fields, ",")
}

func buildCounters(oCk, mCk int64, touchCount, sensorEvents int, initTS, nowMS int64, buildStarted time.Time) string {
	elapsed := nowMS - initTS
	checksum := GQRJZH(int(oCk+mCk), touchCount+sensorEvents*2, elapsed)
	buildMicros := time.Since(buildStarted).Microseconds()
	// Order mirrors CYFManager.t(): four component checksums, sum, age,
	// event counts, sensor sample counts, init/build times, flags and hash.
	return fmt.Sprintf("0,0,%d,%d,%d,%d,0,%d,%d,%d,36000,%d,-1,%d,%d,1,19,0,0",
		oCk, mCk, oCk+mCk, elapsed, touchCount,
		sensorEvents, sensorEvents, buildMicros, checksum, initTS)
}

func itoa(i int) string { return strconv.Itoa(i) }

func generateAppiumSignal() string {
	// The SDK emits four linked integers when its root/Appium checks are clear.
	i := mrand.Intn(1000) + 1
	a := 7 * i
	b := (8 * i) ^ a
	c := (9 * i) ^ b
	d := (5 * i) ^ c
	return fmt.Sprintf("%d,%d,%d,%d", a, b, c, d)
}

func BuildSensorPairs(d DeviceProfile, pkg, appVer string, appCode int, serverURL, jsSignals, cprSignal string, touchTaps, sensorEvents int) [][]string {
	buildStarted := time.Now()
	nowMS := time.Now().UnixMilli()
	initTS := nowMS - int64(mrand.Intn(4001)+2000)
	if d.AppStartTimestampMS > 0 && initTS < d.AppStartTimestampMS {
		initTS = d.AppStartTimestampMS
	}

	oData, oSum, oCk := GenerateOrientation(sensorEvents)
	mData, mSum, mCk := GenerateMotion(sensorEvents)
	touchStr, touchCount := GenerateTouchEvents(touchTaps, d.ScreenWidth, d.ScreenHeight)
	lifecycle := GenerateLifecycle(3, nowMS-int64(mrand.Intn(3001)+3000))
	perf := GeneratePerformance()
	counters := buildCounters(oCk, mCk, touchCount, sensorEvents, initTS, nowMS, buildStarted)

	if jsSignals == "" {
		jsSignals = fmt.Sprintf("buildId=%s#screenWidth=%d#cpuABI=%s#serverSideSignal=#pureJsSignal=8,%s-%s,%d,%d,%s,,0,-1,-1,%d,%d,%d#mapping_flag=1#jvx=cf-sdk-2-08.js",
			d.BuildID, d.ScreenWidth, d.CPUABI, d.LocaleLanguage, d.LocaleCountry,
			d.ScreenHeight/2-8, d.ScreenWidth/2-8, d.WebviewFPHash,
			mrand.Intn(8001)+1000, mrand.Intn(4501)+500, mrand.Intn(7001)+2000)
	}

	fp := buildDeviceFP(d, pkg)
	installTS := d.InstallTimestampMS
	if installTS <= 0 {
		installTS = nowMS - int64(30*24*time.Hour/time.Millisecond)
	}
	appStartTS := d.AppStartTimestampMS
	if appStartTS <= 0 {
		appStartTS = initTS
	}
	appIdentity := fmt.Sprintf(",%s,%s %d,0,%d,%d,false,false", d.AppSignatureSHA1, appVer, appCode, installTS, appStartTS)

	return [][]string{
		{"", SDKVersion},
		{"-90", jsSignals},
		{"-91", cprSignal},
		{"-70", ""}, {"-80", ""}, {"-121", ""},
		{"-100", fp},
		{"-101", "do_en,dm_en,t_en"},
		{"-102", "-1"},
		{"-103", lifecycle},
		{"-104", fmt.Sprintf("%d,%d,-50,-301,%d", d.TimezoneOffset/60, mrand.Intn(4), mrand.Intn(20)+1)},
		{"-108", ""},
		{"-112", perf},
		{"-115", counters},
		{"-117", touchStr},
		{"-120", ""},
		{"-144", oSum},
		{"-160", fmt.Sprintf("%d,%d", mrand.Intn(21)+10, mrand.Intn(1501)+500)},
		{"-142", oData},
		{"-145", mSum},
		{"-161", fmt.Sprintf("%d,%d", mrand.Intn(16)+10, mrand.Intn(1001)+500)},
		{"-143", mData},
		{"-150", "1,0"},
		{"-163", appIdentity},
		{"-165", buildCommonInfo(d)},
		{"-166", buildAndroidInfo(d, pkg)},
		{"-171", serverURL},
		{"-240", "0"},
		{"-172", generateAppiumSignal()},
		{"-180", ""}, // enabled accessibility services
	}
}

func SerializePairs(pairs [][]string, securityPatch string) string {
	var b strings.Builder
	b.WriteString(pairs[0][1])
	for _, p := range pairs[1:] {
		b.WriteString(Separator)
		b.WriteString(p[0])
		b.WriteString(",")
		b.WriteString(p[1])
	}
	b.WriteString(Separator)
	b.WriteString("-164,")
	b.WriteString(securityPatch)
	return b.String()
}

func BuildHeader(pairs [][]string, securityPatch string, opts GenerateOpts, ctx *CryptoContext) string {
	serialized := SerializePairs(pairs, securityPatch)

	mt := NewMT(uint32(time.Now().UnixNano()))
	verification := MTVerification(mt)
	plaintext := serialized + Separator + "-170," + verification

	b64, timing := EncryptPayload(ctx, plaintext)

	header := fmt.Sprintf("6,a,%s,%s", ctx.RSAAesB64, ctx.RSAHMACB64)
	metadata := fmt.Sprintf("%s&&&%s&&&%s&&&%s", opts.CPRSignal, opts.DeviceID, opts.CPRToken, SDKVersion)

	return fmt.Sprintf("%s$%s$%s$%s$%s$%s$%s",
		header, b64, timing, opts.PoWResponse, opts.CCAToken, opts.ServerSignal, metadata)
}

// ── Generator ────────────────────────────────────────────────────────────────

func NewGenerator(device DeviceProfile, pkg, appVer string, appCode int, serverURL string) (*Generator, error) {
	ctx, err := NewCryptoContext()
	if err != nil {
		return nil, err
	}
	return &Generator{
		Device:         device,
		AppPackage:     pkg,
		AppVersion:     appVer,
		AppVersionCode: appCode,
		ServerURL:      serverURL,
		Ctx:            ctx,
	}, nil
}

func (g *Generator) Generate(opts GenerateOpts) string {
	if opts.NumTouchTaps == 0 {
		opts.NumTouchTaps = 3
	}
	if opts.NumSensorEvents == 0 {
		opts.NumSensorEvents = 32
	}
	if opts.CPRSignal == "" {
		opts.CPRSignal = "0"
	}
	if opts.DeviceID == "" {
		opts.DeviceID = g.Device.DeviceID
	}

	pairs := BuildSensorPairs(
		g.Device, g.AppPackage, g.AppVersion, g.AppVersionCode,
		g.ServerURL, opts.JSSignals, opts.CPRSignal,
		opts.NumTouchTaps, opts.NumSensorEvents,
	)

	return BuildHeader(pairs, g.Device.SecurityPatch, opts, g.Ctx)
}

// BotManager adapts the 4.2.0 BAP-style generator to the server interface used
// by the rest of x-acf-sensor-data-generator.
type BotManager struct {
	*Generator
	device       dm.Device
	androidID    string
	challenge    bool
	challengeURL string
}

func NewStable(app string, lang string, challenge bool, challengeURL string, deviceManager dm.DeviceManager) *BotManager {
	if app == "" {
		app = DefaultAppPackage
	}
	if lang == "" {
		lang = "pt_BR"
	}
	if challengeURL == "" {
		challengeURL = DefaultServerURL
	}

	device := deviceManager.GetRandomDevice()
	profile := DeviceProfileFromDM(device, lang)
	gen, err := NewGenerator(profile, app, DefaultAppVersion, DefaultAppVersionCode, challengeURL)
	if err != nil {
		panic(err)
	}

	return &BotManager{
		Generator:    gen,
		device:       device,
		androidID:    profile.AndroidID,
		challenge:    challenge,
		challengeURL: challengeURL,
	}
}

func (bm *BotManager) GetAndroidId() string {
	return bm.androidID
}

func (bm *BotManager) GetDevice() dm.Device {
	return bm.device
}

func (bm *BotManager) GenerateSensorData() (string, error) {
	return bm.Generate(GenerateOpts{
		CPRSignal:       "0",
		DeviceID:        bm.androidID,
		NumTouchTaps:    3,
		NumSensorEvents: 32,
	}), nil
}

func DeviceProfileFromDM(device dm.Device, lang string) DeviceProfile {
	language, country := splitLocale(lang)
	androidID := device.AndroidID
	if androidID == "" {
		androidID = randomHex(8)
	}
	// K.E() reads WebSettings.getDefaultUserAgent(), not the app's API UA.
	// Chrome/WebView version is a profile approximation until calibrated for
	// a particular device, but the native grammar matters for -166.
	userAgent := fmt.Sprintf(
		"Mozilla/5.0 (Linux; Android %s; %s Build/%s; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/125.0.6422.113 Mobile Safari/537.36",
		device.Build.Version.Release, device.Build.Model, device.Build.ID,
	)

	// The APK reads fixed Build.TIME and SECURITY_PATCH values. Derive a
	// stable, release-era approximation when the device database omits them;
	// basing either on time.Now makes one persistent device change on every
	// sensor generation.
	majorRelease, _ := strconv.Atoi(strings.Split(device.Build.Version.Release, ".")[0])
	buildYear := 2010 + majorRelease
	if majorRelease < 7 || majorRelease > 16 {
		buildYear = 2023
	}
	buildMonth := time.December
	if majorRelease >= 16 {
		buildMonth = time.August
	}
	buildSeed := sha256.Sum256([]byte(device.Build.Display + device.Build.Version.Incremental))
	deviceSeed := sha256.Sum256([]byte(device.Build.Fingerprint + "|" + device.Build.Model))
	buildDay := 5 + int(buildSeed[0])%20
	buildTime := time.Date(buildYear, buildMonth, buildDay, 12, 0, 0, 0, time.UTC).UnixMilli()
	securityPatch := time.Date(buildYear, buildMonth, 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02")

	return DeviceProfile{
		Model:             device.Build.Model,
		Manufacturer:      device.Build.Manufacturer,
		Brand:             device.Build.Brand,
		Device:            device.Build.Device,
		Product:           device.Build.Product,
		Board:             device.Build.Board,
		Hardware:          device.Build.Hardware,
		Bootloader:        device.Build.Bootloader,
		Fingerprint:       device.Build.Fingerprint,
		BuildID:           device.Build.ID,
		BuildDisplay:      device.Build.Display,
		BuildTags:         device.Build.Tags,
		BuildType:         device.Build.Type,
		BuildUser:         device.Build.User,
		Incremental:       device.Build.Version.Incremental,
		Codename:          device.Build.Version.Codename,
		Release:           device.Build.Version.Release,
		SDKInt:            device.Build.Version.SdkInt,
		SecurityPatch:     securityPatch,
		PreviewSDKInt:     0,
		BaseOS:            "",
		ABI32:             "armeabi-v7a#armeabi",
		ABI64:             "arm64-v8a",
		CPUABI:            "arm64-v8a",
		ScreenHeight:      device.Screen.HeightPixels,
		ScreenWidth:       device.Screen.WidthPixels,
		ScreenCount:       1,
		BatteryPercent:    50,
		Orientation:       1,
		AutoRotate:        1,
		DensityDPI:        "dpi",
		RefreshRate:       60.0,
		Host:              device.Build.Host,
		Serial:            "-1",
		RadioVersion:      "-1",
		BuildTime:         buildTime,
		UserAgent:         userAgent,
		UAHash:            sha256Hex(userAgent),
		LocaleLanguage:    language,
		LocaleCountry:     country,
		TimezoneOffset:    -180,
		BluetoothName:     "-1",
		TelephonyStatus:   -1,
		SIMStatus:         -1,
		NFCEnabled:        1,
		AirplaneMode:      0,
		IsTablet:          0,
		MemoryTotalKB:     8192000 + int(deviceSeed[0])*8192,
		StorageTotalBytes: 128000000000 + int64(deviceSeed[1])*250000000,
		AppSignatureSHA1:  DefaultSignatureSHA1,
		WebviewFPHash:     sha256Hex(userAgent + "|webview"),
		SensorRates: SensorRates{
			AccelUS:    72000,
			GyroUS:     51000,
			AccelRange: 128,
			GyroRange:  128,
		},
		AndroidID: androidID,
		DeviceID:  androidID,
	}
}

func splitLocale(lang string) (string, string) {
	normalized := strings.ReplaceAll(lang, "-", "_")
	parts := strings.SplitN(normalized, "_", 2)
	language := parts[0]
	if language == "" {
		language = "pt"
	}
	country := "BR"
	if len(parts) == 2 && parts[1] != "" {
		country = strings.ToUpper(parts[1])
	}
	return language, country
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	const hex = "0123456789abcdef"
	out := make([]byte, n*2)
	for i, b := range buf {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return string(out)
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	const hex = "0123456789abcdef"
	out := make([]byte, len(sum)*2)
	for i, b := range sum {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return string(out)
}
