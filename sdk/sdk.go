package sdk

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"math/rand"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	http "github.com/bogdanfinn/fhttp"

	"github.com/JulianKnodt/vector"
	"github.com/google/uuid"
)

var (
	RANDOMCHARS = []rune("0123456789abcdefghijklmopqrstuvwxyz")
	f7912a      = []uint32{3523407757, 2768625435, 1007455905, 1259060791, 3580832660, 2724731650, 996231864, 1281784366, 3705235391, 2883475241, 852952723, 1171273221, 3686048678, 2897449776, 901431946, 1119744540, 3484811241, 3098726271, 565944005, 1455205971, 3369614320, 3219065702, 651582172, 1372678730, 3245242331, 3060352845, 794826487, 1483155041, 3322131394, 2969862996, 671994606, 1594548856, 3916222277, 2657877971, 123907689, 1885708031, 3993045852, 2567322570, 1010288, 1997036262, 3887548279, 2427484129, 163128923, 2126386893, 3772416878, 2547889144, 248832578, 2043925204, 4108050209, 2212294583, 450215437, 1842515611, 4088798008, 2226203566, 498629140, 1790921346, 4194326291, 2366072709, 336475711, 1661535913, 4251816714, 2322244508, 325317158, 1684325040, 2766056989, 3554254475, 1255198513, 1037565863, 2746444292, 3568589458, 1304234792, 985283518, 2852464175, 3707901625, 1141589763, 856455061, 2909332022, 3664761504, 1130791706, 878818188, 3110715001, 3463352047, 1466425173, 543223747, 3187964512, 3372436214, 1342839628, 655174618, 3081909835, 3233089245, 1505515367, 784033777, 2967466578, 3352871620, 1590793086, 701932520, 2679148245, 3904355907, 1908338681, 112844655, 2564639436, 4024072794, 1993550816, 30677878, 2439710439, 3865851505, 2137352139, 140662621, 2517025534, 3775001192, 2013832146, 252678980, 2181537457, 4110462503, 1812594589, 453955339, 2238339752, 4067256894, 1801730948, 476252946, 2363233923, 4225443349, 1657960367, 366298937, 2343686810, 4239843852, 1707062198, 314082080, 1069182125, 1220369467, 3518238081, 2796764439, 953657524, 1339070498, 3604597144, 2715744526, 828499103, 1181144073, 3748627891, 2825434405, 906764422, 1091244048, 3624026538, 2936369468, 571309257, 1426738271, 3422756325, 3137613171, 627095760, 1382516806, 3413039612, 3161057642, 752284923, 1540473965, 3268974039, 3051332929, 733688034, 1555824756, 3316994510, 2998034776, 81022053, 1943239923, 3940166985, 2648514015, 62490748, 1958656234, 3988253008, 2595281350, 168805463, 2097738945, 3825313147, 2466682349, 224526414, 2053451992, 3815530850, 2490061300, 425942017, 1852075159, 4151131437, 2154433979, 504272920, 1762240654, 4026595636, 2265434530, 397988915, 1623188645, 4189500703, 2393998729, 282398762, 1741824188, 4275794182, 2312913296, 1231433021, 1046551979, 2808630289, 3496967303, 1309403428, 957143474, 2684717064, 3607279774, 1203610895, 817534361, 2847130659, 3736401077, 1087398166, 936857984, 2933784634, 3654889644, 1422998873, 601230799, 3135200373, 3453512931, 1404893504, 616286678, 3182598252, 3400902906, 1510651243, 755860989, 3020215367, 3271812305, 1567060338, 710951396, 3010007134, 3295551688, 1913130485, 84884835, 2617666777, 3942734927, 1969605100, 40040826, 2607524032, 3966539862, 2094237127, 198489425, 2464015595, 3856323709, 2076066270, 213479752, 2511347954, 3803648100, 1874795921, 414723335, 2175892669, 4139142187, 1758648712, 534112542, 2262612132, 4057696306, 1633981859, 375629109, 2406151311, 4167943193, 1711886778, 286155052, 2282172566, 4278190080}
	client      = &http.Client{
		Timeout: 10 * time.Second,
	}
	MIN_RADIX = 2
	MAX_RADIX = 36
)

type Pair struct {
	Id, Value interface{}
}

type PowParams struct {
	UptimeMillis int64   `json:"uptimeMillis"`
	AndroidId    string  `json:"androidId"`
	Mode         int     `json:"mode"`
	Nonce        string  `json:"nonce"`
	Difficulty   float64 `json:"difficulty"`
	Checksum     string  `json:"checksum"`
}

func GetDomainFromURL(inputURL string) (string, error) {
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return "", err
	}

	domain := parsedURL.Hostname()
	return domain, nil
}

func GetPowParams(userAgent string, bootTime int64, androidId string, baseUrl string) (*PowParams, error) {
	var pow PowParams

	domain, err := GetDomainFromURL(baseUrl)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", "http://"+domain+"/_bm/get_params?type=sdk-pow", nil)
	if err != nil {
		return nil, err
	}

	req.Header = http.Header{
		"User-Agent":      {userAgent},
		"Connection":      {"keep-alive"},
		"Accept-Encoding": {"gzip"},
		http.HeaderOrderKey: {
			"User-Agent",
			"Host",
			"Connection",
			"Accept-Encoding",
		},
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected response %v", res.StatusCode)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(body, &pow); err != nil {
		return nil, err
	}

	(&pow).UptimeMillis = UptimeMillis(bootTime)
	(&pow).AndroidId = androidId

	return &pow, nil
}

func GeneratePow(params PowParams) (string, error) {
	var sb strings.Builder
	var upTimeMillis = params.UptimeMillis

	sb.WriteString(params.AndroidId + ";")
	sb.WriteString(strconv.Itoa(int(upTimeMillis)) + ";")
	sb.WriteString(params.Nonce + ";")
	sb.WriteString(strconv.Itoa(int(params.Difficulty)) + ";")
	sb.WriteString(params.Checksum + ";")

	if params.Mode == 0 {
		final := sb.String()
		return final[:len(final)-1], nil
	}

	var answers []string
	var iterations []string
	var elapsed []string

	for i := 0; i < 10; i++ {
		answer, loops, err := SolvePow(i, params)
		if err != nil {
			return "", err
		}
		answers = append(answers, answer)
		iterations = append(iterations, strconv.Itoa(loops))
		elapsed = append(elapsed, strconv.Itoa(RandomInt(1000, 9000)))
	}

	sb.WriteString(strings.Join(answers, ",") + ";")
	sb.WriteString(strings.Join(iterations, ",") + ";")
	sb.WriteString(strings.Join(elapsed, ","))

	return sb.String(), nil
}

func SolvePow(i int, params PowParams) (string, int, error) {
	iter := 0
	for {
		format := GetPowRandom()
		str := fmt.Sprintf("%v%v%v%v%v", params.AndroidId, params.UptimeMillis, params.Nonce, int(params.Difficulty)+i, format)
		messageDigest := sha256.New()
		messageDigest.Write([]byte(str))
		if FindPowAnswer(messageDigest.Sum(nil), int64(params.Difficulty)+int64(i)) == 0 {
			return format, iter, nil
		} else {
			iter++
		}
	}
}

func FindPowAnswer(bArr []byte, j int64) int64 {
	var j2 int64 = 0
	for _, b2 := range bArr {
		j2 = ((j2 << 8) | int64(b2&255)) % j
	}
	return j2
}

func GetPowRandom() string {
	return fmt.Sprintf("%.12f", rand.Float64())
}

func SerializeBmp(pairs []Pair) string {
	var sb strings.Builder
	for i := 0; i < len(pairs); i++ {
		pair := pairs[i]
		if pair.Id != "" {
			sb.WriteString(fmt.Sprintf("-1,2,-94,%v,%v", pair.Id, pair.Value))
		} else {
			sb.WriteString(fmt.Sprintf("%v", pair.Value))
		}
	}

	return sb.String()

}

func GenBackgroundEvents(startTs int64) string {
	var (
		actions = []int{2, 3}
		maxStep = 10
		minStep = 1
		maxDx   = 5000
		minDx   = 100
		steps   = RandomInt(minStep, maxStep)
		data    = ""
	)

	if RandomBool() {
		steps /= 2
	}

	for i := 0; i < steps; i++ {
		dx := RandomInt(minDx, maxDx)
		data += fmt.Sprintf("%v,%v;", actions[rand.Intn(len(actions))], startTs+int64(dx))
		startTs += int64(dx)
	}

	return data
}

func Ab(t string) int {
	a := 0
	for e := 0; e < len(t); e++ {
		n := []rune(t)[e]
		if n < 128 {
			a += int(n)
		}
	}
	return a
}

func NumOfSetBits(n int) int {
	count := 0
	for n != 0 {
		count += n & 1
		n >>= 1
	}
	return count
}

func Normalize(f float64) float64 {
	return (math.Round(f*100.0) / 100.0)
}

func UptimeMillis(startTime int64) int64 {
	return GetCfDate() - startTime
}

func RsaEncrypt(ciphertext []byte, pubKey []byte) ([]byte, error) {
	_, bytes := pem.Decode(pubKey)
	pub, err := x509.ParsePKIXPublicKey(bytes)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(crand.Reader, pub.(*rsa.PublicKey), ciphertext)
}

func AESEncrypt(src string, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	if src == "" {
		return nil, nil, errors.New("source content empty, can't encrypt")
	}
	iv := []byte(RandomByteArray(16))
	ecb := cipher.NewCBCEncrypter(block, iv)
	content := []byte(src)
	content = PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)

	return crypted, iv, nil
}

func ComputeHmac256(src []byte, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(src)
	return h.Sum(nil)
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

func RandomByteArray(length int) []byte {
	ret := make([]byte, length)
	rand.Read(ret)
	return ret
}

func RandomFloat(min float64, max float64) float64 {
	a, _ := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	f := float64(a.Int64()) / (1 << 63)
	return min + f*(max-min)
}

func BmpHash(fArr []float64, lower float64, higher float64) string {
	var (
		sb     strings.Builder
		length = len(fArr)
		f3     = (higher - lower) / 60.0
	)
	for i := 0; i < length; i++ {
		floor := rune(math.Floor((fArr[i]-lower)/f3) + 65)
		if fArr[i] == higher {
			floor = '}'
		}
		if floor == '\\' {
			floor = '.'
		} else if floor == '.' {
			floor = '\\'
		}
		sb.WriteRune(floor)
	}

	return sb.String()
}

func FakeArray(arr []float64) []float64 {
	similarArr := make([]float64, len(arr))
	for i, val := range arr {
		// Generate a random value within a small range around the original value
		similarArr[i] = val * (rand.Float64())
	}

	return similarArr
}

func ReverseBmpHash(hash string, lower float64, higher float64) []float64 {
	var (
		fArr   []float64
		length = len(hash)
		f3     = (higher - lower) / 60.0
	)

	for i := 0; i < length; i++ {
		floor := hash[i]
		if floor == '}' {
			fArr = append(fArr, higher)
		} else if floor == '\\' {
			fArr = append(fArr, lower)
		} else if floor == '.' {
			fArr = append(fArr, lower+f3/2)
		} else {
			f := float64(floor) - 65
			fArr = append(fArr, lower+f*f3)
		}
	}

	return fArr
}

func ShortenBmpHash(str string) string {
	var (
		sb     strings.Builder
		length = len(str)
		chars  = []rune(str)
		i      = 0
	)

	for i < length {
		i2 := i + 1
		charAt := chars[i]
		i3 := 1

		for i2 < length && charAt == chars[i2] {
			i3++
			i2++
		}
		if i3 > 1 {
			sb.WriteString(strconv.Itoa(i3))
		}
		sb.WriteRune(charAt)
		i = i2
	}
	return sb.String()
}

func ExpandBmpHash(str string) string {
	var (
		sb     strings.Builder
		length = len(str)
		chars  = []rune(str)
		i      = 0
	)

	for i < length {
		if unicode.IsDigit(chars[i]) {
			// Extract the repeat count
			repeatCountStr := ""
			for i < length && unicode.IsDigit(chars[i]) {
				repeatCountStr += string(chars[i])
				i++
			}
			repeatCount, _ := strconv.Atoi(repeatCountStr)

			// Repeat the following character by the repeat count
			if i < length {
				sb.WriteString(strings.Repeat(string(chars[i]), repeatCount))
				i++
			}
		} else {
			sb.WriteRune(chars[i])
			i++
		}
	}

	return sb.String()
}

// Generate noise with an mu and sigma with how many arrays you want
func GenerateNoise(mu float64, sigma float64, dimensions []int) [][]float64 {
	noise := make([][]float64, len(dimensions))
	for i := range noise {
		noise[i] = make([]float64, dimensions[i])
		for i2 := range noise[i] {
			noise[i][i2] = rand.NormFloat64()*sigma + mu
		}
	}
	return noise
}

func SubtractSlice(fArr, fArr2 []float64) []float64 {
	if len(fArr) != len(fArr2) {
		panic(fmt.Sprintf("Cannot add arrays must be the same length %v vs %v", len(fArr), len(fArr2)))
	}

	added := make([]float64, len(fArr))

	for i := 0; i < len(added); i++ {
		added[i] = fArr[i] - fArr2[i]
	}

	return added
}

func INegate(f int, should bool) int {
	if should {
		return -f
	}
	return f

}
func Negate(f float64, should bool) float64 {
	if should {
		return -f
	}
	return f
}

func DivideSlice(fArr, fArr2 []float64) []float64 {
	if len(fArr) != len(fArr2) {
		panic(fmt.Sprintf("Cannot add arrays must be the same length %v vs %v", len(fArr), len(fArr2)))
	}

	added := make([]float64, len(fArr))

	for i := 0; i < len(added); i++ {
		added[i] = fArr[i] / fArr2[i]
	}

	return added
}

func MultiplySlice(fArr, fArr2 []float64) []float64 {
	if len(fArr) != len(fArr2) {
		panic(fmt.Sprintf("Cannot add arrays must be the same length %v vs %v", len(fArr), len(fArr2)))
	}

	added := make([]float64, len(fArr))

	for i := 0; i < len(added); i++ {
		added[i] = fArr[i] * fArr2[i]
	}

	return added
}

func AddSlice(fArr, fArr2 []float64) []float64 {
	if len(fArr) != len(fArr2) {
		panic(fmt.Sprintf("Cannot add arrays must be the same length %v vs %v", len(fArr), len(fArr2)))
	}

	added := make([]float64, len(fArr))

	for i := 0; i < len(added); i++ {
		added[i] = fArr[i] + fArr2[i]
	}

	return added
}

func NormalizeBmp(f12 float64) float64 {
	return math.Round(f12*100.0) / 100.0
}

func AddSliceAndRound(fArr, fArr2 []float64) []float64 {
	if len(fArr) != len(fArr2) {
		panic(fmt.Sprintf("Cannot add arrays must be the same length %v vs %v", len(fArr), len(fArr2)))
	}

	added := make([]float64, len(fArr))

	for i := 0; i < len(added); i++ {
		added[i] = math.Abs(math.Round(fArr[i] + fArr2[i]))
	}

	return added
}

func SubtractSliceAndRound(fArr, fArr2 []float64) []float64 {
	if len(fArr) != len(fArr2) {
		panic(fmt.Sprintf("Cannot add arrays must be the same length %v vs %v", len(fArr), len(fArr2)))
	}

	added := make([]float64, len(fArr))

	for i := 0; i < len(added); i++ {
		added[i] = math.Abs(math.Round(fArr[i] - fArr2[i]))
	}

	return added
}

func UrlDecode(encodedValue string) string {
	decodedValue, _ := url.QueryUnescape(encodedValue)
	return decodedValue
}

func HashF7(str string) int {
	length := len(str)
	chars := []rune(str)
	var j uint32 = 0
	for i := 0; i < length; i++ {
		j2 := j >> 8
		j = j2 ^ f7912a[uint32((255&j)^uint32(chars[i]))]
	}
	return int(j)
}

func IntToBool(i int) bool {
	return i == 1
}

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = RANDOMCHARS[rand.Intn(len(RANDOMCHARS))]
	}
	return string(b)
}

func RandomBool() bool {
	return rand.Intn(2) == 1
}

func RandomUint64() uint64 {
	buf := make([]byte, 8)
	crand.Read(buf) // Always succeeds, no need to check error
	return binary.LittleEndian.Uint64(buf)
}

func GenRandomVec() vector.Vec3 {
	return vector.Vec3{
		RandomFloat(0, 300),
		Negate(RandomFloat(0, 350), RandomBool()),
		Negate(RandomFloat(0, 360), RandomBool()),
	}
}

func GenTimeEvent(count int) []float64 {
	var (
		timeArr = make([]float64, 0)
	)

	for i := 0; i < count; i++ {

		timeArr = append(timeArr, float64(200))

	}

	return timeArr
}
func lerpProportion(x float64) float64 {
	a := rand.Float64()*(2.0-0.5) + 0.5 // Random coefficient
	b := rand.Float64()*(2.0-0.5) + 0.5 // Random exponent

	y := a * math.Pow(x, b) // Non-linear proportion

	return y
}
func GenGenericEvents(count int) ([]float64, []float64, []float64) {

	var (
		x       = make([]float64, 0)
		y       = make([]float64, 0)
		z       = make([]float64, 0)
		divider = 1.0 / float64(count)
		prop    = float64(0.0)
	)

	startAngle := vector.Vec3{
		Negate(9.78*rand.Float64(), RandomBool()),
		Negate(9.78*rand.Float64(), RandomBool()),
		Negate(9.78*rand.Float64(), RandomBool()),
	}

	// Get random angle
	endAngle := vector.Vec3{
		Negate(9.78*rand.Float64(), RandomBool()),
		Negate(9.78*rand.Float64(), RandomBool()),
		Negate(9.78*rand.Float64(), RandomBool()),
	}

	// Generate all angles inbetween start and found then put int floats
	for i := 0; i < count; i++ {
		if i == 0 {
			prop = divider / 2
		} else {
			prop += divider
		}
		// lerp start, found angle
		angle := startAngle.Lerp(endAngle, lerpProportion(prop))
		x = append(x, angle.X())
		y = append(y, angle.Y())
		z = append(z, angle.Z())
	}

	return x, y, z
}

func Lerp3(a, b, c vector.Vec3, t float64) *vector.Vec3 {
	if t <= 0.5 {
		return a.Lerp(b, t*2)
	} else {
		return b.Lerp(c, (t*2)-1)
	}
}
func GenerateOrientationEvents(count int) (orientationData string, d int64, orientationCount int) {
	pitch, yaw, roll := GenOrientationEvents(GenRandomVec(), GenRandomVec(), count)

	a13 := CreateMotionPair(pitch, 0.6000000238418579)
	a14 := CreateMotionPair(yaw, 0.6000000238418579)
	a15 := CreateMotionPair(roll, 0.6000000238418579)

	orientationData = a13.Id.(string) + ":" + a14.Id.(string) + ":" + a15.Id.(string)
	d = a13.Value.(int64) + a14.Value.(int64) + a15.Value.(int64)
	orientationCount = count

	return
}
func GenerateMotionData(count int) (string, int64, int) {

	// Gyroscope & Accelometer

	fArr, fArr2, fArr3 := GenGenericEvents(count)  // Accelometer 2
	fArr4, fArr5, fArr6 := GenGenericEvents(count) // Accelometer 1

	fArr7 := make([]float64, count)
	fArr9 := make([]float64, count)
	fArr10 := make([]float64, count)

	for i := 0; i < count; i++ {
		fArr[i] = fArr4[i] * rand.Float64()
		fArr2[i] = fArr5[i] * rand.Float64()
		fArr3[i] = fArr6[i] * rand.Float64()
		fArr7[i] = -100
		fArr9[i] = -100
		fArr10[i] = -100
	}

	a2 := CreateMotionPair(fArr, 0.6000000238418579)
	a3 := CreateMotionPair(fArr2, 0.6000000238418579)
	a4 := CreateMotionPair(fArr3, 0.6000000238418579)
	a5 := CreateMotionPair(fArr4, 0.6000000238418579)
	a6 := CreateMotionPair(fArr5, 0.6000000238418579)
	a7 := CreateMotionPair(fArr6, 0.6000000238418579)
	a8 := CreateMotionPair(fArr7, 0.6000000238418579)
	a9 := CreateMotionPair(fArr9, 0.6000000238418579)
	a10 := CreateMotionPair(fArr10, 0.6000000238418579)

	dctData := a2.Id.(string) + ":" + a3.Id.(string) + ":" + a4.Id.(string) + ":" + a5.Id.(string) + ":" + a6.Id.(string) + ":" + a7.Id.(string) + ":" + a8.Id.(string) + ":" + a9.Id.(string) + ":" + a10.Id.(string)
	d2 := a2.Value.(int64) + a3.Value.(int64) + a4.Value.(int64) + a5.Value.(int64) + a6.Value.(int64) + a7.Value.(int64) + a8.Value.(int64) + a9.Value.(int64) + a10.Value.(int64)

	return dctData, d2, count
}

func GenerateMotionString(count int) (string, int64, int) {
	return GenerateMotionData(count)
}

func GenOrientationEvents(src, dst vector.Vec3, count int) ([]float64, []float64, []float64) {
	var (
		yaw     = make([]float64, 0)
		pitch   = make([]float64, 0)
		roll    = make([]float64, 0)
		divider = 1.0 / float64(count)
		linear  = float64(0.0)
	)

	// Get angle between src & dst
	endAngle := vector.Vec3{
		NormalizeAngle(math.Atan2(dst[0]-src[0], dst[1]-src[1])/math.Pi*180.0 + 180.0), // pitch
		Negate(9.78*rand.Float64(), RandomBool()),
		Negate(9.78*rand.Float64(), RandomBool()),
	}

	/*startAngle := vector.Vec3{
		NormalizeAngle(math.Atan2(dst[0]-src[0], dst[1]-src[1])/math.Pi*180.0 + 180.0),  // pitch
		NormalizeAngle(math.Asin((dst[2]-src[2])/Distance(src, dst)) * 180.0 / math.Pi), // yaw
		NormalizeAngle(-math.Atan2(dst[1]-src[1], dst[2]-src[2])/math.Pi*180 + 180),     // roll
	}*/

	startAngle := vector.Vec3{
		180 * RandomFloat(0.4, 0.95),
		Negate(9.78*rand.Float64(), RandomBool()),
		Negate(9.78*rand.Float64(), RandomBool()),
	}

	// Generate all angles inbetween start and found then put int floats
	for i := 0; i < count; i++ {
		if i == 0 {
			linear = divider / 2
		} else {
			linear += divider
		}
		// lerp start, found angle
		angle := startAngle.Lerp(endAngle, linear*linear*linear)
		pitch = append(pitch, angle.X()*rand.Float64())
		yaw = append(yaw, angle.Y()*rand.Float64())
		roll = append(roll, angle.Z()*rand.Float64())
	}

	return pitch, yaw, roll
}

func NormalizeAndroidAngle(angle float64) float64 {
	if angle > 9.8 {
		return angle - 9.8
	}
	if angle < -9.8 {
		return angle + 9.8

	}
	return angle
}

func NormalizeAngle(angle float64) float64 {
	if angle > 360 {
		return angle - 360
	}
	if angle < -360 {
		return angle + 360
	}
	return angle
}

func LowHigh(fArr []float64) Pair {
	low := fArr[0]
	high := fArr[0]

	for i := 0; i < len(fArr); i++ {
		f3 := fArr[i]
		if f3 < low {
			low = f3
		} else if f3 > high {
			high = f3
		}
	}
	return Pair{float64(low), float64(high)}
}

func MotionFirstSendData(fArr []float64) string {
	ap2 := ""
	for i := 0; i < 3; i++ {
		randomIndex := rand.Intn(len(fArr))
		if randomIndex == 0 {
			i--
			continue
		}
		ap2 = strconv.Itoa(randomIndex) + "," + strconv.Itoa(int(fArr[randomIndex])) + ";"
	}
	ap2 = ap2[:len(ap2)-1]
	return ap2
}

func CreateMotionPair(fArr []float64, f12 float64) Pair {
	var (
		length     = len(fArr)
		fArr2      = fArr
		motionPair Pair
		a4         = LowHigh(fArr)
		lower      = (a4.Id.(float64))
		higher     = (a4.Value.(float64))
		a5         = ShortenBmpHash(BmpHash(fArr, lower, higher))
		a6         = HashF7(a5)
		a7         = Normalize(lower)
		a8         = Normalize(higher)
	)

	apVar := fmt.Sprintf("2;%.2f;%.2f;%v;%v", a7, a8, a6, a5)
	longValue := int(a7*100+a8*100) + a6
	motionPair = Pair{apVar, int64(longValue)}
	intValue := len(a5)

	if BitCount(length) == 1 {
		aeA(fArr2, 0, length, make([]float64, length))
		agA(fArr2, f12)
		f13 := fArr2[0]
		fArr3 := fArr2[1:]
		lhPair := LowHigh(fArr3)
		floatValue3 := lhPair.Id.(float64)
		floatValue4 := lhPair.Value.(float64)
		a16 := ShortenBmpHash(BmpHash(fArr3, floatValue3, floatValue4))
		a17 := HashF7(a16)
		a18 := Normalize(floatValue3)
		a19 := Normalize(floatValue4)
		a20 := Normalize(f13)

		intValue2 := len(a16)
		longValue2 := int64(math.Round((a20*100.0)+(a19*100.0)+(a18*100.0)) + float64(a17))
		apVar2 := fmt.Sprintf("1;%.2f;%.2f;%.2f;%v;%v", a18, a19, a20, a17, a16)
		altMotionPair := Pair{apVar2, int64(longValue2)}
		if !(intValue-intValue2 < 20) {
			motionPair = altMotionPair
		}
	}

	return motionPair
}

// Unamed transform function 1
func aeA(fArr []float64, i12, i13 int, fArr2 []float64) {
	if i13 == 1 {
		return
	}
	i14 := i13 / 2
	for i15 := 0; i15 < i14; i15++ {
		i16 := i12 + i15
		f12 := fArr[i16]
		f13 := fArr[((i12+i13)-1)-i15]
		fArr2[i16] = f12 + f13
		fArr2[i16+i14] = (f12 - f13) / ((math.Cos(((float64(i15) + float64(0.5)) * 3.141592653589793) / float64(i13))) * 2)
	}
	aeA(fArr2, i12, i14, fArr)
	i17 := i12 + i14
	aeA(fArr2, i17, i14, fArr)
	for i18 := 0; i18 < i14-1; i18++ {
		i19 := (i18 * 2) + i12
		i22 := i12 + i18
		fArr[i19+0] = fArr2[i22]
		i23 := i22 + i14
		fArr[i19+1] = fArr2[i23] + fArr2[i23+1]
	}
	i24 := i12 + i13
	fArr[i24-2] = fArr2[i17-1]
	i25 := i24 - 1
	fArr[i25] = fArr2[i25]
}

// Unamed transform function 2
func agA(fArr []float64, f12 float64) float64 {
	length := len(fArr)
	fArr2 := make([]float64, length)
	for i12 := 0; i12 < length; i12++ {
		fArr2[i12] = float64(math.Abs(fArr[i12]))
	}
	sort.Float64s(fArr2)
	floatValue := fArr2[int(math.Floor(float64(length-1)*f12))]
	for i13 := 0; i13 < length; i13++ {
		if math.Abs(fArr[i13]) < floatValue {
			fArr[i13] = 0.0
		}
	}
	return floatValue
}

func GenerateMotionDataFromAi(data [][]float64, count int) (string, int64, int) {
	var (
		fArr   = data[0][:count]
		fArr2  = data[1][:count]
		fArr3  = data[2][:count]
		fArr4  = data[3][:count]
		fArr5  = data[4][:count]
		fArr6  = data[5][:count]
		fArr7  = make([]float64, count)
		fArr9  = make([]float64, count)
		fArr10 = make([]float64, count)
	)

	for i := 0; i < count; i++ {
		fArr7[i] = -100
		fArr9[i] = -100
		fArr10[i] = -100
	}

	a2 := CreateMotionPair(fArr, 0.6000000238418579)
	a3 := CreateMotionPair(fArr2, 0.6000000238418579)
	a4 := CreateMotionPair(fArr3, 0.6000000238418579)
	a5 := CreateMotionPair(fArr4, 0.6000000238418579)
	a6 := CreateMotionPair(fArr5, 0.6000000238418579)
	a7 := CreateMotionPair(fArr6, 0.6000000238418579)
	a8 := CreateMotionPair(fArr7, 0.6000000238418579)
	a9 := CreateMotionPair(fArr9, 0.6000000238418579)
	a10 := CreateMotionPair(fArr10, 0.6000000238418579)

	dctData := a2.Id.(string) + ":" + a3.Id.(string) + ":" + a4.Id.(string) + ":" + a5.Id.(string) + ":" + a6.Id.(string) + ":" + a7.Id.(string) + ":" + a8.Id.(string) + ":" + a9.Id.(string) + ":" + a10.Id.(string)
	d2 := a2.Value.(int64) + a3.Value.(int64) + a4.Value.(int64) + a5.Value.(int64) + a6.Value.(int64) + a7.Value.(int64) + a8.Value.(int64) + a9.Value.(int64) + a10.Value.(int64)

	return dctData, d2, count
}

func GenerateOrientationEventsFromAi(data [][]float64, count int) (orientationData string, d int64, orientationCount int) {
	pitch := data[0][:count]
	yaw := data[1][:count]
	roll := data[2][:count]

	a13 := CreateMotionPair(pitch, 0.6000000238418579)
	a14 := CreateMotionPair(yaw, 0.6000000238418579)
	a15 := CreateMotionPair(roll, 0.6000000238418579)

	orientationData = a13.Id.(string) + ":" + a14.Id.(string) + ":" + a15.Id.(string)
	d = a13.Value.(int64) + a14.Value.(int64) + a15.Value.(int64)
	orientationCount = count

	return
}

func Hypot(dx, dy, dz float64) float64 {
	return math.Sqrt(dx*dx + dy*dy + dz*dz)
}

func Distance(src, dst vector.Vec3) float64 {
	return Magnitude(SubtractVecs(src, dst))
}

func Magnitude(vec vector.Vec3) float64 {
	return math.Sqrt(float64(vec[0]*vec[0] + vec[1]*vec[1] + vec[2]*vec[2]))
}

func SubtractVecs(src, dst vector.Vec3) vector.Vec3 {
	return vector.Vec3{
		src[0] - dst[0],
		src[1] - dst[2],
		src[2] - dst[2],
	}
}

func GenIfv(sdkInt int) string {
	if sdkInt >= 26 {
		return GenAndroidId()
	}
	return uuid.NewString()
}

func GenAndroidId() string {
	return fmt.Sprintf("%016x", RandomUint64())
}

func UrlEncode(s string) (result string) {
	var (
		bytes         = []rune(s)
		stringBuilder strings.Builder
	)

	for i := 0; i < len(bytes); i++ {
		b12 := bytes[i]
		if b12 >= 33 && b12 <= 126 && b12 != 34 && b12 != 37 && b12 != 39 && b12 != 44 && b12 != 92 {
			stringBuilder.WriteRune(rune(b12))
		} else {
			stringBuilder.WriteRune('%')

			forDigit := ForDigit(int((b12>>4))&15, 16)
			if unicode.IsLetter(forDigit) {
				forDigit = rune(forDigit - ' ')
			}
			stringBuilder.WriteRune(forDigit)

			forDigit2 := ForDigit(int(b12&15), 16)
			if unicode.IsLetter(forDigit2) {
				forDigit2 = rune(forDigit2 - ' ')
			}
			stringBuilder.WriteRune(forDigit2)
		}
	}

	return stringBuilder.String()
}

func GetCfDate() int64 {
	t := time.Now()
	tUnixMilli := int64(time.Nanosecond) * t.UnixNano() / int64(time.Millisecond)
	return tUnixMilli
}

func ForDigit(digit, radix int) rune {
	if (digit >= radix) || (digit < 0) {
		return rune(0)
	}

	if (radix < MIN_RADIX) || (radix > MAX_RADIX) {
		return rune(0)
	}

	if digit < 10 {
		return rune('0' + digit)
	}

	return rune('a' - 10 + digit)
}

func BitCount(n int) int {
	count := 0
	for n != 0 {
		count += n & 1
		n >>= 1
	}
	return count
}

func BitLengthShift(j uint64) uint64 {
	if j == 0 {
		return 0
	}
	j2 := j | (j >> 1)
	j3 := j2 | (j2 >> 2)
	j4 := j3 | (j3 >> 4)
	j5 := j4 | (j4 >> 8)
	j6 := j5 | (j5 >> 16)
	return j6 - (j6 >> 1)
}

func FeistelEncode(longValue, eventCount, key int) int {
	var0 := (((eventCount) & 0xffffffff) | (longValue << 32))
	var2 := int32(key)
	var3 := int32(var0)
	var5 := int32(var0 >> 32)
	var4 := 0

	for {
		var6 := int32(var4)
		if var4 >= 16 {
			var9 := int(var5)
			var0 = int(var3)
			return var9<<32 | var0&0xffffffff
		}
		var4++
		var6 = int32(int32(var5) ^ (var2) ^ int32(var3))
		var2 *= 2
		var5 = int32(var3)
		var3 = int32(var6)
	}
}

func RandomInt(min int, max int) int {
	nBig, _ := crand.Int(crand.Reader, big.NewInt(time.Now().UnixNano()))
	rand.Seed(nBig.Int64())
	return rand.Intn(max-min) + min
}

func SerializePair(dataset []Pair) string {
	var sb strings.Builder
	for i := 0; i < len(dataset); i++ {
		pair := dataset[i]
		if pair.Id != "" {
			sb.WriteString(fmt.Sprintf("-1,2,-94,%v,%v", pair.Id, pair.Value))
		} else {
			sb.WriteString(fmt.Sprintf("%v", pair.Id))
		}
	}

	return sb.String()
}

func LegacyEncrypt(i int, src, rsaKey string) (string, error) {
	var (
		sb strings.Builder
	)

	rawRsaKey, err := base64.StdEncoding.DecodeString(rsaKey)
	if err != nil {
		return "", err
	}

	aeskey := RandomByteArray(16)
	aesKeyEncrypted, err := RsaEncrypt(aeskey, rawRsaKey)
	if err != nil {
		return "", err
	}
	aesKeyEncrypted = []byte(base64.StdEncoding.EncodeToString(aesKeyEncrypted))

	doFinal, iv, err := AESEncrypt(src, aeskey)
	if err != nil {
		return "", err
	}
	hmackKey := RandomByteArray(16)
	hmackKeyEncrypted, err := RsaEncrypt(hmackKey, rawRsaKey)
	if err != nil {
		return "", err
	}
	hmackKeyEncrypted = []byte(base64.StdEncoding.EncodeToString(hmackKeyEncrypted))
	obj := append(iv, doFinal...)
	iv = ComputeHmac256(obj, hmackKey)
	doFinal = append(obj, iv...)
	encryptedData := base64.StdEncoding.EncodeToString(doFinal)

	sb.WriteString(strconv.Itoa(i) + ",a,")
	sb.WriteString(string(aesKeyEncrypted))
	sb.WriteString(",")
	sb.WriteString(string(hmackKeyEncrypted))
	sb.WriteString("$")
	sb.WriteString(encryptedData)
	sb.WriteString("$1000,1000,1000")

	return sb.String(), nil
}
