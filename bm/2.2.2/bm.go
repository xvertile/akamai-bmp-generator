package bm

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strconv"
	"strings"

	devicemanager "xvertile/akamai-bmp/dm"
	"xvertile/akamai-bmp/sdk"
)

var (
	BMPVERSION = "2.2.2"
	rsaKey     = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4sA7vA7N/t1SRBS8tugM2X4bByl0jaCZLqxPOql+qZ3sP4UFayqJTvXjd7eTjMwg1T70PnmPWyh1hfQr4s12oSVphTKAjPiWmEBvcpnPPMjr5fGgv0w6+KM9DLTxcktThPZAGoVcoyM/cTO/YsAMIxlmTzpXBaxddHRwi8S2NvwIDAQAB"
)

type BotManager struct {
	*Config

	Device    devicemanager.Device // device
	bmpIndex  int                  // sent count
	bmpType   int                  // reason sensor is sent
	startTime int64
	androidId string
	Time      int64
	Verify    string
}

type Config struct {
	App          string
	Lang         string
	Challenge    bool
	ChallengeUrl string
}

type pair struct {
	first, second interface{}
}

func (bm *BotManager) GetDevice() devicemanager.Device {
	return bm.Device
}

func (bm *BotManager) GetSystemInfo() string {
	var (
		device                = &bm.Device
		orientation           = 0
		keyboard              = 1
		adbEnabled            = 0
		batteryLevel          = sdk.RandomInt(1, 100)
		accelerometerRotation = 1
	)

	bm.androidId = sdk.GenIfv(device.Build.Version.SdkInt)

	systemInfo := fmt.Sprintf(
		"-1,uaend,-1,%v,%v,1,%v,%v,%v,%v,%v,%v,%v,%v,-1,%v,-1,-1,%v,-1,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v",
		device.Screen.HeightPixels,
		device.Screen.WidthPixels,
		strconv.Itoa(batteryLevel),
		orientation,
		sdk.UrlEncode(bm.Lang),
		sdk.UrlEncode(device.Build.Version.Release),
		accelerometerRotation,
		sdk.UrlEncode(device.Build.Model),
		sdk.UrlEncode(device.Build.Bootloader),
		sdk.UrlEncode(device.Build.Hardware),
		bm.App,
		bm.androidId,
		keyboard,
		adbEnabled,
		sdk.UrlEncode(device.Build.Version.Codename),
		sdk.UrlEncode(device.Build.Version.Incremental),
		device.Build.Version.SdkInt,
		sdk.UrlEncode(device.Build.Manufacturer),
		sdk.UrlEncode(device.Build.Product),
		sdk.UrlEncode(device.Build.Tags),
		sdk.UrlEncode(device.Build.Type),
		sdk.UrlEncode(device.Build.User),
		sdk.UrlEncode(device.Build.Display),
		sdk.UrlEncode(device.Build.Board),
		sdk.UrlEncode(device.Build.Brand),
		sdk.UrlEncode(device.Build.Device),
		sdk.UrlEncode(device.Build.Fingerprint),
		sdk.UrlEncode(device.Build.Host),
		sdk.UrlEncode(device.Build.ID),
	)

	return fmt.Sprintf("%v,%v,%v,%v", systemInfo, sdk.Ab(systemInfo), sdk.INegate(int(rand.Int31()), sdk.RandomBool()), bm.startTime/2)
}

func (bm *BotManager) GetEventListeners() string {
	return "do_unr,dm_unr,t_en"
}

func (bm *BotManager) GetEditTextEvents() string {
	if bm.App == "com.kohls.mcommerce.opal" {
		return "511;"
	}
	if bm.App == "de.zalando.mobile" {
		return "515;517;510;520;509;518;516;"
	}
	return ""
}

func (bm *BotManager) GetBackgroundEvents() string {
	var (
		actions = []int{2, 3}
		maxStep = 5
		minStep = 1
		maxDx   = 495
		minDx   = 100
		steps   = sdk.RandomInt(minStep, maxStep)
		startTs = bm.startTime
		data    = ""
	)

	if sdk.RandomBool() {
		steps /= 2
	}

	for i := 0; i < steps; i++ {
		dx := sdk.RandomInt(minDx, maxDx)
		data += fmt.Sprintf("%v,%v;", actions[rand.Intn(len(actions))], startTs+int64(dx))
		startTs += int64(dx)
	}

	if len(data) == 0 {
		dx := sdk.RandomInt(minDx, maxDx)
		data += fmt.Sprintf("%v,%v;", actions[rand.Intn(len(actions))], startTs+int64(dx))
	}

	return data
}

func (bm *BotManager) GetPrefBench() string {
	prefBenchmarks := bm.Device.PerfBench
	if len(prefBenchmarks) == 0 {
		return "17,906,59,822,89000,898,46300,462,3269"
	}
	if len(prefBenchmarks) == 1 {
		return prefBenchmarks[0]
	}
	return prefBenchmarks[rand.Intn(len(prefBenchmarks))]
}

func (bm *BotManager) GenerateTouchEvents() (string, int, int) {
	tact := ""
	count := sdk.RandomInt(1, 7)
	vel := 0

	for i := 0; i < count; i++ {
		time := int(math.Round(300 * rand.Float64()))
		action := 1

		if i == 0 || rand.Float64() >= 0.55 {
			time = int(math.Round(2300 * rand.Float64()))
			action = 2
			tact += fmt.Sprintf("%v,%v,0,0,1,1,1,-1;", action, time)
		} else if sdk.RandomBool() {
			action = 3
			tact += fmt.Sprintf("%v,%v,0,0,1,1,1,-1;", action, time)
		} else {
			tact += fmt.Sprintf("%v,%v,0,0,1,1,1,-1;", action, time)
		}
		vel = vel + time + action
	}

	return tact, vel, count
}

func (bm *BotManager) GenerateSensorData() (string, error) {
	var (
		sensorData           []sdk.Pair
		tact, eact           string
		touchVel, touchSteps int
	)
	var orientationData, oreintationTimeData string
	var d int64
	var orientationCount int

	//orientationData, d, orientationCount = sdk.GenerateOrientationEvents(int(sdk.BitLengthShift(uint64(sdk.RandomInt(16, 32)))))
	motionData, d2, motionCount := sdk.GenerateMotionString(int(sdk.BitLengthShift(uint64(sdk.RandomInt(16, 128)))))
	tact, touchVel, touchSteps = bm.GenerateTouchEvents()

	//orientationTimeArr := sdk.GenTimeEvent(orientationCount)
	//oreintationTimeData = sdk.CreateMotionPair(orientationTimeArr, 0.0).Id.(string)

	motionTimeArr := sdk.GenTimeEvent(motionCount)
	motionTimeData := sdk.CreateMotionPair(motionTimeArr, 0.0).Id.(string)

	bm.Verify = bm.GetVerifyStats(touchVel, touchSteps, int(d), int(d2), orientationCount, motionCount)

	sensorData = append(sensorData, sdk.Pair{Id: "", Value: BMPVERSION})
	sensorData = append(sensorData, sdk.Pair{Id: "-100", Value: bm.GetSystemInfo()})
	sensorData = append(sensorData, sdk.Pair{Id: "-101", Value: bm.GetEventListeners()})
	sensorData = append(sensorData, sdk.Pair{Id: "-102", Value: eact})
	sensorData = append(sensorData, sdk.Pair{Id: "-108", Value: ""}) // text change events
	sensorData = append(sensorData, sdk.Pair{Id: "-117", Value: tact})
	sensorData = append(sensorData, sdk.Pair{Id: "-111", Value: ""}) // Motion events
	sensorData = append(sensorData, sdk.Pair{Id: "-109", Value: ""}) // Motion events
	sensorData = append(sensorData, sdk.Pair{Id: "-144", Value: oreintationTimeData})
	sensorData = append(sensorData, sdk.Pair{Id: "-142", Value: orientationData})
	sensorData = append(sensorData, sdk.Pair{Id: "-145", Value: motionTimeData})
	sensorData = append(sensorData, sdk.Pair{Id: "-143", Value: motionData})

	sensorData = append(sensorData, sdk.Pair{Id: "-115", Value: bm.Verify})
	sensorData = append(sensorData, sdk.Pair{Id: "-106", Value: fmt.Sprintf("%v,%v", 1, 1)})
	sensorData = append(sensorData, sdk.Pair{Id: "-120", Value: ""})
	sensorData = append(sensorData, sdk.Pair{Id: "-112", Value: bm.GetPrefBench()})        //6212842071,6212842071
	sensorData = append(sensorData, sdk.Pair{Id: "-103", Value: bm.GetBackgroundEvents()}) // background events

	encryptedSensor, err := bm.EncryptSensor(sdk.SerializeBmp(sensorData))
	if err != nil {
		panic(err)
	}

	powResponse, err := bm.GetPowResponse()
	if err != nil {
		return "", nil
	}
	powToken := bm.GetPowToken()

	return encryptedSensor + "$" + powResponse + "$" + powToken, nil
}

func (bm *BotManager) PrettyPrintPairs(pairs []sdk.Pair) {
	for i := 0; i < len(pairs); i++ {
		pair := pairs[i]
		fmt.Printf("%v Pair{%v %v}\n", i, pair.Id, pair.Value)
	}
}

// This means a lot
func (bm *BotManager) GetVerifyStats(touchVel, touchSteps, d, d2, shifta, shiftb int) string {
	time := sdk.GetCfDate() - bm.startTime
	longValue := d2 + touchVel + d + 0
	r1 := sdk.RandomInt(4, 16) * 1000
	r2 := sdk.RandomInt(53, 153) * 1000

	return fmt.Sprintf(
		"0,%v,%v,%v,%v,%v,0,%v,%v,%v,%v,%v,1,%v,%v",
		touchVel,
		d,
		d2,
		longValue,
		time,
		touchSteps,
		shifta,
		shiftb,
		r1,
		r2,
		sdk.FeistelEncode(longValue, touchSteps+shifta+shiftb, int(time)),
		bm.startTime,
	)
}

func (bm *BotManager) GenerateOrientationEvents(count int) (orientationData string, d int64, orientationCount int) {
	pitch, yaw, roll := sdk.GenOrientationEvents(sdk.GenRandomVec(), sdk.GenRandomVec(), count)

	a13 := bm.CreateMotionPair(pitch, 0.6000000238418579)
	a14 := bm.CreateMotionPair(yaw, 0.6000000238418579)
	a15 := bm.CreateMotionPair(roll, 0.6000000238418579)

	orientationData = a13.first.(string) + ":" + a14.first.(string) + ":" + a15.first.(string)
	d = a13.second.(int64) + a14.second.(int64) + a15.second.(int64)
	orientationCount = count

	return
}

func (bm *BotManager) GenerateMotionData(count int) (string, int64, int) {
	fArr, fArr2, fArr3 := sdk.GenGenericEvents(count)
	fArr4, fArr5, fArr6 := sdk.GenGenericEvents(count)

	fArr7 := make([]float64, count)
	fArr9 := make([]float64, count)
	fArr10 := make([]float64, count)

	for i := 0; i < count; i++ {
		//fArr6[i] = sdk.RandomFloat(-9.822000503540039, -10.182000160217286)
		fArr7[i] = -100
		fArr9[i] = -100
		fArr10[i] = -100
	}

	a2 := bm.CreateMotionPair(fArr, 0.6000000238418579)
	a3 := bm.CreateMotionPair(fArr2, 0.6000000238418579)
	a4 := bm.CreateMotionPair(fArr3, 0.6000000238418579)
	a5 := bm.CreateMotionPair(fArr4, 0.6000000238418579)
	a6 := bm.CreateMotionPair(fArr5, 0.6000000238418579)
	a7 := bm.CreateMotionPair(fArr6, 0.6000000238418579)
	a8 := bm.CreateMotionPair(fArr7, 0.6000000238418579)
	a9 := bm.CreateMotionPair(fArr9, 0.6000000238418579)
	a10 := bm.CreateMotionPair(fArr10, 0.6000000238418579)

	dctData := a2.first.(string) + ":" + a3.first.(string) + ":" + a4.first.(string) + ":" + a5.first.(string) + ":" + a6.first.(string) + ":" + a7.first.(string) + ":" + a8.first.(string) + ":" + a9.first.(string) + ":" + a10.first.(string)
	d2 := a2.second.(int64) + a3.second.(int64) + a4.second.(int64) + a5.second.(int64) + a6.second.(int64) + a7.second.(int64) + a8.second.(int64) + a9.second.(int64) + a10.second.(int64)

	return dctData, d2, count
}

func (bm *BotManager) GenerateMotionString(count int) (string, int64, int) {
	return bm.GenerateMotionData(count)
}

func (bm *BotManager) CreateMotionPair(fArr []float64, f12 float64) pair {
	var (
		length     = len(fArr)
		fArr2      = fArr
		motionPair pair
		a4         = bm.LowHigh(fArr)
		lower      = (a4.first.(float64))
		higher     = (a4.second.(float64))
		a5         = sdk.ShortenBmpHash(sdk.BmpHash(fArr, lower, higher))
		a6         = sdk.HashF7(a5)
		a7         = sdk.Normalize(lower)
		a8         = sdk.Normalize(higher)
	)

	apVar := fmt.Sprintf("2;%.2f;%.2f;%v;%v", a7, a8, a6, a5)
	longValue := int(a7*100+a8*100) + a6
	motionPair = pair{apVar, int64(longValue)}
	intValue := len(a5)

	if sdk.BitCount(length) == 1 {
		aeA(fArr2, 0, length, make([]float64, length))
		agA(fArr2, f12)
		f13 := fArr2[0]
		fArr3 := fArr2[1:]
		lhPair := bm.LowHigh(fArr3)
		floatValue3 := lhPair.first.(float64)
		floatValue4 := lhPair.second.(float64)
		a16 := sdk.ShortenBmpHash(sdk.BmpHash(fArr3, floatValue3, floatValue4))
		a17 := sdk.HashF7(a16)
		a18 := sdk.Normalize(floatValue3)
		a19 := sdk.Normalize(floatValue4)
		a20 := sdk.Normalize(f13)

		intValue2 := len(a16)
		longValue2 := int64(math.Round((a20*100.0)+(a19*100.0)+(a18*100.0)) + float64(a17))
		apVar2 := fmt.Sprintf("1;%.2f;%.2f;%.2f;%v;%v", a18, a19, a20, a17, a16)
		altMotionPair := pair{apVar2, int64(longValue2)}

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

func (bm *BotManager) LowHigh(fArr []float64) pair {
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
	return pair{float64(low), float64(high)}
}

func (bm *BotManager) GetPowResponse() (string, error) {
	if !bm.Challenge {
		return "", nil
	}

	params, err := sdk.GetPowParams(bm.GetDevice().UserAgent(BMPVERSION, bm.Lang), sdk.GetCfDate()-int64(sdk.RandomInt(6600, 50000)), bm.androidId, bm.ChallengeUrl)
	if err != nil {
		return "", err
	}

	return sdk.GeneratePow(*params)
}

func (bm *BotManager) GetPowToken() string {
	return ""
}
func (bm *BotManager) GetAndroidId() string {
	return bm.androidId
}
func (bm *BotManager) EncryptSensor(src string) (string, error) {
	var (
		sb       strings.Builder
		bootTime = sdk.GetCfDate() - int64(sdk.RandomInt(6600, 50000))
	)

	rawRsaKey, err := base64.StdEncoding.DecodeString(rsaKey)
	if err != nil {
		return "", err
	}

	uptimeMillis := sdk.UptimeMillis(bootTime)
	aeskey := sdk.RandomByteArray(16)
	aesKeyEncrypted, err := sdk.RsaEncrypt(aeskey, rawRsaKey)
	if err != nil {
		return "", err
	}
	aesKeyEncrypted = []byte(base64.StdEncoding.EncodeToString(aesKeyEncrypted))

	doFinal, iv, err := sdk.AESEncrypt(src, aeskey)
	if err != nil {
		return "", err
	}
	aesUptime := (sdk.UptimeMillis(bootTime) - uptimeMillis) * 1000

	uptimeMillis = sdk.UptimeMillis(bootTime)
	hmackKey := sdk.RandomByteArray(16)
	hmackKeyEncrypted, err := sdk.RsaEncrypt(hmackKey, rawRsaKey)
	if err != nil {
		return "", err
	}
	hmackKeyEncrypted = []byte(base64.StdEncoding.EncodeToString(hmackKeyEncrypted))

	obj := append(iv, doFinal...)
	iv = sdk.ComputeHmac256(obj, hmackKey)
	doFinal = append(obj, iv...)
	hmackUptime := (sdk.UptimeMillis(bootTime) - uptimeMillis) * 1000

	uptimeMillis = sdk.UptimeMillis(bootTime)
	encryptedData := base64.StdEncoding.EncodeToString(doFinal)
	b64Uptime := (sdk.UptimeMillis(bootTime) - uptimeMillis) * 1000

	sb.WriteString("1,a,")
	sb.WriteString(string(aesKeyEncrypted))
	sb.WriteString(",")
	sb.WriteString(string(hmackKeyEncrypted))
	sb.WriteString("$")
	sb.WriteString(encryptedData)
	sb.WriteString("$")
	sb.WriteString(strconv.FormatInt(aesUptime, 10))
	sb.WriteString(",")
	sb.WriteString(strconv.FormatInt(hmackUptime, 10))
	sb.WriteString(",")
	sb.WriteString(strconv.FormatInt(b64Uptime, 10))

	return sb.String(), nil
}

func NewStable(app string, lang string, challenge bool, challengeUrl string, dm devicemanager.DeviceManager) *BotManager {
	return New(&Config{App: app, Lang: lang, Challenge: challenge, ChallengeUrl: challengeUrl}, dm)
}

/*
* Time is absolutely checked
* Figure out what does timing
* do timing manually, see if it works
* manually how it would happen in app
 */

func New(cfg *Config, dm devicemanager.DeviceManager) *BotManager {
	bm := &BotManager{Config: cfg}

	bm.bmpIndex = 0
	bm.bmpType = 0

	if bm.Lang == "" {
		bm.Lang = "en"
	}

	if bm.App == "" {
		panic(errors.New("Package/App name must not be empty, app not found"))
	}

	/*devices := []devicemanager.Device{
	}*/

	bm.Device = dm.GetRandomDevice()
	//bm.Device = devicemanager.SystemInfoToDevice(`-1,uaend,-1,1448,720,1,54,1,en,11,1,RMX3201,unknown,mt6765,-1,de.zalando.mobile,-1,-1,f7e9aaa75f6a5bec,-1,0,1,REL,1641524502945,30,realme,RMX3201RU,release-keys,user,root,RMX3201_11_C.07,RM6765,realme,RMX3201,realme/RMX3201RU/RMX3201:11/RP1A.200720.011/1641524502945:user/release-keys,CP-ubuntu-123-174,RP1A.200720.011,22485,1121732414,832919142166`)

	//bm.Device = devicemanager.TestDevice()

	//bm.Device = devicemanager.JsonToDevice(`{"_id":{"$oid":"634a93539bc3970bffd81e61"},"SCREEN":{"heightPixels":1381,"widthPixels":720},"PERF_BENCH":["17,906,59,822,89000,898,46300,462,3269"],"BUILD":{"MANUFACTURER":"samsung","HARDWARE":"mt6762","MODEL":"SM-A107F","BOOTLOADER":"A107FXXU8CVE3","VERSION":{"RELEASE":"11","CODENAME":"REL","INCREMENTAL":"A107FXXU8CVE3","SDK_INT":30},"PRODUCT":"a10sxx","TAGS":"release-keys","TYPE":"user","USER":"dpi","DISPLAY":"RP1A.200720.012.A107FXXU8CVE3","BOARD":"S96116RA1","BRAND":"samsung","DEVICE":"a10s","FINGERPRINT":"samsung/a10sxx/a10s:11/RP1A.200720.012/A107FXXU8CVE3:user/release-keys","HOST":"21DJ6B09","ID":"RP1A.200720.012"}}`)
	bm.Time = int64(sdk.RandomInt(4000, 8000))
	bm.startTime = sdk.GetCfDate() - bm.Time // check

	//bm.Device.PerfBench = []string{"16,504,59,826,148000,1488,91300,912,16"}

	/*for bm.Device.Build.Manufacturer != "vivo" {
		bm.Device = dm.GetRandomDevice()
	}*/

	return bm
}
