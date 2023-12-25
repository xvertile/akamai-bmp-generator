package bm

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strconv"
	"strings"

	devicemanager "xvertile/akamai-bmp/dm"
	"xvertile/akamai-bmp/sdk"
)

var (
	BMPVERSION = "3.3.4"
	rsaKey     = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMUymkqr6SQfxqefXMdkI6E1tDzHispEm4WhZAfIWjhvEqfStzy16HvCjIBX2SRpn5pqW2w1TxqyxRnJOe4NEskWGdYY2y4JiD9vpYpWB54u6TOnKutXn2LzjMrvfIJpVXYZ5LYtD1ZUaeTKPz6qELXmBNcSfh/kGLiP8AH4eWKwIDAQAB"
)

type BotManager struct {
	*Config

	Device                devicemanager.Device // device
	androidId             string
	startTime             int64
	bootTime              int64
	MotionData, MTimeData string
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
		orientation           = 1
		keyboard              = 0
		adbEnabled            = 1
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
	return "do_en,dm_en,t_en"
}

func (bm *BotManager) GetBackgroundEvents() string {
	var (
		actions = []int{2, 3}
		maxStep = 5
		minStep = 1
		maxDx   = 1495
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

	var orientationData, oreintationTimeData, oreintationTimeDataValue string
	var d int64
	var orientationCount int

	//orientationData, d, orientationCount = sdk.GenerateOrientationEvents(int(sdk.BitLengthShift(uint64(sdk.RandomInt(32, 128)))))
	motionData, d2, motionCount := sdk.GenerateMotionString(int(sdk.BitLengthShift(uint64(sdk.RandomInt(32, 128)))))
	tact, touchVel, touchSteps = bm.GenerateTouchEvents()
	/*orientationTimeArr := sdk.GenTimeEvent(orientationCount)
	oreintationTimeData = sdk.CreateMotionPair(orientationTimeArr, 0.0).Id.(string)
	oreintationTimeDataValue = sdk.MotionFirstSendData(orientationTimeArr)*/

	motionTimeArr := sdk.GenTimeEvent(motionCount)
	motionTimeData := sdk.CreateMotionPair(motionTimeArr, 0.0).Id.(string)
	motionTimeDataValue := sdk.MotionFirstSendData(motionTimeArr)

	sensorData = append(sensorData, sdk.Pair{Id: "", Value: BMPVERSION})
	if bm.Challenge {
		sensorData = append(sensorData, sdk.Pair{Id: "-90", Value: "cf-sdk-1-00-0.js#model=" + bm.Device.Build.Model + "#sdkVersion=" + BMPVERSION + "#deviceProperties=[]: []"}) // empty
	}
	sensorData = append(sensorData, sdk.Pair{Id: "-70", Value: ""}) // empty
	sensorData = append(sensorData, sdk.Pair{Id: "-80", Value: ""}) // empty
	sensorData = append(sensorData, sdk.Pair{Id: "-121", Value: ""})
	sensorData = append(sensorData, sdk.Pair{Id: "-100", Value: bm.GetSystemInfo()})
	sensorData = append(sensorData, sdk.Pair{Id: "-101", Value: bm.GetEventListeners()})
	sensorData = append(sensorData, sdk.Pair{Id: "-102", Value: eact})
	sensorData = append(sensorData, sdk.Pair{Id: "-103", Value: bm.GetBackgroundEvents()}) // background events
	sensorData = append(sensorData, sdk.Pair{Id: "-104", Value: "-2,3,-50,-301,null"})     // -2,3,-50,-301,null
	sensorData = append(sensorData, sdk.Pair{Id: "-108", Value: ""})                       // text change events
	sensorData = append(sensorData, sdk.Pair{Id: "-112", Value: bm.GetPrefBench()})        //6212842071,6212842071
	sensorData = append(sensorData, sdk.Pair{Id: "-115", Value: bm.GetVerifyStats(touchVel, touchSteps, int(d), int(d2), orientationCount, motionCount)})
	sensorData = append(sensorData, sdk.Pair{Id: "-117", Value: tact})
	sensorData = append(sensorData, sdk.Pair{Id: "-120", Value: ""})
	sensorData = append(sensorData, sdk.Pair{Id: "-144", Value: oreintationTimeData})
	sensorData = append(sensorData, sdk.Pair{Id: "-160", Value: oreintationTimeDataValue})
	sensorData = append(sensorData, sdk.Pair{Id: "-142", Value: orientationData})
	sensorData = append(sensorData, sdk.Pair{Id: "-145", Value: motionTimeData})
	sensorData = append(sensorData, sdk.Pair{Id: "-161", Value: motionTimeDataValue})
	sensorData = append(sensorData, sdk.Pair{Id: "-143", Value: motionData})
	sensorData = append(sensorData, sdk.Pair{Id: "-150", Value: fmt.Sprintf("%v,%v", 1, 0)})

	bm.MotionData = motionData
	bm.MTimeData = motionTimeData

	encryptedSensor, err := bm.EncryptSensor(sdk.SerializeBmp(sensorData))
	if err != nil {
		return "", err
	}

	powResponse, err := bm.GetPowResponse()
	if err != nil {
		return "", err
	}

	powToken, err := bm.GetPowToken()
	if err != nil {
		return "", err
	}

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
	r2 := sdk.RandomInt(15, 53) * 1000

	return fmt.Sprintf(
		"0,%v,%v,%v,%v,%v,0,%v,%v,%v,%v,%v,0,%v,%v",
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
func (bm *BotManager) GetAndroidId() string {
	return bm.androidId
}

func (bm *BotManager) GetPowResponse() (string, error) {
	if !bm.Challenge {
		return "", nil
	}

	params, err := sdk.GetPowParams(bm.GetDevice().UserAgent(BMPVERSION, bm.Lang), bm.bootTime, bm.androidId, bm.ChallengeUrl)
	if err != nil {
		return "", err
	}

	return sdk.GeneratePow(*params)
}

func (bm *BotManager) GetPowToken() (string, error) {
	return "", nil
}

func (bm *BotManager) EncryptSensor(src string) (string, error) {
	var (
		sb strings.Builder
	)

	rawRsaKey, err := base64.StdEncoding.DecodeString(rsaKey)
	if err != nil {
		return "", err
	}

	//uptimeMillis := sdk.UptimeMillis(bootTime)
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
	//aesUptime := (sdk.UptimeMillis(bootTime) - uptimeMillis) * 1000

	//uptimeMillis = sdk.UptimeMillis(bootTime)
	hmackKey := sdk.RandomByteArray(16)
	hmackKeyEncrypted, err := sdk.RsaEncrypt(hmackKey, rawRsaKey)
	if err != nil {
		return "", err
	}
	hmackKeyEncrypted = []byte(base64.StdEncoding.EncodeToString(hmackKeyEncrypted))

	obj := append(iv, doFinal...)
	iv = sdk.ComputeHmac256(obj, hmackKey)
	doFinal = append(obj, iv...)
	//hmackUptime := (sdk.UptimeMillis(bootTime) - uptimeMillis) * 1000

	//uptimeMillis = sdk.UptimeMillis(bootTime)
	encryptedData := base64.StdEncoding.EncodeToString(doFinal)
	//b64Uptime := (sdk.UptimeMillis(bootTime) - uptimeMillis) * 1000

	sb.WriteString("3,a,")
	sb.WriteString(string(aesKeyEncrypted))
	sb.WriteString(",")
	sb.WriteString(string(hmackKeyEncrypted))
	sb.WriteString("$")
	sb.WriteString(encryptedData)
	sb.WriteString("$1000,1000,1000")
	/*sb.WriteString(strconv.FormatInt(aesUptime, 10))
	sb.WriteString(",")
	sb.WriteString(strconv.FormatInt(hmackUptime, 10))
	sb.WriteString(",")
	sb.WriteString(strconv.FormatInt(b64Uptime, 10))*/

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

	if bm.Lang == "" {
		bm.Lang = "en"
	}

	if bm.App == "" {
		panic(errors.New("Package/App name must not be empty, app not found"))
	}

	bm.bootTime = sdk.GetCfDate() - int64(sdk.RandomInt(6600, 50000))
	bm.Device = dm.GetRandomDevice()
	//bm.Device = devicemanager.SystemInfoToDevice(`-1,uaend,-1,1448,720,1,54,1,en,11,1,RMX3201,unknown,mt6765,-1,de.zalando.mobile,-1,-1,f7e9aaa75f6a5bec,-1,0,1,REL,1641524502945,30,realme,RMX3201RU,release-keys,user,root,RMX3201_11_C.07,RM6765,realme,RMX3201,realme/RMX3201RU/RMX3201:11/RP1A.200720.011/1641524502945:user/release-keys,CP-ubuntu-123-174,RP1A.200720.011,22485,1121732414,832919142166`)

	//bm.Device = devicemanager.TestDevice()

	//bm.Device = devicemanager.JsonToDevice(`{"_id":{"$oid":"634a93539bc3970bffd81e61"},"SCREEN":{"heightPixels":1381,"widthPixels":720},"PERF_BENCH":["17,906,59,822,89000,898,46300,462,3269"],"BUILD":{"MANUFACTURER":"samsung","HARDWARE":"mt6762","MODEL":"SM-A107F","BOOTLOADER":"A107FXXU8CVE3","VERSION":{"RELEASE":"11","CODENAME":"REL","INCREMENTAL":"A107FXXU8CVE3","SDK_INT":30},"PRODUCT":"a10sxx","TAGS":"release-keys","TYPE":"user","USER":"dpi","DISPLAY":"RP1A.200720.012.A107FXXU8CVE3","BOARD":"S96116RA1","BRAND":"samsung","DEVICE":"a10s","FINGERPRINT":"samsung/a10sxx/a10s:11/RP1A.200720.012/A107FXXU8CVE3:user/release-keys","HOST":"21DJ6B09","ID":"RP1A.200720.012"}}`)

	bm.startTime = sdk.GetCfDate() - int64(sdk.RandomInt(4000, 8000)) // check

	//bm.Device.PerfBench = []string{"16,504,59,826,148000,1488,91300,912,16"}
	/*for bm.Device.Build.Manufacturer != "vivo" {
		bm.Device = dm.GetRandomDevice()
	}*/

	return bm
}
