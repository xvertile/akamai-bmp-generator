// Package bm339 implements Akamai BMP 3.3.9 sensor generation.
// RSA modulus is *unchanged* from earlier versions.
package bm339

import (
	"encoding/base64"
	"fmt"
	"math"
	"math/rand"
	dm "xvertile/akamai-bmp/dm"
	"xvertile/akamai-bmp/sdk"
)

// BMP metadata
const (
	BMPVersion = "3.3.9"
	rsaKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMUymkqr6SQfxqefXMdkI6E1tDzHispEm4WhZAfIWjhvEqfStzy16HvCjI" +
		"BX2SRpn5pqW2w1TxqyxRnJOe4NEskWGdYY2y4JiD9vpYpWB54u6TOnKutXn2LzjMrvfIJpVXYZ5LYtD1ZUaeTKPz6qELXmBNcSfh/kGLiP8AH4eWKwIDAQAB"
)

type BotManager struct {
	app, lang     string
	challenge     bool
	challengeURL  string
	deviceManager dm.DeviceManager
	device        dm.Device
}

func NewStable(app, lang string, ch bool, powURL string, dmgr dm.DeviceManager) *BotManager {
	return &BotManager{
		app:           app,
		lang:          lang,
		challenge:     ch,
		challengeURL:  powURL,
		deviceManager: dmgr,
		device:        dmgr.RandomAndroidDevice(),
	}
}

func (bm *BotManager) GetAndroidId() string          { return bm.device.AndroidID }
func (bm *BotManager) GetDevice() dm.Device          { return bm.device }
func (bm *BotManager) GetPowToken() string           { return sdk.RandomHex(64) }
func (bm *BotManager) GetPowResponse() (string, error) { return sdk.SolvePow(bm.challengeURL) }

func (bm *BotManager) GenerateSensorData() (string, error) {
	var data []sdk.Pair
	data = append(data,
		sdk.Pair{"", BMPVersion},
		sdk.Pair{"-70", "{}"},
		sdk.Pair{"-80", "{}"},
		sdk.Pair{"-100", bm.GetSystemInfo()},
		sdk.Pair{"-101", bm.GetEventListeners()},
		sdk.Pair{"-103", bm.GetBackgroundEvents()},
		sdk.Pair{"-108", ""},
		sdk.Pair{"-112", bm.GetPrefBench()},
	)
	tact, vel, steps := bm.generateTouch()
	data = append(data,
		sdk.Pair{"-115", bm.GetVerifyStats(vel, steps)},
		sdk.Pair{"-117", tact},
	)
	data = append(data,
		sdk.Pair{"-160", bm.GetSensorCal()},
		sdk.Pair{"-161", bm.GetGyroDrift()},
		sdk.Pair{"-162", bm.GetMemStats()},
		sdk.Pair{"-163", bm.GetScheduler()},
	)
	plain := sdk.SerializeBmp(data)
	enc, err := bm.encryptSensor(plain)
	if err != nil {
		return "", err
	}
	pow, err := bm.GetPowResponse()
	if err != nil {
		return "", err
	}
	return enc + "$" + pow + "$" + bm.GetPowToken(), nil
}

func (bm *BotManager) generateTouch() (tact string, velocity, steps int) {
	steps = sdk.RandomInt(4, 8)
	for i := 0; i < steps; i++ {
		time := int(math.Round(30 * rand.Float64()))
		action := 1
		if i == 0 || rand.Float64() >= 0.8 {
			time = int(math.Round(1200 * rand.Float64()))
			action = 2
		} else if sdk.RandomBool() {
			action = 3
		}
		tact += fmt.Sprintf("%d,%d,0,0,1,1,1,-1;", action, time)
		velocity += time + action
	}
	return
}

func (bm *BotManager) GetSystemInfo() string     { return sdk.SystemInfo(bm.device) }
func (bm *BotManager) GetEventListeners() string { return sdk.EventListeners() }
func (bm *BotManager) GetBackgroundEvents() string {
	if s := sdk.BackgroundEvents(); s != "" { return s }
	return "2,0;3,100;"
}
func (bm *BotManager) GetPrefBench() string      { return sdk.PrefBench() }
func (bm *BotManager) GetVerifyStats(vel, steps int) string {
	return fmt.Sprintf("%d,%d,0,0,0,0,%d", vel, steps, sdk.RandomInt(5, 14))
}
func (bm *BotManager) GetSensorCal() string   { return sdk.SensorCal() }
func (bm *BotManager) GetGyroDrift() string   { return sdk.GyroDrift() }
func (bm *BotManager) GetMemStats() string    { return sdk.MemStats() }
func (bm *BotManager) GetScheduler() string   { return sdk.Scheduler() }

func (bm *BotManager) encryptSensor(buf []byte) (string, error) {
	aesKey := sdk.RandomBytes(16)
	iv := sdk.RandomBytes(16)
	cipher, err := sdk.AESCBCEncrypt(buf, aesKey, iv)
	if err != nil {
		return "", err
	}
	wrapped, err := sdk.RSAEncryptOAEP(append(aesKey, iv...), rsaKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(wrapped) + "." +
		base64.StdEncoding.EncodeToString(cipher), nil
} 