package dm

import (
	"encoding/json"
	"strconv"
	"strings"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"xvertile/akamai-bmp/sdk"
)

type Device struct {
	AndroidID string `json:"androidId" bson:"androidId"`
	ID     primitive.ObjectID `bson:"_id"`
	Screen struct {
		HeightPixels int `bson:"heightPixels" json:"heightPixels"`
		WidthPixels  int `bson:"widthPixels" json:"widthPixels"`
	} `bson:"SCREEN" json:"SCREEN"`
	PerfBench []string `bson:"PERF_BENCH" json:"PERF_BENCH"`
	Build     struct {
		Manufacturer string `bson:"MANUFACTURER" json:"MANUFACTURER"`
		Hardware     string `bson:"HARDWARE" json:"HARDWARE"`
		Model        string `bson:"MODEL" json:"MODEL"`
		Bootloader   string `bson:"BOOTLOADER" json:"BOOTLOADER"`
		Version      struct {
			Release     string `bson:"RELEASE" json:"RELEASE"`
			Codename    string `bson:"CODENAME" json:"CODENAME"`
			Incremental string `bson:"INCREMENTAL" json:"INCREMENTAL"`
			SdkInt      int    `bson:"SDK_INT" json:"SDK_INT"`
		} `bson:"VERSION" json:"VERSION"`
		Product     string `bson:"PRODUCT" json:"PRODUCT"`
		Tags        string `bson:"TAGS" json:"TAGS"`
		Type        string `bson:"TYPE" json:"TYPE"`
		User        string `bson:"USER" json:"USER"`
		Display     string `bson:"DISPLAY" json:"DISPLAY"`
		Board       string `bson:"BOARD" json:"BOARD"`
		Brand       string `bson:"BRAND" json:"BRAND"`
		Device      string `bson:"DEVICE" json:"DEVICE"`
		Fingerprint string `bson:"FINGERPRINT" json:"FINGERPRINT"`
		Host        string `bson:"HOST" json:"HOST"`
		ID          string `bson:"ID" json:"ID"`
	} `bson:"BUILD" json:"BUILD"`
}

type DeviceVersion struct {
	Release     string
	Codename    string
	Incremental string
	Sdk         int
}

func (dev Device) UserAgent(version string, local string) string {
	return "Akamai BMPSDK/" + version + " (Android; " + dev.Build.Version.Release + "; " + dev.Build.Manufacturer + "; " + dev.Build.Model + "; " + local + ")"
}

func (dev *Device) String() string {
	b, _ := json.Marshal(dev)
	return string(b)
}

func TestDevice() Device {
	dev := JsonToDevice(`{"SCREEN":{"heightPixels":1457,"widthPixels":720},"PERF_BENCH":["15,205,59,481,415800,4166,87300,872,14430","19,3443,59,6490,399100,3999,169700,1696,17469","13,156,59,152,10200,110,4700,46,1171","17,1015,59,692,60000,608,31200,311,901"],"BUILD":{"MANUFACTURER":"samsung","HARDWARE":"mt6853","MODEL":"SM-A326U","BOOTLOADER":"A326USQU8BVG3","VERSION":{"RELEASE":"12","CODENAME":"REL","INCREMENTAL":"A326USQU8BVG3","SDK_INT":31},"PRODUCT":"a32xsq","TAGS":"release-keys","TYPE":"user","USER":"dpi","DISPLAY":"SP1A.210812.016.A326USQU8BVG3","BOARD":"a32x","BRAND":"samsung","DEVICE":"a32x","FINGERPRINT":"samsung\/a32xsq\/a32x:12\/SP1A.210812.016\/A326USQU8BVG3:user\/release-keys","HOST":"SWDK3601","ID":"SP1A.210812.016"}}`)

	return dev
}

func JsonToDevice(jsonStr string) Device {
	var dev Device

	err := json.Unmarshal([]byte(jsonStr), &dev)
	if err != nil {
		panic(err)
	}

	return dev
}

func SystemInfoToDevice(sysInfo string) Device {
	data := strings.Split(sysInfo, ",")
	height, _ := strconv.Atoi(data[3])
	width, _ := strconv.Atoi(data[4])
	verRelease := sdk.UrlDecode(data[9])
	model := sdk.UrlDecode(data[11])
	bootloader := sdk.UrlDecode(data[12])
	hardware := sdk.UrlDecode(data[13])
	codename := data[22]
	incremental := data[23]
	sdkint, _ := strconv.Atoi(data[24])
	manufacturer := sdk.UrlDecode(data[25])
	product := sdk.UrlDecode(data[26])
	tags := sdk.UrlDecode(data[27])
	androidType := sdk.UrlDecode(data[28])
	user := sdk.UrlDecode(data[29])
	display := sdk.UrlDecode(data[30])
	board := sdk.UrlDecode(data[31])
	brand := sdk.UrlDecode(data[32])
	dev := sdk.UrlDecode(data[33])
	fp := data[34]
	host := data[35]
	id := data[36]
	return Device{
		Screen: struct {
			HeightPixels int "bson:\"heightPixels\" json:\"heightPixels\""
			WidthPixels  int "bson:\"widthPixels\" json:\"widthPixels\""
		}{
			HeightPixels: height,
			WidthPixels:  width,
		},
		PerfBench: []string{"17,1015,59,692,60000,608,31200,311,901"},
		Build: struct {
			Manufacturer string "bson:\"MANUFACTURER\" json:\"MANUFACTURER\""
			Hardware     string "bson:\"HARDWARE\" json:\"HARDWARE\""
			Model        string "bson:\"MODEL\" json:\"MODEL\""
			Bootloader   string "bson:\"BOOTLOADER\" json:\"BOOTLOADER\""
			Version      struct {
				Release     string "bson:\"RELEASE\" json:\"RELEASE\""
				Codename    string "bson:\"CODENAME\" json:\"CODENAME\""
				Incremental string "bson:\"INCREMENTAL\" json:\"INCREMENTAL\""
				SdkInt      int    "bson:\"SDK_INT\" json:\"SDK_INT\""
			} "bson:\"VERSION\" json:\"VERSION\""
			Product     string "bson:\"PRODUCT\" json:\"PRODUCT\""
			Tags        string "bson:\"TAGS\" json:\"TAGS\""
			Type        string "bson:\"TYPE\" json:\"TYPE\""
			User        string "bson:\"USER\" json:\"USER\""
			Display     string "bson:\"DISPLAY\" json:\"DISPLAY\""
			Board       string "bson:\"BOARD\" json:\"BOARD\""
			Brand       string "bson:\"BRAND\" json:\"BRAND\""
			Device      string "bson:\"DEVICE\" json:\"DEVICE\""
			Fingerprint string "bson:\"FINGERPRINT\" json:\"FINGERPRINT\""
			Host        string "bson:\"HOST\" json:\"HOST\""
			ID          string "bson:\"ID\" json:\"ID\""
		}{
			Manufacturer: manufacturer,
			Hardware:     hardware,
			Model:        model,
			Bootloader:   bootloader,
			Version: struct {
				Release     string "bson:\"RELEASE\" json:\"RELEASE\""
				Codename    string "bson:\"CODENAME\" json:\"CODENAME\""
				Incremental string "bson:\"INCREMENTAL\" json:\"INCREMENTAL\""
				SdkInt      int    "bson:\"SDK_INT\" json:\"SDK_INT\""
			}{
				Release:     verRelease,
				Codename:    codename,
				Incremental: incremental,
				SdkInt:      sdkint,
			},
			Product:     product,
			Tags:        tags,
			Type:        androidType,
			User:        user,
			Display:     display,
			Board:       board,
			Brand:       brand,
			Device:      dev,
			Fingerprint: fp,
			Host:        host,
			ID:          id,
		},
	}

}
