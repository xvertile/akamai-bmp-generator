package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strconv"

	bmp212 "xvertile/akamai-bmp/bm/2.1.2"
	bmp222 "xvertile/akamai-bmp/bm/2.2.2"
	bmp223 "xvertile/akamai-bmp/bm/2.2.3"
	bmp310 "xvertile/akamai-bmp/bm/3.1.0"
	bmp323 "xvertile/akamai-bmp/bm/3.2.3"
	bmp330 "xvertile/akamai-bmp/bm/3.3.0"
	bmp331 "xvertile/akamai-bmp/bm/3.3.1"
	bmp334 "xvertile/akamai-bmp/bm/3.3.4"
	"xvertile/akamai-bmp/dm"
	devicemanager "xvertile/akamai-bmp/dm"
)

type AkamaiRequest struct {
	App          string `json:"app"`
	Lang         string `json:"lang"`
	Version      string `json:"version"`
	Challenge    bool   `json:"challenge"`
	ChallengeUrl string `json:"powUrl"`
}

type AkamaiResponse struct {
	SensorData     string `json:"sensor"`
	AndroidVersion string `json:"androidVersion"`
	Model          string `json:"model"`
	Brand          string `json:"brand"`
	ScreenSize     string `json:"screenSize"`
}

type AkamaiBmpGen interface {
	GetAndroidId() string
	GenerateSensorData() (string, error)
	GetDevice() devicemanager.Device
}

var deviceManager devicemanager.DeviceManager

var akamaiBmpVersions = map[string]interface{}{
	"3.3.4": bmp334.NewStable,
	"3.3.1": bmp331.NewStable,
	"3.3.0": bmp330.NewStable,
	"3.2.3": bmp323.NewStable,
	"3.1.0": bmp310.NewStable,
	"2.2.3": bmp223.NewStable,
	"2.2.2": bmp222.NewStable,
	"2.1.2": bmp212.NewStable,
}

func Call(funcName string, params ...interface{}) (result interface{}, err error) {
	f := reflect.ValueOf(akamaiBmpVersions[funcName])
	if len(params) != f.Type().NumIn() {
		fmt.Println(len(params), f.Type().NumIn())
		err = errors.New("The number of params is out of index.")
		return
	}
	in := make([]reflect.Value, len(params))
	for k, param := range params {
		in[k] = reflect.ValueOf(param)
	}
	var res []reflect.Value
	res = f.Call(in)
	result = res[0].Interface()
	return
}

func handleBmpRequest(w http.ResponseWriter, r *http.Request) {
	// Check if the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request body into an ExampleRequest struct
	var req AkamaiRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Error parsing request body", http.StatusBadRequest)
		return
	}

	if req.Challenge && len(req.ChallengeUrl) == 0 {
		http.Error(w, "Challenge set to true but no challenge url provided", http.StatusBadRequest)
		return
	}

	if _, ok := akamaiBmpVersions[req.Version]; !ok {
		http.Error(w, "Bmp version not found", http.StatusBadRequest)
		return
	} else {
		result, err := Call(req.Version, req.App, req.Lang, req.Challenge, req.ChallengeUrl, deviceManager)
		if err != nil {
			http.Error(w, "Error generating sensor data "+err.Error(), http.StatusBadRequest)
			return
		}
		//.(AkamaiBmpGen)
		gen := result.(AkamaiBmpGen)
		sensor, err := gen.GenerateSensorData()
		if err != nil {
			http.Error(w, "Error generating sensor data "+err.Error(), http.StatusBadRequest)
			return
		}

		// Create a new ExampleResponse struct
		resp := AkamaiResponse{
			Brand:          gen.GetDevice().Build.Brand,
			SensorData:     sensor,
			AndroidVersion: gen.GetDevice().Build.Version.Release,
			Model:          gen.GetDevice().Build.Model,
			ScreenSize:     strconv.Itoa(gen.GetDevice().Screen.WidthPixels) + "x" + strconv.Itoa(gen.GetDevice().Screen.HeightPixels),
		}

		// Marshal the ExampleResponse struct to JSON
		respJSON, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "Error encoding response", http.StatusInternalServerError)
			return
		}
		if req.App == "com.adidas.confirmed.app" {
			respJSON = respJSON[:len(respJSON)-1]
			respJSON = append(respJSON, []byte(`,"userAgent":"`+generateAdidasDevice(result.(AkamaiBmpGen).GetAndroidId(), result.(AkamaiBmpGen).GetDevice())+`"}`)...)
		}

		// Set the response content type to application/json
		w.Header().Set("Content-Type", "application/json")

		// Write the response JSON to the response writer
		w.Write(respJSON)
		return
	}

}

func generateAdidasDevice(androidId string, device dm.Device) string {
	hash := sha256.Sum256([]byte(androidId))
	hashHex := hex.EncodeToString(hash[:])

	return fmt.Sprintf("app/com.adidas.confirmed.app; os/Android; os-version/%v; app-version/4.23.0; buildnumber/42300291; type/%v/%v/%v/%vx%v; fingerprint/%v", device.Build.Version.SdkInt, device.Build.Device, device.Build.Model, "1.0", device.Screen.WidthPixels, device.Screen.HeightPixels, hashHex)
}

func main() {
	var (
		host       string
		port       int
		devicePath string
	)
	flag.StringVar(&host, "host", "localhost", "Specify the host on which the server will run")
	flag.IntVar(&port, "port", 1337, "Specify the port on which the server will run")
	flag.StringVar(&devicePath, "devicepath", "db/devices.json", "Specify the path to the device configuration file")
	help := flag.Bool("h", false, "Display help")
	flag.Parse()

	if *help {
		fmt.Println("Usage of Akamai BMP server:")
		flag.PrintDefaults()
		return
	}
	deviceManager = devicemanager.New(devicePath)
	httpAddr := fmt.Sprintf("%s:%d", host, port)
	http.HandleFunc("/akamai/bmp", handleBmpRequest)
	log.Printf("Starting server on %s with device config from %s\n", httpAddr, devicePath)
	log.Fatal(http.ListenAndServe(httpAddr, nil))
}
