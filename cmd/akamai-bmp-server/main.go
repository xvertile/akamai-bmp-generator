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

	// ─── BMP generators ────────────────────────────────────────────────
	bmp212 "xvertile/akamai-bmp/bm/2.1.2"
	bmp222 "xvertile/akamai-bmp/bm/2.2.2"
	bmp223 "xvertile/akamai-bmp/bm/2.2.3"
	bmp310 "xvertile/akamai-bmp/bm/3.1.0"
	bmp323 "xvertile/akamai-bmp/bm/3.2.3"
	bmp330 "xvertile/akamai-bmp/bm/3.3.0"
	bmp331 "xvertile/akamai-bmp/bm/3.3.1"
	bmp334 "xvertile/akamai-bmp/bm/3.3.4"
	bmp339 "xvertile/akamai-bmp/bm/3.3.9"
	bmp402 "xvertile/akamai-bmp/bm/4.0.2"
	dm "xvertile/akamai-bmp/dm"
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
	UserAgent      string `json:"userAgent,omitempty"`
}

type AkamaiBmpGen interface {
	GetAndroidId() string
	GenerateSensorData() (string, error)
	GetDevice() dm.Device
}

var (
	deviceManager dm.DeviceManager

	akamaiBmpVersions = map[string]interface{}{
		"4.0.2": bmp402.NewStable,
		"3.3.9": bmp339.NewStable,
		"3.3.4": bmp334.NewStable,
		"3.3.1": bmp331.NewStable,
		"3.3.0": bmp330.NewStable,
		"3.2.3": bmp323.NewStable,
		"3.1.0": bmp310.NewStable,
		"2.2.3": bmp223.NewStable,
		"2.2.2": bmp222.NewStable,
		"2.1.2": bmp212.NewStable,
	}
)

// ---------------------------------------------------------------------
// Reflection helper to call the correct generator constructor
// ---------------------------------------------------------------------
func call(fn string, params ...interface{}) (interface{}, error) {
	f := reflect.ValueOf(akamaiBmpVersions[fn])
	if len(params) != f.Type().NumIn() {
		return nil, errors.New("parameter count mismatch")
	}
	in := make([]reflect.Value, len(params))
	for i, p := range params {
		in[i] = reflect.ValueOf(p)
	}
	return f.Call(in)[0].Interface(), nil
}

// ---------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------
func handleBmpRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req AkamaiRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Challenge && req.ChallengeUrl == "" {
		http.Error(w, "challenge=true but powUrl empty", http.StatusBadRequest)
		return
	}

	newGen, ok := akamaiBmpVersions[req.Version]
	if !ok {
		http.Error(w, "unsupported BMP version", http.StatusBadRequest)
		return
	}

	genIface, err := call(req.Version, req.App, req.Lang, req.Challenge, req.ChallengeUrl, deviceManager)
	if err != nil {
		http.Error(w, "generator error: "+err.Error(), http.StatusBadRequest)
		return
	}
	gen := genIface.(AkamaiBmpGen)

	sensor, err := gen.GenerateSensorData()
	if err != nil {
		http.Error(w, "sensor error: "+err.Error(), http.StatusBadRequest)
		return
	}

	dev := gen.GetDevice()
	resp := AkamaiResponse{
		SensorData:     sensor,
		AndroidVersion: dev.Build.Version.Release,
		Model:          dev.Build.Model,
		Brand:          dev.Build.Brand,
		ScreenSize:     fmt.Sprintf("%dx%d", dev.Screen.WidthPixels, dev.Screen.HeightPixels),
	}

	// optional Adidas UA helper
	if req.App == "com.adidas.confirmed.app" {
		resp.UserAgent = generateAdidasUA(gen.GetAndroidId(), dev)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func generateAdidasUA(androidID string, dev dm.Device) string {
	hash := sha256.Sum256([]byte(androidID))
	return fmt.Sprintf("app/com.adidas.confirmed.app; os/Android; os-version/%s; "+
		"app-version/4.23.0; buildnumber/42300291; type/%s/%s/1.0/%dx%d; fingerprint/%s",
		dev.Build.Version.Release, dev.Build.Device, dev.Build.Model,
		dev.Screen.WidthPixels, dev.Screen.HeightPixels, hex.EncodeToString(hash[:]))
}

// ---------------------------------------------------------------------
// main
// ---------------------------------------------------------------------
func main() {
	var (
		host, devicePath string
		port             int
	)
	flag.StringVar(&host, "host", "localhost", "bind host")
	flag.IntVar(&port, "port", 1337, "bind port")
	flag.StringVar(&devicePath, "devicepath", "db/devices.json", "device DB path")
	flag.Parse()

	deviceManager = dm.New(devicePath)

	addr := fmt.Sprintf("%s:%d", host, port)
	http.HandleFunc("/akamai/bmp", handleBmpRequest)
	log.Printf("[+] BMP server on %s (devices: %s)", addr, devicePath)
	log.Fatal(http.ListenAndServe(addr, nil))
} 