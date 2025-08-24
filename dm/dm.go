package dm

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
)

type DeviceManager struct {
	devices []Device
}

func New(path string) DeviceManager {
	dm := DeviceManager{}
	dm.Init(path)
	return dm
}

func (dm *DeviceManager) GetRandomDevice() Device {
	if len(dm.devices) == 1 {
		return dm.devices[0]
	}
	return dm.devices[rand.Intn(len(dm.devices))]
}

func (dm *DeviceManager) GetDevices() []Device {
	return dm.devices
}

func (dm *DeviceManager) Init(path string) {
	dm.devices = GetAllDevices(path)
	fmt.Printf("Successfully loaded %v devices\n", len(dm.devices))
}

func GetAllDevices(path string) []Device {
	devices, err := LoadDevicesFromFile(path)
	if err != nil {
		panic(err)
	}
	return devices
}

func LoadDevicesFromFile(filePath string) ([]Device, error) {
	// Read the JSON file into a byte slice
	jsonData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Unmarshal the JSON data into an array of Person structs
	var people []Device
	err = json.Unmarshal(jsonData, &people)
	if err != nil {
		return nil, err
	}

	return people, nil
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func (dm *DeviceManager) RandomAndroidDevice() Device {
	return dm.GetRandomDevice()
}
