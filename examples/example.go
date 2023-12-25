package main

import (
	"encoding/json"
	"fmt"
	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"io"
	"log"
	"strings"
)

type ResponseData struct {
	Sensor         string `json:"sensor"`
	AndroidVersion string `json:"androidVersion"`
	Model          string `json:"model"`
	Brand          string `json:"brand"`
	ScreenSize     string `json:"screenSize"`
}

func getbmp(client tls_client.HttpClient) ResponseData {
	req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:1337/akamai/bmp", strings.NewReader("{\"app\": \"com.ihg.apps.android\",\"lang\": \"en\",\"version\": \"3.3.4\"}"))
	if err != nil {
		log.Println(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
	}
	defer resp.Body.Close()
	if err != nil {
		fmt.Errorf("error executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Errorf("error reading response body: %w", err)
	}

	var responseData ResponseData
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		fmt.Errorf("error unmarshalling response JSON: %w", err)
	}
	return responseData
}

func main() {
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeout(60),
	}
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		log.Println(err)
		return
	}
	sensorData := getbmp(client)
	fmt.Println(sensorData)
}
