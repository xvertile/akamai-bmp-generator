# Akamai BMP Generator
### Generate sensor data for Akamai's Bot Management Protocol (BMP) to bypass bot detection.
#### Original creator https://github.com/ui0x
![Akamai BMP Generator Image](https://i.imgur.com/FnC4D3O.png)

The Akamai BMP Generator is a fully reversed implementation of Akamai's BMP (Bot Management Protocol). This tool is designed for educational and research purposes, providing insights into various versions of Akamai BMP.

## Features

- ✅ Proof of Work (PoW) support
- ✅ Easy to use interface
- ✅ 2K unique device fingerprints included
- ✅ fast
- ✅ Made in goLang
- ✅ Support for multiple Akamai BMP versions:

    - **3.3.4**
    - **3.3.1**
    - **3.3.0**
    - **3.2.3**
    - **3.1.0**
    - **2.2.3**
    - **2.2.2**
    - **2.1.2**

## Usage
Command line arguments:
```
  --host string
        Hostname to listen on (default localhost)
  --port string
        Port to listen on (default 1337)
  --devicepath string
        Path to device fingerprints (default "devices.json")
```
1. ``git clone https://github.com/xvertile/akamai-bmp-generator.git``
2. ``cd akamai-bmp-generator/server``
3. ``go run main.go``

## Additional Information
By default the server will use devices.json as the device fingerprint file. This file contains 1000 unique device fingerprints. If you want to use your own device fingerprints, you can use the ``--devicepath`` argument to specify a different file.

## Screenshots
![Akamai BMP Generator Image](https://i.imgur.com/FnC4D3O.png)
## Example
Example of a request to the server check ```examples/example.go``` for the full example.
```go
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

```


