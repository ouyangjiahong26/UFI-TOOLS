package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) // 默认就是小写
}

// 生成 kano-sign，标准 HMAC-SHA256
func makeKanoSign(methodUpper, urlPath, tsMillis string, key []byte) string {
	rawData := "minikano" + methodUpper + urlPath + tsMillis
	h := hmac.New(sha256.New, key)
	h.Write([]byte(rawData))
	return hex.EncodeToString(h.Sum(nil))
}

func normalizeMethod(m string) string {
	m = strings.TrimSpace(m)
	if m == "" {
		return "GET"
	}
	return strings.ToUpper(m)
}

// endpoint 可以是：
// - "/api/user?id=1"
// - "http://192.168.1.1/api/user?id=1"
// host 如 "192.168.1.1" 或 "192.168.1.1:8080"
func buildURL(host, endpoint string) (*url.URL, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("endpoint 不能为空")
	}

	// 如果 endpoint 已经是完整 URL
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return url.Parse(endpoint)
	}

	// 否则拼接成 http://host + endpoint
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	full := "http://" + host + endpoint
	return url.Parse(full)
}

// 从设备私有存储读取按设备生成的签名密钥
func GetSignKey() (string, error) {
	return readPrefValue("sign_key")
}

func readPrefValue(name string) (string, error) {
	path := "/data/data/com.minikano.f50_sms/shared_prefs/kano_ZTE_store.xml"

	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	var prefs SharedPrefs

	err = xml.Unmarshal(data, &prefs)
	if err != nil {
		return "", err
	}

	for _, item := range prefs.Items {
		if item.Name == name {
			return item.Value, nil
		}
	}

	return "", nil
}

func printJSONError(msg string, err error) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{
		"error": fmt.Sprintf("%s: %v", msg, err),
	})
}

type SharedPrefs struct {
	XMLName xml.Name `xml:"map"`
	Items   []Item   `xml:"string"`
}

type Item struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

// 远程使用时从目标服务器获取该设备的签名密钥
func getSignKeyFromServer(hostPort string) (string, error) {
	resp, err := http.Get("http://" + hostPort + "/api/get_sign_key")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var out struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Key == "" {
		return "", fmt.Errorf("服务器未返回签名密钥")
	}
	return out.Key, nil
}

func main() {
	var (
		host     string
		password string
		method   string
		endpoint string
		data     string
		timeout  int
	)

	//获取本机签名密钥
	signKey, _ := GetSignKey()

	flag.StringVar(&host, "host", "192.168.0.1:2333", `目标地址，比如 "192.168.0.1" 或 "192.168.0.1:2333" (选填)`)
	// 设备存储的口令已是加盐多轮哈希，无法还原为 authorization 值，必须提供明文
	flag.StringVar(&password, "pass", "", "密码明文，用于生成 Authorization=sha256(password) (必填)")
	flag.StringVar(&method, "X", "GET", "HTTP 方法：GET/POST/PUT/DELETE...")
	flag.StringVar(&endpoint, "e", "", `请求路径或完整URL，如 "/api/xxx" (必填)`)
	flag.StringVar(&data, "d", "", `请求体(JSON字符串)。GET 一般不需要。例：'{"command":"ls"}'`)
	flag.IntVar(&timeout, "t", 10, "超时秒数 (默认 15)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `ufi_req - MiniKano签名请求工具

用法：
  ufi_req -host 192.168.1.1 -pass 123456 -X POST -e /api/xxx -d '{"command":"ls"}'
  ufi_req -host 192.168.1.1 -pass 123456 -X GET  -e "/api/AT?command=AT&slot=0"

参数：
`)
		flag.PrintDefaults()
	}
	flag.Parse()

	if host == "" || password == "" || endpoint == "" {
		flag.Usage()
		os.Exit(2)
	}

	u, err := buildURL(host, endpoint)
	if err != nil {
		printJSONError("URL 解析失败", err)
		os.Exit(1)
	}

	// 签名密钥按设备随机生成：本机读不到时向目标服务器获取
	if signKey == "" {
		signKey, err = getSignKeyFromServer(u.Host)
		if err != nil {
			printJSONError("获取签名密钥失败", err)
			os.Exit(1)
		}
	}

	m := normalizeMethod(method)

	// 签名只用 path，不包含 query
	urlPath := u.Path
	if urlPath == "" {
		urlPath = "/"
	}

	auth := sha256Hex([]byte(password))

	ts := fmt.Sprintf("%d", time.Now().UnixMilli())
	sign := makeKanoSign(m, urlPath, ts, []byte(signKey))

	var body io.Reader
	if data != "" {
		body = bytes.NewBufferString(data)
	}

	req, err := http.NewRequest(m, u.String(), body)
	if err != nil {
		printJSONError("创建请求失败", err)
		os.Exit(1)
	}

	// 必要请求头
	req.Header.Set("kano-t", ts)
	req.Header.Set("kano-sign", sign)
	req.Header.Set("Authorization", auth)

	// JSON 约定：只要有 body 就默认 JSON（你也可以改成只对 POST）
	if data != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		printJSONError("响应失败", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// 输出：状态码 + body
	if resp.StatusCode != 200 {
		fmt.Printf("{\"error\":\"HTTP %d %s\"}", resp.StatusCode, http.StatusText(resp.StatusCode))
	} else {
		fmt.Print(string(respBody))
	}
}
