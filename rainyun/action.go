package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 雨云 SSL 证书管理的最小化 API 客户端

type rainyunClient struct {
	baseURL  string
	apiToken string
}

func newClientWithBase(baseURL, token string) *rainyunClient {
	// 若未配置，使用雨云 v2 默认地址
	base := strings.TrimSpace(baseURL)
	if base == "" {
		base = "https://api.v2.rainyun.com"
	}
	// 允许末尾斜杠，统一去掉
	base = strings.TrimRight(base, "/")
	return &rainyunClient{baseURL: base, apiToken: token}
}

func (c *rainyunClient) doJSON(method, path string, body any, v any) error {
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		buf = bytes.NewBuffer(b)
	}
	req, err := http.NewRequest(method, c.baseURL+path, buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.apiToken) != "" {
		req.Header.Set("x-api-key", c.apiToken)
		debugLog("请求头 x-api-key 已设置: %s", maskToken(c.apiToken))
	}
	debugLog("请求 -> %s %s | base=%s", method, path, c.baseURL)
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		debugLog("请求错误 <- %s %s | err=%v", method, path, err)
		return err
	}
	defer resp.Body.Close()
	// 先记录状态码，再读取 body，方便排查大包或超时
	debugLog("响应(头) <- %s %s | 状态: %s", method, path, resp.Status)
	bodyBytes, _ := io.ReadAll(resp.Body)
	debugLog("响应(体) <- %s %s | 体积: %dB", method, path, len(bodyBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// 记录失败时的响应内容
		debugLog("错误响应内容: %s", truncate(string(bodyBytes), 2048))
		return fmt.Errorf("rainyun api %s %s failed: %s - %s", method, path, resp.Status, truncate(string(bodyBytes), 512))
	}
	if v != nil {
		if err := json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(v); err != nil {
			return err
		}
	}
	return nil
}

// doRaw：发送请求并返回原始响应体与状态码
func (c *rainyunClient) doRaw(method, path string, body any) ([]byte, int, error) {
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		buf = bytes.NewBuffer(b)
	}
	req, err := http.NewRequest(method, c.baseURL+path, buf)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.apiToken) != "" {
		req.Header.Set("x-api-key", c.apiToken)
	}
	debugLog("请求 -> %s %s | base=%s", method, path, c.baseURL)
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		debugLog("请求错误 <- %s %s | err=%v", method, path, err)
		return nil, 0, err
	}
	defer resp.Body.Close()
	debugLog("响应(头) <- %s %s | 状态: %s", method, path, resp.Status)
	bodyBytes, _ := io.ReadAll(resp.Body)
	debugLog("响应(体) <- %s %s | 体积: %dB", method, path, len(bodyBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		debugLog("错误响应内容: %s", truncate(string(bodyBytes), 2048))
		return bodyBytes, resp.StatusCode, fmt.Errorf("rainyun api %s %s failed: %s - %s", method, path, resp.Status, truncate(string(bodyBytes), 512))
	}
	return bodyBytes, resp.StatusCode, nil
}

// 证书对象（字段结构根据接口文档可能需要微调）
type sslCert struct {
	ID      string   `json:"id"`
	Domains []string `json:"domains"`
	Name    string   `json:"name"`
}

type listResp struct {
	Data []sslCert `json:"data"`
}

func (c *rainyunClient) listCertificates() ([]sslCert, error) {
	// 按 OpenAPI 要求，必须带上 options 查询参数，这里默认传 {}
	body, _, err := c.doRaw("GET", "/product/sslcenter/?options=%7B%7D", nil)
	if err != nil {
		return nil, err
	}

	// 优先尝试通用 envelope: { code, message, data }
	var env struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		// 回退：直接尝试解析为数组或带 list/items 的对象
		return parseCertListFallback(body)
	}
	if len(env.Data) == 0 {
		// 没有 data 字段，尝试回退解析
		return parseCertListFallback(body)
	}
	// data 可能是数组或对象
	if len(env.Data) > 0 && env.Data[0] == '[' {
		var arr []map[string]any
		if err := json.Unmarshal(env.Data, &arr); err != nil {
			return nil, err
		}
		return normalizeCerts(arr), nil
	}
	// 对象：可能包含 list/items/Records 等
	var obj map[string]any
	if err := json.Unmarshal(env.Data, &obj); err != nil {
		return nil, err
	}
	if arr, ok := obj["list"].([]any); ok {
		return normalizeCertsAny(arr), nil
	}
	if arr, ok := obj["items"].([]any); ok {
		return normalizeCertsAny(arr), nil
	}
	if arr, ok := obj["Records"].([]any); ok {
		return normalizeCertsAny(arr), nil
	}
	// 若对象本身就是单条，包成切片
	return normalizeCertsAny([]any{obj}), nil
}

// parseCertListFallback: 尝试更多形态解析
func parseCertListFallback(body []byte) ([]sslCert, error) {
	// 数组
	var arrDirect []map[string]any
	if err := json.Unmarshal(body, &arrDirect); err == nil {
		return normalizeCerts(arrDirect), nil
	}
	// 对象，可能 data/list/items/Records
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("无法解析证书列表: %v", err)
	}
	if d, ok := obj["data"].([]any); ok {
		return normalizeCertsAny(d), nil
	}
	if o, ok := obj["data"].(map[string]any); ok {
		if arr, ok := o["list"].([]any); ok {
			return normalizeCertsAny(arr), nil
		}
		if arr, ok := o["items"].([]any); ok {
			return normalizeCertsAny(arr), nil
		}
		if arr, ok := o["Records"].([]any); ok {
			return normalizeCertsAny(arr), nil
		}
		return normalizeCertsAny([]any{o}), nil
	}
	if arr, ok := obj["list"].([]any); ok {
		return normalizeCertsAny(arr), nil
	}
	if arr, ok := obj["items"].([]any); ok {
		return normalizeCertsAny(arr), nil
	}
	if arr, ok := obj["Records"].([]any); ok {
		return normalizeCertsAny(arr), nil
	}
	return normalizeCertsAny([]any{obj}), nil
}

func normalizeCerts(arr []map[string]any) []sslCert {
	out := make([]sslCert, 0, len(arr))
	for _, m := range arr {
		out = append(out, mapToCert(m))
	}
	return out
}

func normalizeCertsAny(arr []any) []sslCert {
	out := make([]sslCert, 0, len(arr))
	for _, it := range arr {
		if m, ok := it.(map[string]any); ok {
			out = append(out, mapToCert(m))
		}
	}
	return out
}

func mapToCert(m map[string]any) sslCert {
	c := sslCert{}
	// id 可能是字符串或数字
	if v, ok := m["id"]; ok {
		c.ID = fmt.Sprint(v)
	}
	if c.ID == "" {
		if v, ok := m["cert_id"]; ok {
			c.ID = fmt.Sprint(v)
		}
		if v, ok := m["ID"]; ok {
			c.ID = fmt.Sprint(v)
		}
	}
	if name, ok := m["name"].(string); ok {
		c.Name = name
	}
	if c.Name == "" {
		if name, ok := m["Name"].(string); ok {
			c.Name = name
		}
	}
	// domains 可能是数组或字符串
	if v, ok := m["domains"]; ok {
		switch vv := v.(type) {
		case []any:
			for _, d := range vv {
				c.Domains = append(c.Domains, fmt.Sprint(d))
			}
		case string:
			// 逗号分隔或单个
			for _, d := range strings.Split(vv, ",") {
				s := strings.TrimSpace(d)
				if s != "" {
					c.Domains = append(c.Domains, s)
				}
			}
		}
	}
	if v, ok := m["domain"].(string); ok && v != "" {
		c.Domains = append(c.Domains, v)
	}
	if v, ok := m["Domain"].(string); ok && v != "" {
		c.Domains = append(c.Domains, v)
	}
	// 兼容 BindDomains（数组/字符串/空）
	if v, ok := m["BindDomains"]; ok && v != nil {
		switch vv := v.(type) {
		case []any:
			for _, d := range vv {
				s := strings.TrimSpace(fmt.Sprint(d))
				if s != "" {
					c.Domains = append(c.Domains, s)
				}
			}
		case string:
			for _, d := range strings.Split(vv, ",") {
				s := strings.TrimSpace(d)
				if s != "" {
					c.Domains = append(c.Domains, s)
				}
			}
		}
	}
	return c
}

type uploadReq struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type uploadResp struct {
	ID string `json:"id"`
}

func (c *rainyunClient) uploadCertificate(cert, key, name string) (string, string, string, string, error) {
	// 使用原始请求以便根据真实响应结构提取 ID
	body, _, err := c.doRaw("POST", "/product/sslcenter/", uploadReq{Cert: cert, Key: key})
	if err != nil {
		return "", "", "", "", err
	}
	// 典型：{"code":200,"data":{"TotalRecords":1,"Records":[{"ID":27527,"Domain":"...","Issuer":"..."}]}}
	var env struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err == nil && len(env.Data) > 0 {
		// data 可能是对象，优先找 Records/records
		var dobj map[string]any
		if err := json.Unmarshal(env.Data, &dobj); err == nil {
			if arr, ok := dobj["Records"].([]any); ok && len(arr) > 0 {
				if m, ok := arr[0].(map[string]any); ok {
					id := firstStringField(m, "ID", "id", "cert_id", "CertID")
					domain := firstStringField(m, "Domain", "domain")
					issuer := firstStringField(m, "Issuer", "issuer")
					if id != "" {
						return id, domain, issuer, string(body), nil
					}
				}
			}
			if arr, ok := dobj["records"].([]any); ok && len(arr) > 0 { // 兼容小写
				if m, ok := arr[0].(map[string]any); ok {
					id := firstStringField(m, "ID", "id", "cert_id", "CertID")
					domain := firstStringField(m, "Domain", "domain")
					issuer := firstStringField(m, "Issuer", "issuer")
					if id != "" {
						return id, domain, issuer, string(body), nil
					}
				}
			}
			// 退化：data 直接就是一个对象
			id := firstStringField(dobj, "ID", "id")
			domain := firstStringField(dobj, "Domain", "domain")
			issuer := firstStringField(dobj, "Issuer", "issuer")
			if id != "" {
				return id, domain, issuer, string(body), nil
			}
		}
	}
	// 顶层直接尝试
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err == nil {
		id := firstStringField(obj, "ID", "id")
		domain := firstStringField(obj, "Domain", "domain")
		issuer := firstStringField(obj, "Issuer", "issuer")
		if id != "" {
			return id, domain, issuer, string(body), nil
		}
	}
	debugLog("上传成功但未解析到ID，原始响应(截断): %s", truncate(string(body), 10240))
	// 不触发错误，返回空 ID 由上层决定是否使用，同时返回原始 JSON
	return "", "", "", string(body), nil
}

// 辅助：从 map 提取第一个存在的字符串字段
func firstStringField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			s := strings.TrimSpace(fmt.Sprint(v))
			if s != "" {
				return s
			}
		}
	}
	return ""
}

func (c *rainyunClient) replaceCertificate(id, cert, key string) error {
	path := "/product/sslcenter/" + id
	payload := map[string]string{"cert": cert, "key": key}
	debugLog("请求 -> %s %s | base=%s | 使用JSON提交", "PUT", path, c.baseURL)
	var out map[string]any
	if err := c.doJSON("PUT", path, payload, &out); err != nil {
		return err
	}
	return nil
}

// Upload：按域名匹配证书，决定是新增还是替换
func Upload(cfg map[string]any) (*Response, error) {
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}
	token, _ := cfg["apiToken"].(string)
	domain, _ := cfg["domain"].(string)
	cert, _ := cfg["cert"].(string)
	key, _ := cfg["key"].(string)
	note, _ := cfg["note"].(string)
	debugLog("收到参数 | domain=%s, certLen=%d, keyLen=%d, noteLen=%d, token=%s", domain, len(cert), len(key), len(note), maskToken(token))
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("apiToken is required")
	}
	if strings.TrimSpace(domain) == "" {
		return nil, errors.New("domain is required")
	}
	if strings.TrimSpace(cert) == "" {
		return nil, errors.New("cert is required")
	}
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("key is required")
	}

	baseURL, _ := cfg["baseURL"].(string)
	client := newClientWithBase(baseURL, token)
	certs, err := client.listCertificates()
	if err != nil {
		return nil, err
	}
	debugLog("当前证书数量: %d", len(certs))
	for _, c := range certs {
		debugLog("证书 | id=%s name=%s domains=%v", c.ID, c.Name, c.Domains)
	}

	var matched *sslCert
	for i := range certs {
		for _, d := range certs[i].Domains {
			cond := strings.EqualFold(d, domain) || (strings.HasPrefix(d, "*.") && strings.HasSuffix(domain, strings.TrimPrefix(d, "*")))
			debugLog("匹配检查 | cert.id=%s name=%s | pattern=%s target=%s | matched=%t", certs[i].ID, certs[i].Name, d, domain, cond)
			if cond {
				matched = &certs[i]
				break
			}
		}
		if matched != nil {
			break
		}
	}

	result := map[string]interface{}{}
	if matched == nil {
		debugLog("未找到匹配域名，执行上传新证书")
		id, upDomain, upIssuer, raw, err := client.uploadCertificate(cert, key, note)
		if err != nil {
			return nil, err
		}
		result["action"] = "created"
		result["id"] = id
		if upDomain != "" {
			result["domain"] = upDomain
		}
		if upIssuer != "" {
			result["issuer"] = upIssuer
		}
		if id == "" && raw != "" {
			result["raw_json"] = raw
		}
	} else {
		debugLog("找到匹配证书，执行替换 | id=%s name=%s", matched.ID, matched.Name)
		if err := client.replaceCertificate(matched.ID, cert, key); err != nil {
			return nil, err
		}
		result["action"] = "replaced"
		result["id"] = matched.ID
		name := matched.Name
		if name == "" && len(matched.Domains) > 0 {
			name = matched.Domains[0]
		}
		result["name"] = name
	}

	return &Response{Status: "success", Message: "ok", Result: result}, nil
}

// ------- 调试日志工具 -------

// debugLog 将调试信息追加写入运行目录下的 rainyun-debug.log
func debugLog(format string, a ...any) {
	// 避免日志失败影响主流程
	defer func() { _ = recover() }()
	// 日志文件放到可执行文件同目录的上级 logs 目录：../logs/rainyun-debug.log
	exe, _ := os.Executable()
	dir := "."
	if exe != "" {
		dir = filepath.Dir(exe)
	}
	parent := filepath.Dir(dir)
	dataDir := filepath.Join(parent, "logs")
	_ = os.MkdirAll(dataDir, 0755)
	logPath := filepath.Join(dataDir, "rainyun-debug.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05.000")
	line := fmt.Sprintf("%s | "+format+"\n", append([]any{ts}, a...)...)
	// 写文件
	_, _ = f.WriteString(line)
	// 同步输出到标准错误，方便实时查看
	_, _ = fmt.Fprint(os.Stderr, line)
}

// maskToken 脱敏显示 Token，仅保留后 4 位
func maskToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 4 {
		return t
	}
	return strings.Repeat("*", len(t)-4) + t[len(t)-4:]
}

// truncate 截断字符串到指定长度
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
