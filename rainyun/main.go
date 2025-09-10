package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type ActionInfo struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Params      map[string]any `json:"params,omitempty"`
}

type Request struct {
	Action string                 `json:"action"`
	Params map[string]interface{} `json:"params"`
}

type Response struct {
	Status  string                 `json:"status"`
	Message string                 `json:"message"`
	Result  map[string]interface{} `json:"result"`
}

var pluginMeta = map[string]interface{}{
	"name":        "rainyun",
	"description": "上传/替换证书到雨云",
	"version":     "1.0.1",
	"author":      "Young[16c.top]",
	"config": map[string]interface{}{
		"apiToken": "雨云 API Token",
		"baseURL":  "API 根地址，留空则为：https://api.v2.rainyun.com",
	},
	"actions": []ActionInfo{
		{
			Name:        "upload",
			Description: "上传或替换证书（按域名匹配）",
			Params: map[string]any{
				"domain": "ssl 域名",
			},
		},
	},
}

func outputJSON(resp *Response) {
	_ = json.NewEncoder(os.Stdout).Encode(resp)
}

func outputError(msg string, err error) {
	outputJSON(&Response{
		Status:  "error",
		Message: fmt.Sprintf("%s: %v", msg, err),
	})
}

func main() {
	var req Request
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		outputError("读取输入失败", err)
		return
	}

	if err := json.Unmarshal(input, &req); err != nil {
		outputError("解析请求失败", err)
		return
	}

	// 记录入口日志：动作与参数（值做长度和脱敏展示）
	if req.Params == nil {
		req.Params = map[string]any{}
	}
	// 构造精简参数日志
	masked := map[string]any{}
	for k, v := range req.Params {
		switch vv := v.(type) {
		case string:
			if k == "apiToken" {
				masked[k] = maskToken(vv)
				break
			}
			if len(vv) > 64 {
				masked[k] = fmt.Sprintf("len=%d", len(vv))
			} else {
				masked[k] = vv
			}
		default:
			masked[k] = v
		}
	}
	debugLog("入口 | action=%s | params=%v", req.Action, masked)

	switch req.Action {
	case "get_metadata":
		outputJSON(&Response{Status: "success", Message: "插件信息", Result: pluginMeta})
	case "list_actions":
		outputJSON(&Response{Status: "success", Message: "支持的动作", Result: map[string]interface{}{"actions": pluginMeta["actions"]}})
	case "upload":
		rep, err := Upload(req.Params)
		if err != nil {
			outputError("雨云证书上传/替换失败", err)
			return
		}
		outputJSON(rep)
	default:
		outputJSON(&Response{Status: "error", Message: "未知 action: " + req.Action})
	}
}
