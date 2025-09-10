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
	"name":        "kuocai",
	"description": "部署到括彩云",
	"version":     "1.0.0",
	"author":      "coclyun",
	"config": map[string]interface{}{
		"username": "括彩云账号",
		"password": "括彩云密码",
	},
	"actions": []ActionInfo{
		{
			Name:        "upload",
			Description: "部署到括彩云",
			Params:      map[string]any{},
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

	switch req.Action {
	case "get_metadata":
		outputJSON(&Response{
			Status:  "success",
			Message: "插件信息",
			Result:  pluginMeta,
		})
	case "list_actions":
		outputJSON(&Response{
			Status:  "success",
			Message: "支持的动作",
			Result:  map[string]interface{}{"actions": pluginMeta["actions"]},
		})
	case "upload":
		rep, err := Upload(req.Params)
		if err != nil {
			outputError("CDN 部署失败", err)
			return
		}
		outputJSON(rep)

	default:
		outputJSON(&Response{
			Status:  "error",
			Message: "未知 action: " + req.Action,
		})
	}
}