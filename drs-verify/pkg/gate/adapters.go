package gate

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
)

// rpcErrorCode is DRS's JSON-RPC error code, inside the implementation-defined
// server-error range (-32000 to -32019) reserved by MCP 2026-07-28.
const rpcErrorCode = -32010

// HTTP is the plain-JSON adapter: every request is gated, the bundle travels
// in the X-DRS-Bundle header, and the request body must equal the signed args.
type HTTP struct{}

func (HTTP) Name() string { return "http" }

func (HTTP) Extract(in Inbound) (Call, bool, error) {
	bundle, err := headerBundle(in.Header)
	if err != nil {
		return Call{}, true, err
	}
	return Call{Bundle: bundle, Args: in.Body}, true, nil
}

func (HTTP) Reject(_ json.RawMessage, d *Denial) (int, []byte) {
	body, _ := json.Marshal(map[string]string{"error": d.Code, "detail": d.Detail, "suggestion": d.Suggestion})
	return d.Status, body
}

// MCP gates `tools/call` on the Model Context Protocol (2025-11-25 and
// 2026-07-28, Streamable HTTP or stdio). Everything else — initialize,
// server/discover, list calls, notifications, stream GETs — passes through.
// The signed args are params.arguments plus {"tool": params.name}, under
// cmd /mcp/tools/call.
type MCP struct{}

func (MCP) Name() string { return "mcp" }

func (MCP) Extract(in Inbound) (Call, bool, error) {
	if pass, err := screenMethod(in.Method); pass || err != nil {
		return Call{}, false, err
	}
	msg, err := parseRPC(in.Body)
	if err != nil {
		return Call{}, false, err
	}
	if h := in.Header.Get("Mcp-Method"); h != "" && h != msg.Method {
		return Call{ID: msg.ID}, false, deny(http.StatusBadRequest, "HEADER_MISMATCH",
			"Mcp-Method header does not match the JSON-RPC method", "")
	}
	if msg.Method != "tools/call" {
		return Call{}, false, nil
	}
	var params struct {
		Name      string                     `json:"name"`
		Arguments map[string]json.RawMessage `json:"arguments"`
		Meta      map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil || params.Name == "" {
		return Call{ID: msg.ID}, true, deny(http.StatusBadRequest, "INVALID_TOOL_CALL",
			"tools/call needs params.name and object params.arguments", "")
	}
	if h := in.Header.Get("Mcp-Name"); h != "" && h != params.Name {
		return Call{ID: msg.ID}, true, deny(http.StatusBadRequest, "HEADER_MISMATCH",
			"Mcp-Name header does not match params.name", "")
	}
	args, err := withTool(params.Arguments, params.Name)
	if err != nil {
		return Call{ID: msg.ID}, true, err
	}
	bundle, err := pickBundle(in.Header, params.Meta)
	if err != nil {
		return Call{ID: msg.ID}, true, err
	}
	return Call{Bundle: bundle, Cmd: "/mcp/tools/call", Args: args, ID: msg.ID}, true, nil
}

func (MCP) Reject(id json.RawMessage, d *Denial) (int, []byte) { return rpcReject(id, d) }

// A2A gates every JSON-RPC method of the Agent2Agent protocol (v1.0 and
// v0.3). The bundle travels in the X-DRS-Bundle header (A2A JSON-RPC always
// runs over HTTP). The signed args are params plus {"tool": method}, under
// cmd /a2a/<method>.
type A2A struct{}

func (A2A) Name() string { return "a2a" }

func (A2A) Extract(in Inbound) (Call, bool, error) {
	if pass, err := screenMethod(in.Method); pass || err != nil {
		return Call{}, false, err
	}
	msg, err := parseRPC(in.Body)
	if err != nil {
		return Call{}, true, err
	}
	params := map[string]json.RawMessage{}
	if len(msg.Params) > 0 {
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			return Call{ID: msg.ID}, true, deny(http.StatusBadRequest, "INVALID_PARAMS", "params must be an object", "")
		}
	}
	args, err := withTool(params, msg.Method)
	if err != nil {
		return Call{ID: msg.ID}, true, err
	}
	bundle, err := headerBundle(in.Header)
	if err != nil {
		return Call{ID: msg.ID}, true, err
	}
	return Call{Bundle: bundle, Cmd: "/a2a/" + msg.Method, Args: args, ID: msg.ID}, true, nil
}

func (A2A) Reject(id json.RawMessage, d *Denial) (int, []byte) { return rpcReject(id, d) }

// AdapterFor returns the adapter for a protocol name.
func AdapterFor(protocol string) (Adapter, bool) {
	switch protocol {
	case "http":
		return HTTP{}, true
	case "mcp":
		return MCP{}, true
	case "a2a":
		return A2A{}, true
	}
	return nil, false
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// screenMethod lets body-less protocol traffic (stream GETs, session DELETE,
// HEAD, CORS OPTIONS) through ungated, gates POST, and refuses every other
// method so an unsigned call cannot slip in as PUT or PATCH.
func screenMethod(method string) (pass bool, err error) {
	switch method {
	case "", http.MethodPost:
		return false, nil
	case http.MethodGet, http.MethodDelete, http.MethodHead, http.MethodOptions:
		return true, nil
	}
	return false, deny(http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
		"JSON-RPC endpoints accept POST", "Send JSON-RPC requests with POST.")
}

func parseRPC(body []byte) (rpcMessage, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return rpcMessage{}, deny(http.StatusBadRequest, "BATCH_NOT_SUPPORTED",
			"JSON-RPC batches cannot be gated", "Send one request per HTTP call.")
	}
	var msg rpcMessage
	if err := json.Unmarshal(trimmed, &msg); err != nil || msg.JSONRPC != "2.0" {
		return rpcMessage{}, deny(http.StatusBadRequest, "INVALID_JSONRPC", "body is not a JSON-RPC 2.0 message", "")
	}
	return msg, nil
}

// withTool returns args as a JSON object with "tool" set to name. A caller
// argument already named "tool" is refused: overwriting it would execute a
// value the agent never signed.
func withTool(args map[string]json.RawMessage, name string) ([]byte, error) {
	if _, clash := args["tool"]; clash {
		return nil, deny(http.StatusBadRequest, "RESERVED_ARGUMENT",
			`an argument named "tool" is reserved by DRS`, "Rename the argument.")
	}
	merged := make(map[string]json.RawMessage, len(args)+1)
	for k, v := range args {
		merged[k] = v
	}
	quoted, _ := json.Marshal(name)
	merged["tool"] = quoted
	return json.Marshal(merged)
}

func headerBundle(h http.Header) (string, error) {
	values := h.Values(BundleHeader)
	if len(values) > 1 {
		return "", deny(http.StatusBadRequest, "MULTIPLE_BUNDLES", "multiple X-DRS-Bundle headers", "")
	}
	if len(values) == 0 {
		return "", nil
	}
	return strings.TrimSpace(values[0]), nil
}

// pickBundle reads the header and metadata carriers. Supplying both with
// different values is ambiguous and refused.
func pickBundle(h http.Header, meta map[string]json.RawMessage) (string, error) {
	fromHeader, err := headerBundle(h)
	if err != nil {
		return "", err
	}
	var fromMeta string
	if raw, ok := meta[BundleMetaKey]; ok {
		if err := json.Unmarshal(raw, &fromMeta); err != nil {
			return "", deny(http.StatusBadRequest, "MALFORMED_BUNDLE", BundleMetaKey+" must be a string", "")
		}
	}
	if fromHeader != "" && fromMeta != "" && fromHeader != fromMeta {
		return "", deny(http.StatusBadRequest, "MULTIPLE_BUNDLES", "header and metadata carry different bundles", "")
	}
	if fromHeader != "" {
		return fromHeader, nil
	}
	return fromMeta, nil
}

// rpcReject renders a JSON-RPC error. A missing bundle is answered with 403,
// never 401: MCP clients treat 401 as an OAuth challenge.
func rpcReject(id json.RawMessage, d *Denial) (int, []byte) {
	status := d.Status
	if status == http.StatusUnauthorized {
		status = http.StatusForbidden
	}
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    rpcErrorCode,
			"message": "DRS: " + d.Code,
			"data":    map[string]string{"code": d.Code, "detail": d.Detail, "suggestion": d.Suggestion},
		},
	})
	return status, body
}
