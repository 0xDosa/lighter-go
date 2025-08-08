//go:build js && wasm

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"syscall/js"
	"time"

	"github.com/elliottech/lighter-go/client"
	"github.com/elliottech/lighter-go/types"
	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
	schnorr "github.com/elliottech/poseidon_crypto/signature/schnorr"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// Global client instance (same as original)
var (
	txClient        *client.TxClient
	backupTxClients map[uint8]*client.TxClient
)

// validateArg checks if a JavaScript argument at the given index is valid (not null/undefined)
func validateArg(args []js.Value, index int, argName string) error {
	if index >= len(args) {
		return fmt.Errorf("missing required argument: %s (index %d)", argName, index)
	}
	if args[index].IsNull() {
		return fmt.Errorf("argument %s cannot be null", argName)
	}
	if args[index].IsUndefined() {
		return fmt.Errorf("argument %s cannot be undefined", argName)
	}
	return nil
}

// Response types matching original CGO patterns
type APIKeyResponse struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	Error      string `json:"error,omitempty"`
}

// For transaction functions and auth token (replaces C.StrOrErr)
type StringResponse struct {
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
}

// For simple success/error functions like CreateClient, CheckClient
type ErrorResponse struct {
	Error string `json:"error,omitempty"`
}

// Function #1: GenerateAPIKey (matches C.ApiKeyResponse)
func generateAPIKey(this js.Value, args []js.Value) any {
	var seed string

	// Get seed from JavaScript arguments (optional)
	if len(args) > 0 && !args[0].IsNull() && !args[0].IsUndefined() {
		seed = args[0].String()
	}

	// Convert empty string to nil pointer for the crypto function
	var seedP *string
	if seed != "" {
		seedP = &seed
	}

	response := APIKeyResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Generate the cryptographic key
	key := curve.SampleScalar(seedP)
	schnorrPk := schnorr.SchnorrPkFromSk(key)

	// Convert to hex strings
	response.PublicKey = hexutil.Encode(schnorrPk.ToLittleEndianBytes())
	response.PrivateKey = hexutil.Encode(key.ToLittleEndianBytes())

	// Convert to JSON and return
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		errorResponse := APIKeyResponse{
			Error: fmt.Sprintf("JSON marshal error: %v", err),
		}
		errorBytes, _ := json.Marshal(errorResponse)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #2: CreateClient (matches *C.char return - error only)
func createClient(this js.Value, args []js.Value) any {
	response := ErrorResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 5 {
		response.Error = "createClient requires 5 arguments: url, privateKey, chainId, apiKeyIndex, accountIndex"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "url"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 1, "privateKey"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 2, "chainId"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 3, "apiKeyIndex"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 4, "accountIndex"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	url := args[0].String()
	privateKey := args[1].String()
	chainId := uint32(args[2].Int())
	apiKeyIndex := uint8(args[3].Int())
	accountIndex := int64(args[4].Int())

	// Validate accountIndex
	if accountIndex <= 0 {
		response.Error = "invalid account index"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Create HTTP client
	httpClient := client.NewHTTPClient(url)

	// Create TxClient
	var err error
	txClient, err = client.NewTxClient(httpClient, privateKey, accountIndex, apiKeyIndex, chainId)
	if err != nil {
		response.Error = fmt.Sprintf("error occurred when creating TxClient. err: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if backupTxClients == nil {
		backupTxClients = make(map[uint8]*client.TxClient)
	}
	backupTxClients[apiKeyIndex] = txClient

	// Success case - return empty error response
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #3: CheckClient (matches *C.char return - error only)
func checkClient(this js.Value, args []js.Value) (result any) {
	// Use named return and defer for panic recovery
	defer func() {
		if r := recover(); r != nil {
			response := ErrorResponse{Error: fmt.Sprintf("PANIC in checkClient: %v", r)}
			jsonBytes, _ := json.Marshal(response)
			result = js.ValueOf(string(jsonBytes))
		}
	}()

	response := ErrorResponse{}

	// Add a simple test - if this doesn't return then there's a basic WASM issue
	if len(args) == 0 {
		response.Error = "no arguments provided"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate argument count
	if len(args) != 2 {
		response.Error = "checkClient requires 2 arguments: apiKeyIndex, accountIndex"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "apiKeyIndex"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 1, "accountIndex"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	apiKeyIndex := uint8(args[0].Int())
	accountIndex := int64(args[1].Int())

	// Check if client exists
	client, ok := backupTxClients[apiKeyIndex]
	if !ok {
		response.Error = "api key not registered"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate apiKeyIndex matches
	if client.GetApiKeyIndex() != apiKeyIndex {
		response.Error = fmt.Sprintf("apiKeyIndex does not match. expected %v but got %v", client.GetApiKeyIndex(), apiKeyIndex)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate accountIndex matches
	if client.GetAccountIndex() != accountIndex {
		response.Error = fmt.Sprintf("accountIndex does not match. expected %v but got %v", client.GetAccountIndex(), accountIndex)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Check that the API key registered on Lighter matches this one
	key, err := client.HTTP().GetApiKey(accountIndex, apiKeyIndex)
	if err != nil {
		response.Error = fmt.Sprintf("failed to get Api Keys. err: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Get our public key and format it
	pubKeyBytes := client.GetKeyManager().PubKeyBytes()
	pubKeyStr := hexutil.Encode(pubKeyBytes[:])
	pubKeyStr = strings.Replace(pubKeyStr, "0x", "", 1)

	// Compare with registered key
	ak := key.ApiKeys[0]
	if ak.PublicKey != pubKeyStr {
		response.Error = fmt.Sprintf("private key does not match the one on Lighter. ownPubKey: %s response: %+v", pubKeyStr, ak)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return empty error response
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #4: SignChangePubKey (matches C.StrOrErr - returns transaction JSON)
func signChangePubKey(this js.Value, args []js.Value) any {
	response := StringResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 2 {
		response.Error = "signChangePubKey requires 2 arguments: pubKey, nonce"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "pubKey"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 1, "nonce"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Check if client exists
	if txClient == nil {
		response.Error = "client is not created, call CreateClient() first"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	pubKeyStr := args[0].String()
	nonce := int64(args[1].Int())

	// Handle PubKey - decode and validate
	pubKeyBytes, err := hexutil.Decode(pubKeyStr)
	if err != nil {
		response.Error = fmt.Sprintf("invalid public key format: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if len(pubKeyBytes) != 40 {
		response.Error = fmt.Sprintf("invalid pub key length. expected 40 but got %v", len(pubKeyBytes))
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	var pubKey [40]byte
	copy(pubKey[:], pubKeyBytes)

	// Create transaction request
	txInfo := &types.ChangePubKeyReq{
		PubKey: pubKey,
	}
	ops := &types.TransactOpts{}
	if nonce != -1 {
		ops.Nonce = &nonce
	}

	// Get transaction from client
	tx, err := txClient.GetChangePubKeyTransaction(txInfo, ops)
	if err != nil {
		response.Error = fmt.Sprintf("failed to create transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// === manually add MessageToSign to the response (same as original):
	// - marshal the tx
	// - unmarshal it into a generic map
	// - add the new field
	// - marshal it again
	txInfoBytes, err := json.Marshal(tx)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	obj := make(map[string]interface{})
	err = json.Unmarshal(txInfoBytes, &obj)
	if err != nil {
		response.Error = fmt.Sprintf("failed to unmarshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	obj["MessageToSign"] = tx.GetL1SignatureBody()
	txInfoBytes, err = json.Marshal(obj)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal final transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return transaction JSON
	response.Result = string(txInfoBytes)
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #5: SignCreateOrder (matches C.StrOrErr - returns transaction JSON)
func signCreateOrder(this js.Value, args []js.Value) any {
	response := StringResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 11 {
		response.Error = "signCreateOrder requires 11 arguments: marketIndex, clientOrderIndex, baseAmount, price, isAsk, orderType, timeInForce, reduceOnly, triggerPrice, orderExpiry, nonce"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	argNames := []string{"marketIndex", "clientOrderIndex", "baseAmount", "price", "isAsk", "orderType", "timeInForce", "reduceOnly", "triggerPrice", "orderExpiry", "nonce"}
	for i, argName := range argNames {
		if err := validateArg(args, i, argName); err != nil {
			response.Error = err.Error()
			jsonBytes, _ := json.Marshal(response)
			return js.ValueOf(string(jsonBytes))
		}
	}

	// Check if client exists
	if txClient == nil {
		response.Error = "client is not created, call CreateClient() first"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	marketIndex := uint8(args[0].Int())
	clientOrderIndex := int64(args[1].Int())
	baseAmount := int64(args[2].Int())
	price := uint32(args[3].Int())
	isAsk := uint8(args[4].Int())
	orderType := uint8(args[5].Int())
	timeInForce := uint8(args[6].Int())
	reduceOnly := uint8(args[7].Int())
	triggerPrice := uint32(args[8].Int())
	orderExpiry := int64(args[9].Int())
	nonce := int64(args[10].Int())

	// Handle default orderExpiry (same as original)
	if orderExpiry == -1 {
		orderExpiry = time.Now().Add(time.Hour * 24 * 28).UnixMilli() // 28 days
	}

	// Create transaction request
	txInfo := &types.CreateOrderTxReq{
		MarketIndex:      marketIndex,
		ClientOrderIndex: clientOrderIndex,
		BaseAmount:       baseAmount,
		Price:            price,
		IsAsk:            isAsk,
		Type:             orderType,
		TimeInForce:      timeInForce,
		ReduceOnly:       reduceOnly,
		TriggerPrice:     triggerPrice,
		OrderExpiry:      orderExpiry,
	}
	ops := new(types.TransactOpts)
	if nonce != -1 {
		ops.Nonce = &nonce
	}

	// Get transaction from client
	tx, err := txClient.GetCreateOrderTransaction(txInfo, ops)
	if err != nil {
		response.Error = fmt.Sprintf("failed to create transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Marshal transaction to JSON
	txInfoBytes, err := json.Marshal(tx)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return transaction JSON
	response.Result = string(txInfoBytes)
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #6: SignCancelOrder (matches C.StrOrErr - returns transaction JSON)
func signCancelOrder(this js.Value, args []js.Value) any {
	response := StringResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 3 {
		response.Error = "signCancelOrder requires 3 arguments: marketIndex, orderIndex, nonce"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "marketIndex"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 1, "orderIndex"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 2, "nonce"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Check if client exists
	if txClient == nil {
		response.Error = "client is not created, call CreateClient() first"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	marketIndex := uint8(args[0].Int())
	orderIndex := int64(args[1].Int())
	nonce := int64(args[2].Int())

	// Create transaction request
	txInfo := &types.CancelOrderTxReq{
		MarketIndex: marketIndex,
		Index:       orderIndex,
	}
	ops := new(types.TransactOpts)
	if nonce != -1 {
		ops.Nonce = &nonce
	}

	// Get transaction from client
	tx, err := txClient.GetCancelOrderTransaction(txInfo, ops)
	if err != nil {
		response.Error = fmt.Sprintf("failed to create transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Marshal transaction to JSON
	txInfoBytes, err := json.Marshal(tx)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return transaction JSON
	response.Result = string(txInfoBytes)
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #7: SignWithdraw (matches C.StrOrErr - returns transaction JSON)
func signWithdraw(this js.Value, args []js.Value) any {
	response := StringResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 2 {
		response.Error = "signWithdraw requires 2 arguments: usdcAmount, nonce"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "usdcAmount"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 1, "nonce"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Check if client exists
	if txClient == nil {
		response.Error = "client is not created, call CreateClient() first"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	usdcAmount := uint64(args[0].Int())
	nonce := int64(args[1].Int())

	// Create transaction request
	txInfo := types.WithdrawTxReq{
		USDCAmount: usdcAmount,
	}
	ops := new(types.TransactOpts)
	if nonce != -1 {
		ops.Nonce = &nonce
	}

	// Get transaction from client
	tx, err := txClient.GetWithdrawTransaction(&txInfo, ops)
	if err != nil {
		response.Error = fmt.Sprintf("failed to create transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Marshal transaction to JSON
	txInfoBytes, err := json.Marshal(tx)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return transaction JSON
	response.Result = string(txInfoBytes)
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #8: SignCreateSubAccount (matches C.StrOrErr - returns transaction JSON)
func signCreateSubAccount(this js.Value, args []js.Value) any {
	response := StringResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 1 {
		response.Error = "signCreateSubAccount requires 1 argument: nonce"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "nonce"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Check if client exists
	if txClient == nil {
		response.Error = "client is not created, call CreateClient() first"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	nonce := int64(args[0].Int())

	// Create transaction options
	ops := new(types.TransactOpts)
	if nonce != -1 {
		ops.Nonce = &nonce
	}

	// Get transaction from client
	tx, err := txClient.GetCreateSubAccountTransaction(ops)
	if err != nil {
		response.Error = fmt.Sprintf("failed to create transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Marshal transaction to JSON
	txInfoBytes, err := json.Marshal(tx)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return transaction JSON
	response.Result = string(txInfoBytes)
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #9: SignCancelAllOrders (matches C.StrOrErr - returns transaction JSON)
func signCancelAllOrders(this js.Value, args []js.Value) any {
	response := StringResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 3 {
		response.Error = "signCancelAllOrders requires 3 arguments: timeInForce, time, nonce"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "timeInForce"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 1, "time"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 2, "nonce"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Check if client exists
	if txClient == nil {
		response.Error = "client is not created, call CreateClient() first"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	timeInForce := uint8(args[0].Int())
	t := int64(args[1].Int())
	nonce := int64(args[2].Int())

	// Create transaction request
	txInfo := &types.CancelAllOrdersTxReq{
		TimeInForce: timeInForce,
		Time:        t,
	}
	ops := new(types.TransactOpts)
	if nonce != -1 {
		ops.Nonce = &nonce
	}

	// Get transaction from client
	tx, err := txClient.GetCancelAllOrdersTransaction(txInfo, ops)
	if err != nil {
		response.Error = fmt.Sprintf("failed to create transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Marshal transaction to JSON
	txInfoBytes, err := json.Marshal(tx)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return transaction JSON
	response.Result = string(txInfoBytes)
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #10: SignModifyOrder (matches C.StrOrErr - returns transaction JSON)
func signModifyOrder(this js.Value, args []js.Value) any {
	response := StringResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 6 {
		response.Error = "signModifyOrder requires 6 arguments: marketIndex, index, baseAmount, price, triggerPrice, nonce"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "marketIndex"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 1, "index"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 2, "baseAmount"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 3, "price"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 4, "triggerPrice"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 5, "nonce"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Check if client exists
	if txClient == nil {
		response.Error = "client is not created, call CreateClient() first"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	marketIndex := uint8(args[0].Int())
	index := int64(args[1].Int())
	baseAmount := int64(args[2].Int())
	price := uint32(args[3].Int())
	triggerPrice := uint32(args[4].Int())
	nonce := int64(args[5].Int())

	// Create transaction request
	txInfo := &types.ModifyOrderTxReq{
		MarketIndex:  marketIndex,
		Index:        index,
		BaseAmount:   baseAmount,
		Price:        price,
		TriggerPrice: triggerPrice,
	}
	ops := new(types.TransactOpts)
	if nonce != -1 {
		ops.Nonce = &nonce
	}

	// Get transaction from client
	tx, err := txClient.GetModifyOrderTransaction(txInfo, ops)
	if err != nil {
		response.Error = fmt.Sprintf("failed to create transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Marshal transaction to JSON
	txInfoBytes, err := json.Marshal(tx)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return transaction JSON
	response.Result = string(txInfoBytes)
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #11: SignTransfer (matches C.StrOrErr - returns transaction JSON)
func signTransfer(this js.Value, args []js.Value) any {
	response := StringResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 5 {
		response.Error = "signTransfer requires 5 arguments: toAccountIndex, usdcAmount, fee, memo, nonce"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "toAccountIndex"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 1, "usdcAmount"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 2, "fee"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 3, "memo"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 4, "nonce"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Check if client exists
	if txClient == nil {
		response.Error = "client is not created, call CreateClient() first"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	toAccountIndex := int64(args[0].Int())
	usdcAmount := int64(args[1].Int())
	fee := int64(args[2].Int())
	memoStr := args[3].String()
	nonce := int64(args[4].Int())

	// Handle memo - allow empty string for zero memo
	memo := [32]byte{} // Initialize with zeros

	if memoStr != "" {
		// Validate memo length (should be 64 hex characters for 32 bytes)
		if len(memoStr) != 64 {
			response.Error = "memo expected to be 64 hex characters (32 bytes) or empty string"
			jsonBytes, _ := json.Marshal(response)
			return js.ValueOf(string(jsonBytes))
		}
		// Decode hex string to bytes
		memoBytes, err := hexutil.Decode("0x" + memoStr)
		if err != nil {
			response.Error = fmt.Sprintf("invalid hex memo: %v", err)
			jsonBytes, _ := json.Marshal(response)
			return js.ValueOf(string(jsonBytes))
		}
		if len(memoBytes) != 32 {
			response.Error = fmt.Sprintf("memo must be exactly 32 bytes, got %d", len(memoBytes))
			jsonBytes, _ := json.Marshal(response)
			return js.ValueOf(string(jsonBytes))
		}
		copy(memo[:], memoBytes)
	}

	// Create transaction request
	txInfo := &types.TransferTxReq{
		ToAccountIndex: toAccountIndex,
		USDCAmount:     usdcAmount,
		Fee:            fee,
		Memo:           memo,
	}
	ops := new(types.TransactOpts)
	if nonce != -1 {
		ops.Nonce = &nonce
	}

	// Get transaction from client
	tx, err := txClient.GetTransferTransaction(txInfo, ops)
	if err != nil {
		response.Error = fmt.Sprintf("failed to create transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// === manually add MessageToSign to the response (same as original):
	// - marshal the tx
	// - unmarshal it into a generic map
	// - add the new field
	// - marshal it again
	txInfoBytes, err := json.Marshal(tx)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	obj := make(map[string]interface{})
	err = json.Unmarshal(txInfoBytes, &obj)
	if err != nil {
		response.Error = fmt.Sprintf("failed to unmarshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	obj["MessageToSign"] = tx.GetL1SignatureBody()
	txInfoBytes, err = json.Marshal(obj)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal final transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return transaction JSON
	response.Result = string(txInfoBytes)
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #12: SignCreatePublicPool (matches C.StrOrErr - returns transaction JSON)
func signCreatePublicPool(this js.Value, args []js.Value) any {
	response := StringResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 4 {
		response.Error = "signCreatePublicPool requires 4 arguments: operatorFee, initialTotalShares, minOperatorShareRate, nonce"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "operatorFee"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 1, "initialTotalShares"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 2, "minOperatorShareRate"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 3, "nonce"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Check if client exists
	if txClient == nil {
		response.Error = "client is not created, call CreateClient() first"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	operatorFee := int64(args[0].Int())
	initialTotalShares := int64(args[1].Int())
	minOperatorShareRate := int64(args[2].Int())
	nonce := int64(args[3].Int())

	// Create transaction request
	txInfo := &types.CreatePublicPoolTxReq{
		OperatorFee:          operatorFee,
		InitialTotalShares:   initialTotalShares,
		MinOperatorShareRate: minOperatorShareRate,
	}
	ops := new(types.TransactOpts)
	if nonce != -1 {
		ops.Nonce = &nonce
	}

	// Get transaction from client
	tx, err := txClient.GetCreatePublicPoolTransaction(txInfo, ops)
	if err != nil {
		response.Error = fmt.Sprintf("failed to create transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Marshal transaction to JSON
	txInfoBytes, err := json.Marshal(tx)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return transaction JSON
	response.Result = string(txInfoBytes)
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #13: SignUpdatePublicPool (matches C.StrOrErr - returns transaction JSON)
func signUpdatePublicPool(this js.Value, args []js.Value) any {
	response := StringResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 5 {
		response.Error = "signUpdatePublicPool requires 5 arguments: publicPoolIndex, status, operatorFee, minOperatorShareRate, nonce"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "publicPoolIndex"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 1, "status"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 2, "operatorFee"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 3, "minOperatorShareRate"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 4, "nonce"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Check if client exists
	if txClient == nil {
		response.Error = "client is not created, call CreateClient() first"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	publicPoolIndex := int64(args[0].Int())
	status := uint8(args[1].Int())
	operatorFee := int64(args[2].Int())
	minOperatorShareRate := int64(args[3].Int())
	nonce := int64(args[4].Int())

	// Create transaction request
	txInfo := &types.UpdatePublicPoolTxReq{
		PublicPoolIndex:      publicPoolIndex,
		Status:               status,
		OperatorFee:          operatorFee,
		MinOperatorShareRate: minOperatorShareRate,
	}
	ops := new(types.TransactOpts)
	if nonce != -1 {
		ops.Nonce = &nonce
	}

	// Get transaction from client
	tx, err := txClient.GetUpdatePublicPoolTransaction(txInfo, ops)
	if err != nil {
		response.Error = fmt.Sprintf("failed to create transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Marshal transaction to JSON
	txInfoBytes, err := json.Marshal(tx)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return transaction JSON
	response.Result = string(txInfoBytes)
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #14: SignMintShares (matches C.StrOrErr - returns transaction JSON)
func signMintShares(this js.Value, args []js.Value) any {
	response := StringResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 3 {
		response.Error = "signMintShares requires 3 arguments: publicPoolIndex, shareAmount, nonce"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "publicPoolIndex"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 1, "shareAmount"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 2, "nonce"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Check if client exists
	if txClient == nil {
		response.Error = "client is not created, call CreateClient() first"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	publicPoolIndex := int64(args[0].Int())
	shareAmount := int64(args[1].Int())
	nonce := int64(args[2].Int())

	// Create transaction request
	txInfo := &types.MintSharesTxReq{
		PublicPoolIndex: publicPoolIndex,
		ShareAmount:     shareAmount,
	}
	ops := new(types.TransactOpts)
	if nonce != -1 {
		ops.Nonce = &nonce
	}

	// Get transaction from client
	tx, err := txClient.GetMintSharesTransaction(txInfo, ops)
	if err != nil {
		response.Error = fmt.Sprintf("failed to create transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Marshal transaction to JSON
	txInfoBytes, err := json.Marshal(tx)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return transaction JSON
	response.Result = string(txInfoBytes)
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #15: SignBurnShares (matches C.StrOrErr - returns transaction JSON)
func signBurnShares(this js.Value, args []js.Value) any {
	response := StringResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 3 {
		response.Error = "signBurnShares requires 3 arguments: publicPoolIndex, shareAmount, nonce"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "publicPoolIndex"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 1, "shareAmount"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 2, "nonce"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Check if client exists
	if txClient == nil {
		response.Error = "client is not created, call CreateClient() first"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	publicPoolIndex := int64(args[0].Int())
	shareAmount := int64(args[1].Int())
	nonce := int64(args[2].Int())

	// Create transaction request
	txInfo := &types.BurnSharesTxReq{
		PublicPoolIndex: publicPoolIndex,
		ShareAmount:     shareAmount,
	}
	ops := new(types.TransactOpts)
	if nonce != -1 {
		ops.Nonce = &nonce
	}

	// Get transaction from client
	tx, err := txClient.GetBurnSharesTransaction(txInfo, ops)
	if err != nil {
		response.Error = fmt.Sprintf("failed to create transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Marshal transaction to JSON
	txInfoBytes, err := json.Marshal(tx)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return transaction JSON
	response.Result = string(txInfoBytes)
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #16: SignUpdateLeverage (matches C.StrOrErr - returns transaction JSON)
func signUpdateLeverage(this js.Value, args []js.Value) any {
	response := StringResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 4 {
		response.Error = "signUpdateLeverage requires 4 arguments: marketIndex, initialMarginFraction, marginMode, nonce"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "marketIndex"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 1, "initialMarginFraction"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 2, "marginMode"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 3, "nonce"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Check if client exists
	if txClient == nil {
		response.Error = "client is not created, call CreateClient() first"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	marketIndex := uint8(args[0].Int())
	initialMarginFraction := uint16(args[1].Int())
	marginMode := uint8(args[2].Int())
	nonce := int64(args[3].Int())

	// Create transaction request
	txInfo := &types.UpdateLeverageTxReq{
		MarketIndex:           marketIndex,
		InitialMarginFraction: initialMarginFraction,
		MarginMode:            marginMode,
	}
	ops := new(types.TransactOpts)
	if nonce != -1 {
		ops.Nonce = &nonce
	}

	// Get transaction from client
	tx, err := txClient.GetUpdateLeverageTransaction(txInfo, ops)
	if err != nil {
		response.Error = fmt.Sprintf("failed to create transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Marshal transaction to JSON
	txInfoBytes, err := json.Marshal(tx)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return transaction JSON
	response.Result = string(txInfoBytes)
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #17: SignUpdateMargin (matches C.StrOrErr - returns transaction JSON)
func signUpdateMargin(this js.Value, args []js.Value) any {
	response := StringResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 4 {
		response.Error = "signUpdateMargin requires 4 arguments: marketIndex, usdcAmount, direction, nonce"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "marketIndex"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 1, "usdcAmount"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 2, "direction"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 3, "nonce"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Check if client exists
	if txClient == nil {
		response.Error = "client is not created, call CreateClient() first"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	marketIndex := uint8(args[0].Int())
	usdcAmount := int64(args[1].Int())
	direction := uint8(args[2].Int())
	nonce := int64(args[3].Int())

	// Create transaction request
	txInfo := &types.UpdateMarginTxReq{
		MarketIndex: marketIndex,
		USDCAmount:  usdcAmount,
		Direction:   direction,
	}
	ops := new(types.TransactOpts)
	if nonce != -1 {
		ops.Nonce = &nonce
	}

	// Get transaction from client
	tx, err := txClient.GetUpdateMarginTransaction(txInfo, ops)
	if err != nil {
		response.Error = fmt.Sprintf("failed to create transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Marshal transaction to JSON
	txInfoBytes, err := json.Marshal(tx)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return transaction JSON
	response.Result = string(txInfoBytes)
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #18: SignCreateGroupedOrders (matches C.StrOrErr - returns transaction JSON)
func signCreateGroupedOrders(this js.Value, args []js.Value) any {
	response := StringResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 4 {
		response.Error = "signCreateGroupedOrders requires 4 arguments: groupingType, ordersJSON, expiredAt, nonce"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "groupingType"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 1, "ordersJSON"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 2, "expiredAt"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}
	if err := validateArg(args, 3, "nonce"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Check if client exists
	if txClient == nil {
		response.Error = "client is not created, call CreateClient() first"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	groupingType := uint8(args[0].Int())
	ordersJSON := args[1].String()
	expiredAt := int64(args[2].Int())
	nonce := int64(args[3].Int())

	// Parse orders JSON
	var orderRequests []struct {
		MarketIndex  uint8  `json:"marketIndex"`
		BaseAmount   int64  `json:"baseAmount"`
		Price        uint32 `json:"price"`
		IsAsk        uint8  `json:"isAsk"`
		Type         uint8  `json:"type"`
		TimeInForce  uint8  `json:"timeInForce"`
		ReduceOnly   uint8  `json:"reduceOnly"`
		TriggerPrice uint32 `json:"triggerPrice"`
		OrderExpiry  int64  `json:"orderExpiry"`
	}

	err := json.Unmarshal([]byte(ordersJSON), &orderRequests)
	if err != nil {
		response.Error = fmt.Sprintf("failed to parse ordersJSON: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate orders count
	if len(orderRequests) < 2 || len(orderRequests) > 3 {
		response.Error = "grouped orders must contain 2 or 3 orders"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Build orders array
	orders := []*types.CreateOrderTxReq{}
	for _, orderReq := range orderRequests {
		orderExpiry := orderReq.OrderExpiry
		if orderExpiry == -1 {
			orderExpiry = time.Now().Add(time.Hour * 24 * 28).UnixMilli() // 28 days
		}

		orders = append(orders, &types.CreateOrderTxReq{
			MarketIndex:      orderReq.MarketIndex,
			ClientOrderIndex: 0, // Must be NilClientOrderIndex (0) for grouped orders
			BaseAmount:       orderReq.BaseAmount,
			Price:            orderReq.Price,
			IsAsk:            orderReq.IsAsk,
			Type:             orderReq.Type,
			TimeInForce:      orderReq.TimeInForce,
			ReduceOnly:       orderReq.ReduceOnly,
			TriggerPrice:     orderReq.TriggerPrice,
			OrderExpiry:      orderExpiry,
		})
	}

	// Create transaction request
	txInfo := &types.CreateGroupedOrdersTxReq{
		GroupingType: groupingType,
		Orders:       orders,
	}

	ops := new(types.TransactOpts)
	if nonce != -1 {
		ops.Nonce = &nonce
	}
	if expiredAt != -1 {
		ops.ExpiredAt = expiredAt
	}

	// Get transaction from client
	tx, err := txClient.GetCreateGroupedOrdersTransaction(txInfo, ops)
	if err != nil {
		response.Error = fmt.Sprintf("failed to create transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Marshal transaction to JSON
	txInfoBytes, err := json.Marshal(tx)
	if err != nil {
		response.Error = fmt.Sprintf("failed to marshal transaction: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return transaction JSON
	response.Result = string(txInfoBytes)
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #19: CreateAuthToken (matches C.StrOrErr - returns auth token string)
func createAuthToken(this js.Value, args []js.Value) any {
	response := StringResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count (deadline is optional, defaults to 0)
	var deadline int64 = 0
	if len(args) > 0 {
		deadline = int64(args[0].Int())
	}

	// Check if client exists
	if txClient == nil {
		response.Error = "client is not created, call CreateClient() first"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Handle default deadline (same as original - 7 hours from now)
	if deadline == 0 {
		deadline = time.Now().Add(time.Hour * 7).Unix()
	}

	// Get auth token from client
	authToken, err := txClient.GetAuthToken(time.Unix(deadline, 0))
	if err != nil {
		response.Error = fmt.Sprintf("failed to create auth token: %v", err)
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Success case - return auth token string
	response.Result = authToken
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

// Function #20: SwitchAPIKey (matches *C.char return - error only)
func switchAPIKey(this js.Value, args []js.Value) any {
	response := ErrorResponse{}

	defer func() {
		if r := recover(); r != nil {
			response.Error = fmt.Sprintf("%v", r)
		}
	}()

	// Validate argument count
	if len(args) != 1 {
		response.Error = "switchAPIKey requires 1 argument: apiKeyIndex"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Validate all required arguments
	if err := validateArg(args, 0, "apiKeyIndex"); err != nil {
		response.Error = err.Error()
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	// Extract parameters from JavaScript arguments
	apiKeyIndex := uint8(args[0].Int())

	// Switch to the specified client
	client, ok := backupTxClients[apiKeyIndex]
	if !ok {
		response.Error = "no client initialized for api key"
		jsonBytes, _ := json.Marshal(response)
		return js.ValueOf(string(jsonBytes))
	}

	txClient = client

	// Success case - return empty error response
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		response.Error = fmt.Sprintf("JSON marshal error: %v", err)
		errorBytes, _ := json.Marshal(response)
		return js.ValueOf(string(errorBytes))
	}

	return js.ValueOf(string(jsonBytes))
}

func main() {
	fmt.Println("WASM Signer Library loaded")

	// Export functions to JavaScript
	js.Global().Set("generateAPIKey", js.FuncOf(generateAPIKey))
	js.Global().Set("createClient", js.FuncOf(createClient))
	js.Global().Set("checkClient", js.FuncOf(checkClient))
	js.Global().Set("signChangePubKey", js.FuncOf(signChangePubKey))
	js.Global().Set("signCreateOrder", js.FuncOf(signCreateOrder))
	js.Global().Set("signCancelOrder", js.FuncOf(signCancelOrder))
	js.Global().Set("signWithdraw", js.FuncOf(signWithdraw))
	js.Global().Set("signCreateSubAccount", js.FuncOf(signCreateSubAccount))
	js.Global().Set("signCancelAllOrders", js.FuncOf(signCancelAllOrders))
	js.Global().Set("signModifyOrder", js.FuncOf(signModifyOrder))
	js.Global().Set("signTransfer", js.FuncOf(signTransfer))
	js.Global().Set("signCreatePublicPool", js.FuncOf(signCreatePublicPool))
	js.Global().Set("signUpdatePublicPool", js.FuncOf(signUpdatePublicPool))
	js.Global().Set("signMintShares", js.FuncOf(signMintShares))
	js.Global().Set("signBurnShares", js.FuncOf(signBurnShares))
	js.Global().Set("signUpdateLeverage", js.FuncOf(signUpdateLeverage))
	js.Global().Set("signUpdateMargin", js.FuncOf(signUpdateMargin))
	js.Global().Set("signCreateGroupedOrders", js.FuncOf(signCreateGroupedOrders))
	js.Global().Set("createAuthToken", js.FuncOf(createAuthToken))
	js.Global().Set("switchAPIKey", js.FuncOf(switchAPIKey))

	// Keep the program running
	select {}
}
