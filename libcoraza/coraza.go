package main

/*
#ifndef _LIBCORAZA_H_
#define _LIBCORAZA_H_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct coraza_intervention_t
{
	char *action;
	char *log;
    char *url;
    int status;
    int pause;
    int disruptive;
} coraza_intervention_t;

typedef uint64_t coraza_waf_t;
typedef uint64_t coraza_transaction_t;

typedef void (*coraza_log_cb) (const void *);
void send_log_to_cb(coraza_log_cb cb, const char *msg);
#endif
*/
import "C"
import (
	"encoding/json"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"hash/fnv"
	"io"
	"math/rand"
	"os"
	"path"
	"reflect"
	"sync"
	"unsafe"
)

var wafMap = sync.Map{}
var txMap = sync.Map{}

type MessageData struct {
	Message   string             `json:"message"`
	File_     string             `json:"file"`
	Line_     int                `json:"line"`
	ID_       int                `json:"id"`
	Rev_      string             `json:"rev"`
	Msg_      string             `json:"msg"`
	Data_     string             `json:"data"`
	Severity_ types.RuleSeverity `json:"severity"`
	Ver_      string             `json:"ver"`
	Maturity_ int                `json:"maturity"`
	Accuracy_ int                `json:"accuracy"`
	Tags_     []string           `json:"tags"`
	Raw_      string             `json:"raw"`
}

/**
 * Creates a new  WAF instance
 * @returns pointer to WAF instance
 */
//export coraza_new_waf
func coraza_new_waf() C.coraza_waf_t {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig().WithDirectivesFromFile("coraza.conf").
		WithDirectivesFromFile("rules/crs-setup.conf").
		WithDirectivesFromFile("rules/rules/*.conf"))
	ptr := wafToPtr(waf)
	wafMap.Store(ptr, waf)
	return C.coraza_waf_t(ptr)
}

//export coraza_new_waf_with_base_path
func coraza_new_waf_with_base_path(base *C.char) C.coraza_waf_t {
	base_path := C.GoString(base)
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig().WithDirectivesFromFile(path.Join(base_path, "coraza.conf")).
		WithDirectivesFromFile(path.Join(base_path, "rules/crs-setup.conf")).
		WithDirectivesFromFile(path.Join(base_path, "rules/rules/*.conf")))
	ptr := wafToPtr(waf)
	wafMap.Store(ptr, waf)
	return C.coraza_waf_t(ptr)
}

/**
 * Creates a new transaction for a WAF instance
 * @param[in] pointer to valid WAF instance
 * @param[in] pointer to log callback, can be null
 * @returns pointer to transaction
 */
//export coraza_new_transaction
func coraza_new_transaction(waf C.coraza_waf_t, logCb unsafe.Pointer) C.coraza_transaction_t {
	w := ptrToWaf(waf)
	tx := w.NewTransaction()
	ptr := transactionToPtr(tx)
	txMap.Store(ptr, tx)
	return C.coraza_transaction_t(ptr)
}

//export coraza_new_transaction_with_id
func coraza_new_transaction_with_id(waf C.coraza_waf_t, id *C.char, logCb unsafe.Pointer) C.coraza_transaction_t {
	w := ptrToWaf(waf)
	tx := w.NewTransactionWithID(C.GoString(id))
	ptr := transactionToPtr(tx)
	txMap.Store(ptr, tx)
	return C.coraza_transaction_t(ptr)
}

//export coraza_intervention
func coraza_intervention(tx C.coraza_transaction_t) *C.coraza_intervention_t {
	t := ptrToTransaction(tx)
	if t.Interruption() == nil {
		return nil
	}
	mem := (*C.coraza_intervention_t)(C.malloc(C.size_t(unsafe.Sizeof(C.coraza_intervention_t{}))))
	mem.action = C.CString(t.Interruption().Action)
	mem.status = C.int(t.Interruption().Status)
	return mem
}

//export coraza_process_connection
func coraza_process_connection(t C.coraza_transaction_t, sourceAddress *C.char, clientPort C.int, serverHost *C.char, serverPort C.int) C.int {
	tx := ptrToTransaction(t)
	srcAddr := CChartoString(sourceAddress)
	cp := int(clientPort)
	ch := CChartoString(serverHost)
	sp := int(serverPort)
	tx.ProcessConnection(srcAddr, cp, ch, sp)
	return 0
}

//export coraza_process_request_body
func coraza_process_request_body(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	if _, err := tx.ProcessRequestBody(); err != nil {
		return 1
	}
	return 0
}

//export coraza_update_status_code
func coraza_update_status_code(t C.coraza_transaction_t, code C.int) C.int {
	// tx := ptrToTransaction(t)
	// c := strconv.Itoa(int(code))
	// tx.Variables.ResponseStatus.Set(c)
	return 0
}

// msr->t, r->unparsed_uri, r->method, r->protocol + offset
//
//export coraza_process_uri
func coraza_process_uri(t C.coraza_transaction_t, uri *C.char, method *C.char, proto *C.char) C.int {
	tx := ptrToTransaction(t)

	tx.ProcessURI(CChartoString(uri), CChartoString(method), CChartoString(proto))
	return 0
}

//export coraza_add_request_header
func coraza_add_request_header(t C.coraza_transaction_t, name *C.char, name_len C.int, value *C.char, value_len C.int) C.int {
	tx := ptrToTransaction(t)
	tx.AddRequestHeader(C.GoStringN(name, name_len), C.GoStringN(value, value_len))
	return 0
}

//export coraza_process_request_headers
func coraza_process_request_headers(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	tx.ProcessRequestHeaders()
	return 0
}

//export coraza_process_logging
func coraza_process_logging(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	tx.ProcessLogging()
	return 0
}

//export coraza_append_request_body
func coraza_append_request_body(t C.coraza_transaction_t, data *C.uchar, length C.int) C.int {
	tx := ptrToTransaction(t)
	if _, _, err := tx.WriteRequestBody(C.GoBytes(unsafe.Pointer(data), length)); err != nil {
		return 1
	}
	return 0
}

//export coraza_add_response_header
func coraza_add_response_header(t C.coraza_transaction_t, name *C.char, name_len C.int, value *C.char, value_len C.int) C.int {
	tx := ptrToTransaction(t)
	tx.AddResponseHeader(C.GoStringN(name, name_len), C.GoStringN(value, value_len))
	return 0
}

//export coraza_append_response_body
func coraza_append_response_body(t C.coraza_transaction_t, data *C.uchar, length C.int) C.int {
	tx := ptrToTransaction(t)
	if _, _, err := tx.WriteResponseBody(C.GoBytes(unsafe.Pointer(data), length)); err != nil {
		return 1
	}
	return 0
}

//export coraza_process_response_body
func coraza_process_response_body(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	if _, err := tx.ProcessResponseBody(); err != nil {
		return 1
	}
	return 0
}

//export coraza_process_response_headers
func coraza_process_response_headers(t C.coraza_transaction_t, status C.int, proto *C.char) C.int {
	tx := ptrToTransaction(t)
	tx.ProcessResponseHeaders(int(status), C.GoString(proto))
	return 0
}

//export coraza_rules_add_file
func coraza_rules_add_file(w C.coraza_waf_t, file *C.char, er **C.char) C.int {
	conf := coraza.NewWAFConfig().WithDirectivesFromFile(C.GoString(file))
	waf, err := coraza.NewWAF(conf)
	if err != nil {
		*er = C.CString(err.Error())
		// we share the pointer, so we shouldn't free it, right?
		return 0
	}
	wafMap.Store(uint64(w), waf)
	return 1
}

//export coraza_rules_add
func coraza_rules_add(w C.coraza_waf_t, directives *C.char, er **C.char) C.int {
	conf := coraza.NewWAFConfig().WithDirectives(C.GoString(directives))
	waf, err := coraza.NewWAF(conf)
	if err != nil {
		*er = C.CString(err.Error())
		// we share the pointer, so we shouldn't free it, right?
		return 0
	}
	wafMap.Store(uint64(w), waf)
	return 1
}

//export coraza_rules_count
func coraza_rules_count(w C.coraza_waf_t) C.int {
	return 0
}

//export coraza_free_transaction
func coraza_free_transaction(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	if tx.Close() != nil {
		return 1
	}
	txMap.Delete(uint64(t))
	return 0
}

//export coraza_free_intervention
func coraza_free_intervention(it *C.coraza_intervention_t) C.int {
	if it == nil {
		return 1
	}
	defer C.free(unsafe.Pointer(it))
	C.free(unsafe.Pointer(it.log))
	C.free(unsafe.Pointer(it.url))
	C.free(unsafe.Pointer(it.action))
	return 0
}

//export coraza_rules_merge
func coraza_rules_merge(w1 C.coraza_waf_t, w2 C.coraza_waf_t, er **C.char) C.int {
	return 0
}

//export coraza_request_body_from_file
func coraza_request_body_from_file(t C.coraza_transaction_t, file *C.char) C.int {
	tx := ptrToTransaction(t)
	f, err := os.Open(C.GoString(file))
	if err != nil {
		return 1
	}
	defer f.Close()
	// we read the file in chunks and send it to the engine
	for {
		buf := make([]byte, 1024)
		n, err := f.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return 1
		}
		if _, _, err := tx.WriteRequestBody(buf[:n]); err != nil {
			return 1
		}
	}
	return 0
}

//export coraza_free_waf
func coraza_free_waf(t C.coraza_waf_t) C.int {
	// waf := ptrToWaf(t)
	txMap.Delete(uint64(t))
	return 0
}

//export coraza_set_log_cb
func coraza_set_log_cb(waf C.coraza_waf_t, cb C.coraza_log_cb) {
}

//export coraza_get_log_data
func coraza_get_log_data(t C.coraza_transaction_t) *C.char {
	tx := ptrToTransaction(t)
	if len(tx.MatchedLogRules()) == 0 {
		return nil
	}
	// we need to build a json object with the matched rules
	// and the corresponding data
	var logData []byte
	var err error

	message := make([]MessageData, 0)
	for _, mr := range tx.MatchedLogRules() {
		if mr.Message() == "" {
			continue
		}
		r := mr.Rule()
		for _, matchData := range mr.MatchedDatas() {
			message = append(message, MessageData{
				Message:   mr.Message(),
				File_:     mr.Rule().File(),
				Line_:     mr.Rule().Line(),
				ID_:       r.ID(),
				Rev_:      r.Revision(),
				Msg_:      matchData.Message(),
				Data_:     matchData.Data(),
				Severity_: r.Severity(),
				Ver_:      r.Version(),
				Maturity_: r.Maturity(),
				Accuracy_: r.Accuracy(),
				Tags_:     r.Tags(),
			})
		}
	}
	if logData, err = json.Marshal(message); err != nil {
		return nil
	}

	return C.CString(string(logData))
}

//export coraza_free_log_data
func coraza_free_log_data(log *C.char) {
	C.free(unsafe.Pointer(log))
}

//export coraza_set_server_name
func coraza_set_server_name(t C.coraza_transaction_t, name *C.char, name_len C.int) {
	tx := ptrToTransaction(t)
	tx.SetServerName(CChartoStringN(name, name_len))
}

// TODO: implement
func coraza_request_body_reader() {

}

//export coraza_add_get_request_argument
func coraza_add_get_request_argument(t C.coraza_transaction_t, key *C.char, key_len C.int, value *C.char, value_len C.int) {
	tx := ptrToTransaction(t)
	tx.AddGetRequestArgument(CChartoStringN(key, key_len), CChartoStringN(value, value_len))
}

//export coraza_add_post_request_argument
func coraza_add_post_request_argument(t C.coraza_transaction_t, key *C.char, key_len C.int, value *C.char, value_len C.int) {
	tx := ptrToTransaction(t)
	tx.AddPostRequestArgument(CChartoStringN(key, key_len), CChartoStringN(value, value_len))
}

//export coraza_add_path_request_argument
func coraza_add_path_request_argument(t C.coraza_transaction_t, key *C.char, key_len C.int, value *C.char, value_len C.int) {
	tx := ptrToTransaction(t)
	tx.AddPathRequestArgument(CChartoStringN(key, key_len), CChartoStringN(value, value_len))
}

//export coraza_add_response_argument
func coraza_add_response_argument(t C.coraza_transaction_t, key *C.char, key_len C.int, value *C.char, value_len C.int) {
	tx := ptrToTransaction(t)
	tx.AddResponseArgument(CChartoStringN(key, key_len), CChartoStringN(value, value_len))
}

// TODO: implement
func coraza_read_request_body_from() {

}

// TODO: impement
func coraza_response_body_reader() {

}

// TODO:implement
func coraza_read_response_body_from() {

}

//export coraza_is_rule_engine_off
func coraza_is_rule_engine_off(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	if tx.IsRuleEngineOff() {
		return 1
	}
	return 0
}

//export coraza_is_request_body_accessible
func coraza_is_request_body_accessible(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	if tx.IsRequestBodyAccessible() {
		return 1
	}
	return 0
}

//export coraza_is_response_body_accessible
func coraza_is_response_body_accessible(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	if tx.IsResponseBodyAccessible() {
		return 1
	}
	return 0
}

//export coraza_is_response_body_processable
func coraza_is_response_body_processable(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	if tx.IsResponseBodyProcessable() {
		return 1
	}
	return 0
}

//export coraza_is_interrupted
func coraza_is_interrupted(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	if tx.IsInterrupted() {
		return 1
	}
	return 0
}

//export coraza_get_transcation_id
func coraza_get_transcation_id(t C.coraza_transaction_t) *C.char {
	tx := ptrToTransaction(t)
	return C.CString(tx.ID())
}

//export coraza_free_transaction_id
func coraza_free_transaction_id(id *C.char) {
	C.free(unsafe.Pointer(id))
}

/*
Internal helpers
*/

func ptrToWaf(waf C.coraza_waf_t) coraza.WAF {

	if val, ok := wafMap.Load(uint64(waf)); ok {
		return val.(coraza.WAF)
	}
	return nil
}

func ptrToTransaction(t C.coraza_transaction_t) types.Transaction {
	if val, ok := txMap.Load(uint64(t)); ok {
		return val.(types.Transaction)
	}

	return nil
}

func transactionToPtr(tx types.Transaction) uint64 {
	h := fnv.New64a()
	h.Write([]byte(tx.ID()))
	return h.Sum64()
}

func wafToPtr(waf coraza.WAF) uint64 {
	return rand.Uint64()
}

// It should just be C.CString(s) but we need this to build tests
func stringToC(s string) *C.char {
	return C.CString(s)
}
func CChartoString(cStr *C.char) string {
	// zero copy C.char convert to go string
	myStr := new(reflect.StringHeader)
	cStrLen := C.strnlen(cStr, 65535)
	myStr.Data = (uintptr)(unsafe.Pointer(cStr))
	myStr.Len = int(cStrLen)
	golongStr := *(*string)(unsafe.Pointer(myStr))
	return golongStr
}
func CChartoStringN(cStr *C.char, len C.int) string {
	// zero copy C.char convert to go string with length
	myStr := new(reflect.StringHeader)
	//cStrLen := C.strnlen(cStr, 65535)
	myStr.Data = (uintptr)(unsafe.Pointer(cStr))
	myStr.Len = int(len)
	golongStr := *(*string)(unsafe.Pointer(myStr))
	return golongStr
}
func main() {}
