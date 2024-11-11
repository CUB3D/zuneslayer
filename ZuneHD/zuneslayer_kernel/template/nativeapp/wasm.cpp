

#include "wasm.h"

#include <string>

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <math.h>
#include <zdk.h>

#include "kwasm/thunk.h"
#include "kwasm/util.h"
#include "kwasm/platform.h"
#include "kwasm/wa.h"

#include "plugin.h"


/////////////////////////////////////////////////////////
// memory layout


#define PAGE_COUNT   1     // 64K each
#define TOTAL_PAGES  0x100000 / PAGE_SIZE   // use 1MByte of memory
#define TABLE_COUNT  20

Memory _env__memory_ = {
    PAGE_COUNT,  // initial size (64K pages)
    TOTAL_PAGES, // max size (64K pages)
    PAGE_COUNT,  // current size (64K pages)
    NULL};       // memory base
uint8_t  *_env__memoryBase_;

Table     _env__table_ = {
    ANYFUNC,       // on;y allowed value in WASM MVP
    TABLE_COUNT,   // initial
    TABLE_COUNT,   // max
    TABLE_COUNT,   // current
    0};
//uint32_t *_env__table_ = 0;
uint32_t *_env__tableBase_;

uint32_t **_env__DYNAMICTOP_PTR_;
uint32_t *_env__tempDoublePtr_;

// Initialize memory globals
void init_wac_eps() {
    _env__memoryBase_ = (uint8_t*)calloc(PAGE_COUNT, PAGE_SIZE);

    _env__tempDoublePtr_ = (uint32_t*)_env__memoryBase_;
    _env__DYNAMICTOP_PTR_ = (uint32_t**)(_env__memoryBase_ + 16);

    *_env__DYNAMICTOP_PTR_ = (uint32_t*)(_env__memoryBase_ + PAGE_COUNT * PAGE_SIZE);

    // This arrangement correlates to the module mangle_table_offset option
  _env__table_.entries = (uint32_t*)malloc(TABLE_COUNT*sizeof(uint32_t));
    if (_env__table_.entries == NULL) {
    
        exit(1);
    }
    _env__tableBase_ = _env__table_.entries;

    info("init_mem results:\n");
    info("  _env__memory_.bytes: %p\n", _env__memory_.bytes);
    info("  _env__memoryBase_: %p\n", _env__memoryBase_);
    info("  _env__DYNAMIC_TOP_PTR_: %p\n", _env__DYNAMICTOP_PTR_);
    info("  *_env__DYNAMIC_TOP_PTR_: %p\n", *_env__DYNAMICTOP_PTR_);
    info("  _env__table_.entries: %p\n", _env__table_.entries);
    info("  _env__tableBase_: 0x%x\n", (unsigned int) _env__tableBase_);
}

void run() {
	wchar_t foo[1024];
    char     *mod_path;
    int       fidx = 0, res = 0;
    uint8_t  *bytes = NULL;
    int       byte_count;
Options opts;

    init_wac_eps();

    // Load the module
    bytes =  target_wasm32_unknown_unknown_debug_plugin_wasm_wasm;
    byte_count =  target_wasm32_unknown_unknown_debug_plugin_wasm_wasm_len;

    if (bytes == NULL) {
		ZDKSystem_ShowMessageBox(L"load f", MESSAGEBOX_TYPE_OK);
        return;
    }

    
    Module *m = load_module(bytes, byte_count, opts);
    m->path = "arith,wasm";

    init_thunk_in(m);

    // setup argc/argv
    m->stack[++m->sp].value_type = I32;
   m->stack[m->sp].value.uint32 = 3; 

    // Invoke main/_main function and exit
    fidx = get_export_fidx(m, "wasm_main");
    
	if (fidx == -1) {
		return;
	}
    
    res = invoke(m, fidx);

    if (!res) {
        error("Exception: %s\n", exception);
		return;
    }

	char out[1024];
    if (m->sp >= 0) {
        StackValue *result = &m->stack[m->sp--];
         switch (result->value_type) {
            case I32: sprintf(out, "I32 return value: 0x%x:i32",  result->value.uint32); break;
            case I64: sprintf(out, "I64 return value: 0x%llx:i64", result->value.uint64); break;
            case F32: sprintf(out, "F32 return value: %.7g:f32",  result->value.f32);    break;
            case F64: sprintf(out, "F64 return value: %.7g:f64",  result->value.f64);    break;
        }
        // value_repr(&m->stack[m->sp--]);
        
    } else {
        printf("No result.\n");
    }

	std::swprintf(foo, L"%S", out);
ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);

    return;
}
