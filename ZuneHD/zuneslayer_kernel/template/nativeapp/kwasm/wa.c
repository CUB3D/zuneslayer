#include <stdlib.h>
#include "fixes.h"
#include <string.h>
#include <math.h>

#include "util.h"
#include "platform.h"
#include "thunk.h"
#include "wa.h"

#ifndef isnan
int isnan(double x) { return (x != x); }
#endif

static uint32_t popcnt( uint32_t x )
{
    x -= ((x >> 1) & 0x55555555);
    x = (((x >> 2) & 0x33333333) + (x & 0x33333333));
    x = (((x >> 4) + x) & 0x0f0f0f0f);
    x += (x >> 8);
    x += (x >> 16);
    return x & 0x0000003f;
}
static uint32_t clz( uint32_t x )
{
    x |= (x >> 1);
    x |= (x >> 2);
    x |= (x >> 4);
    x |= (x >> 8);
    x |= (x >> 16);
    return 32 - popcnt(x);
}

static uint32_t clzll( uint64_t x ) {
    uint32_t a = 0;
    for(a=0; a < 64; a++) {
        if((x & (1<<(63-a))) == (1<<(63-a))) {
            return a;
        }
    }
    return 64;
}

static uint32_t popcntll( uint64_t x ) {
    uint32_t a = 0;
    for(a=0; a < 64; a++) {
        if((x & (1<<(63-a))) != (1<<(63-a))) {
            return a;
        }
    }
    return 64;
}

static uint32_t ctzll( uint64_t x ) {
    uint32_t a = 0;
    for(a=0; a < 64; a++) {
        if((x & (1<<a)) == (1<<a) ) {
            return a;
        }
    }
    return 64;
}

static uint32_t ctz( uint32_t x )
{
    return popcnt((x & -x) - 1);
}

static bool wa_signbit(double x) {
    return x < 0;
}

// this is wrong but close enough
static uint32_t wa_rint(double x) {
        return floor(x);
}



char OPERATOR_INFO[][20] = {
    // Control flow operators
    "unreachable",           // 0x00
    "nop",                   // 0x01
    "block",                 // 0x02
    "loop",                  // 0x03
    "if",                    // 0x04
    "else",                  // 0x05
    "RESERVED",              // 0x06
    "RESERVED",              // 0x07
    "RESERVED",              // 0x08
    "RESERVED",              // 0x09
    "RESERVED",              // 0x0a
    "end",                   // 0x0b
    "br",                    // 0x0c
    "br_if",                 // 0x0d
    "br_table",              // 0x0e
    "return",                // 0x0f

    // Call operators
    "call",                  // 0x10
    "call_indirect",         // 0x11

    "RESERVED",              // 0x12
    "RESERVED",              // 0x13
    "RESERVED",              // 0x14
    "RESERVED",              // 0x15
    "RESERVED",              // 0x16
    "RESERVED",              // 0x17
    "RESERVED",              // 0x18
    "RESERVED",              // 0x19

    // Parametric operators
    "drop",                  // 0x1a
    "select",                // 0x1b

    "RESERVED",              // 0x1c
    "RESERVED",              // 0x1d
    "RESERVED",              // 0x1e
    "RESERVED",              // 0x1f

    // Variable access
    "get_local",             // 0x20
    "set_local",             // 0x21
    "tee_local",             // 0x22
    "get_global",            // 0x23
    "set_global",            // 0x24

    "RESERVED",              // 0x25
    "RESERVED",              // 0x26
    "RESERVED",              // 0x27

    // Memory-related operator
    "i32.load",              // 0x28
    "i64.load",              // 0x29
    "f32.load",              // 0x2a
    "f64.load",              // 0x2b
    "i32.load8_s",           // 0x2c
    "i32.load8_u",           // 0x2d
    "i32.load16_s",          // 0x2e
    "i32.load16_u",          // 0x2f
    "i64.load8_s",           // 0x30
    "i64.load8_u",           // 0x31
    "i64.load16_s",          // 0x32
    "i64.load16_u",          // 0x33
    "i64.load32_s",          // 0x34
    "i64.load32_u",          // 0x35
    "i32.store",             // 0x36
    "i64.store",             // 0x37
    "f32.store",             // 0x38
    "f64.store",             // 0x39
    "i32.store8",            // 0x3a
    "i32.store16",           // 0x3b
    "i64.store8",            // 0x3c
    "i64.store16",           // 0x3d
    "i64.store32",           // 0x3e
    "current_memory",        // 0x3f
    "grow_memory",           // 0x40

    // Constants
    "i32.const",             // 0x41
    "i64.const",             // 0x42
    "f32.const",             // 0x43
    "f64.const",             // 0x44

    // Comparison operators
    "i32.eqz",               // 0x45
    "i32.eq",                // 0x46
    "i32.ne",                // 0x47
    "i32.lt_s",              // 0x48
    "i32.lt_u",              // 0x49
    "i32.gt_s",              // 0x4a
    "i32.gt_u",              // 0x4b
    "i32.le_s",              // 0x4c
    "i32.le_u",              // 0x4d
    "i32.ge_s",              // 0x4e
    "i32.ge_u",              // 0x4f

    "i64.eqz",               // 0x50
    "i64.eq",                // 0x51
    "i64.ne",                // 0x52
    "i64.lt_s",              // 0x53
    "i64.lt_u",              // 0x54
    "i64.gt_s",              // 0x55
    "i64.gt_u",              // 0x56
    "i64.le_s",              // 0x57
    "i64.le_u",              // 0x58
    "i64.ge_s",              // 0x59
    "i64.ge_u",              // 0x5a

    "f32.eq",                // 0x5b
    "f32.ne",                // 0x5c
    "f32.lt",                // 0x5d
    "f32.gt",                // 0x5e
    "f32.le",                // 0x5f
    "f32.ge",                // 0x60

    "f64.eq",                // 0x61
    "f64.ne",                // 0x62
    "f64.lt",                // 0x63
    "f64.gt",                // 0x64
    "f64.le",                // 0x65
    "f64.ge",                // 0x66

    // Numeric operators
    "i32.clz",               // 0x67
    "i32.ctz",               // 0x68
    "i32.popcnt",            // 0x69
    "i32.add",               // 0x6a
    "i32.sub",               // 0x6b
    "i32.mul",               // 0x6c
    "i32.div_s",             // 0x6d
    "i32.div_u",             // 0x6e
    "i32.rem_s",             // 0x6f
    "i32.rem_u",             // 0x70
    "i32.and",               // 0x71
    "i32.or",                // 0x72
    "i32.xor",               // 0x73
    "i32.shl",               // 0x74
    "i32.shr_s",             // 0x75
    "i32.shr_u",             // 0x76
    "i32.rotl",              // 0x77
    "i32.rotr",              // 0x78

    "i64.clz",               // 0x79
    "i64.ctz",               // 0x7a
    "i64.popcnt",            // 0x7b
    "i64.add",               // 0x7c
    "i64.sub",               // 0x7d
    "i64.mul",               // 0x7e
    "i64.div_s",             // 0x7f
    "i64.div_u",             // 0x80
    "i64.rem_s",             // 0x81
    "i64.rem_u",             // 0x82
    "i64.and",               // 0x83
    "i64.or",                // 0x84
    "i64.xor",               // 0x85
    "i64.shl",               // 0x86
    "i64.shr_s",             // 0x87
    "i64.shr_u",             // 0x88
    "i64.rotl",              // 0x89
    "i64.rotr",              // 0x8a

    "f32.abs",               // 0x8b
    "f32.neg",               // 0x8c
    "f32.ceil",              // 0x8d
    "f32.floor",             // 0x8e
    "f32.trunc",             // 0x8f
    "f32.nearest",           // 0x90
    "f32.sqrt",              // 0x91
    "f32.add",               // 0x92
    "f32.sub",               // 0x93
    "f32.mul",               // 0x94
    "f32.div",               // 0x95
    "f32.min",               // 0x96
    "f32.max",               // 0x97
    "f32.copysign",          // 0x98

    "f64.abs",               // 0x99
    "f64.neg",               // 0x9a
    "f64.ceil",              // 0x9b
    "f64.floor",             // 0x9c
    "f64.trunc",             // 0x9d
    "f64.nearest",           // 0x9e
    "f64.sqrt",              // 0x9f
    "f64.add",               // 0xa0
    "f64.sub",               // 0xa1
    "f64.mul",               // 0xa2
    "f64.div",               // 0xa3
    "f64.min",               // 0xa4
    "f64.max",               // 0xa5
    "f64.copysign",          // 0xa6

    // Conversions
    "i32.wrap/i64",          // 0xa7
    "i32.trunc_s/f32",       // 0xa8
    "i32.trunc_u/f32",       // 0xa9
    "i32.trunc_s/f64",       // 0xaa
    "i32.trunc_u/f64",       // 0xab

    "i64.extend_s/i32",      // 0xac
    "i64.extend_u/i32",      // 0xad
    "i64.trunc_s/f32",       // 0xae
    "i64.trunc_u/f32",       // 0xaf
    "i64.trunc_s/f64",       // 0xb0
    "i64.trunc_u/f64",       // 0xb1

    "f32.convert_s/i32",     // 0xb2
    "f32.convert_u/i32",     // 0xb3
    "f32.convert_s/i64",     // 0xb4
    "f32.convert_u/i64",     // 0xb5
    "f32.demote/f64",        // 0xb6

    "f64.convert_s/i32",     // 0xb7
    "f64.convert_u/i32",     // 0xb8
    "f64.convert_s/i64",     // 0xb9
    "f64.convert_u/i64",     // 0xba
    "f64.promote/f32",       // 0xbb

    // Reinterpretations
    "i32.reinterpret/f32",   // 0xbc
    "i64.reinterpret/f64",   // 0xbd
    "f32.reinterpret/i32",   // 0xbe
    "f64.reinterpret/i64"    // 0xbf
};

// Size of memory load.
// This starts with the first memory load operator at opcode 0x28
uint32_t LOAD_SIZE[] = {
    4, 8, 4, 8, 1, 1, 2, 2, 1, 1, 2, 2, 4, 4, // loads
    4, 8, 4, 8, 1, 2, 1, 2, 4};               // stores


// global exception message
char  exception[4096];

// Static definition of block_types
uint32_t block_type_results[4][1] = {{I32}, {I64}, {F32}, {F64}};

Type block_types[5] = {
    { BLOCK, 0,0, 0, 0, 0},
    { BLOCK, 0,0, 1, block_type_results[0], 0},
    { BLOCK, 0,0, 1, block_type_results[1], 0},
    { BLOCK, 0,0, 1, block_type_results[2], 0},
    { BLOCK, 0,0, 1, block_type_results[3], 0}
};

Type *get_block_type(uint8_t value_type) {
    switch (value_type) {
    case 0x40: return &block_types[0];
    case I32:  return &block_types[1];
    case I64:  return &block_types[2];
    case F32:  return &block_types[3];
    case F64:  return &block_types[4];
    default:   FATAL("invalid block_type value_type: %d\n", value_type);
               return NULL;
    }
}

// TODO: calculate this while parsing types
uint64_t get_type_mask(Type *type) {
	uint32_t p;
    uint64_t  mask = 0x80;

    if (type->result_count == 1) {
        mask |= 0x80 - type->results[0];
    }
    mask = mask << 4;
    for(p=0; p<type->param_count; p++) {
        mask = ((uint64_t)mask) << 4;
        mask |= 0x80 - type->params[p];
    }
    return mask;
}

// FIXME: waisting 256Bytes!
char _value_str[256];
char *value_repr(StackValue *v) {
    switch (v->value_type) {
    case I32: sprintf(_value_str, "0x%x:i32",  v->value.uint32); break;
    case I64: sprintf(_value_str, "0x%llx:i64", v->value.uint64); break;
    case F32: sprintf(_value_str, "%.7g:f32",  v->value.f32);    break;
    case F64: sprintf(_value_str, "%.7g:f64",  v->value.f64);    break;
    }
    return _value_str;
}

char _block_str[1024];
char *block_repr(Block *b) {
    if (b->block_type == 0) {
        sprintf(_block_str,
                 "fn0x%x<%d/%d->%d>", b->fidx, b->type->param_count,
                 b->local_count, b->type->result_count);
    } else {
        sprintf(_block_str, "%s<0/0->%d>",
                 b->block_type == 0x01 ? "init" :
                 b->block_type == 0x02 ? "block" :
                 b->block_type == 0x03 ? "loop" : "if",
                 b->type->result_count);
    }
    return _block_str;
}

void dump_stacks(Module *m) {
	int i;
    warn("      * stack:     [");
    for (i=0; i<=m->sp; i++) {
        if (i == m->fp) { warn("* "); }
        warn("%s", value_repr(&m->stack[i]));
        if (i != m->sp) { warn(" "); }
    }
    warn("]\n");

    warn("      * callstack: [");
    for (i=0; i<=m->csp; i++) {
        Frame *f = &m->callstack[i]; (void)f;
        warn("%s(sp:%d/fp:%d/ra:0x%x)", block_repr(f->block), f->sp, f->fp,
               f->ra);
        if (i != m->csp) { warn(" "); }
    }
    warn("]\n");
}


void parse_table_type(Module *m, uint32_t *pos) {
	uint32_t flags;
	uint32_t tsize;
    m->table.elem_type = read_LEB(m->bytes, pos, 7);
    ASSERT(m->table.elem_type == ANYFUNC,
            "Table elem_type 0x%x unsupported",
            m->table.elem_type);
    flags = read_LEB(m->bytes, pos, 32);
    tsize = read_LEB(m->bytes, pos, 32); // Initial size
    m->table.initial = tsize;
    m->table.size = tsize;
    // Limit maximum to 64K
    if (flags & 0x1) {
        tsize = read_LEB(m->bytes, pos, 32); // Max size
        m->table.maximum = 0x10000 < tsize ? 0x10000 : tsize;
    } else {
        m->table.maximum = 0x10000;
    }
    debug("  table size: %d\n", tsize);
}

void parse_memory_type(Module *m, uint32_t *pos) {
    uint32_t flags = read_LEB(m->bytes, pos, 32);
    uint32_t pages = read_LEB(m->bytes, pos, 32); // Initial size
    m->memory.initial = pages;
    m->memory.pages = pages;
    // Limit the maximum to 2GB
    if (flags & 0x1) {
        pages = read_LEB(m->bytes, pos, 32); // Max size
        m->memory.maximum = (uint32_t)fmin(0x8000, pages);
    } else {
        m->memory.maximum = 0x8000;
    }
}

void skip_immediates(uint8_t *bytes, uint32_t *pos) {
	uint32_t i;

    uint32_t count, opcode = bytes[*pos];
    *pos = *pos+1;
    switch (opcode) {
    // varuint1
    case 0x3f:
    case 0x40:    // current_memory, grow_memory
        read_LEB(bytes, pos, 1); break;
    // varuint32, varint32
    case 0x0c:
case 0x0d:    // br, br_if
    case 0x10:            // call
    case 0x20:
	case 0x21:    // get/set_local, tee_local, get/set_global
	case 0x22:    // get/set_local, tee_local, get/set_global
	case 0x23:    // get/set_local, tee_local, get/set_global
	case 0x24:    // get/set_local, tee_local, get/set_global
    case 0x41:            // i32.const
        read_LEB(bytes, pos, 32); break;
    // varuint32 + varuint1
    case 0x11:            // call_indirect
        read_LEB(bytes, pos, 1); read_LEB(bytes, pos, 32); break;
    // varint64
    case 0x42:            // i64.const
        read_LEB(bytes, pos, 64); break;
    // uint32
    case 0x43:            // f32.const
        *pos += 4; break;
    // uint64
    case 0x44:            // f64.const
        *pos += 8; break;
    // block_type
    case 0x02:
    case 3:
	case 0x04:    // block, loop, if
        read_LEB(bytes, pos, 7); break;
    // memory_immediate
	case 0x28:
	case 0x29:
	case 0x2a:
	case 0x2b:
	case 0x2c:
	case 0x2d:
	case 0x2e:
	case 0x2f:
	case 0x30:
	case 0x31:
	case 0x32:
	case 0x33:
	case 0x34:
	case 0x35:
	case 0x36:
	case 0x37:
	case 0x38:
	case 0x39:
	case 0x3a:
	case 0x3b:
	case 0x3c:
	case 0x3d:
	case 0x3e:
        read_LEB(bytes, pos, 32); read_LEB(bytes, pos, 32); break;
    // br_table
    case 0x0e:            // br_table
        count = read_LEB(bytes, pos, 32); // target count
        for (i=0; i<count; i++) {
            read_LEB(bytes, pos, 32);
        }
        read_LEB(bytes, pos, 32); // default target
        break;
    default:              // no immediates
        break;
    }
}

void find_blocks(Module *m) {
    Block    *function;
    Block    *block;
    Block    *blockstack[BLOCKSTACK_SIZE];
    int       top = -1;
    uint8_t   opcode = 0x00;
	uint32_t f, pos;
    info("  find_blocks: function_count: %d\n", m->function_count);
    for (f=m->import_count; f<m->function_count; f++) {
        function = &m->functions[f];
        debug("    fidx: 0x%x, start: 0x%x, end: 0x%x\n",
               f, function->start_addr, function->end_addr);
        pos = function->start_addr;
        while (pos <= function->end_addr) {
            opcode = m->bytes[pos];
            switch (opcode) {
            case 0x02: // block
            case 0x03: // loop
            case 0x04: // if
                block = acalloc(1, sizeof(Block), "Block");
                block->block_type = opcode;
                block->type = get_block_type(m->bytes[pos+1]);
                block->start_addr = pos;
                blockstack[++top] = block;
                m->block_lookup[pos] = block;
                break;
            case 0x05: // else
                ASSERT(blockstack[top]->block_type == 0x04,
                       "else not matched with if")
                blockstack[top]->else_addr = pos+1;
                break;
            case 0x0b: // end
                if (pos == function->end_addr) { break; }
                ASSERT(top >= 0, "blockstack underflow");
                block = blockstack[top--];
                block->end_addr = pos;
                if (block->block_type == 0x03) {
                    // loop: label after start
                    block->br_addr = block->start_addr+2;
                } else {
                    // block, if: label at end
                    block->br_addr = pos;
                }
                debug("      block start: 0x%x, end: 0x%x,"
                       " br_addr: 0x%x, else_addr: 0x%x\n",
                       block->start_addr, block->end_addr, block->br_addr,
                       block->else_addr);
                break;
            }
            skip_immediates(m->bytes, &pos);
        }

        ASSERT(top == -1, "Function ended in middle of block\n")
        ASSERT(opcode == 0x0b, "Function block did not end with 0xb\n")
    }
}


//
// Stack machine (byte code related functions)
//

void push_block(Module *m, Block *block, int sp) {
    m->csp += 1;
    m->callstack[m->csp].block = block;
    m->callstack[m->csp].sp = sp;
    m->callstack[m->csp].fp = m->fp;
    m->callstack[m->csp].ra = m->pc;
}

Block *pop_block(Module *m) {
    Frame *frame = &m->callstack[m->csp--];
    Type *t = frame->block->type;

    // TODO: validate return value if there is one

    m->fp = frame->fp; // Restore frame pointer

    // Validate the return value
    if (t->result_count == 1) {
        if (m->stack[m->sp].value_type != t->results[0]) {
            sprintf(exception, "call type mismatch");
            return NULL;
        }
    }

    // Restore stack pointer
    if (t->result_count == 1) {
        // Save top value as result
        if (frame->sp < m->sp) {
            m->stack[frame->sp+1] = m->stack[m->sp];
            m->sp = frame->sp+1;
        }
    } else {
        if (frame->sp < m->sp) {
            m->sp = frame->sp;
        }
    }

    if (frame->block->block_type == 0x00) {
        // Function, set pc to return address
        m->pc = frame->ra;
    }

    return frame->block;
}

// Setup a function
// Push params and locals on the stack and save a call frame on the call stack
// Sets new pc value for the start of the function
void setup_call(Module *m, uint32_t fidx) {
	uint32_t lidx;
	int p;
    Block  *func = &m->functions[fidx];
    Type   *type = func->type;

    // Push current frame on the call stack
    push_block(m, func, m->sp - type->param_count);

    if (TRACE) {
        warn("  >> fn0x%x(%d) %s(",
             fidx, fidx, func->export_name ? func->export_name : "");
        for (p=type->param_count-1; p >= 0; p--) {
            warn("%s%s", value_repr(&m->stack[m->sp-p]),
                 p ? " " : "");
        }
        warn("), %d locals, %d results\n",
             func->local_count, type->result_count);
    }

    // Push locals (dropping extras)
    m->fp = m->sp - type->param_count + 1;
    // TODO: validate arguments vs formal params

    // Push function locals
    for (lidx=0; lidx<func->local_count; lidx++) {
        m->sp += 1;
        m->stack[m->sp].value_type = func->locals[lidx];
        m->stack[m->sp].value.uint64 = 0; // Initialize whole union to 0
    }

    // Set program counter to start of function
    m->pc = func->start_addr;
    return;
}

bool interpret(Module *m) {
    int ii;
	uint32_t didx,prev_pages,delta;
    uint8_t     *bytes = m->bytes;
    StackValue  *stack = m->stack;

    uint32_t     cur_pc;
    Block       *block;
    uint32_t     arg, val, fidx, tidx, cond, depth, count;
    uint32_t     flags, offset, addr;
    uint8_t     *maddr, *mem_end;
    //uint32_t    *depths;
    uint8_t      opcode;
    uint32_t     a, b, c; // I32 math
    uint64_t     d, e, f; // I64 math
    float        g, h, i; // F32 math
    double       j, k, l; // F64 math
    bool         overflow = false;
    StackValue* sval;

    while (m->pc < m->byte_count) {
        opcode = bytes[m->pc];
        cur_pc = m->pc;
        m->pc += 1;

        if (TRACE) {
            if (DEBUG) { dump_stacks(m); }
            info("    0x%x <0x%x/%s>\n", cur_pc, opcode, OPERATOR_INFO[opcode]);
        }

        switch (opcode) {

        //
        // Control flow operators
        //
        case 0x00:  // unreachable
            sprintf(exception, "%s", "unreachable");
            return false;
        case 0x01:  // nop
            continue;
        case 0x02:  // block
            read_LEB(bytes, &m->pc, 32);  // ignore block type
            if (m->csp >= CALLSTACK_SIZE) {
                sprintf(exception, "call stack exhausted");
                return false;
            }
            push_block(m, m->block_lookup[cur_pc], m->sp);
            continue;
        case 0x03:  // loop
            read_LEB(bytes, &m->pc, 32);  // ignore block type
            if (m->csp >= CALLSTACK_SIZE) {
                sprintf(exception, "call stack exhausted");
                return false;
            }
            push_block(m, m->block_lookup[cur_pc], m->sp);
            continue;
        case 0x04:  // if
            read_LEB(bytes, &m->pc, 32);  // ignore block type
            block = m->block_lookup[cur_pc];
            if (m->csp >= CALLSTACK_SIZE) {
                sprintf(exception, "call stack exhausted");
                return false;
            }
            push_block(m, block, m->sp);

            cond = stack[m->sp--].value.uint32;
            if (cond == 0) { // if false (I32)
                // branch to else block or after end of if
                if (block->else_addr == 0) {
                    // no else block, pop if block and skip end
                    m->csp -= 1;
                    m->pc = block->br_addr+1;
                } else {
                    m->pc = block->else_addr;
                }
            }
            // if true, keep going
            if (TRACE) {
                debug("      - cond: 0x%x jump to 0x%x, block: %s\n",
                       cond, m->pc, block_repr(block));
            }
            continue;
        case 0x05:  // else
            block = m->callstack[m->csp].block;
            m->pc = block->br_addr;
            if (TRACE) {
                debug("      - of %s jump to 0x%x\n", block_repr(block), m->pc);
            }
            continue;
        case 0x0b:  // end
            block = pop_block(m);
            if (block == NULL) {
                return false; // an exception (set by pop_block)
            }
            if (TRACE) { debug("      - of %s\n", block_repr(block)); }
            if (block->block_type == 0x00) { // Function
                if (TRACE) {
                 warn("  << fn0x%x(%d) %s = %s\n",
                      block->fidx, block->fidx,
                      block->export_name ? block->export_name : "",
                      block->type->result_count > 0 ?
                        value_repr(&m->stack[m->sp]) :
                        "_");
                }
                if (m->csp == -1) {
                    // Return to top-level
                    return true;
                } else {
                    // Keep going at return address
                }
            } else if (block->block_type == 0x01) { // init_expr
                return true;
            } else {  // Block
                // End of block/loop/if, keep going
            }
            continue;
        case 0x0c:  // br
            depth = read_LEB(bytes, &m->pc, 32);
            m->csp -= depth;
            // set to end for pop_block
            m->pc = m->callstack[m->csp].block->br_addr;
         //   if (TRACE) { debug("      - to: 0x%x\n", &m->pc); }
            if (TRACE) { debug("      - to: 0x%x\n", m->pc); }
            continue;
        case 0x0d:  // br_if
            depth = read_LEB(bytes, &m->pc, 32);

            cond = stack[m->sp--].value.uint32;
            if (cond) { // if true
                m->csp -= depth;
                // set to end for pop_block
                m->pc = m->callstack[m->csp].block->br_addr;
            }
            if (TRACE) { debug("      - depth: 0x%x, cond: 0x%x, to: 0x%x\n", depth, cond, m->pc); }
            continue;
        case 0x0e:  // br_table
            count = read_LEB(bytes, &m->pc, 32);
            if (count > BR_TABLE_SIZE) {
                // TODO: check this prior to runtime
                sprintf(exception, "br_table size %d exceeds max %d\n",
                        count, BR_TABLE_SIZE);
                return false;
            }
            for(ii=0; ii<count; ii++) {
                m->br_table[ii] = read_LEB(bytes, &m->pc, 32);
            }
            depth = read_LEB(bytes, &m->pc, 32);

            didx = stack[m->sp--].value.int32;
            if (didx >= 0 && didx < (int32_t)count) {
                depth = m->br_table[didx];
            }

            m->csp -= depth;
            // set to end for pop_block
            m->pc = m->callstack[m->csp].block->br_addr;
            if (TRACE) {
                debug("      - count: %d, didx: %d, to: 0x%x\n", count, didx, m->pc);
            }
            continue;
        case 0x0f:  // return
            while (m->csp >= 0 &&
                   m->callstack[m->csp].block->block_type != 0x00) {
                m->csp--;
            }
            // Set the program count to the end of the function
            // The actual pop_block and return is handled by the end opcode.
            m->pc = m->callstack[0].block->end_addr;
            if (TRACE) {
                debug("      - to: 0x%x\n", m->pc);
            }
            continue;


        //
        // Call operators
        //
        case 0x10:  // call
            fidx = read_LEB(bytes, &m->pc, 32);

            if (fidx < m->import_count) {
                thunk_out(m, fidx);   // import/thunk call
            } else {
                if (m->csp >= CALLSTACK_SIZE) {
                    sprintf(exception, "call stack exhausted");
                    return false;
                }
                setup_call(m, fidx);  // regular function call
                if (TRACE) {
                    debug("      - calling function fidx: %d at: 0x%x\n", fidx, m->pc);
                }
            }
            continue;
        case 0x11:  // call_indirect
            tidx = read_LEB(bytes, &m->pc, 32); // TODO: use tidx?
            (void)tidx;
            read_LEB(bytes, &m->pc, 1); // reserved immediate
            val = stack[m->sp--].value.uint32;
            if (m->options.mangle_table_index) {
                // val is the table address + the index (not sized for the
                // pointer size) so get the actual (sized) index
                if (TRACE) {
                    debug("      - entries: %p, original val: 0x%x, new val: 0x%x\n",
                        m->table.entries, val, (uint32_t)m->table.entries - val);
                }
                //val = val - (uint32_t)((uint64_t)m->table.entries & 0xFFFFFFFF);
                val = val - (uint32_t)m->table.entries;
            }
            if (val >= m->table.maximum) {
                sprintf(exception, "undefined element 0x%x (max: 0x%x) in table",
                        val, m->table.maximum);
                return false;
            }

            fidx = m->table.entries[val];
            if (TRACE) {
                debug("       - call_indirect tidx: %d, val: 0x%x, fidx: 0x%x\n",
                      tidx, val, fidx);
            }

            if (fidx < m->import_count) {
                thunk_out(m, fidx);    // import/thunk call
            } else {
                Block *func = &m->functions[fidx];
                Type *ftype = func->type;

                if (m->csp >= CALLSTACK_SIZE) {
                    sprintf(exception, "call stack exhausted");
                    return false;
                }
                if (ftype->mask != m->types[tidx].mask) {
                    sprintf(exception, "indirect call type mismatch (call type and function type differ)");
                    return false;
                }

                setup_call(m, fidx);   // regular function call

                // Validate signatures match
                if (ftype->param_count + func->local_count != m->sp - m->fp + 1) {
                    sprintf(exception, "indirect call type mismatch (param counts differ)");
                    return false;
                }
                for (f=0; f<ftype->param_count; f++) {
                    if (ftype->params[f] != m->stack[m->fp+f].value_type) {
                        sprintf(exception, "indirect call type mismatch (param types differ)");
                        return false;
                    }
                }

                if (TRACE) {
                    debug("      - tidx: %d, table idx: %d, "
                          "calling function fidx: %d at: 0x%x\n",
                        tidx, val, fidx, m->pc);
                }
            }
            continue;

        //
        // Parametric operators
        //
        case 0x1a:  // drop
            m->sp--;
            continue;
        case 0x1b:  // select
            cond = stack[m->sp--].value.uint32;
            m->sp--;
            if (!cond) {  // use a instead of b
                stack[m->sp] = stack[m->sp+1];
            }
            continue;


        //
        // Variable access
        //
        case 0x20:  // get_local
            arg = read_LEB(bytes, &m->pc, 32);
            if (TRACE) {
                debug("      - arg: 0x%x, got %s\n",
                       arg, value_repr(&stack[m->fp+arg]));
            }
            stack[++m->sp] = stack[m->fp+arg];
            continue;
        case 0x21:  // set_local
            arg = read_LEB(bytes, &m->pc, 32);
            stack[m->fp+arg] = stack[m->sp--];
            if (TRACE) {
                debug("      - arg: 0x%x, to %s\n",
                       arg, value_repr(&stack[m->sp]));
            }
            continue;
        case 0x22:  // tee_local
            arg = read_LEB(bytes, &m->pc, 32);
            stack[m->fp+arg] = stack[m->sp];
            if (TRACE) {
                debug("      - arg: 0x%x, to %s\n",
                       arg, value_repr(&stack[m->sp]));
            }
            continue;
        case 0x23:  // get_global
            arg = read_LEB(bytes, &m->pc, 32);
            if (TRACE) {
                debug("      - arg: 0x%x, got %s\n",
                       arg, value_repr(&m->globals[arg]));
            }
            stack[++m->sp] = m->globals[arg];
            continue;
        case 0x24:  // set_global
            arg = read_LEB(bytes, &m->pc, 32);
            m->globals[arg] = stack[m->sp--];
            if (TRACE) {
                debug("      - arg: 0x%x, to %s\n",
                       arg, value_repr(&m->globals[arg]));
            }
            continue;

        //
        // Memory-related operators
        //
        case 0x3f:  // current_memory
            read_LEB(bytes, &m->pc, 32); // ignore reserved
            stack[++m->sp].value_type = I32;
            stack[m->sp].value.uint32 = m->memory.pages;
            continue;
        case 0x40:  // grow_memory
            read_LEB(bytes, &m->pc, 32); // ignore reserved
            prev_pages = m->memory.pages;
            delta = stack[m->sp].value.uint32;
            stack[m->sp].value.uint32 = prev_pages;
            if (delta == 0) {
                continue; // No change
            } else if (delta+prev_pages > m->memory.maximum) {
                stack[m->sp].value.uint32 = -1;
                continue;
            }
            m->memory.pages += delta;
            m->memory.bytes = arecalloc(m->memory.bytes,
                                        prev_pages*PAGE_SIZE,
                                        m->memory.pages*PAGE_SIZE,
                                        sizeof(uint32_t),
                                        "grow_memory: Module->memory.bytes");
            continue;

        // Memory load operators
	case 0x28:
	case 0x29:
	case 0x2a:
	case 0x2b:
	case 0x2c:
	case 0x2d:
	case 0x2e:
	case 0x2f:
	case 0x30:
	case 0x31:
	case 0x32:
	case 0x33:
	case 0x34:
	case 0x35:
            flags = read_LEB(bytes, &m->pc, 32);
            offset = read_LEB(bytes, &m->pc, 32);
            addr = stack[m->sp--].value.uint32;
            if (flags != 2 && TRACE) {
                info("      - unaligned load - flags: 0x%x,"
                      " offset: 0x%x, addr: 0x%x\n",
                      flags, offset, addr);
            }
            if (offset+addr < addr) { overflow = true; }
            maddr = m->memory.bytes+offset+addr;
            if (maddr < m->memory.bytes) { overflow = true; }
            mem_end = m->memory.bytes+m->memory.pages*(uint32_t)PAGE_SIZE;
            if (maddr+LOAD_SIZE[opcode-0x28] > mem_end) {
                overflow = true;
            }
            info("      - addr: 0x%x, offset: 0x%x, maddr: %p, mem_end: %p\n",
                 addr, offset, maddr, mem_end);
            if (!m->options.disable_memory_bounds) {
                if (overflow) {
                    warn("memory start: %p, memory end: %p, maddr: %p\n",
                        m->memory.bytes, mem_end, maddr);
                    sprintf(exception, "out of bounds memory access");
                    return false;
                }
            }
            stack[++m->sp].value.uint64 = 0; // initialize to 0
            switch (opcode) {
            case 0x28: memcpy(&stack[m->sp].value, maddr, 4);
                       stack[m->sp].value_type = I32; break; // i32.load
            case 0x29: memcpy(&stack[m->sp].value, maddr, 8);
                       stack[m->sp].value_type = I64; break; // i64.load
            case 0x2a: memcpy(&stack[m->sp].value, maddr, 4);
                       stack[m->sp].value_type = F32; break; // f32.load
            case 0x2b: memcpy(&stack[m->sp].value, maddr, 8);
                       stack[m->sp].value_type = F64; break; // f64.load
            case 0x2c: memcpy(&stack[m->sp].value, maddr, 1);
                       sext_8_32(&stack[m->sp].value.uint32);
                       stack[m->sp].value_type = I32;
                       break; // i32.load8_s
            case 0x2d: memcpy(&stack[m->sp].value, maddr, 1);
                       stack[m->sp].value_type = I32; break; // i32.load8_u
            case 0x2e: memcpy(&stack[m->sp].value, maddr, 2);
                       sext_16_32(&stack[m->sp].value.uint32);
                       stack[m->sp].value_type = I32; break; // i32.load16_s
            case 0x2f: memcpy(&stack[m->sp].value, maddr, 2);
                       stack[m->sp].value_type = I32; break; // i32.load16_u
            case 0x30: memcpy(&stack[m->sp].value, maddr, 1);
                       sext_8_64(&stack[m->sp].value.uint64);
                       stack[m->sp].value_type = I64; break; // i64.load8_s
            case 0x31: memcpy(&stack[m->sp].value, maddr, 1);
                       stack[m->sp].value_type = I64; break; // i64.load8_u
            case 0x32: memcpy(&stack[m->sp].value, maddr, 2);
                       sext_16_64(&stack[m->sp].value.uint64);
                       stack[m->sp].value_type = I64; break; // i64.load16_s
            case 0x33: memcpy(&stack[m->sp].value, maddr, 2);
                       stack[m->sp].value_type = I64; break; // i64.load16_u
            case 0x34: memcpy(&stack[m->sp].value, maddr, 4);
                       sext_32_64(&stack[m->sp].value.uint64);
                       stack[m->sp].value_type = I64; break; // i64.load32_s
            case 0x35: memcpy(&stack[m->sp].value, maddr, 4);
                       stack[m->sp].value_type = I64; break; // i64.load32_u
            }
            continue;

        // Memory store operators
            case 0x36:
case 0x37:
case 0x38:
case 0x39:
case 0x3a:
case 0x3b:
case 0x3c:
case 0x3d:
case 0x3e:
            flags = read_LEB(bytes, &m->pc, 32);
            offset = read_LEB(bytes, &m->pc, 32);
            sval = &stack[m->sp--];
            addr = stack[m->sp--].value.uint32;
            if (flags != 2 && TRACE) {
                info("      - unaligned store - flags: 0x%x,"
                      " offset: 0x%x, addr: 0x%x, val: %s\n",
                      flags, offset, addr, value_repr(sval));
            }
            if (offset+addr < addr) { overflow = true; }
            maddr = m->memory.bytes+offset+addr;
            if (maddr < m->memory.bytes) { overflow = true; }
            mem_end = m->memory.bytes+m->memory.pages*(uint32_t)PAGE_SIZE;
            if (maddr+LOAD_SIZE[opcode-0x28] > mem_end) {
                overflow = true;
            }
            info("      - addr: 0x%x, offset: 0x%x, maddr: %p, mem_end: %p, value: %s\n",
                 addr, offset, maddr, mem_end, value_repr(sval));
            if (!m->options.disable_memory_bounds) {
                if (overflow) {
                    warn("memory start: %p, memory end: %p, maddr: %p\n",
                        m->memory.bytes, mem_end, maddr);
                    sprintf(exception, "out of bounds memory access");
                    return false;
                }
            }
            switch (opcode) {
            case 0x36: memcpy(maddr, &sval->value.uint32, 4); break; // i32.store
            case 0x37: memcpy(maddr, &sval->value.uint64, 8); break; // i64.store
            case 0x38: memcpy(maddr, &sval->value.f32, 4); break;    // f32.store
            case 0x39: memcpy(maddr, &sval->value.f64, 8); break;    // f64.store
            case 0x3a: memcpy(maddr, &sval->value.uint32, 1); break; // i32.store8
            case 0x3b: memcpy(maddr, &sval->value.uint32, 2); break; // i32.store16
            case 0x3c: memcpy(maddr, &sval->value.uint64, 1); break; // i64.store8
            case 0x3d: memcpy(maddr, &sval->value.uint64, 2); break; // i64.store16
            case 0x3e: memcpy(maddr, &sval->value.uint64, 4); break; // i64.store32
            }
            continue;

        //
        // Constants
        //
        case 0x41:  // i32.const
            stack[++m->sp].value_type = I32;
            stack[m->sp].value.uint32 = read_LEB_signed(bytes, &m->pc, 32);
            continue;
        case 0x42:  // i64.const
            stack[++m->sp].value_type = I64;
            stack[m->sp].value.int64 = read_LEB_signed(bytes, &m->pc, 64);
            continue;
        case 0x43:  // f32.const
            stack[++m->sp].value_type = F32;
            memcpy(&stack[m->sp].value.uint32, bytes+m->pc, 4);
            m->pc += 4;
            //stack[m->sp].value.uint32 = read_LEB_signed(bytes, pm->c, 32);
            continue;
        case 0x44:  // f64.const
            stack[++m->sp].value_type = F64;
            memcpy(&stack[m->sp].value.uint64, bytes+m->pc, 8);
            m->pc += 8;
            //stack[m->sp].value.uint64 = read_LEB_signed(bytes, m->pc, 64);
            continue;

        //
        // Comparison operators
        //

        // unary
        case 0x45:  // i32.eqz
            stack[m->sp].value.uint32 = stack[m->sp].value.uint32 == 0;
            continue;
        case 0x50:  // i64.eqz
            stack[m->sp].value_type = I32;
            stack[m->sp].value.uint32 = stack[m->sp].value.uint64 == 0;
            continue;

        // i32 binary
	case 0x46:
	case 0x47:
	case 0x48:
	case 0x49:
	case 0x4a:
	case 0x4b:
	case 0x4c:
	case 0x4d:
	case 0x4e:
	case 0x4f:
            a = stack[m->sp-1].value.uint32;
            b = stack[m->sp].value.uint32;
            m->sp -= 1;
            switch (opcode) {
            case 0x46: c = a == b; break;  // i32.eq
            case 0x47: c = a != b; break;  // i32.ne
            case 0x48: c = (int32_t)a <  (int32_t)b; break;  // i32.lt_s
            case 0x49: c = a <  b; break;  // i32.lt_u
            case 0x4a: c = (int32_t)a >  (int32_t)b; break;  // i32.gt_s
            case 0x4b: c = a >  b; break;  // i32.gt_u
            case 0x4c: c = (int32_t)a <= (int32_t)b; break;  // i32.le_s
            case 0x4d: c = a <= b; break;  // i32.le_u
            case 0x4e: c = (int32_t)a >= (int32_t)b; break;  // i32.ge_s
            case 0x4f: c = a >= b; break;  // i32.ge_u
            }
            stack[m->sp].value_type = I32;
            stack[m->sp].value.uint32 = c;
            continue;
	case 0x51:
	case 0x52:
	case 0x53:
	case 0x54:
	case 0x55:
	case 0x56:
	case 0x57:
	case 0x58:
	case 0x59:
	case 0x5a:
            d = stack[m->sp-1].value.uint64;
            e = stack[m->sp].value.uint64;
            m->sp -= 1;
            switch (opcode) {
            case 0x51: c = d == e; break;  // i64.eq
            case 0x52: c = d != e; break;  // i64.ne
            case 0x53: c = (int64_t)d <  (int64_t)e; break;  // i64.lt_s
            case 0x54: c = d <  e; break;  // i64.lt_u
            case 0x55: c = (int64_t)d >  (int64_t)e; break;  // i64.gt_s
            case 0x56: c = d >  e; break;  // i64.gt_u
            case 0x57: c = (int64_t)d <= (int64_t)e; break;  // i64.le_s
            case 0x58: c = d <= e; break;  // i64.le_u
            case 0x59: c = (int64_t)d >= (int64_t)e; break;  // i64.ge_s
            case 0x5a: c = d >= e; break;  // i64.ge_u
            }
            stack[m->sp].value_type = I32;
            stack[m->sp].value.uint32 = c;
            continue;
	case 0x5b:
	case 0x5c:
	case 0x5d:
	case 0x5e:
	case 0x5f:
	case 0x60:
            g = stack[m->sp-1].value.f32;
            h = stack[m->sp].value.f32;
            m->sp -= 1;
            switch (opcode) {
            case 0x5b: c = g == h; break;  // f32.eq
            case 0x5c: c = g != h; break;  // f32.ne
            case 0x5d: c = g <  h; break;  // f32.lt
            case 0x5e: c = g >  h; break;  // f32.gt
            case 0x5f: c = g <= h; break;  // f32.le
            case 0x60: c = g >= h; break;  // f32.ge
            }
            stack[m->sp].value_type = I32;
            stack[m->sp].value.uint32 = c;
            continue;
	case 0x61:
	case 0x62:
	case 0x63:
	case 0x64:
	case 0x65:
	case 0x66:
            j = stack[m->sp-1].value.f64;
            k = stack[m->sp].value.f64;
            m->sp -= 1;
            switch (opcode) {
            case 0x61: c = j == k; break;  // f64.eq
            case 0x62: c = j != k; break;  // f64.ne
            case 0x63: c = j <  k; break;  // f64.lt
            case 0x64: c = j >  k; break;  // f64.gt
            case 0x65: c = j <= k; break;  // f64.le
            case 0x66: c = j >= k; break;  // f64.ge
            }
            stack[m->sp].value_type = I32;
            stack[m->sp].value.uint32 = c;
            continue;

        //
        // Numeric operators
        //

        // unary i32
	case 0x67:
	case 0x68:
	case 0x69:
            a = stack[m->sp].value.uint32;
            switch (opcode) {
            case 0x67: c = a==0 ? 32 : clz(a); break; // i32.clz
            case 0x68: c = a==0 ? 32 : ctz(a); break; // i32.ctz
            case 0x69: c = popcnt(a); break;        // i32.popcnt
            }
            stack[m->sp].value.uint32 = c;
            continue;

        // unary i64
	case 0x79:
	case 0x7a:
	case 0x7b:
            d = stack[m->sp].value.uint64;
            switch (opcode) {
            case 0x79: f = d==0 ? 64 : clzll(d); break; // i64.clz
            case 0x7a: f = d==0 ? 64 : ctzll(d); break; // i64.ctz
            case 0x7b: f = popcntll(d); break;        // i64.popcnt
            }
            stack[m->sp].value.uint64 = f;
            continue;

        // unary f32
        case 0x8b: stack[m->sp].value.f32
                   = fabs(stack[m->sp].value.f32); break;  // f32.abs
        case 0x8c: stack[m->sp].value.f32
                   = -stack[m->sp].value.f32; break;       // f32.neg
        case 0x8d: stack[m->sp].value.f32
                   = ceil(stack[m->sp].value.f32); break;  // f32.ceil
        case 0x8e: stack[m->sp].value.f32
                   = floor(stack[m->sp].value.f32); break; // f32.floor
        case 0x8f: stack[m->sp].value.f32
                   = trunc(stack[m->sp].value.f32); break; // f32.trunc
        case 0x90: stack[m->sp].value.f32
                   = wa_rint(stack[m->sp].value.f32); break; // f32.nearest
        case 0x91: stack[m->sp].value.f32
                   = sqrt(stack[m->sp].value.f32); break;  // f32.sqrt

        // unary f64
        case 0x99: stack[m->sp].value.f64
                   = fabs(stack[m->sp].value.f64); break;  // f64.abs
        case 0x9a: stack[m->sp].value.f64
                   = -stack[m->sp].value.f64; break;       // f64.neg
        case 0x9b: stack[m->sp].value.f64
                   = ceil(stack[m->sp].value.f64); break;  // f64.ceil
        case 0x9c: stack[m->sp].value.f64
                   = floor(stack[m->sp].value.f64); break; // f64.floor
        case 0x9d: stack[m->sp].value.f64
                   = trunc(stack[m->sp].value.f64); break; // f64.trunc
        case 0x9e: stack[m->sp].value.f64
                   = wa_rint(stack[m->sp].value.f64); break; // f64.nearest
        case 0x9f: stack[m->sp].value.f64
                   = sqrt(stack[m->sp].value.f64); break;  // f64.sqrt

        // i32 binary
	case 0x6a:
	case 0x6b:
	case 0x6c:
	case 0x6d:
	case 0x6e:
	case 0x6f:
	case 0x70:
	case 0x71:
	case 0x72:
	case 0x73:
	case 0x74:
	case 0x75:
	case 0x76:
	case 0x77:
	case 0x78:
            a = stack[m->sp-1].value.uint32;
            b = stack[m->sp].value.uint32;
            m->sp -= 1;
            if (opcode >= 0x6d && opcode <= 0x70 && b == 0) {
                sprintf(exception, "integer divide by zero");
                return false;
            }
            switch (opcode) {
            //case 0x6a: o = __builtin_add_overflow(a, b, &c); break;  // i32.add
            //case 0x6b: o = __builtin_sub_overflow(a, b, &c); break;  // i32.sub
            case 0x6a: c = a + b; break;  // i32.add
            case 0x6b: c = a - b; break;  // i32.sub
            case 0x6c: c = a * b; break;  // i32.mul
            case 0x6d: if (a == 0x80000000 && b == -1) {
                           sprintf(exception, "integer overflow");
                           return false;
                       }
                       c = (int32_t)a / (int32_t)b; break;  // i32.div_s
            case 0x6e: c = a / b; break;  // i32.div_u
            case 0x6f: if (a == 0x80000000 && b == -1) {
                           c = 0;
                       } else {
                           c = (int32_t)a % (int32_t)b;
                       }; break;  // i32.rem_s
            case 0x70: c = a % b; break;  // i32.rem_u
            case 0x71: c = a & b; break;  // i32.and
            case 0x72: c = a | b; break;  // i32.or
            case 0x73: c = a ^ b; break;  // i32.xor
            case 0x74: c = a << b; break; // i32.shl
            case 0x75: c = (int32_t)a >> b; break; // i32.shr_s
            case 0x76: c = a >> b; break; // i32.shr_u
            case 0x77: c = rotl32(a, b); break; // i32.rotl
            case 0x78: c = rotr32(a, b); break; // i32.rotr
            }
            //if (o == 1) {
            //    sprintf(exception, "integer overflow");
            //    return false;
            //}
            stack[m->sp].value.uint32 = c;
            continue;

        // i64 binary
case 0x7c:
case 0x7d:
case 0x7e:
case 0x7f:                
case 0x80:
case 0x81:                
case 0x82:
case 0x83:
case 0x84:
case 0x85:
case 0x86:
case 0x87:
case 0x88:
case 0x89:
case 0x8a:
            d = stack[m->sp-1].value.uint64;
            e = stack[m->sp].value.uint64;
            m->sp -= 1;
            if (opcode >= 0x7f && opcode <= 0x82 && e == 0) {
                sprintf(exception, "integer divide by zero");
                return false;
            }
            switch (opcode) {
            case 0x7c: f = d + e; break;  // i64.add
            case 0x7d: f = d - e; break;  // i64.sub
            case 0x7e: f = d * e; break;  // i64.mul
            case 0x7f: if (d == 0x8000000000000000 && e == -1) {
                           sprintf(exception, "integer overflow");
                           return false;
                       }
                       f = (int64_t)d / (int64_t)e; break;  // i64.div_s
            case 0x80: f = d / e; break;  // i64.div_u
            case 0x81: if (d == 0x8000000000000000 && e == -1) {
                           f = 0;
                       } else {
                           f = (int64_t)d % (int64_t)e;
                       }
                       break;  // i64.rem_s
            case 0x82: f = d % e; break;  // i64.rem_u
            case 0x83: f = d & e; break;  // i64.and
            case 0x84: f = d | e; break;  // i64.or
            case 0x85: f = d ^ e; break;  // i64.xor
            case 0x86: f = d << e; break; // i64.shl
            case 0x87: f = ((int64_t)d) >> e; break; // i64.shr_s
            case 0x88: f = d >> e; break; // i64.shr_u
            case 0x89: f = rotl64(d, e); break; // i64.rotl
            case 0x8a: f = rotr64(d, e); break; // i64.rotr
            }
            stack[m->sp].value.uint64 = f;
            continue;

        // f32 binary
            case 0x92:case 0x93:case 0x94:case 0x95:case 0x96:case 0x97:case 0x98:
                
            g = stack[m->sp-1].value.f32;
            h = stack[m->sp].value.f32;
            m->sp -= 1;
            switch (opcode) {
            case 0x92: i = g + h; break;  // f32.add
            case 0x93: i = g - h; break;  // f32.sub
            case 0x94: i = g * h; break;  // f32.mul
            case 0x95: i = g / h; break;  // f32.div
            case 0x96: i = wa_fmin(g, h); break;  // f32.min
            case 0x97: i = wa_fmax(g, h); break;  // f32.max
            case 0x98: i = wa_signbit(h) ? -fabs(g) : fabs(g); break;  // f32.copysign
            }
            stack[m->sp].value.f32 = i;
            continue;

        // f64 binary
            case 0xa0:case 0xa1:case 0xa2:case 0xa3:case 0xa4:case 0xa5:case 0xa6:
            j = stack[m->sp-1].value.f64;
            k = stack[m->sp].value.f64;
            m->sp -= 1;
            switch (opcode) {
            case 0xa0: l = j + k; break;  // f64.add
            case 0xa1: l = j - k; break;  // f64.sub
            case 0xa2: l = j * k; break;  // f64.mul
            case 0xa3: l = j / k; break;  // f64.div
            case 0xa4: l = wa_fmin(j, k); break;  // f64.min
            case 0xa5: l = wa_fmax(j, k); break;  // f64.max
            case 0xa6: l = wa_signbit(k) ? -fabs(j) : fabs(j); break;  // f64.copysign
            }
            stack[m->sp].value.f64 = l;
            continue;

        // conversion operations
        //case 0xa7 ... 0xbb:
        case 0xa7: stack[m->sp].value.uint64 &= 0x00000000ffffffff;
                   stack[m->sp].value_type = I32; break;  // i32.wrap/i64
        case 0xa8: if (isnan(stack[m->sp].value.f32)) {
                       sprintf(exception, "invalid conversion to integer");
                       return false;
                   } else if (stack[m->sp].value.f32 >= INT32_MAX ||
                              stack[m->sp].value.f32 < INT32_MIN) {
                       sprintf(exception, "integer overflow");
                       return false;
                   }
                   stack[m->sp].value.int32 = stack[m->sp].value.f32;
                   stack[m->sp].value_type = I32; break;  // i32.trunc_s/f32
        case 0xa9: if (isnan(stack[m->sp].value.f32)) {
                       sprintf(exception, "invalid conversion to integer");
                       return false;
                   } else if (stack[m->sp].value.f32 >= UINT32_MAX ||
                              stack[m->sp].value.f32 <= -1) {
                       sprintf(exception, "integer overflow");
                       return false;
                   }
                   stack[m->sp].value.uint32 = stack[m->sp].value.f32;
                   stack[m->sp].value_type = I32; break;  // i32.trunc_u/f32
        case 0xaa: if (isnan(stack[m->sp].value.f64)) {
                       sprintf(exception, "invalid conversion to integer");
                       return false;
                   } else if (stack[m->sp].value.f64 > INT32_MAX ||
                              stack[m->sp].value.f64 < INT32_MIN) {
                       sprintf(exception, "integer overflow");
                       return false;
                   }
                   stack[m->sp].value.int32 = stack[m->sp].value.f64;
                   stack[m->sp].value_type = I32; break;  // i32.trunc_s/f64
        case 0xab: if (isnan(stack[m->sp].value.f64)) {
                       sprintf(exception, "invalid conversion to integer");
                       return false;
                   } else if (stack[m->sp].value.f64 > UINT32_MAX ||
                              stack[m->sp].value.f64 <= -1) {
                       sprintf(exception, "integer overflow");
                       return false;
                   }
                   stack[m->sp].value.uint32 = stack[m->sp].value.f64;
                   stack[m->sp].value_type = I32; break;  // i32.trunc_u/f64
        case 0xac: stack[m->sp].value.uint64 = stack[m->sp].value.uint32;
                   sext_32_64(&stack[m->sp].value.uint64);
                   stack[m->sp].value_type = I64; break;  // i64.extend_s/i32
        case 0xad: stack[m->sp].value.uint64 = stack[m->sp].value.uint32;
                   stack[m->sp].value_type = I64; break;  // i64.extend_u/i32
        case 0xae: if (isnan(stack[m->sp].value.f32)) {
                       sprintf(exception, "invalid conversion to integer");
                       return false;
                   } else if (stack[m->sp].value.f32 >= INT64_MAX ||
                              stack[m->sp].value.f32 < INT64_MIN) {
                       sprintf(exception, "integer overflow");
                       return false;
                   }
                   stack[m->sp].value.int64 = stack[m->sp].value.f32;
                   stack[m->sp].value_type = I64; break;  // i64.trunc_s/f32
        case 0xaf: if (isnan(stack[m->sp].value.f32)) {
                       sprintf(exception, "invalid conversion to integer");
                       return false;
                   } else if (stack[m->sp].value.f32 >= UINT64_MAX ||
                              stack[m->sp].value.f32 <= -1) {
                       sprintf(exception, "integer overflow");
                       return false;
                   }
                   stack[m->sp].value.uint64 = stack[m->sp].value.f32;
                   stack[m->sp].value_type = I64; break;  // i64.trunc_u/f32
        case 0xb0: if (isnan(stack[m->sp].value.f64)) {
                       sprintf(exception, "invalid conversion to integer");
                       return false;
                   } else if (stack[m->sp].value.f64 >= INT64_MAX ||
                              stack[m->sp].value.f64 < INT64_MIN) {
                       sprintf(exception, "integer overflow");
                       return false;
                   }
                   stack[m->sp].value.int64 = stack[m->sp].value.f64;
                   stack[m->sp].value_type = I64; break;  // i64.trunc_s/f64
        case 0xb1: if (isnan(stack[m->sp].value.f64)) {
                       sprintf(exception, "invalid conversion to integer");
                       return false;
                   } else if (stack[m->sp].value.f64 >= UINT64_MAX ||
                              stack[m->sp].value.f64 <= -1) {
                       sprintf(exception, "integer overflow");
                       return false;
                   }
                   stack[m->sp].value.uint64 = stack[m->sp].value.f64;
                   stack[m->sp].value_type = I64; break;  // i64.trunc_u/f64
        case 0xb2: stack[m->sp].value.f32 = stack[m->sp].value.int32;
                   stack[m->sp].value_type = F32; break;  // f32.convert_s/i32
        case 0xb3: stack[m->sp].value.f32 = stack[m->sp].value.uint32;
                   stack[m->sp].value_type = F32; break;  // f32.convert_u/i32
        case 0xb4: stack[m->sp].value.f32 = stack[m->sp].value.int64;
                   stack[m->sp].value_type = F32; break;  // f32.convert_s/i64
        case 0xb5: stack[m->sp].value.f32 = stack[m->sp].value.uint64;
                   stack[m->sp].value_type = F32; break;  // f32.convert_u/i64
        case 0xb6: stack[m->sp].value.f32 = stack[m->sp].value.f64;
                   stack[m->sp].value_type = F32; break;  // f32.demote/f64
        case 0xb7: stack[m->sp].value.f64 = stack[m->sp].value.int32;
                   stack[m->sp].value_type = F64; break;  // f64.convert_s/i32
        case 0xb8: stack[m->sp].value.f64 = stack[m->sp].value.uint32;
                   stack[m->sp].value_type = F64; break;  // f64.convert_u/i32
        case 0xb9: stack[m->sp].value.f64 = stack[m->sp].value.int64;
                   stack[m->sp].value_type = F64; break;  // f64.convert_s/i64
        case 0xba: stack[m->sp].value.f64 = stack[m->sp].value.uint64;
                   stack[m->sp].value_type = F64; break;  // f64.convert_u/i64
        case 0xbb: stack[m->sp].value.f64 = stack[m->sp].value.f32;
                   stack[m->sp].value_type = F64; break;  // f64.promote/f32

        // reinterpretations
        case 0xbc: stack[m->sp].value_type = I32; break;  // i32.reinterpret/f32
        case 0xbd: stack[m->sp].value_type = I64; break;  // i64.reinterpret/f64
        case 0xbe: //memmove(&stack[m->sp].value.f32, &stack[m->sp].value.uint32, 4);
                   stack[m->sp].value_type = F32; break;  // f32.reinterpret/i32
        case 0xbf: stack[m->sp].value_type = F64; break;  // f64.reinterpret/i64

        default:
            sprintf(exception, "unrecognized opcode 0x%x", opcode);
            return false;
        }
    }
    return false; // We shouldn't reach here
}

void run_init_expr(Module *m, uint8_t type, uint32_t *pc) {
    // Run the init_expr
    Block block = {  0x01,0,
                    get_block_type(type),0,0,
                    *pc,0,0,0,0,0,0,0 };
    m->pc = *pc;
    push_block(m, &block, m->sp);
    // WARNING: running code here to get initial value!
    info("  running init_expr at 0x%x: %s\n",
            m->pc, block_repr(&block));
    interpret(m);
    *pc = m->pc;

    ASSERT(m->stack[m->sp].value_type == type,
            "init_expr type mismatch 0x%x != 0x%x",
            m->stack[m->sp].value_type, type);
}



//
// Public API
//

uint32_t get_export_fidx(Module *m, char *name) {
    uint32_t f;
    // Find name function index
    for (f=0; f<m->function_count; f++) {
        char *fname = m->functions[f].export_name;
        if (!fname) { continue; }
        if (strncmp(name, fname, 1024) == 0) {
            return f;
        }
    }
    return -1;
}

Module *load_module(uint8_t *bytes, uint32_t byte_count, Options options) {
    uint8_t   vt;
    uint32_t  pos = 0, word;
    Module   *m;
uint32_t id;
 uint32_t slen;
 uint32_t end_pos;
 char *name;
 StackValue* glob;
  uint32_t memorysize;
   uint32_t tablesize;
   uint32_t c,p,r,import_count,module_len,field_len,gidx,external_kind,type_index,fidx,f,table_count,tidx,memory_count,global_count,type,g,e,n,s,b,l,export_count,element_count,offset,num_elem,seg_count,size,body_count,body_size,payload_start,local_count,save_pos, lidx, lecount;
   int start_pos;
   char* import_module,*import_field;
   uint8_t content_type,mutability,type1;
   
   void *val;
    char *err;
    char  *sym;
    
    Block *func;
    Table *tval;
    Memory *mval;
    Block *functions,*function;
   
    // Allocate the module
#ifdef LOW_MEMORY_CONFIG
    warn("Using low memory configuration: sizeof(Module)=%ul.\n", (unsigned int) sizeof(Module));
    dumpMemoryInfo();
#endif
    m = acalloc(1, sizeof(Module), "Module");
    m->options = options;

    // Empty stacks
    m->sp  = -1;
    m->fp  = -1;
    m->csp = -1;

    m->bytes = bytes;
    m->byte_count = byte_count;
    m->block_lookup = acalloc(m->byte_count, sizeof(Block *),
                                "function->block_lookup");
    m->start_function = -1;

    // Check the module
    pos = 0;
    word = read_uint32(bytes, &pos);
    ASSERT(word == WA_MAGIC, "Wrong module magic 0x%x\n", word);
    word = read_uint32(bytes, &pos);
    ASSERT(word == WA_VERSION, "Wrong module version 0x%x\n", word);

    // Read the sections
    while (pos < byte_count) {
        id = read_LEB(bytes, &pos, 7);
        slen = read_LEB(bytes, &pos, 32);
        start_pos = pos;
        debug("Reading section %d at 0x%x, length %d\n", id, pos, slen);
        switch (id) {
        case 0:
            warn("Parsing Custom(0) section (length: 0x%x)\n", slen);
            end_pos = pos+slen;
            name = read_string(bytes, &pos, NULL);
            warn("  Section name '%s'\n", name);
            if (strncmp(name, "dylink", 7) == 0) {
                // https://github.com/WebAssembly/tool-conventions/blob/master/DynamicLinking.md
                // TODO: make use of these
                memorysize = read_LEB(bytes, &pos, 32);
                tablesize = read_LEB(bytes, &pos, 32);
                (void)memorysize; (void)tablesize;
            } else {
                error("Ignoring unknown custom section '%s'\n", name);
            }
            pos = end_pos;
            break;
        case 1:
            warn("Parsing Type(1) section (length: 0x%x)\n", slen);
            m->type_count = read_LEB(bytes, &pos, 32);
            m->types = acalloc(m->type_count, sizeof(Type),
                                 "Module->types");

            for (c=0; c<m->type_count; c++) {
                Type *type = &m->types[c];
                type->form = read_LEB(bytes, &pos, 7);
                type->param_count = read_LEB(bytes, &pos, 32);
                type->params = acalloc(type->param_count, sizeof(uint32_t),
                                      "type->params");
                for (p=0; p<type->param_count; p++) {
                    type->params[p] = read_LEB(bytes, &pos, 32);
                }
                type->result_count = read_LEB(bytes, &pos, 32);
                type->results = acalloc(type->result_count, sizeof(uint32_t),
                                       "type->results");
                for (r=0; r<type->result_count; r++) {
                    type->results[r] = read_LEB(bytes, &pos, 32);
                }
                // TODO: calculate this above and remove get_type_mask
                type->mask = get_type_mask(type);
                debug("  form: 0x%x, params: %d, results: %d\n",
                      type->form, type->param_count, type->result_count);
            }
            break;
        case 2:
            warn("Parsing Import(2) section (length: 0x%x)\n", slen);
            import_count = read_LEB(bytes, &pos, 32);
            for (gidx=0; gidx<import_count; gidx++) {
                import_module = read_string(bytes, &pos, &module_len);
                import_field = read_string(bytes, &pos, &field_len);

                external_kind = bytes[pos++];

                debug("  import: %d/%d, external_kind: %d, %s.%s\n",
                      gidx, import_count, external_kind, import_module,
                      import_field);

                type_index = 0;
                content_type = 0;

                switch (external_kind) {
                case 0x00: // Function
                    type_index = read_LEB(bytes, &pos, 32); break;
                case 0x01: // Table
                    parse_table_type(m, &pos); break;
                case 0x02: // Memory
                    parse_memory_type(m, &pos); break;
                case 0x03: // Global
                    content_type = read_LEB(bytes, &pos, 7);
                    // TODO: use mutability
                    mutability = read_LEB(bytes, &pos, 1);
                    (void)mutability; break;
                }

                sym = malloc(module_len + field_len + 5);

/*
                do {
                    // Try using module as handle filename
                    if (resolvesym(import_module, import_field, &val, &err)) { break; }

                    // Try concatenating module and field using underscores
                    // Also, replace '-' with '_'
                    sprintf(sym, "_%s__%s_", import_module, import_field);
                    int sidx = -1;
                    while (sym[++sidx]) {
                        if (sym[sidx] == '-') { sym[sidx] = '_'; }
                    }
                    if (resolvesym(NULL, sym, &val, &err)) { break; }

                    // If enabled, try without the leading underscore (added
                    // by emscripten for external symbols)
                    if (m->options.dlsym_trim_underscore &&
                        (strncmp("env", import_module, 4) == 0) &&
                        (strncmp("_", import_field, 1) == 0)) {
                        sprintf(sym, "%s", import_field+1);
                        if (resolvesym(NULL, sym, &val, &err)) { break; }
                    }

                    // Try the plain symbol by itself with module name/handle
                    sprintf(sym, "%s", import_field);
                    if (resolvesym(NULL, sym, &val, &err)) { break; }

                    FATAL("Error: %s\n", err);
                } while(false);
                */
                /*sprintf(sym, "%s", import_field);
                FATAL("Error: wac's functinality to load import function from DLL has been removed. %s\n", err);              
                free(sym);
                exit(-1);*/

                // Store in the right place
                switch (external_kind) {
                case 0x00:  // Function
                    fidx = m->function_count;
                    m->import_count += 1;
                    m->function_count += 1;
                    m->functions = arecalloc(m->functions,
                                           fidx, m->import_count,
                                           sizeof(Block), "Block(imports)");

                    func = &m->functions[fidx];
                    func->import_module = import_module;
                    func->import_field = import_field;
                    func->type = &m->types[type_index];
                    debug("  import: %s.%s, fidx: 0x%x, type_index: 0x%x\n",
                        func->import_module, func->import_field, fidx,
                        type_index);

                    func->func_ptr = val;
                    break;
                case 0x01:  // Table
                    ASSERT(!m->table.entries,
                           "More than 1 table not supported\n");
                    tval = val;
                    m->table.entries = val;
                    ASSERT(m->table.initial <= tval->maximum,
                        "Imported table is not large enough\n");
                    warn("  setting table.entries to: %p\n", *(uint32_t **)val);
                    m->table.entries = *(uint32_t **)val;
                    m->table.size = tval->size;
                    m->table.maximum = tval->maximum;
                    m->table.entries = tval->entries;
                    break;
                case 0x02:  // Memory
                    ASSERT(!m->memory.bytes,
                           "More than 1 memory not supported\n");
                    mval = val;
                    ASSERT(m->memory.initial <= mval->maximum,
                        "Imported memory is not large enough\n");
                    warn("  setting memory pages: %d, max: %d, bytes: %p\n",
                         mval->pages, mval->maximum, mval->bytes);
                    m->memory.pages = mval->pages;
                    m->memory.maximum = mval->maximum;
                    m->memory.bytes = mval->bytes;
                    break;
                case 0x03:  // Global
                    m->global_count += 1;
                    m->globals = arecalloc(m->globals,
                                           m->global_count-1, m->global_count,
                                           sizeof(StackValue), "globals");
                    glob = &m->globals[m->global_count-1];
                    glob->value_type = content_type;

                    switch (content_type) {
                    case I32: memcpy(&glob->value.uint32, val, 4); break;
                    case I64: memcpy(&glob->value.uint64, val, 8); break;
                    case F32: memcpy(&glob->value.f32, val, 4); break;
                    case F64: memcpy(&glob->value.f64, val, 8); break;
                    }
                    debug("    setting global %d (content_type %d) to %p: %s\n",
                           m->global_count-1, content_type, val, value_repr(glob));
                    break;
                default:
                    FATAL("Import of kind %d not supported\n", external_kind);
                }

            }
            break;
        case 3:
            warn("Parsing Function(3) section (length: 0x%x)\n", slen);
            m->function_count += read_LEB(bytes, &pos, 32);
            debug("  import_count: %d, new count: %d\n",
                  m->import_count, m->function_count);

            
            functions = acalloc(m->function_count, sizeof(Block),
                                "Block(function)");
            if (m->import_count != 0) {
                memcpy(functions, m->functions, sizeof(Block)*m->import_count);
            }
            m->functions = functions;

            for (f=m->import_count; f<m->function_count; f++) {
                tidx = read_LEB(bytes, &pos, 32);
                m->functions[f].fidx = f;
                m->functions[f].type = &m->types[tidx];
                debug("  function fidx: 0x%x, tidx: 0x%x\n",
                      f, tidx);
            }
            break;
        case 4:
            warn("Parsing Table(4) section\n");
            table_count = read_LEB(bytes, &pos, 32);
            debug("  table count: 0x%x\n", table_count);
            ASSERT(table_count == 1, "More than 1 table not supported");

            // Allocate the table
            //for (uint32_t c=0; c<table_count; c++) {
            parse_table_type(m, &pos);
            // If it's not imported then don't mangle it
            m->options.mangle_table_index = false;
            m->table.entries = acalloc(m->table.size,
                                       sizeof(uint32_t),
                                       "Module->table.entries");
            //}
            break;
        case 5:
            warn("Parsing Memory(5) section\n");
            memory_count = read_LEB(bytes, &pos, 32);
            debug("  memory count: 0x%x\n", memory_count);
            ASSERT(memory_count == 1, "More than 1 memory not supported\n");

            // Allocate memory
            //for (uint32_t c=0; c<memory_count; c++) {
            parse_memory_type(m, &pos);
            debug("parse memory section: about to allocate %i pages, total size %i Bytes ... \n", (int) m->memory.pages, (int) m->memory.pages*PAGE_SIZE);
            m->memory.bytes = acalloc(1,
                                    m->memory.pages*PAGE_SIZE,
                                    "parse memory section\n");
            //m->memory.bytes = acalloc(m->memory.pages*PAGE_SIZE,
            //                        sizeof(uint32_t),  // GGr: shoudn't this be bytes (means 1) ?!
            //                        "parse memory section: Module->memory.bytes\n");
            //}
            break;
        case 6:
            warn("Parsing Global(6) section\n");
            global_count = read_LEB(bytes, &pos, 32);
            for (g=0; g<global_count; g++) {
                // Same allocation Import of global above
                type1 = read_LEB(bytes, &pos, 7);
                // TODO: use mutability
                mutability = read_LEB(bytes, &pos, 1);
                (void)mutability;
                gidx = m->global_count;
                m->global_count += 1;
                m->globals = arecalloc(m->globals, gidx, m->global_count,
                                        sizeof(StackValue), "globals");
                m->globals[gidx].value_type = type1;

                // Run the init_expr to get global value
                run_init_expr(m, type1, &pos);

                m->globals[gidx] = m->stack[m->sp--];
            }
            pos = start_pos+slen;
            break;
        case 7:
            warn("Parsing Export(7) section (length: 0x%x)\n", slen);
            export_count = read_LEB(bytes, &pos, 32);
            for (e=0; e<export_count; e++) {
                char *name = read_string(bytes, &pos, NULL);

                uint32_t kind = bytes[pos++];
                uint32_t index = read_LEB(bytes, &pos, 32);
                if (kind != 0x00) {
                    warn("  ignoring non-function export '%s'"
                         " kind 0x%x index 0x%x\n",
                         name, kind, index);
                    continue;
                }
                m->functions[index].export_name = name;
                debug("  export: %s (0x%x)\n", name, index);
            }
            break;
        case 8:
            warn("Parsing Start(8) section (length: 0x%x)\n", slen);
            m->start_function = read_LEB(bytes, &pos, 32);
            break;
        case 9:
            warn("Parsing Element(9) section (length: 0x%x)\n", slen);
            element_count = read_LEB(bytes, &pos, 32);

            for(c=0; c<element_count; c++) {
                uint32_t index = read_LEB(bytes, &pos, 32);
                ASSERT(index == 0, "Only 1 default table in MVP");

                // Run the init_expr to get offset
                run_init_expr(m, I32, &pos);

                offset = m->stack[m->sp--].value.uint32;

                if (m->options.mangle_table_index) {
                    // offset is the table address + the index (not sized for the
                    // pointer size) so get the actual (sized) index
                    debug("   origin offset: 0x%x, table addr: 0x%x, new offset: 0x%x\n",
                          offset, (uint32_t)m->table.entries,
                          offset - (uint32_t)m->table.entries);
                    //offset = offset - (uint32_t)((uint64_t)m->table.entries & 0xFFFFFFFF);
                    offset = offset - (uint32_t)m->table.entries;
                }

                num_elem = read_LEB(bytes, &pos, 32);
                warn("  table.entries: %p, offset: 0x%x\n", m->table.entries, offset);
                if (!m->options.disable_memory_bounds) {
                    ASSERT(offset+num_elem <= m->table.size,
                        "table overflow %d+%d > %d\n", offset, num_elem,
                        m->table.size);
                }
                for (n=0; n<num_elem; n++) {
                    debug("  write table entries %p, offset: 0x%x, n: 0x%x, addr: %p\n",
                            m->table.entries, offset, n, &m->table.entries[offset+n]);
                    m->table.entries[offset+n] = read_LEB(bytes, &pos, 32);
                }
            }
            pos = start_pos+slen;
            break;
        // 9 and 11 are similar so keep them together, 10 is below 11
        case 11:
            warn("Parsing Data(11) section (length: 0x%x)\n", slen);
            seg_count = read_LEB(bytes, &pos, 32);
            for (s=0; s<seg_count; s++) {
                uint32_t midx = read_LEB(bytes, &pos, 32);
                ASSERT(midx == 0, "Only 1 default memory in MVP");

                // Run the init_expr to get the offset
                run_init_expr(m, I32, &pos);

                offset = m->stack[m->sp--].value.uint32;

                // Copy the data to the memory offset
                size = read_LEB(bytes, &pos, 32);
                if (!m->options.disable_memory_bounds) {
                    ASSERT(offset+size <= m->memory.pages*PAGE_SIZE,
                        "memory overflow %d+%d > %d\n", offset, size,
                        (uint32_t)(m->memory.pages*PAGE_SIZE));
                }
                info("  setting 0x%x bytes of memory at 0x%x + offset 0x%x\n",
//                     size, m->memory.bytes, offset);
                     size, (unsigned int) m->memory.bytes, offset);
                memcpy(m->memory.bytes+offset, bytes+pos, size);
                pos += size;
            }

            break;
        case 10:
            warn("Parsing Code(10) section (length: 0x%x)\n", slen);
            body_count = read_LEB(bytes, &pos, 32);
            for (b=0; b<body_count; b++) {
                function = &m->functions[m->import_count+b];
                body_size = read_LEB(bytes, &pos, 32);
                payload_start = pos;
                local_count = read_LEB(bytes, &pos, 32);

                // Local variable handling

                // Get number of locals for alloc
                save_pos = pos;
                function->local_count = 0;
                for (l=0; l<local_count; l++) {
                    lecount = read_LEB(bytes, &pos, 32);
                    function->local_count += lecount;
                    tidx =  read_LEB(bytes, &pos, 7);
                    (void)tidx; // TODO: use tidx?
                }
                function->locals = acalloc(function->local_count,
                                           sizeof(uint32_t),
                                           "function->locals");

                // Restore position and read the locals
                pos = save_pos;
                lidx = 0;
                for (l=0; l<local_count; l++) {
                    lecount = read_LEB(bytes, &pos, 32);
                    vt = read_LEB(bytes, &pos, 7);
                    for (l=0; l<lecount; l++) {
                        function->locals[lidx++] = vt;
                    }
                }

                function->start_addr = pos;
                function->end_addr = payload_start + body_size - 1;
                function->br_addr = function->end_addr;
                ASSERT(bytes[function->end_addr] == 0x0b,
                       "Code section did not end with 0x0b\n");
                pos = function->end_addr + 1;
            }
            break;
        default:
            FATAL("Section %d unimplemented\n", id);
            pos += slen;
        }

    }


    find_blocks(m);

    if (m->start_function != -1) {
        uint32_t fidx = m->start_function;
        bool     result;
        warn("Running start function 0x%x ('%s')\n",
             fidx, m->functions[fidx].export_name);

        if (TRACE && DEBUG) { dump_stacks(m); }

        if (fidx < m->import_count) {
            thunk_out(m, fidx);     // import/thunk call
        } else {
            setup_call(m, fidx);    // regular function call
        }

        if (m->csp < 0) {
            // start function was a direct external call
            result = true;
        } else {
            // run the function setup by setup_call
            result = interpret(m);
        }
        if (!result) {
            FATAL("Exception: %s\n", exception);
        }
    }

    return m;
}

// if entry == NULL,  attempt to invoke 'main' or '_main'
// Return value of false means exception occured
bool invoke(Module *m, uint32_t fidx) {
    bool      result;

    if (TRACE && DEBUG) { dump_stacks(m); }

    setup_call(m, fidx);

    result = interpret(m);

    if (TRACE && DEBUG) { dump_stacks(m); }

    return result;
}
