#include "pcap_filter.h"
#include "net_util.h"
#include "weblog.h"
#include <string.h>
#include <ctype.h>

#define Serial Out

// =============================================================================
// Filter AST node types
// =============================================================================
enum FilterOp : uint8_t {
    FOP_TRUE,       // always match
    FOP_FALSE,      // never match
    FOP_AND,        // left AND right
    FOP_OR,         // left OR right
    FOP_NOT,        // NOT left
    // Protocol primitives
    FOP_PROTO_ARP,
    FOP_PROTO_IP,
    FOP_PROTO_IP6,
    FOP_PROTO_TCP,
    FOP_PROTO_UDP,
    FOP_PROTO_ICMP,
    FOP_PROTO_VLAN,
    // Host / net / port
    FOP_HOST,       // src or dst matches ip
    FOP_SRC_HOST,
    FOP_DST_HOST,
    FOP_NET,        // src or dst in subnet
    FOP_SRC_NET,
    FOP_DST_NET,
    FOP_PORT,       // src or dst port
    FOP_SRC_PORT,
    FOP_DST_PORT,
    FOP_PORTRANGE,
    FOP_SRC_PORTRANGE,
    FOP_DST_PORTRANGE,
    // Ether host
    FOP_ETHER_HOST,
    FOP_ETHER_SRC,
    FOP_ETHER_DST,
};

struct FilterNode {
    FilterOp op;
    uint8_t  left;   // index of left child (for AND/OR/NOT)
    uint8_t  right;  // index of right child (for AND/OR)
    // Payload for primitives:
    union {
        struct { uint32_t ip; uint32_t mask; } net;   // host uses mask=0xFFFFFFFF
        struct { uint16_t lo; uint16_t hi; } port;    // port uses lo==hi
        uint8_t mac[6];
    };
};

// =============================================================================
// Static filter state
// =============================================================================
static FilterNode _nodes[PCAP_FILTER_MAX_NODES];
static uint8_t _nodeCount = 0;
static uint8_t _rootNode  = 0;
static bool    _filterActive = false;

// =============================================================================
// Tokenizer
// =============================================================================
#define MAX_TOKENS 64

enum TokenType : uint8_t {
    TOK_WORD,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_END,
};

struct Token {
    TokenType type;
    const char *start;
    uint8_t len;
};

static Token _tokens[MAX_TOKENS];
static uint8_t _tokenCount;
static uint8_t _tokenPos;

static bool _tokenize(const char *expr)
{
    _tokenCount = 0;
    const char *p = expr;
    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;
        if (_tokenCount >= MAX_TOKENS) return false;

        Token &t = _tokens[_tokenCount];
        if (*p == '(') { t.type = TOK_LPAREN; t.start = p; t.len = 1; p++; }
        else if (*p == ')') { t.type = TOK_RPAREN; t.start = p; t.len = 1; p++; }
        else {
            t.type = TOK_WORD;
            t.start = p;
            while (*p && !isspace((unsigned char)*p) && *p != '(' && *p != ')') p++;
            t.len = p - t.start;
        }
        _tokenCount++;
    }
    _tokens[_tokenCount] = {TOK_END, nullptr, 0};
    _tokenPos = 0;
    return true;
}

static inline Token &_peek() { return _tokens[_tokenPos]; }
static inline Token &_next() { return _tokens[_tokenPos++]; }

static inline bool _wordIs(const Token &t, const char *w)
{
    return t.type == TOK_WORD && t.len == strlen(w) &&
           strncasecmp(t.start, w, t.len) == 0;
}

// =============================================================================
// Helpers: parse IP, MAC, CIDR
// =============================================================================
static bool _parseIp(const Token &t, uint32_t *ip)
{
    char buf[20];
    if (t.len >= sizeof(buf)) return false;
    memcpy(buf, t.start, t.len);
    buf[t.len] = '\0';
    return strToIp(buf, ip);
}

static bool _parseCidr(const Token &t, uint32_t *ip, uint32_t *mask)
{
    char buf[24];
    if (t.len >= sizeof(buf)) return false;
    memcpy(buf, t.start, t.len);
    buf[t.len] = '\0';

    char *slash = strchr(buf, '/');
    if (!slash) {
        // No CIDR -- treat as /32
        if (!strToIp(buf, ip)) return false;
        *mask = 0xFFFFFFFFUL;
        return true;
    }
    *slash = '\0';
    if (!strToIp(buf, ip)) return false;
    int bits = atoi(slash + 1);
    if (bits < 0 || bits > 32) return false;
    *mask = bits ? (0xFFFFFFFFUL << (32 - bits)) : 0;
    *ip &= *mask;
    return true;
}

static bool _parseMac(const Token &t, uint8_t mac[6])
{
    char buf[20];
    if (t.len >= sizeof(buf) || t.len < 11) return false;
    memcpy(buf, t.start, t.len);
    buf[t.len] = '\0';
    unsigned m[6];
    if (sscanf(buf, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) != 6)
        return false;
    for (int i = 0; i < 6; i++) { if (m[i] > 255) return false; mac[i] = m[i]; }
    return true;
}

static bool _parsePort(const Token &t, uint16_t *port)
{
    char buf[8];
    if (t.len >= sizeof(buf)) return false;
    memcpy(buf, t.start, t.len);
    buf[t.len] = '\0';
    unsigned long v = strtoul(buf, nullptr, 10);
    if (v > 65535) return false;
    *port = (uint16_t)v;
    return true;
}

static bool _parsePortRange(const Token &t, uint16_t *lo, uint16_t *hi)
{
    char buf[16];
    if (t.len >= sizeof(buf)) return false;
    memcpy(buf, t.start, t.len);
    buf[t.len] = '\0';
    char *dash = strchr(buf, '-');
    if (!dash) return false;
    *dash = '\0';
    unsigned long a = strtoul(buf, nullptr, 10);
    unsigned long b = strtoul(dash + 1, nullptr, 10);
    if (a > 65535 || b > 65535 || a > b) return false;
    *lo = (uint16_t)a;
    *hi = (uint16_t)b;
    return true;
}

// =============================================================================
// Node allocation
// =============================================================================
static uint8_t _alloc(FilterOp op)
{
    if (_nodeCount >= PCAP_FILTER_MAX_NODES) return 0;
    uint8_t idx = _nodeCount++;
    memset(&_nodes[idx], 0, sizeof(FilterNode));
    _nodes[idx].op = op;
    return idx;
}

// =============================================================================
// Recursive descent parser: expr -> orExpr
//   orExpr  -> andExpr ('or' andExpr)*
//   andExpr -> unary ('and' unary)* | unary unary (implicit AND)
//   unary   -> 'not' unary | '(' expr ')' | primitive
// =============================================================================
static int _parseExpr();  // forward decl; returns node index or -1 on error

static int _parsePrimitive()
{
    Token &t = _peek();
    if (t.type != TOK_WORD) {
        Serial.println("[filter] Expected keyword.");
        return -1;
    }

    // Protocol keywords
    if (_wordIs(t, "arp"))  { _next(); return _alloc(FOP_PROTO_ARP); }
    if (_wordIs(t, "ip"))   { _next(); return _alloc(FOP_PROTO_IP); }
    if (_wordIs(t, "ip6"))  { _next(); return _alloc(FOP_PROTO_IP6); }
    if (_wordIs(t, "tcp"))  { _next(); return _alloc(FOP_PROTO_TCP); }
    if (_wordIs(t, "udp"))  { _next(); return _alloc(FOP_PROTO_UDP); }
    if (_wordIs(t, "icmp")) { _next(); return _alloc(FOP_PROTO_ICMP); }
    if (_wordIs(t, "vlan")) { _next(); return _alloc(FOP_PROTO_VLAN); }

    // Direction qualifiers
    bool isSrc = false, isDst = false;
    if (_wordIs(t, "src")) { isSrc = true; _next(); t = _peek(); }
    else if (_wordIs(t, "dst")) { isDst = true; _next(); t = _peek(); }

    // "ether host/src/dst"
    if (_wordIs(t, "ether")) {
        _next();
        Token &t2 = _peek();
        // After "ether", expect "host", "src", or "dst"
        FilterOp eop = FOP_ETHER_HOST;
        if (_wordIs(t2, "host")) { _next(); eop = FOP_ETHER_HOST; }
        else if (_wordIs(t2, "src")) { _next(); eop = FOP_ETHER_SRC; }
        else if (_wordIs(t2, "dst")) { _next(); eop = FOP_ETHER_DST; }
        // Next token must be a MAC address
        Token &mt = _peek();
        if (mt.type != TOK_WORD) { Serial.println("[filter] Expected MAC address."); return -1; }
        uint8_t idx = _alloc(eop);
        if (!_parseMac(mt, _nodes[idx].mac)) {
            Serial.println("[filter] Invalid MAC address.");
            return -1;
        }
        _next();
        return idx;
    }

    // "host <ip>"
    if (_wordIs(t, "host")) {
        _next();
        Token &ht = _peek();
        if (ht.type != TOK_WORD) { Serial.println("[filter] Expected IP after 'host'."); return -1; }
        FilterOp hop = isSrc ? FOP_SRC_HOST : (isDst ? FOP_DST_HOST : FOP_HOST);
        uint8_t idx = _alloc(hop);
        if (!_parseIp(ht, &_nodes[idx].net.ip)) {
            Serial.println("[filter] Invalid IP address.");
            return -1;
        }
        _nodes[idx].net.mask = 0xFFFFFFFFUL;
        _next();
        return idx;
    }

    // "net <ip/cidr>"
    if (_wordIs(t, "net")) {
        _next();
        Token &nt = _peek();
        if (nt.type != TOK_WORD) { Serial.println("[filter] Expected CIDR after 'net'."); return -1; }
        FilterOp nop = isSrc ? FOP_SRC_NET : (isDst ? FOP_DST_NET : FOP_NET);
        uint8_t idx = _alloc(nop);
        if (!_parseCidr(nt, &_nodes[idx].net.ip, &_nodes[idx].net.mask)) {
            Serial.println("[filter] Invalid CIDR notation.");
            return -1;
        }
        _next();
        return idx;
    }

    // "port <n>"
    if (_wordIs(t, "port")) {
        _next();
        Token &pt = _peek();
        if (pt.type != TOK_WORD) { Serial.println("[filter] Expected port number."); return -1; }
        FilterOp pop = isSrc ? FOP_SRC_PORT : (isDst ? FOP_DST_PORT : FOP_PORT);
        uint8_t idx = _alloc(pop);
        uint16_t p;
        if (!_parsePort(pt, &p)) { Serial.println("[filter] Invalid port."); return -1; }
        _nodes[idx].port.lo = p;
        _nodes[idx].port.hi = p;
        _next();
        return idx;
    }

    // "portrange <lo-hi>"
    if (_wordIs(t, "portrange")) {
        _next();
        Token &pt = _peek();
        if (pt.type != TOK_WORD) { Serial.println("[filter] Expected port range (lo-hi)."); return -1; }
        FilterOp pop = isSrc ? FOP_SRC_PORTRANGE : (isDst ? FOP_DST_PORTRANGE : FOP_PORTRANGE);
        uint8_t idx = _alloc(pop);
        if (!_parsePortRange(pt, &_nodes[idx].port.lo, &_nodes[idx].port.hi)) {
            Serial.println("[filter] Invalid port range (use lo-hi).");
            return -1;
        }
        _next();
        return idx;
    }

    // If we had a direction qualifier but no keyword matched, check if it's
    // a bare IP (src/dst <ip> as shorthand for src/dst host <ip>)
    if ((isSrc || isDst) && t.type == TOK_WORD) {
        uint32_t ip;
        if (_parseIp(t, &ip)) {
            FilterOp hop = isSrc ? FOP_SRC_HOST : FOP_DST_HOST;
            uint8_t idx = _alloc(hop);
            _nodes[idx].net.ip = ip;
            _nodes[idx].net.mask = 0xFFFFFFFFUL;
            _next();
            return idx;
        }
    }

    Serial.printf("[filter] Unexpected token: '%.*s'\r\n", (int)t.len, t.start);
    return -1;
}

static int _parseUnary()
{
    Token &t = _peek();

    // Parenthesised expression
    if (t.type == TOK_LPAREN) {
        _next();
        int node = _parseExpr();
        if (node < 0) return -1;
        Token &close = _peek();
        if (close.type != TOK_RPAREN) {
            Serial.println("[filter] Missing ')'.");
            return -1;
        }
        _next();
        return node;
    }

    // NOT
    if (_wordIs(t, "not") || (_wordIs(t, "!") && t.len == 1)) {
        _next();
        int child = _parseUnary();
        if (child < 0) return -1;
        uint8_t idx = _alloc(FOP_NOT);
        _nodes[idx].left = child;
        return idx;
    }

    return _parsePrimitive();
}

static int _parseAnd()
{
    int left = _parseUnary();
    if (left < 0) return -1;

    while (true) {
        Token &t = _peek();
        if (t.type == TOK_END || t.type == TOK_RPAREN) break;
        if (_wordIs(t, "or")) break;

        // Explicit 'and' or implicit juxtaposition
        if (_wordIs(t, "and") || (_wordIs(t, "&&") && t.len == 2)) _next();

        int right = _parseUnary();
        if (right < 0) return -1;

        uint8_t idx = _alloc(FOP_AND);
        _nodes[idx].left = left;
        _nodes[idx].right = right;
        left = idx;
    }
    return left;
}

static int _parseExpr()
{
    int left = _parseAnd();
    if (left < 0) return -1;

    while (true) {
        Token &t = _peek();
        if (!_wordIs(t, "or") && !(_wordIs(t, "||") && t.len == 2)) break;
        _next();

        int right = _parseAnd();
        if (right < 0) return -1;

        uint8_t idx = _alloc(FOP_OR);
        _nodes[idx].left = left;
        _nodes[idx].right = right;
        left = idx;
    }
    return left;
}

// =============================================================================
// Public: compile
// =============================================================================
bool pcapFilterCompile(const char *expr)
{
    pcapFilterClear();
    if (!expr || !*expr) return true;  // empty = accept all

    // Trim leading/trailing whitespace
    while (*expr && isspace((unsigned char)*expr)) expr++;
    if (!*expr) return true;

    if (!_tokenize(expr)) {
        Serial.println("[filter] Too many tokens in expression.");
        return false;
    }
    if (_tokenCount == 0) return true;

    _nodeCount = 0;
    int root = _parseExpr();
    if (root < 0) return false;

    // Ensure all tokens consumed
    if (_peek().type != TOK_END) {
        Serial.printf("[filter] Unexpected trailing token: '%.*s'\r\n",
                      (int)_peek().len, _peek().start);
        return false;
    }

    _rootNode = root;
    _filterActive = true;
    Serial.printf("[filter] Compiled: %u nodes\r\n", _nodeCount);
    return true;
}

void pcapFilterClear()
{
    _filterActive = false;
    _nodeCount = 0;
}

bool pcapFilterActive()
{
    return _filterActive;
}

// =============================================================================
// Frame evaluation helpers
// =============================================================================

// Extract EtherType (handles 802.1Q VLAN tags)
static uint16_t _ethType(const uint8_t *frame, uint16_t len, uint16_t *ipOffset)
{
    if (len < 14) { *ipOffset = 14; return 0; }
    uint16_t et = ((uint16_t)frame[12] << 8) | frame[13];
    *ipOffset = 14;
    // 802.1Q VLAN tag
    if (et == 0x8100 && len >= 18) {
        et = ((uint16_t)frame[16] << 8) | frame[17];
        *ipOffset = 18;
    }
    return et;
}

// Get IPv4 src/dst from frame (network-order -> host-order)
static bool _getIpv4(const uint8_t *frame, uint16_t len, uint16_t ipOff,
                     uint32_t *srcIp, uint32_t *dstIp, uint8_t *proto,
                     uint16_t *l4Off)
{
    if (len < ipOff + 20) return false;
    const uint8_t *iph = frame + ipOff;
    uint8_t ihl = (iph[0] & 0x0F) * 4;
    if (len < ipOff + ihl) return false;
    *srcIp = get32(iph + 12);
    *dstIp = get32(iph + 16);
    *proto = iph[9];
    *l4Off = ipOff + ihl;
    return true;
}

// Get L4 ports (TCP or UDP)
static bool _getPorts(const uint8_t *frame, uint16_t len, uint16_t l4Off,
                      uint16_t *srcPort, uint16_t *dstPort)
{
    if (len < l4Off + 4) return false;
    *srcPort = ((uint16_t)frame[l4Off] << 8) | frame[l4Off + 1];
    *dstPort = ((uint16_t)frame[l4Off + 2] << 8) | frame[l4Off + 3];
    return true;
}

// =============================================================================
// Recursive evaluator
// =============================================================================
static bool _eval(uint8_t nodeIdx, const uint8_t *frame, uint16_t len)
{
    const FilterNode &n = _nodes[nodeIdx];
    uint16_t ipOff;
    uint16_t etherType = _ethType(frame, len, &ipOff);
    uint32_t srcIp = 0, dstIp = 0;
    uint8_t  proto = 0;
    uint16_t l4Off = 0;
    bool haveIp = false;
    uint16_t srcPort = 0, dstPort = 0;
    bool havePorts = false;

    switch (n.op) {
    case FOP_TRUE:  return true;
    case FOP_FALSE: return false;
    case FOP_AND:   return _eval(n.left, frame, len) && _eval(n.right, frame, len);
    case FOP_OR:    return _eval(n.left, frame, len) || _eval(n.right, frame, len);
    case FOP_NOT:   return !_eval(n.left, frame, len);

    case FOP_PROTO_ARP:  return etherType == 0x0806;
    case FOP_PROTO_IP:   return etherType == 0x0800;
    case FOP_PROTO_IP6:  return etherType == 0x86DD;
    case FOP_PROTO_VLAN: return ((uint16_t)frame[12] << 8 | frame[13]) == 0x8100;

    case FOP_PROTO_TCP:
        if (etherType != 0x0800) return false;
        haveIp = _getIpv4(frame, len, ipOff, &srcIp, &dstIp, &proto, &l4Off);
        return haveIp && proto == 6;

    case FOP_PROTO_UDP:
        if (etherType != 0x0800) return false;
        haveIp = _getIpv4(frame, len, ipOff, &srcIp, &dstIp, &proto, &l4Off);
        return haveIp && proto == 17;

    case FOP_PROTO_ICMP:
        if (etherType != 0x0800) return false;
        haveIp = _getIpv4(frame, len, ipOff, &srcIp, &dstIp, &proto, &l4Off);
        return haveIp && proto == 1;

    case FOP_HOST:
    case FOP_SRC_HOST:
    case FOP_DST_HOST:
        if (etherType != 0x0800) return false;
        haveIp = _getIpv4(frame, len, ipOff, &srcIp, &dstIp, &proto, &l4Off);
        if (!haveIp) return false;
        if (n.op == FOP_HOST)     return srcIp == n.net.ip || dstIp == n.net.ip;
        if (n.op == FOP_SRC_HOST) return srcIp == n.net.ip;
        return dstIp == n.net.ip;

    case FOP_NET:
    case FOP_SRC_NET:
    case FOP_DST_NET:
        if (etherType != 0x0800) return false;
        haveIp = _getIpv4(frame, len, ipOff, &srcIp, &dstIp, &proto, &l4Off);
        if (!haveIp) return false;
        if (n.op == FOP_NET)     return (srcIp & n.net.mask) == n.net.ip ||
                                        (dstIp & n.net.mask) == n.net.ip;
        if (n.op == FOP_SRC_NET) return (srcIp & n.net.mask) == n.net.ip;
        return (dstIp & n.net.mask) == n.net.ip;

    case FOP_PORT:
    case FOP_SRC_PORT:
    case FOP_DST_PORT:
        if (etherType != 0x0800) return false;
        haveIp = _getIpv4(frame, len, ipOff, &srcIp, &dstIp, &proto, &l4Off);
        if (!haveIp || (proto != 6 && proto != 17)) return false;
        havePorts = _getPorts(frame, len, l4Off, &srcPort, &dstPort);
        if (!havePorts) return false;
        if (n.op == FOP_PORT)     return srcPort == n.port.lo || dstPort == n.port.lo;
        if (n.op == FOP_SRC_PORT) return srcPort == n.port.lo;
        return dstPort == n.port.lo;

    case FOP_PORTRANGE:
    case FOP_SRC_PORTRANGE:
    case FOP_DST_PORTRANGE:
        if (etherType != 0x0800) return false;
        haveIp = _getIpv4(frame, len, ipOff, &srcIp, &dstIp, &proto, &l4Off);
        if (!haveIp || (proto != 6 && proto != 17)) return false;
        havePorts = _getPorts(frame, len, l4Off, &srcPort, &dstPort);
        if (!havePorts) return false;
        {
            bool srcMatch = srcPort >= n.port.lo && srcPort <= n.port.hi;
            bool dstMatch = dstPort >= n.port.lo && dstPort <= n.port.hi;
            if (n.op == FOP_PORTRANGE)     return srcMatch || dstMatch;
            if (n.op == FOP_SRC_PORTRANGE) return srcMatch;
            return dstMatch;
        }

    case FOP_ETHER_HOST:
        return (len >= 14) && (memcmp(frame, n.mac, 6) == 0 || memcmp(frame + 6, n.mac, 6) == 0);
    case FOP_ETHER_DST:
        return (len >= 6) && memcmp(frame, n.mac, 6) == 0;
    case FOP_ETHER_SRC:
        return (len >= 12) && memcmp(frame + 6, n.mac, 6) == 0;
    }
    return true;
}

// =============================================================================
// Public: match
// =============================================================================
bool pcapFilterMatch(const uint8_t *frame, uint16_t len)
{
    if (!_filterActive) return true;  // no filter = accept all
    return _eval(_rootNode, frame, len);
}
