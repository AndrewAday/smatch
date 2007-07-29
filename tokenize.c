/*
 * This is a really stupid C tokenizer. It doesn't do any include
 * files or anything complex at all. That's the preprocessor.
 *
 * Copyright (C) 2003 Transmeta Corp.
 *               2003 Linus Torvalds
 *
 *  Licensed under the Open Software License version 1.1
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "lib.h"
#include "allocate.h"
#include "token.h"
#include "symbol.h"

#define EOF (-1)

int input_stream_nr = 0;
struct stream *input_streams;
static int input_streams_allocated;

#define BUFSIZE (8192)

typedef struct {
	int fd, offset, size;
	int pos, line, nr;
	int newline, whitespace;
	struct token **tokenlist;
	struct token *token;
	unsigned char *buffer;
} stream_t;

const char *stream_name(int stream)
{
	if (stream < 0 || stream > input_stream_nr)
		return "<bad stream>";
	return input_streams[stream].name;
}

static struct position stream_pos(stream_t *stream)
{
	struct position pos;
	pos.type = 0;
	pos.stream = stream->nr;
	pos.newline = stream->newline;
	pos.whitespace = stream->whitespace;
	pos.pos = stream->pos;
	pos.line = stream->line;
	pos.noexpand = 0;
	return pos;
}

const char *show_special(int val)
{
	static char buffer[4];

	buffer[0] = val;
	buffer[1] = 0;
	if (val >= SPECIAL_BASE)
		strcpy(buffer, (char *) combinations[val - SPECIAL_BASE]);
	return buffer;
}

const char *show_ident(const struct ident *ident)
{
	static char buffer[256];
	if (!ident)
		return "<noident>";
	sprintf(buffer, "%.*s", ident->len, ident->name);
	return buffer;
}

static char *charstr(char *ptr, unsigned char c, unsigned char escape, unsigned char next)
{
	if (isprint(c)) {
		if (c == escape || c == '\\')
			*ptr++ = '\\';
		*ptr++ = c;
		return ptr;
	}
	*ptr++ = '\\';
	switch (c) {
	case '\n':
		*ptr++ = 'n';
		return ptr;
	case '\t':
		*ptr++ = 't';
		return ptr;
	}
	if (!isdigit(next))
		return ptr + sprintf(ptr, "%o", c);
		
	return ptr + sprintf(ptr, "%03o", c);
}

const char *show_string(const struct string *string)
{
	static char buffer[4 * MAX_STRING + 3];
	char *ptr;
	int i;

	if (!string->length)
		return "<bad_string>";
	ptr = buffer;
	*ptr++ = '"';
	for (i = 0; i < string->length-1; i++) {
		const char *p = string->data + i;
		ptr = charstr(ptr, p[0], '"', p[1]);
	}
	*ptr++ = '"';
	*ptr = '\0';
	return buffer;
}

const char *show_token(const struct token *token)
{
	static char buffer[256];

	if (!token)
		return "<no token>";
	switch (token_type(token)) {
	case TOKEN_ERROR:
		return "syntax error";

	case TOKEN_EOF:
		return "end-of-input";

	case TOKEN_IDENT:
		return show_ident(token->ident);

	case TOKEN_STRING:
		return show_string(token->string);

	case TOKEN_NUMBER:
		return token->number;

	case TOKEN_SPECIAL:
		return show_special(token->special);

	case TOKEN_CHAR: {
		char *ptr = buffer;
		int c = token->character;
		*ptr++ = '\'';
		ptr = charstr(ptr, c, '\'', 0);
		*ptr++ = '\'';
		*ptr++ = '\0';
		return buffer;
	}

	case TOKEN_STREAMBEGIN:
		sprintf(buffer, "<beginning of '%s'>", stream_name(token->pos.stream));
		return buffer;

	case TOKEN_STREAMEND:
		sprintf(buffer, "<end of '%s'>", stream_name(token->pos.stream));
		return buffer;
	
	default:
		return "WTF???";
	}
}

int init_stream(const char *name, int fd, const char **next_path)
{
	int stream = input_stream_nr;
	struct stream *current;

	if (stream >= input_streams_allocated) {
		int newalloc = stream * 4 / 3 + 10;
		input_streams = realloc(input_streams, newalloc * sizeof(struct stream));
		if (!input_streams)
			die("Unable to allocate more streams space");
		input_streams_allocated = newalloc;
	}
	current = input_streams + stream;
	memset(current, 0, sizeof(*current));
	current->name = name;
	current->fd = fd;
	current->next_path = next_path;
	current->path = NULL;
	current->constant = CONSTANT_FILE_MAYBE;
	input_stream_nr = stream+1;
	return stream;
}

static struct token * alloc_token(stream_t *stream)
{
	struct token *token = __alloc_token(0);
	token->pos = stream_pos(stream);
	return token;
}

/*
 *  Argh...  That was surprisingly messy - handling '\r' complicates the
 *  things a _lot_.
 */
static int nextchar_slow(stream_t *stream)
{
	int offset = stream->offset;
	int size = stream->size;
	int c;
	int spliced = 0, had_cr, had_backslash, complain;

restart:
	had_cr = had_backslash = complain = 0;

repeat:
	if (offset >= size) {
		size = read(stream->fd, stream->buffer, BUFSIZE);
		if (size <= 0)
			goto got_eof;
		stream->size = size;
		stream->offset = offset = 0;
	}

	c = stream->buffer[offset++];

	if (had_cr && c != '\n')
		complain = 1;

	if (c == '\r') {
		had_cr = 1;
		goto repeat;
	}

	stream->pos++;

	if (c == '\n') {
		stream->line++;
		stream->pos = 0;
	}

	if (!had_backslash) {
		if (c == '\\') {
			had_backslash = 1;
			goto repeat;
		}
		if (c == '\n')
			stream->newline = 1;
	} else {
		if (c == '\n') {
			if (complain)
				warning(stream_pos(stream), "non-ASCII data stream");
			spliced = 1;
			goto restart;
		}
		stream->pos--;
		offset--;
		c = '\\';
	}

out:
	stream->offset = offset;
	if (complain)
		warning(stream_pos(stream), "non-ASCII data stream");

	return c;

got_eof:
	if (had_backslash) {
		c = '\\';
		goto out;
	}
	if (stream->pos)
		warning(stream_pos(stream), "no newline at end of file");
	else if (had_cr)
		warning(stream_pos(stream), "non-ASCII data stream");
	else if (spliced)
		warning(stream_pos(stream), "backslash-newline at end of file");
	return EOF;
}

/*
 *  We want that as light as possible while covering all normal cases.
 *  Slow path (including the logics with line-splicing and EOF sanity
 *  checks) is in nextchar_slow().
 */
static inline int nextchar(stream_t *stream)
{
	int offset = stream->offset;

	if (offset < stream->size) {
		int c = stream->buffer[offset++];
		static const char special[256] = {
			['\r'] = 1, ['\n'] = 1, ['\\'] = 1
		};
		if (!special[c]) {
			stream->offset = offset;
			stream->pos++;
			return c;
		}
	}
	return nextchar_slow(stream);
}

struct token eof_token_entry;

static void mark_eof(stream_t *stream, struct token *end_token)
{
	struct token *end;

	end = alloc_token(stream);
	token_type(end) = TOKEN_STREAMEND;
	end->pos.newline = 1;

	eof_token_entry.next = &eof_token_entry;
	eof_token_entry.pos.newline = 1;

	if (!end_token)
		end_token =  &eof_token_entry;
	end->next = end_token;
	*stream->tokenlist = end;
	stream->tokenlist = NULL;
}

static void add_token(stream_t *stream)
{
	struct token *token = stream->token;

	stream->token = NULL;
	token->next = NULL;
	*stream->tokenlist = token;
	stream->tokenlist = &token->next;
}

static void drop_token(stream_t *stream)
{
	stream->newline |= stream->token->pos.newline;
	stream->whitespace |= stream->token->pos.whitespace;
	stream->token = NULL;
}

enum {
	Letter = 1,
	Digit = 2,
	Hex = 4,
	Exp = 8,
	Dot = 16,
	ValidSecond = 32,
};

static const long cclass[257] = {
	['0' + 1 ... '9' + 1] = Digit | Hex,
	['A' + 1 ... 'D' + 1] = Letter | Hex,
	['E' + 1] = Letter | Hex | Exp,
	['F' + 1] = Letter | Hex,
	['G' + 1 ... 'O' + 1] = Letter,
	['P' + 1] = Letter | Exp,
	['Q' + 1 ... 'Z' + 1] = Letter,
	['a' + 1 ... 'd' + 1] = Letter | Hex,
	['e' + 1] = Letter | Hex | Exp,
	['f' + 1] = Letter | Hex,
	['g' + 1 ... 'o' + 1] = Letter,
	['p' + 1] = Letter | Exp,
	['q' + 1 ... 'z' + 1] = Letter,
	['_' + 1] = Letter,
	['.' + 1] = Dot | ValidSecond,
	['=' + 1] = ValidSecond,
	['+' + 1] = ValidSecond,
	['-' + 1] = ValidSecond,
	['>' + 1] = ValidSecond,
	['<' + 1] = ValidSecond,
	['&' + 1] = ValidSecond,
	['|' + 1] = ValidSecond,
	['#' + 1] = ValidSecond,
};

/*
 * pp-number:
 *	digit
 *	. digit
 *	pp-number digit
 *	pp-number identifier-nodigit
 *	pp-number e sign
 *	pp-number E sign
 *	pp-number p sign
 *	pp-number P sign
 *	pp-number .
 */
static int get_one_number(int c, int next, stream_t *stream)
{
	struct token *token;
	static char buffer[4095];
	char *p = buffer, *buf, *buffer_end = buffer + sizeof (buffer);
	int len;

	*p++ = c;
	for (;;) {
		long class =  cclass[next + 1];
		if (!(class & (Dot | Digit | Letter)))
			break;
		if (p != buffer_end)
			*p++ = next;
		next = nextchar(stream);
		if (class & Exp) {
			if (next == '-' || next == '+') {
				if (p != buffer_end)
					*p++ = next;
				next = nextchar(stream);
			}
		}
	}

	if (p == buffer_end) {
		sparse_error(stream_pos(stream), "number token exceeds %td characters",
		      buffer_end - buffer);
		// Pretend we saw just "1".
		buffer[0] = '1';
		p = buffer + 1;
	}

	*p++ = 0;
	len = p - buffer;
	buf = __alloc_bytes(len);
	memcpy(buf, buffer, len);

	token = stream->token;
	token_type(token) = TOKEN_NUMBER;
	token->number = buf;
	add_token(stream);

	return next;
}

static int escapechar(int first, int type, stream_t *stream, int *valp)
{
	int next, value;

	next = nextchar(stream);
	value = first;

	if (first == '\n')
		warning(stream_pos(stream), "Newline in string or character constant");

	if (first == '\\' && next != EOF) {
		value = next;
		next = nextchar(stream);
		if (value != type) {
			switch (value) {
			case 'a':
				value = '\a';
				break;
			case 'b':
				value = '\b';
				break;
			case 't':
				value = '\t';
				break;
			case 'n':
				value = '\n';
				break;
			case 'v':
				value = '\v';
				break;
			case 'f':
				value = '\f';
				break;
			case 'r':
				value = '\r';
				break;
			case 'e':
				value = '\e';
				break;
			case '\\':
				break;
			case '?':
				break;
			case '\'':
				break;
			case '"':
				break;
			case '\n':
				warning(stream_pos(stream), "Newline in string or character constant");
				break;
			case '0'...'7': {
				int nr = 2;
				value -= '0';
				while (next >= '0' && next <= '9') {
					value = (value << 3) + (next-'0');
					next = nextchar(stream);
					if (!--nr)
						break;
				}
				value &= 0xff;
				break;
			}
			case 'x': {
				int hex = hexval(next);
				if (hex < 16) {
					value = hex;
					next = nextchar(stream);
					while ((hex = hexval(next)) < 16) {
						value = (value << 4) + hex;
						next = nextchar(stream);
					}
					value &= 0xff;
					break;
				}
			}
			/* Fall through */
			default:
				warning(stream_pos(stream), "Unknown escape '%c'", value);
			}
		}
		/* Mark it as escaped */
		value |= 0x100;
	}
	*valp = value;
	return next;
}

static int get_char_token(int next, stream_t *stream)
{
	int value;
	struct token *token;

	next = escapechar(next, '\'', stream, &value);
	if (value == '\'' || next != '\'') {
		sparse_error(stream_pos(stream), "Bad character constant");
		drop_token(stream);
		return next;
	}

	token = stream->token;
	token_type(token) = TOKEN_CHAR;
	token->character = value & 0xff;

	add_token(stream);
	return nextchar(stream);
}

static int get_string_token(int next, stream_t *stream)
{
	static char buffer[MAX_STRING];
	struct string *string;
	struct token *token;
	int len = 0;

	for (;;) {
		int val;
		next = escapechar(next, '"', stream, &val);
		if (val == '"')
			break;
		if (next == EOF) {
			warning(stream_pos(stream), "End of file in middle of string");
			return next;
		}
		if (len < MAX_STRING)
			buffer[len] = val;
		len++;
	}

	if (len > MAX_STRING) {
		warning(stream_pos(stream), "string too long (%d bytes, %d bytes max)", len, MAX_STRING);
		len = MAX_STRING;
	}

	string = __alloc_string(len+1);
	memcpy(string->data, buffer, len);
	string->data[len] = '\0';
	string->length = len+1;

	/* Pass it on.. */
	token = stream->token;
	token_type(token) = TOKEN_STRING;
	token->string = string;
	add_token(stream);
	
	return next;
}

static int drop_stream_eoln(stream_t *stream)
{
	drop_token(stream);
	for (;;) {
		switch (nextchar(stream)) {
		case EOF:
			return EOF;
		case '\n':
			return nextchar(stream);
		}
	}
}

static int drop_stream_comment(stream_t *stream)
{
	int newline;
	int next;
	drop_token(stream);
	newline = stream->newline;

	next = nextchar(stream);
	for (;;) {
		int curr = next;
		if (curr == EOF) {
			warning(stream_pos(stream), "End of file in the middle of a comment");
			return curr;
		}
		next = nextchar(stream);
		if (curr == '*' && next == '/')
			break;
	}
	stream->newline = newline;
	return nextchar(stream);
}

unsigned char combinations[][4] = COMBINATION_STRINGS;

#define NR_COMBINATIONS (SPECIAL_ARG_SEPARATOR - SPECIAL_BASE)

/* hash function for two-character punctuators - all give unique values */
#define special_hash(c0, c1) (((c0*8+c1*2)+((c0*8+c1*2)>>5))&31)

/*
 * note that we won't get false positives - special_hash(0,0) is 0 and
 * entry 0 is filled (by +=), so all the missing ones are OK.
 */
static unsigned char hash_results[32][2] = {
#define RES(c0, c1) [special_hash(c0, c1)] = {c0, c1}
	RES('+', '='), /* 00 */
	RES('/', '='), /* 01 */
	RES('^', '='), /* 05 */
	RES('&', '&'), /* 07 */
	RES('#', '#'), /* 08 */
	RES('<', '<'), /* 0a */
	RES('<', '='), /* 0c */
	RES('!', '='), /* 0e */
	RES('%', '='), /* 0f */
	RES('-', '-'), /* 10 */
	RES('-', '='), /* 11 */
	RES('-', '>'), /* 13 */
	RES('=', '='), /* 15 */
	RES('&', '='), /* 17 */
	RES('*', '='), /* 18 */
	RES('.', '.'), /* 1a */
	RES('+', '+'), /* 1b */
	RES('|', '='), /* 1c */
	RES('>', '='), /* 1d */
	RES('|', '|'), /* 1e */
	RES('>', '>')  /* 1f */
#undef RES
};
static int code[32] = {
#define CODE(c0, c1, value) [special_hash(c0, c1)] = value
	CODE('+', '=', SPECIAL_ADD_ASSIGN), /* 00 */
	CODE('/', '=', SPECIAL_DIV_ASSIGN), /* 01 */
	CODE('^', '=', SPECIAL_XOR_ASSIGN), /* 05 */
	CODE('&', '&', SPECIAL_LOGICAL_AND), /* 07 */
	CODE('#', '#', SPECIAL_HASHHASH), /* 08 */
	CODE('<', '<', SPECIAL_LEFTSHIFT), /* 0a */
	CODE('<', '=', SPECIAL_LTE), /* 0c */
	CODE('!', '=', SPECIAL_NOTEQUAL), /* 0e */
	CODE('%', '=', SPECIAL_MOD_ASSIGN), /* 0f */
	CODE('-', '-', SPECIAL_DECREMENT), /* 10 */
	CODE('-', '=', SPECIAL_SUB_ASSIGN), /* 11 */
	CODE('-', '>', SPECIAL_DEREFERENCE), /* 13 */
	CODE('=', '=', SPECIAL_EQUAL), /* 15 */
	CODE('&', '=', SPECIAL_AND_ASSIGN), /* 17 */
	CODE('*', '=', SPECIAL_MUL_ASSIGN), /* 18 */
	CODE('.', '.', SPECIAL_DOTDOT), /* 1a */
	CODE('+', '+', SPECIAL_INCREMENT), /* 1b */
	CODE('|', '=', SPECIAL_OR_ASSIGN), /* 1c */
	CODE('>', '=', SPECIAL_GTE), /* 1d */
	CODE('|', '|', SPECIAL_LOGICAL_OR), /* 1e */
	CODE('>', '>', SPECIAL_RIGHTSHIFT)  /* 1f */
#undef CODE
};

static int get_one_special(int c, stream_t *stream)
{
	struct token *token;
	int next, value, i;

	next = nextchar(stream);

	/*
	 * Check for numbers, strings, character constants, and comments
	 */
	switch (c) {
	case '.':
		if (next >= '0' && next <= '9')
			return get_one_number(c, next, stream);
		break;
	case '"':
		return get_string_token(next, stream);
	case '\'':
		return get_char_token(next, stream);
	case '/':
		if (next == '/')
			return drop_stream_eoln(stream);
		if (next == '*')
			return drop_stream_comment(stream);
	}

	/*
	 * Check for combinations
	 */
	value = c;
	if (cclass[next + 1] & ValidSecond) {
		i = special_hash(c, next);
		if (hash_results[i][0] == c && hash_results[i][1] == next) {
			value = code[i];
			next = nextchar(stream);
			if (value >= SPECIAL_LEFTSHIFT &&
			    next == "==."[value - SPECIAL_LEFTSHIFT]) {
				value += 3;
				next = nextchar(stream);
			}
		}
	}

	/* Pass it on.. */
	token = stream->token;
	token_type(token) = TOKEN_SPECIAL;
	token->special = value;
	add_token(stream);
	return next;
}

#define IDENT_HASH_BITS (13)
#define IDENT_HASH_SIZE (1<<IDENT_HASH_BITS)
#define IDENT_HASH_MASK (IDENT_HASH_SIZE-1)

#define ident_hash_init(c)		(c)
#define ident_hash_add(oldhash,c)	((oldhash)*11 + (c))
#define ident_hash_end(hash)		((((hash) >> IDENT_HASH_BITS) + (hash)) & IDENT_HASH_MASK)

static struct ident *hash_table[IDENT_HASH_SIZE];
static int ident_hit, ident_miss, idents;

void show_identifier_stats(void)
{
	int i;
	int distribution[100];

	fprintf(stderr, "identifiers: %d hits, %d misses\n",
		ident_hit, ident_miss);

	for (i = 0; i < 100; i++)
		distribution[i] = 0;

	for (i = 0; i < IDENT_HASH_SIZE; i++) {
		struct ident * ident = hash_table[i];
		int count = 0;

		while (ident) {
			count++;
			ident = ident->next;
		}
		if (count > 99)
			count = 99;
		distribution[count]++;
	}

	for (i = 0; i < 100; i++) {
		if (distribution[i])
			fprintf(stderr, "%2d: %d buckets\n", i, distribution[i]);
	}
}

static struct ident *alloc_ident(const char *name, int len)
{
	struct ident *ident = __alloc_ident(len);
	ident->symbols = NULL;
	ident->len = len;
	ident->tainted = 0;
	memcpy(ident->name, name, len);
	return ident;
}

static struct ident * insert_hash(struct ident *ident, unsigned long hash)
{
	ident->next = hash_table[hash];
	hash_table[hash] = ident;
	ident_miss++;
	return ident;
}

static struct ident *create_hashed_ident(const char *name, int len, unsigned long hash)
{
	struct ident *ident;
	struct ident **p;

	p = &hash_table[hash];
	while ((ident = *p) != NULL) {
		if (ident->len == (unsigned char) len) {
			if (strncmp(name, ident->name, len) != 0)
				goto next;

			ident_hit++;
			return ident;
		}
next:
		//misses++;
		p = &ident->next;
	}
	ident = alloc_ident(name, len);
	*p = ident;
	ident->next = NULL;
	ident_miss++;
	idents++;
	return ident;
}

static unsigned long hash_name(const char *name, int len)
{
	unsigned long hash;
	const unsigned char *p = (const unsigned char *)name;

	hash = ident_hash_init(*p++);
	while (--len) {
		unsigned int i = *p++;
		hash = ident_hash_add(hash, i);
	}
	return ident_hash_end(hash);
}

struct ident *hash_ident(struct ident *ident)
{
	return insert_hash(ident, hash_name(ident->name, ident->len));
}

struct ident *built_in_ident(const char *name)
{
	int len = strlen(name);
	return create_hashed_ident(name, len, hash_name(name, len));
}

struct token *built_in_token(int stream, const char *name)
{
	struct token *token;

	token = __alloc_token(0);
	token->pos.stream = stream;
	token_type(token) = TOKEN_IDENT;
	token->ident = built_in_ident(name);
	return token;
}

static int get_one_identifier(int c, stream_t *stream)
{
	struct token *token;
	struct ident *ident;
	unsigned long hash;
	char buf[256];
	int len = 1;
	int next;

	hash = ident_hash_init(c);
	buf[0] = c;
	for (;;) {
		next = nextchar(stream);
		if (!(cclass[next + 1] & (Letter | Digit)))
			break;
		if (len >= sizeof(buf))
			break;
		hash = ident_hash_add(hash, next);
		buf[len] = next;
		len++;
	};
	hash = ident_hash_end(hash);

	ident = create_hashed_ident(buf, len, hash);

	/* Pass it on.. */
	token = stream->token;
	token_type(token) = TOKEN_IDENT;
	token->ident = ident;
	add_token(stream);
	return next;
}		

static int get_one_token(int c, stream_t *stream)
{
	long class = cclass[c + 1];
	if (class & Digit)
		return get_one_number(c, nextchar(stream), stream);
	if (class & Letter)
		return get_one_identifier(c, stream);
	return get_one_special(c, stream);
}

static struct token *setup_stream(stream_t *stream, int idx, int fd,
	unsigned char *buf, unsigned int buf_size)
{
	struct token *begin;

	stream->nr = idx;
	stream->line = 1;
	stream->newline = 1;
	stream->whitespace = 0;
	stream->pos = 0;

	stream->token = NULL;
	stream->fd = fd;
	stream->offset = 0;
	stream->size = buf_size;
	stream->buffer = buf;

	begin = alloc_token(stream);
	token_type(begin) = TOKEN_STREAMBEGIN;
	stream->tokenlist = &begin->next;
	return begin;
}

static void tokenize_stream(stream_t *stream, struct token *endtoken)
{
	int c = nextchar(stream);
	while (c != EOF) {
		if (!isspace(c)) {
			struct token *token = alloc_token(stream);
			stream->token = token;
			stream->newline = 0;
			stream->whitespace = 0;
			c = get_one_token(c, stream);
			continue;
		}
		stream->whitespace = 1;
		c = nextchar(stream);
	}
	mark_eof(stream, endtoken);
}

struct token * tokenize_buffer(void *buffer, unsigned long size, struct token *endtoken)
{
	stream_t stream;
	struct token *begin;

	begin = setup_stream(&stream, 0, -1, buffer, size);
	tokenize_stream(&stream, endtoken);
	return begin;
}

struct token * tokenize(const char *name, int fd, struct token *endtoken, const char **next_path)
{
	struct token *begin;
	stream_t stream;
	unsigned char buffer[BUFSIZE];
	int idx;

	idx = init_stream(name, fd, next_path);
	if (idx < 0) {
		// info(endtoken->pos, "File %s is const", name);
		return endtoken;
	}

	begin = setup_stream(&stream, idx, fd, buffer, 0);
	tokenize_stream(&stream, endtoken);
	return begin;
}
