/*-
 * Copyright (c) 2016 Dridi Boukelmoune
 * All rights reserved.
 *
 * Author: Dridi Boukelmoune <dridi.boukelmoune@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * HPACK: Header Compression for HTTP/2 (RFC 7541)
 */

#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hpack.h"
#include "hpack_assert.h"
#include "hpack_priv.h"

enum hpack_prefix_e {
	HPACK_PFX_STRING	= 7,
	HPACK_PFX_INDEXED	= 7,
	HPACK_PFX_DYNAMIC	= 6,
	HPACK_PFX_LITERAL	= 4,
	HPACK_PFX_NEVER		= 4,
	HPACK_PFX_UPDATE	= 5,
};

/**********************************************************************
 */

static void *
hpack_libc_malloc(size_t size, void *priv)
{

	(void)priv;
	return (malloc(size));
}

static void *
hpack_libc_realloc(void *ptr, size_t size, void *priv)
{

	(void)priv;
	return (realloc(ptr, size));
}

static void
hpack_libc_free(void *ptr, void *priv)
{

	(void)priv;
	free(ptr);
}

const struct hpack_alloc hpack_libc_alloc = {
	hpack_libc_malloc,
	hpack_libc_realloc,
	hpack_libc_free,
	NULL
};

const struct hpack_alloc *hpack_default_alloc = &hpack_libc_alloc;

/**********************************************************************
 */

static struct hpack *
hpack_new(uint32_t magic, size_t max, const struct hpack_alloc *ha)
{
	struct hpack *hp;
	size_t max_init;

	if (ha == NULL || ha->malloc == NULL || max > UINT16_MAX)
		return (NULL);

	hp = ha->malloc(sizeof *hp + max, ha->priv);
	if (hp == NULL)
		return (NULL);

	max_init = sizeof *hp->tbl;
	if (max_init > max)
		max_init = max;

	(void)memset(hp, 0, sizeof *hp + max_init);
	hp->magic = magic;
	(void)memcpy(&hp->alloc, ha, sizeof *ha);
	hp->sz.mem = max;
	hp->sz.max = max;
	hp->sz.lim = -1;
	hp->sz.cap = -1;
	hp->sz.nxt = -1;
	hp->sz.min = -1;
	return (hp);
}

struct hpack *
hpack_encoder(size_t max, const struct hpack_alloc *ha)
{

	return (hpack_new(ENCODER_MAGIC, max, ha));
}

struct hpack *
hpack_decoder(size_t max, const struct hpack_alloc *ha)
{

	return (hpack_new(DECODER_MAGIC, max, ha));
}

enum hpack_result_e
hpack_resize(struct hpack **hpp, size_t len)
{
	struct hpack *hp;
	size_t max, mem;

	if (hpp == NULL)
		return (HPACK_RES_ARG);

	hp = *hpp;
	if (hp == NULL)
		return (HPACK_RES_ARG);
	if (hp->magic != DECODER_MAGIC && hp->magic != ENCODER_MAGIC)
		return (HPACK_RES_ARG);

	if (hp->ctx.res != HPACK_RES_OK) {
		assert(hp->ctx.res == HPACK_RES_BLK);
		return (HPACK_RES_BSY);
	}

	max = hp->alloc.realloc == NULL ? hp->sz.mem : UINT16_MAX;
	mem = len;

	if (hp->magic == ENCODER_MAGIC) {
		if (hp->sz.lim >= 0 && (size_t)hp->sz.lim < mem)
			mem = hp->sz.lim;
		if (hp->sz.cap >= 0 && (size_t)hp->sz.cap < mem)
			mem = hp->sz.lim >= 0 ? hp->sz.lim : hp->sz.cap;
	}

	if (mem > max) {
		hp->magic = DEFUNCT_MAGIC;
		return (HPACK_RES_LEN);
	}

	if (mem > hp->sz.mem) {
		assert(hp->alloc.realloc != NULL);
		assert(hp->sz.len <= mem);
		hp = hp->alloc.realloc(hp, sizeof *hp + mem, hp->alloc.priv);
		if (hp == NULL) {
			(*hpp)->magic = DEFUNCT_MAGIC;
			return (HPACK_RES_OOM);
		}
		hp->sz.mem = mem;
		*hpp = hp;
	}

	if (hp->sz.min < 0) {
		assert(hp->sz.nxt < 0);
		hp->sz.nxt = len;
		hp->sz.min = len;
	}
	else {
		assert(hp->sz.nxt >= hp->sz.min);
		hp->sz.nxt = len;
		if (hp->sz.min > (ssize_t)len)
			hp->sz.min = len;
	}

	return (HPACK_RES_OK);
}

enum hpack_result_e
hpack_limit(struct hpack *hp, size_t len)
{
	size_t max;

	if (hp == NULL || hp->magic != ENCODER_MAGIC)
		return (HPACK_RES_ARG);

	if (hp->ctx.res != HPACK_RES_OK) {
		assert(hp->ctx.res == HPACK_RES_BLK);
		return (HPACK_RES_BSY);
	}

	max = hp->alloc.realloc == NULL ? hp->sz.mem : UINT16_MAX;
	if (len > max)
		return (HPACK_RES_LEN); /* the codec is NOT defunct */

	hp->sz.cap = len;
	return (HPACK_RES_OK);
}

enum hpack_result_e
hpack_trim(struct hpack **hpp)
{
	struct hpack *hp;
	size_t max;

	if (hpp == NULL)
		return (HPACK_RES_ARG);

	hp = *hpp;
	if (hp == NULL || hp->alloc.realloc == NULL)
		return (HPACK_RES_ARG);
	if (hp->magic != DECODER_MAGIC && hp->magic != ENCODER_MAGIC)
		return (HPACK_RES_ARG);

	if (hp->ctx.res != HPACK_RES_OK) {
		assert(hp->ctx.res == HPACK_RES_BLK);
		return (HPACK_RES_BSY);
	}

	assert(hp->sz.lim <= (ssize_t) hp->sz.max);
	if (hp->magic != ENCODER_MAGIC)
		max = HPACK_LIMIT(hp);
	else
		max = hp->sz.max;

	if (hp->sz.mem > max) {
		hp = hp->alloc.realloc(hp, sizeof *hp + max, hp->alloc.priv);
		if (hp == NULL)
			return (HPACK_RES_OOM); /* the codec is NOT defunct */
		hp->sz.mem = max;
		*hpp = hp;
	}

	return (HPACK_RES_OK);
}

void
hpack_free(struct hpack **hpp)
{
	struct hpack *hp;

	if (hpp == NULL)
		return;

	hp = *hpp;
	if (hp == NULL)
		return;

	*hpp = NULL;
	if (hp->magic != ENCODER_MAGIC && hp->magic != DECODER_MAGIC &&
	    hp->magic != DEFUNCT_MAGIC)
		return;

	hp->magic = 0;
	if (hp->alloc.free != NULL)
		hp->alloc.free(hp, hp->alloc.priv);
}

enum hpack_result_e
hpack_foreach(struct hpack *hp, hpack_decoded_f cb, void *priv)
{
	struct hpack_ctx *ctx;

	if (hp == NULL || cb == NULL)
		return (HPACK_RES_ARG);
	if (hp->magic != DECODER_MAGIC && hp->magic != ENCODER_MAGIC)
		return (HPACK_RES_ARG);

	ctx = &hp->ctx;

	if (ctx->res != HPACK_RES_OK) {
		assert(ctx->res == HPACK_RES_BLK);
		return (HPACK_RES_BSY);
	}

	(void)memset(ctx, 0, sizeof *ctx);
	ctx->hp = hp;
	ctx->dec = cb;
	ctx->priv = priv;

	HPT_foreach(ctx);
	return (HPACK_RES_OK);
}

const char *
hpack_strerror(enum hpack_result_e res)
{

#define HPR(val, cod, txt, rst)	\
	if (res == cod)		\
		return (txt);
#include "tbl/hpack_tbl.h"
#undef HPR
	return (NULL);
}

/**********************************************************************
 * Decoder
 */

static int
hpack_decode_raw_string(HPACK_CTX, enum hpack_event_e evt, size_t len)
{
	struct hpack_state *hs;
	hpack_validate_f *val;

	hs = &ctx->hp->state;
	val = evt == HPACK_EVT_NAME ? HPV_token : HPV_value;

	if (len > ctx->len)
		len = ctx->len;

	CALL(val, ctx, (char *)ctx->buf, len, hs->first);
	if (hs->len <= len || !hs->first) {
		if (hs->first)
			CALLBACK(ctx, evt, NULL, hs->len);
		if (len > 0)
			CALLBACK(ctx, HPACK_EVT_DATA, (char *)ctx->buf, len);
	}
	else
		CALLBACK(ctx, evt, (char *)ctx->buf, len);

	ctx->buf += len;
	ctx->len -= len;
	hs->len -= len;
	hs->first = 0;
	EXPECT(ctx, BUF, hs->len == 0);

	return (0);
}

static int
hpack_decode_string(HPACK_CTX, enum hpack_event_e evt)
{
	struct hpack_state *hs;
	uint16_t len;
	uint8_t huf;

	hs = &ctx->hp->state;

	switch (hs->stp) {
	case HPACK_STP_NAM_LEN:
	case HPACK_STP_VAL_LEN:
		/* decode integer */
		huf = *ctx->buf & HPACK_HUFFMAN;
		CALL(HPI_decode, ctx, HPACK_PFX_STRING, &len);

		/* set up string decoding */
		hs->magic = huf ?  HUF_STATE_MAGIC : STR_STATE_MAGIC;
		hs->len = len;
		hs->first = 1;
		hs->stp++;

		if (evt == HPACK_EVT_NAME)
			EXPECT(ctx, LEN, len > 0);

		if (len > 0)
			EXPECT(ctx, BUF, ctx->len > 0);

		/* fall through */
	case HPACK_STP_NAM_STR:
	case HPACK_STP_VAL_STR:
		break;
	default:
		WRONG("Unknown step");
	}

	assert(hs->len > 0 || evt != HPACK_EVT_NAME);

	if (hs->magic == HUF_STATE_MAGIC)
		CALL(HPH_decode, ctx, evt, hs->len);
	else {
		assert(hs->magic == STR_STATE_MAGIC);
		CALL(hpack_decode_raw_string, ctx, evt, hs->len);
	}

	return (0);
}

static int
hpack_decode_field(HPACK_CTX)
{

	switch (ctx->hp->state.stp) {
	case HPACK_STP_FLD_INT:
		ctx->hp->state.stp = HPACK_STP_NAM_LEN;
		/* fall through */
	case HPACK_STP_NAM_LEN:
	case HPACK_STP_NAM_STR:
		if (ctx->hp->state.idx == 0)
			CALL(hpack_decode_string, ctx, HPACK_EVT_NAME);
		else
			CALL(HPT_decode_name, ctx);
		ctx->hp->state.stp = HPACK_STP_VAL_LEN;
		/* fall through */
	case HPACK_STP_VAL_LEN:
	case HPACK_STP_VAL_STR:
		CALL(hpack_decode_string, ctx, HPACK_EVT_VALUE);
		ctx->hp->state.stp = HPACK_STP_FLD_INT;
		break;
	default:
		WRONG("Unknown step");
	}

	return (0);
}

static int
hpack_decode_indexed(HPACK_CTX)
{
	uint16_t idx;

	CALL(HPI_decode, ctx, HPACK_PFX_INDEXED, &idx);
	CALLBACK(ctx, HPACK_EVT_FIELD, NULL, idx);
	return (HPT_decode(ctx, idx));
}

static int
hpack_decode_dynamic(HPACK_CTX)
{
	struct hpack *hp;
	struct hpack_ctx tbl_ctx;
	struct hpt_priv priv;
#ifndef NDEBUG
	struct hpt_entry tmp;
#endif

	hp = ctx->hp;

	(void)memset(&priv, 0, sizeof priv);
	priv.ctx = ctx;
	priv.nam = hp->state.stp <= HPACK_STP_NAM_STR;
	priv.he = (void *)((uintptr_t)hp->tbl + hp->off);

	if (hp->state.stp == HPACK_STP_FLD_INT) {
		CALL(HPI_decode, ctx, HPACK_PFX_DYNAMIC, &hp->state.idx);
		CALLBACK(ctx, HPACK_EVT_FIELD, NULL, 0);
	}

	(void)memcpy(&tbl_ctx, ctx, sizeof tbl_ctx);
	tbl_ctx.dec = HPT_insert;
	tbl_ctx.priv = &priv;

	if (hpack_decode_field(&tbl_ctx) != 0) {
		assert(tbl_ctx.res != ctx->res);
		ctx->res = tbl_ctx.res;
		return (-1);
	}

	assert(tbl_ctx.res == ctx->res);
	ctx->buf = tbl_ctx.buf;
	ctx->len = tbl_ctx.len;
	hp->off = 0;

	assert(hp->sz.lim <= (ssize_t) hp->sz.max);

	if (ctx->ins <= HPACK_LIMIT(hp)) {
		CALLBACK(&tbl_ctx, HPACK_EVT_INDEX, NULL, 0);
		hp->sz.len += ctx->ins;
		if (++ctx->hp->cnt > 1) {
#ifndef NDEBUG
			(void)memcpy(&tmp, priv.he, sizeof tmp);
			assert(tmp.pre_sz > 0);
			assert((size_t)tmp.pre_sz == ctx->ins);
#endif
		}
	}
	else {
		assert(hp->sz.len == 0);
		assert(hp->cnt == 0);
	}

	return (0);
}

static int
hpack_decode_literal(HPACK_CTX)
{

	if (ctx->hp->state.stp == HPACK_STP_FLD_INT) {
		CALL(HPI_decode, ctx, HPACK_PFX_LITERAL, &ctx->hp->state.idx);
		CALLBACK(ctx, HPACK_EVT_FIELD, NULL, 0);
	}
	return (hpack_decode_field(ctx));
}

static int
hpack_decode_never(HPACK_CTX)
{

	if (ctx->hp->state.stp == HPACK_STP_FLD_INT) {
		CALL(HPI_decode, ctx, HPACK_PFX_NEVER, &ctx->hp->state.idx);
		CALLBACK(ctx, HPACK_EVT_FIELD, NULL, 0);
		CALLBACK(ctx, HPACK_EVT_NEVER, NULL, 0);
	}
	return (hpack_decode_field(ctx));
}

static int
hpack_decode_update(HPACK_CTX)
{
	uint16_t sz;

	EXPECT(ctx, UPD, ctx->can_upd);

	CALL(HPI_decode, ctx, HPACK_PFX_UPDATE, &sz);
	if (ctx->hp->sz.min >= 0) {
		assert(ctx->hp->sz.min <= ctx->hp->sz.nxt);
		if (ctx->hp->sz.min < ctx->hp->sz.nxt) {
			EXPECT(ctx, UPD, sz == ctx->hp->sz.min);
			ctx->hp->sz.min = ctx->hp->sz.nxt;
		}
		else {
			EXPECT(ctx, UPD, sz == ctx->hp->sz.nxt ||
			    sz < ctx->hp->sz.nxt);
			ctx->hp->sz.max = ctx->hp->sz.nxt;
			ctx->hp->sz.lim = sz;
			ctx->hp->sz.min = -1;
			ctx->hp->sz.nxt = -1;
			ctx->can_upd = 0;
		}
	}
	else
		ctx->can_upd = 0;
	EXPECT(ctx, LEN, sz <= ctx->hp->sz.max);
	ctx->hp->sz.lim = sz;
	HPT_adjust(ctx, ctx->hp->sz.len);
	CALLBACK(ctx, HPACK_EVT_TABLE, NULL, sz);
	return (0);
}

enum hpack_result_e
hpack_decode(struct hpack *hp, const void *buf, size_t len, unsigned cut,
    hpack_decoded_f cb, void *priv)
{
	struct hpack_ctx *ctx;
	int retval;

	if (hp == NULL || hp->magic != DECODER_MAGIC || buf == NULL ||
	    len == 0 || cb == NULL)
		return (HPACK_RES_ARG);

	ctx = &hp->ctx;

	if (ctx->res == HPACK_RES_BLK) {
		assert(ctx->hp == hp);
	}
	else {
		assert(ctx->res == HPACK_RES_OK);
		ctx->hp = hp;
		ctx->can_upd = 1;
		hp->state.stp = HPACK_STP_FLD_INT;
	}

	ctx->buf = buf;
	ctx->len = len;
	ctx->dec = cb;
	ctx->priv = priv;
	ctx->res = cut ? HPACK_RES_BLK : HPACK_RES_OK;

	while (ctx->len > 0) {
		if (!hp->state.bsy && hp->state.stp == HPACK_STP_FLD_INT)
			hp->state.typ = *ctx->buf;
		if ((hp->state.typ & HPACK_PAT_UPDATE) != HPACK_PAT_UPDATE) {
			if (hp->sz.nxt >= 0) {
				hp->magic = DEFUNCT_MAGIC;
				return (HPACK_RES_RSZ);
			}
			assert(hp->sz.min < 0);
			ctx->can_upd = 0;
		}
#define HPACK_DECODE(l, U, or) 						\
		if ((hp->state.typ & HPACK_PAT_##U) == HPACK_PAT_##U)	\
			retval = hpack_decode_##l(ctx); 		\
		or
		HPACK_DECODE(indexed, INDEXED, else)
		HPACK_DECODE(dynamic, DYNAMIC, else)
		HPACK_DECODE(update,  UPDATE,  else)
		HPACK_DECODE(never,   NEVER,   else)
		HPACK_DECODE(literal, LITERAL, /* out of bits */)
#undef HPACK_DECODE
		if (retval != 0) {
			assert(ctx->res != HPACK_RES_OK);
			if (cut && ctx->res == HPACK_RES_BUF)
				ctx->res = HPACK_RES_BLK;
			else
				hp->magic = DEFUNCT_MAGIC;
			return (ctx->res);
		}
	}

	assert(ctx->res == HPACK_RES_OK || ctx->res == HPACK_RES_BLK);
	return (ctx->res);
}

/**********************************************************************
 * Encoder
 */

static int
hpack_encode_string(HPACK_CTX, HPACK_FLD, enum hpack_event_e evt)
{
	const char *str;
	size_t len;
	unsigned huf;
	hpack_validate_f *val;

	if (evt == HPACK_EVT_NAME) {
		assert(~fld->flg & HPACK_FLG_NAM_IDX);
		str = fld->nam;
		huf = fld->flg & HPACK_FLG_NAM_HUF;
		val = HPV_token;
	}
	else {
		str = fld->val;
		huf = fld->flg & HPACK_FLG_VAL_HUF;
		val = HPV_value;
	}

	len = strlen(str);
	CALL(val, ctx, str, len, 1);

	if (huf != 0) {
		HPH_size(str, &len);
		HPI_encode(ctx, HPACK_PFX_STRING, HPACK_HUFFMAN, len);
		HPH_encode(ctx, str);
	}
	else {
		HPI_encode(ctx, HPACK_PFX_STRING, HPACK_RAW, len);
		HPE_push(ctx, str, len);
	}

	return (0);
}

static int
hpack_encode_field(HPACK_CTX, HPACK_FLD, enum hpack_pattern_e pat, size_t pfx)
{
	uint16_t idx;

	if (fld->flg & HPACK_FLG_NAM_IDX) {
		idx = fld->nam_idx;
		EXPECT(ctx, IDX, idx > 0 &&
		    idx <= ctx->hp->cnt + HPT_STATIC_MAX);
	}
	else
		idx = 0;

	HPI_encode(ctx, pfx, pat, idx);

	if (idx == 0)
		CALL(hpack_encode_string, ctx, fld, HPACK_EVT_NAME);

	return (hpack_encode_string(ctx, fld, HPACK_EVT_VALUE));
}

static int
hpack_encode_indexed(HPACK_CTX, HPACK_FLD)
{

	EXPECT(ctx, IDX, fld->idx > 0 &&
	    fld->idx <= ctx->hp->cnt + HPT_STATIC_MAX);

	HPI_encode(ctx, HPACK_PFX_INDEXED, HPACK_PAT_INDEXED, fld->idx);
	return (0);
}

static int
hpack_encode_dynamic(HPACK_CTX, HPACK_FLD)
{
	struct hpack *hp;
	struct hpt_field hf;
	struct hpt_priv priv;
	size_t nam_sz, val_sz;
#ifndef NDEBUG
	struct hpt_entry tmp;
#endif

	CALL(hpack_encode_field, ctx, fld, HPACK_PAT_DYNAMIC,
	    HPACK_PFX_DYNAMIC);

	hp = ctx->hp;

	(void)memset(&priv, 0, sizeof priv);
	priv.ctx = ctx;
	priv.he = hp->tbl;

	if (fld->flg & HPACK_FLG_NAM_IDX) {
		(void)HPT_search(ctx, fld->nam_idx, &hf);
		assert(ctx->res == HPACK_RES_BLK);
		HPT_insert(&priv, HPACK_EVT_NAME, hf.nam, hf.nam_sz);
	}
	else {
		nam_sz = strlen(fld->nam);
		HPT_insert(&priv, HPACK_EVT_NAME, fld->nam, nam_sz);
	}

	val_sz = strlen(fld->val);
	HPT_insert(&priv, HPACK_EVT_VALUE, fld->val, val_sz);

	hp->off = 0;
	assert(hp->sz.lim <= (ssize_t) hp->sz.max);

	if (ctx->ins <= HPACK_LIMIT(hp)) {
		HPT_insert(&priv, HPACK_EVT_INDEX, NULL, 0);
		hp->sz.len += ctx->ins;
		if (++ctx->hp->cnt > 1) {
#ifndef NDEBUG
			(void)memcpy(&tmp, priv.he, sizeof tmp);
			assert(tmp.pre_sz > 0);
			assert((size_t)tmp.pre_sz == ctx->ins);
#endif
		}
	}

	return (0);
}

static int
hpack_encode_literal(HPACK_CTX, HPACK_FLD)
{

	return (hpack_encode_field(ctx, fld, HPACK_PAT_LITERAL,
	    HPACK_PFX_LITERAL));
}

static int
hpack_encode_never(HPACK_CTX, HPACK_FLD)
{

	return (hpack_encode_field(ctx, fld, HPACK_PAT_NEVER,
	    HPACK_PFX_NEVER));
}

static int
hpack_encode_update(HPACK_CTX, size_t lim)
{

	assert(ctx->can_upd);
	assert(lim <= UINT16_MAX);

	if (ctx->hp->sz.min >= 0) {
		assert(ctx->hp->sz.min <= ctx->hp->sz.nxt);
		if (ctx->hp->sz.min < ctx->hp->sz.nxt)
			assert(lim == (size_t)ctx->hp->sz.min);
		else if (ctx->hp->sz.cap >= 0) {
			lim = ctx->hp->sz.cap;
			ctx->hp->sz.cap = -1;
		}
	}

	ctx->hp->sz.lim = lim;

	HPT_adjust(ctx, ctx->hp->sz.len);
	HPI_encode(ctx, HPACK_PFX_UPDATE, HPACK_PAT_UPDATE, lim);
	CALLBACK(ctx, HPACK_EVT_TABLE, NULL, lim);

	if (ctx->hp->sz.min < ctx->hp->sz.nxt) {
		assert(ctx->hp->sz.min >= 0);
		ctx->hp->sz.min = ctx->hp->sz.nxt;
	}
	else if (ctx->hp->sz.min >= 0) {
		assert(ctx->hp->sz.min == ctx->hp->sz.nxt);
		ctx->hp->sz.max = ctx->hp->sz.nxt;
		ctx->hp->sz.min = -1;
		ctx->hp->sz.nxt = -1;
		ctx->can_upd = 0;
	}

	assert(lim <= ctx->hp->sz.max);
	return (0);
}

enum hpack_result_e
hpack_encode(struct hpack *hp, HPACK_FLD, size_t len, hpack_encoded_f cb,
    void *priv)
{
	struct hpack_ctx *ctx;
	uint8_t buf[256];
	int retval;

	if (hp == NULL || hp->magic != ENCODER_MAGIC || fld == NULL ||
	    len == 0 || cb == NULL)
		return (HPACK_RES_ARG);

	ctx = &hp->ctx;

	ctx->res = HPACK_RES_BLK;
	ctx->hp = hp;
	ctx->buf = buf;
	ctx->cur = TRUST_ME(ctx->buf);
	ctx->len = 0;
	ctx->max = sizeof buf;
	ctx->enc = cb;
	ctx->priv = priv;
	ctx->can_upd = 1;

	if (hp->sz.min >= 0) {
		assert(hp->sz.min <= hp->sz.nxt);
		retval = hpack_encode_update(ctx, hp->sz.min);
		assert(retval == 0);
		assert(hp->sz.min == hp->sz.nxt);
		if (hp->sz.nxt >= 0) {
			retval = hpack_encode_update(ctx, hp->sz.nxt);
			assert(retval == 0);
		}
		assert(ctx->hp->sz.cap < 0);
		assert(!ctx->can_upd);
	}

	if (ctx->hp->sz.cap >= 0) {
		retval = hpack_encode_update(ctx, hp->sz.cap);
		assert(retval == 0);
		hp->sz.cap = -1;
	}

	while (len > 0) {
		switch (fld->flg & HPACK_FLG_TYP_MSK) {
#define HPACK_ENCODE(l, U)					\
		case HPACK_FLG_TYP_##U:				\
			retval = hpack_encode_##l(ctx, fld);	\
			break;
		HPACK_ENCODE(indexed, IDX)
		HPACK_ENCODE(dynamic, DYN)
		HPACK_ENCODE(never,   NVR)
		HPACK_ENCODE(literal, LIT)
#undef HPACK_ENCODE
		default:
			hp->magic = DEFUNCT_MAGIC;
			return (HPACK_RES_ARG);
		}
		if (retval != 0) {
			assert(ctx->res != HPACK_RES_OK);
			assert(ctx->res != HPACK_RES_BLK);
			hp->magic = DEFUNCT_MAGIC;
			return (ctx->res);
		}
		fld++;
		len--;
	}

	HPE_send(ctx);

	assert(ctx->res == HPACK_RES_BLK);
	ctx->res = HPACK_RES_OK;
	return (ctx->res);
}

enum hpack_result_e
hpack_clean_field(struct hpack_field *fld)
{

	if (fld == NULL)
		return (HPACK_RES_ARG);

	switch (fld->flg & HPACK_FLG_TYP_MSK) {
	case HPACK_FLG_TYP_IDX:
		fld->idx = 0;
		break;
	case HPACK_FLG_TYP_DYN:
	case HPACK_FLG_TYP_LIT:
	case HPACK_FLG_TYP_NVR:
		if (fld->flg & HPACK_FLG_NAM_IDX) {
			fld->nam_idx = 0;
			fld->flg &= ~HPACK_FLG_NAM_IDX;
		}
		else
			fld->nam = NULL;
		fld->val = NULL;
		fld->flg &= ~HPACK_FLG_NAM_HUF;
		fld->flg &= ~HPACK_FLG_VAL_HUF;
		break;
	default:
		return (HPACK_RES_ARG);
	}

	fld->flg &= ~HPACK_FLG_TYP_MSK;

	if (fld->nam != NULL || fld->val != NULL || fld->flg != 0)
		return (HPACK_RES_ARG);

	assert(fld->idx == 0);
	assert(fld->nam_idx == 0);

	return (HPACK_RES_OK);
}
