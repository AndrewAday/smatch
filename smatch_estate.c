/*
 * Copyright (C) 2010 Dan Carpenter.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see http://www.gnu.org/copyleft/gpl.txt
 */

/*
 * smatch_dinfo.c has helper functions for handling data_info structs
 *
 */

#include <stdlib.h>
#ifndef __USE_ISOC99
#define __USE_ISOC99
#endif
#include <limits.h>
#include "parse.h"
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

struct smatch_state *merge_estates(struct smatch_state *s1, struct smatch_state *s2)
{
	struct smatch_state *tmp;
	struct range_list *value_ranges;
	struct related_list *rlist;

	if (estates_equiv(s1, s2))
		return s1;

	value_ranges = rl_union(estate_rl(s1), estate_rl(s2));
	tmp = alloc_estate_rl(value_ranges);
	rlist = get_shared_relations(estate_related(s1), estate_related(s2));
	set_related(tmp, rlist);
	if (estate_has_hard_max(s1) && estate_has_hard_max(s2))
		estate_set_hard_max(tmp);

	estate_set_fuzzy_max(tmp, sval_max(estate_get_fuzzy_max(s1), estate_get_fuzzy_max(s2)));

	return tmp;
}

struct data_info *get_dinfo(struct smatch_state *state)
{
	if (!state)
		return NULL;
	return (struct data_info *)state->data;
}

struct range_list *estate_rl(struct smatch_state *state)
{
	if (!state)
		return NULL;
	return get_dinfo(state)->value_ranges;
}

struct related_list *estate_related(struct smatch_state *state)
{
	if (!state)
		return NULL;
	return get_dinfo(state)->related;
}

sval_t estate_get_fuzzy_max(struct smatch_state *state)
{
	sval_t empty = {};

	if (!state || !get_dinfo(state))
		return empty;
	return get_dinfo(state)->fuzzy_max;
}

int estate_has_fuzzy_max(struct smatch_state *state)
{
	if (estate_get_fuzzy_max(state).type)
		return 1;
	return 0;
}

void estate_set_fuzzy_max(struct smatch_state *state, sval_t fuzzy_max)
{
	if (!rl_has_sval(estate_rl(state), fuzzy_max))
		return;
	get_dinfo(state)->fuzzy_max = fuzzy_max;
}

void estate_copy_fuzzy_max(struct smatch_state *new, struct smatch_state *old)
{
	if (!estate_has_fuzzy_max(old))
		return;
	estate_set_fuzzy_max(new, estate_get_fuzzy_max(old));
}

void estate_clear_fuzzy_max(struct smatch_state *state)
{
	sval_t empty = {};

	get_dinfo(state)->fuzzy_max = empty;
}

int estate_has_hard_max(struct smatch_state *state)
{
	if (!state)
		return 0;
	return get_dinfo(state)->hard_max;
}

void estate_set_hard_max(struct smatch_state *state)
{
	 get_dinfo(state)->hard_max = 1;
}

void estate_clear_hard_max(struct smatch_state *state)
{
	 get_dinfo(state)->hard_max = 0;
}

int estate_get_hard_max(struct smatch_state *state, sval_t *sval)
{
	if (!state || !get_dinfo(state)->hard_max || !estate_rl(state))
		return 0;
	*sval = rl_max(estate_rl(state));
	return 1;
}

sval_t estate_min(struct smatch_state *state)
{
	return rl_min(estate_rl(state));
}

sval_t estate_max(struct smatch_state *state)
{
	return rl_max(estate_rl(state));
}

struct symbol *estate_type(struct smatch_state *state)
{
	return rl_max(estate_rl(state)).type;
}

static int rlists_equiv(struct related_list *one, struct related_list *two)
{
	struct relation *one_rel;
	struct relation *two_rel;

	PREPARE_PTR_LIST(one, one_rel);
	PREPARE_PTR_LIST(two, two_rel);
	for (;;) {
		if (!one_rel && !two_rel)
			return 1;
		if (!one_rel || !two_rel)
			return 0;
		if (one_rel->sym != two_rel->sym)
			return 0;
		if (strcmp(one_rel->name, two_rel->name))
			return 0;
		NEXT_PTR_LIST(one_rel);
		NEXT_PTR_LIST(two_rel);
	}
	FINISH_PTR_LIST(two_rel);
	FINISH_PTR_LIST(one_rel);

	return 1;
}

int estates_equiv(struct smatch_state *one, struct smatch_state *two)
{
	if (one == two)
		return 1;
	if (!rlists_equiv(estate_related(one), estate_related(two)))
		return 0;
	if (strcmp(one->name, two->name) == 0)
		return 1;
	return 0;
}

int estate_is_whole(struct smatch_state *state)
{
	return is_whole_rl(estate_rl(state));
}

int estate_is_unknown(struct smatch_state *state)
{
	if (!estate_is_whole(state))
		return 0;
	if (estate_related(state))
		return 0;
	if (estate_has_fuzzy_max(state))
		return 0;
	return 1;
}

int estate_get_single_value(struct smatch_state *state, sval_t *sval)
{
	sval_t min, max;

	min = rl_min(estate_rl(state));
	max = rl_max(estate_rl(state));
	if (sval_cmp(min, max) != 0)
		return 0;
	*sval = min;
	return 1;
}

static struct data_info *alloc_dinfo(void)
{
	struct data_info *ret;

	ret = __alloc_data_info(0);
	memset(ret, 0, sizeof(*ret));
	return ret;
}

static struct data_info *alloc_dinfo_range(sval_t min, sval_t max)
{
	struct data_info *ret;

	ret = alloc_dinfo();
	add_range(&ret->value_ranges, min, max);
	return ret;
}

static struct data_info *alloc_dinfo_range_list(struct range_list *rl)
{
	struct data_info *ret;

	ret = alloc_dinfo();
	ret->value_ranges = rl;
	return ret;
}

static struct data_info *clone_dinfo(struct data_info *dinfo)
{
	struct data_info *ret;

	ret = alloc_dinfo();
	ret->related = clone_related_list(dinfo->related);
	ret->value_ranges = clone_rl(dinfo->value_ranges);
	ret->hard_max = dinfo->hard_max;
	ret->fuzzy_max = dinfo->fuzzy_max;
	return ret;
}

struct smatch_state *clone_estate(struct smatch_state *state)
{
	struct smatch_state *ret;

	ret = __alloc_smatch_state(0);
	ret->name = state->name;
	ret->data = clone_dinfo(get_dinfo(state));
	return ret;
}

struct smatch_state *alloc_estate_empty(void)
{
	struct smatch_state *state;
	struct data_info *dinfo;

	dinfo = alloc_dinfo();
	state = __alloc_smatch_state(0);
	state->data = dinfo;
	state->name = "";
	return state;
}

struct smatch_state *alloc_estate_whole(struct symbol *type)
{
	return alloc_estate_rl(alloc_whole_rl(type));
}

struct smatch_state *extra_empty(void)
{
	struct smatch_state *ret;

	ret = __alloc_smatch_state(0);
	ret->name = "empty";
	ret->data = alloc_dinfo();
	return ret;
}

struct smatch_state *alloc_estate_sval(sval_t sval)
{
	struct smatch_state *state;

	state = __alloc_smatch_state(0);
	state->data = alloc_dinfo_range(sval, sval);
	state->name = show_rl(get_dinfo(state)->value_ranges);
	estate_set_hard_max(state);
	estate_set_fuzzy_max(state, sval);
	return state;
}

struct smatch_state *alloc_estate_range(sval_t min, sval_t max)
{
	struct smatch_state *state;

	state = __alloc_smatch_state(0);
	state->data = alloc_dinfo_range(min, max);
	state->name = show_rl(get_dinfo(state)->value_ranges);
	return state;
}

struct smatch_state *alloc_estate_rl(struct range_list *rl)
{
	struct smatch_state *state;

	if (!rl)
		return extra_empty();

	state = __alloc_smatch_state(0);
	state->data = alloc_dinfo_range_list(rl);
	state->name = show_rl(rl);
	return state;
}

struct smatch_state *get_implied_estate(struct expression *expr)
{
	struct smatch_state *state;
	struct range_list *rl;

	state = get_state_expr(SMATCH_EXTRA, expr);
	if (state)
		return state;
	if (!get_implied_rl(expr, &rl))
		rl = alloc_whole_rl(get_type(expr));
	return alloc_estate_rl(rl);
}

struct smatch_state *estate_filter_range(struct smatch_state *orig,
				 sval_t filter_min, sval_t filter_max)
{
	struct range_list *rl;
	struct smatch_state *state;

	if (!orig)
		orig = alloc_estate_whole(filter_min.type);

	rl = remove_range(estate_rl(orig), filter_min, filter_max);
	state = alloc_estate_rl(rl);
	if (estate_has_hard_max(orig))
		estate_set_hard_max(state);
	if (estate_has_fuzzy_max(orig))
		estate_set_fuzzy_max(state, estate_get_fuzzy_max(orig));
	return state;
}

struct smatch_state *estate_filter_sval(struct smatch_state *orig, sval_t sval)
{
	return estate_filter_range(orig, sval, sval);
}

/*
 * One of the complications is that smatch tries to free a bunch of data at the
 * end of every function.
 */
struct data_info *clone_dinfo_perm(struct data_info *dinfo)
{
	struct data_info *ret;

	ret = malloc(sizeof(*ret));
	ret->related = NULL;
	ret->value_ranges = clone_rl_permanent(dinfo->value_ranges);
	ret->hard_max = 0;
	ret->fuzzy_max = dinfo->fuzzy_max;
	return ret;
}

struct smatch_state *clone_estate_perm(struct smatch_state *state)
{
	struct smatch_state *ret;

	ret = malloc(sizeof(*ret));
	ret->name = alloc_string(state->name);
	ret->data = clone_dinfo_perm(get_dinfo(state));
	return ret;
}


