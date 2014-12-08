/*
 * Copyright (C) 2009 Dan Carpenter.
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
 * There are several types of function hooks:
 * add_function_hook()        - For any time a function is called.
 * add_function_assign_hook() - foo = the_function().
 * add_implied_return_hook()  - Calculates the implied return value.
 * add_macro_assign_hook()    - foo = the_macro().
 * return_implies_state()     - For when a return value of 1 implies locked
 *                              and 0 implies unlocked. etc. etc.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"
#include "smatch_function_hashtable.h"

struct fcall_back {
	int type;
	struct data_range *range;
	union {
		func_hook *call_back;
		implication_hook *ranged;
		implied_return_hook *implied_return;
	} u;
	void *info;
};

ALLOCATOR(fcall_back, "call backs");
DECLARE_PTR_LIST(call_back_list, struct fcall_back);

DEFINE_FUNCTION_HASHTABLE_STATIC(callback, struct fcall_back, struct call_back_list);
static struct hashtable *func_hash;

#define REGULAR_CALL       0
#define RANGED_CALL        1
#define ASSIGN_CALL        2
#define IMPLIED_RETURN     3
#define MACRO_ASSIGN       4
#define MACRO_ASSIGN_EXTRA 5

struct return_implies_callback {
	int type;
	return_implies_hook *callback;
};
ALLOCATOR(return_implies_callback, "return_implies callbacks");
DECLARE_PTR_LIST(db_implies_list, struct return_implies_callback);
static struct db_implies_list *db_return_states_list;

typedef void (void_fn)(void);
DECLARE_PTR_LIST(void_fn_list, void_fn *);
static struct void_fn_list *return_states_before;
static struct void_fn_list *return_states_after;

static struct fcall_back *alloc_fcall_back(int type, void *call_back,
					   void *info)
{
	struct fcall_back *cb;

	cb = __alloc_fcall_back(0);
	cb->type = type;
	cb->u.call_back = call_back;
	cb->info = info;
	return cb;
}

void add_function_hook(const char *look_for, func_hook *call_back, void *info)
{
	struct fcall_back *cb;

	cb = alloc_fcall_back(REGULAR_CALL, call_back, info);
	add_callback(func_hash, look_for, cb);
}

void add_function_assign_hook(const char *look_for, func_hook *call_back,
			      void *info)
{
	struct fcall_back *cb;

	cb = alloc_fcall_back(ASSIGN_CALL, call_back, info);
	add_callback(func_hash, look_for, cb);
}

void add_implied_return_hook(const char *look_for,
			     implied_return_hook *call_back,
			     void *info)
{
	struct fcall_back *cb;

	cb = alloc_fcall_back(IMPLIED_RETURN, call_back, info);
	add_callback(func_hash, look_for, cb);
}

void add_macro_assign_hook(const char *look_for, func_hook *call_back,
			void *info)
{
	struct fcall_back *cb;

	cb = alloc_fcall_back(MACRO_ASSIGN, call_back, info);
	add_callback(func_hash, look_for, cb);
}

void add_macro_assign_hook_extra(const char *look_for, func_hook *call_back,
			void *info)
{
	struct fcall_back *cb;

	cb = alloc_fcall_back(MACRO_ASSIGN_EXTRA, call_back, info);
	add_callback(func_hash, look_for, cb);
}

void return_implies_state(const char *look_for, long long start, long long end,
			 implication_hook *call_back, void *info)
{
	struct fcall_back *cb;

	cb = alloc_fcall_back(RANGED_CALL, call_back, info);
	cb->range = alloc_range_perm(ll_to_sval(start), ll_to_sval(end));
	add_callback(func_hash, look_for, cb);
}

void select_return_states_hook(int type, return_implies_hook *callback)
{
	struct return_implies_callback *cb = __alloc_return_implies_callback(0);

	cb->type = type;
	cb->callback = callback;
	add_ptr_list(&db_return_states_list, cb);
}

void select_return_states_before(void_fn *fn)
{
	void_fn **p = malloc(sizeof(void_fn *));
	*p = fn;
	add_ptr_list(&return_states_before, p);
}

void select_return_states_after(void_fn *fn)
{
	void_fn **p = malloc(sizeof(void_fn *));
	*p = fn;
	add_ptr_list(&return_states_after, p);
}

static void call_return_states_before_hooks(void)
{
	void_fn **fn;

	FOR_EACH_PTR(return_states_before, fn) {
		(*fn)();
	} END_FOR_EACH_PTR(fn);
}

static void call_return_states_after_hooks(void)
{
	void_fn **fn;

	FOR_EACH_PTR(return_states_after, fn) {
		(*fn)();
	} END_FOR_EACH_PTR(fn);
}

static int call_call_backs(struct call_back_list *list, int type,
			    const char *fn, struct expression *expr)
{
	struct fcall_back *tmp;
	int handled = 0;

	FOR_EACH_PTR(list, tmp) {
		if (tmp->type == type) {
			(tmp->u.call_back)(fn, expr, tmp->info);
			handled = 1;
		}
	} END_FOR_EACH_PTR(tmp);

	return handled;
}

static void call_ranged_call_backs(struct call_back_list *list,
				const char *fn, struct expression *call_expr,
				struct expression *assign_expr)
{
	struct fcall_back *tmp;

	FOR_EACH_PTR(list, tmp) {
		(tmp->u.ranged)(fn, call_expr, assign_expr, tmp->info);
	} END_FOR_EACH_PTR(tmp);
}

static struct call_back_list *get_same_ranged_call_backs(struct call_back_list *list,
						struct data_range *drange)
{
	struct call_back_list *ret = NULL;
	struct fcall_back *tmp;

	FOR_EACH_PTR(list, tmp) {
		if (tmp->type != RANGED_CALL)
			continue;
		if (ranges_equiv(tmp->range, drange))
			add_ptr_list(&ret, tmp);
	} END_FOR_EACH_PTR(tmp);
	return ret;
}

static int in_list_exact_sval(struct range_list *list, struct data_range *drange)
{
	struct data_range *tmp;

	FOR_EACH_PTR(list, tmp) {
		if (ranges_equiv(tmp, drange))
			return 1;
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

static int assign_ranged_funcs(const char *fn, struct expression *expr,
				 struct call_back_list *call_backs)
{
	struct fcall_back *tmp;
	struct sm_state *sm;
	char *var_name;
	struct symbol *sym;
	struct smatch_state *estate;
	struct stree *tmp_stree;
	struct stree *final_states = NULL;
	struct range_list *handled_ranges = NULL;
	struct call_back_list *same_range_call_backs = NULL;
	int handled = 0;

	if (!call_backs)
		return 0;

	var_name = expr_to_var_sym(expr->left, &sym);
	if (!var_name || !sym)
		goto free;

	FOR_EACH_PTR(call_backs, tmp) {
		if (tmp->type != RANGED_CALL)
			continue;

		if (in_list_exact_sval(handled_ranges, tmp->range))
			continue;
		__push_fake_cur_stree();
		tack_on(&handled_ranges, tmp->range);

		same_range_call_backs = get_same_ranged_call_backs(call_backs, tmp->range);
		call_ranged_call_backs(same_range_call_backs, fn, expr->right, expr);
		__free_ptr_list((struct ptr_list **)&same_range_call_backs);

		estate = alloc_estate_range(tmp->range->min, tmp->range->max);
		set_extra_mod(var_name, sym, estate);

		tmp_stree = __pop_fake_cur_stree();
		merge_fake_stree(&final_states, tmp_stree);
		free_stree(&tmp_stree);
		handled = 1;
	} END_FOR_EACH_PTR(tmp);

	FOR_EACH_SM(final_states, sm) {
		__set_sm(sm);
	} END_FOR_EACH_SM(sm);

	free_stree(&final_states);
free:
	free_string(var_name);
	return handled;
}

static void call_implies_callbacks(int comparison, struct expression *expr, sval_t sval, int left, struct stree **implied_true, struct stree **implied_false)
{
	struct call_back_list *call_backs;
	struct fcall_back *tmp;
	const char *fn;
	struct data_range *value_range;
	struct stree *true_states = NULL;
	struct stree *false_states = NULL;
	struct stree *tmp_stree;

	*implied_true = NULL;
	*implied_false = NULL;
	if (expr->fn->type != EXPR_SYMBOL || !expr->fn->symbol)
		return;
	fn = expr->fn->symbol->ident->name;
	call_backs = search_callback(func_hash, (char *)expr->fn->symbol->ident->name);
	if (!call_backs)
		return;
	value_range = alloc_range(sval, sval);

	/* set true states */
	__push_fake_cur_stree();
	FOR_EACH_PTR(call_backs, tmp) {
		if (tmp->type != RANGED_CALL)
			continue;
		if (!true_comparison_range_LR(comparison, tmp->range, value_range, left))
			continue;
		(tmp->u.ranged)(fn, expr, NULL, tmp->info);
	} END_FOR_EACH_PTR(tmp);
	tmp_stree = __pop_fake_cur_stree();
	merge_fake_stree(&true_states, tmp_stree);
	free_stree(&tmp_stree);

	/* set false states */
	__push_fake_cur_stree();
	FOR_EACH_PTR(call_backs, tmp) {
		if (tmp->type != RANGED_CALL)
			continue;
		if (!false_comparison_range_LR(comparison, tmp->range, value_range, left))
			continue;
		(tmp->u.ranged)(fn, expr, NULL, tmp->info);
	} END_FOR_EACH_PTR(tmp);
	tmp_stree = __pop_fake_cur_stree();
	merge_fake_stree(&false_states, tmp_stree);
	free_stree(&tmp_stree);

	*implied_true = true_states;
	*implied_false = false_states;
}

struct db_callback_info {
	int true_side;
	int comparison;
	struct expression *expr;
	struct range_list *rl;
	int left;
	struct stree *stree;
	struct db_implies_list *callbacks;
	int prev_return_id;
	int cull;
	struct smatch_state *ret_state;
};

static void store_return_state(struct db_callback_info *db_info, struct smatch_state *state)
{
	db_info->ret_state = state;
}

static void set_return_state(struct db_callback_info *db_info)
{
	if (db_info->expr->type != EXPR_ASSIGNMENT) {
		sm_msg("Smatch Internal Error: expected an assignment");
		return;
	}
	if (!db_info->ret_state)
		return;

	set_extra_expr_mod(db_info->expr->left, db_info->ret_state);
	db_info->ret_state = NULL;
}

static void handle_ret_equals_param(char *ret_string, struct range_list *rl, struct expression *call)
{
	char *str;
	long long param;
	struct expression *arg;
	struct range_list *orig;

	str = strstr(ret_string, "==$");
	if (!str)
		return;
	str += 3;
	param = strtoll(str, NULL, 10);
	arg = get_argument_from_call_expr(call->args, param);
	if (!arg)
		return;
	get_absolute_rl(arg, &orig);
	rl = rl_intersection(orig, rl);
	if (!rl)
		return;
	set_extra_expr_nomod(arg, alloc_estate_rl(rl));
}

static int impossible_limit(struct expression *expr, int param, char *key, char *value)
{
	struct expression *arg;
	struct range_list *passed;
	struct range_list *limit;
	struct symbol *compare_type;

	if (strcmp(key, "$") != 0)
		return 0;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return 0;

	arg = get_argument_from_call_expr(expr->args, param);
	if (!arg)
		return 0;
	if (!get_implied_rl(arg, &passed))
		return 0;
	if (!passed || is_whole_rl(passed))
		return 0;

	compare_type = get_arg_type(expr->fn, param);
	call_results_to_rl(expr, compare_type, value, &limit);
	if (!limit || is_whole_rl(limit))
		return 0;
	if (possibly_true_rl(passed, SPECIAL_EQUAL, limit))
		return 0;
	return 1;
}

static int db_compare_callback(void *_info, int argc, char **argv, char **azColName)
{
	struct db_callback_info *db_info = _info;
	struct range_list *ret_range;
	int type, param;
	char *key, *value;
	struct return_implies_callback *tmp;
	struct stree *stree;
	int return_id;
	int comparison;

	if (argc != 6)
		return 0;

	return_id = atoi(argv[0]);
	type = atoi(argv[2]);
	param = atoi(argv[3]);
	key = argv[4];
	value = argv[5];

	if (db_info->prev_return_id != -1 && return_id != db_info->prev_return_id) {
		stree = __pop_fake_cur_stree();
		if (!db_info->cull)
			merge_fake_stree(&db_info->stree, stree);
		free_stree(&stree);
		__push_fake_cur_stree();
		db_info->cull = 0;
	}
	db_info->prev_return_id = return_id;

	if (type == LIMITED_VALUE && impossible_limit(db_info->expr, param, key, value))
		db_info->cull = 1;
	if (db_info->cull)
		return 0;

	call_results_to_rl(db_info->expr, get_type(strip_expr(db_info->expr)), argv[1], &ret_range);
	ret_range = cast_rl(get_type(db_info->expr), ret_range);
	if (!ret_range)
		ret_range = alloc_whole_rl(get_type(db_info->expr));

	comparison = db_info->comparison;
	if (!db_info->left)
		comparison = flip_comparison(comparison);

	if (db_info->true_side) {
		if (!possibly_true_rl(ret_range, comparison, db_info->rl))
			return 0;
		filter_by_comparison(&ret_range, comparison, db_info->rl);
	} else {
		if (!possibly_false_rl(ret_range, comparison, db_info->rl))
			return 0;
		filter_by_comparison(&ret_range, negate_comparison(comparison), db_info->rl);
	}

	handle_ret_equals_param(argv[1], ret_range, db_info->expr);

	FOR_EACH_PTR(db_info->callbacks, tmp) {
		if (tmp->type == type)
			tmp->callback(db_info->expr, param, key, value);
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

static void compare_db_return_states_callbacks(int comparison, struct expression *expr, sval_t sval, int left, struct stree *implied_true, struct stree *implied_false)
{
	struct stree *stree;
	struct stree *true_states;
	struct stree *false_states;
	struct sm_state *sm;
	struct db_callback_info db_info = {};

	db_info.comparison = comparison;
	db_info.expr = expr;
	db_info.rl = alloc_rl(sval, sval);
	db_info.left = left;
	db_info.callbacks = db_return_states_list;

	call_return_states_before_hooks();

	db_info.true_side = 1;
	db_info.stree = NULL;
	db_info.prev_return_id = -1;
	__push_fake_cur_stree();
	sql_select_return_states("return_id, return, type, parameter, key, value", expr,
			db_compare_callback, &db_info);
	stree = __pop_fake_cur_stree();
	if (!db_info.cull)
		merge_fake_stree(&db_info.stree, stree);
	free_stree(&stree);
	true_states = db_info.stree;

	db_info.true_side = 0;
	db_info.stree = NULL;
	db_info.prev_return_id = -1;
	db_info.cull = 0;
	__push_fake_cur_stree();
	sql_select_return_states("return_id, return, type, parameter, key, value", expr,
			db_compare_callback, &db_info);
	stree = __pop_fake_cur_stree();
	if (!db_info.cull)
		merge_fake_stree(&db_info.stree, stree);
	free_stree(&stree);
	false_states = db_info.stree;

	FOR_EACH_SM(true_states, sm) {
		__set_true_false_sm(sm, NULL);
	} END_FOR_EACH_SM(sm);
	FOR_EACH_SM(false_states, sm) {
		__set_true_false_sm(NULL, sm);
	} END_FOR_EACH_SM(sm);

	free_stree(&true_states);
	free_stree(&false_states);

	call_return_states_after_hooks();

	FOR_EACH_SM(implied_true, sm) {
		__set_true_false_sm(sm, NULL);
	} END_FOR_EACH_SM(sm);
	FOR_EACH_SM(implied_false, sm) {
		__set_true_false_sm(NULL, sm);
	} END_FOR_EACH_SM(sm);

}

void function_comparison(int comparison, struct expression *expr, sval_t sval, int left)
{
	struct stree *implied_true, *implied_false;

	call_implies_callbacks(comparison, expr, sval, left, &implied_true, &implied_false);
	compare_db_return_states_callbacks(comparison, expr, sval, left, implied_true, implied_false);
	free_stree(&implied_true);
	free_stree(&implied_false);
}

static int db_assign_return_states_callback(void *_info, int argc, char **argv, char **azColName)
{
	struct db_callback_info *db_info = _info;
	struct range_list *ret_range;
	int type, param;
	char *key, *value;
	struct return_implies_callback *tmp;
	struct stree *stree;
	int return_id;

	if (argc != 6)
		return 0;

	return_id = atoi(argv[0]);
	type = atoi(argv[2]);
	param = atoi(argv[3]);
	key = argv[4];
	value = argv[5];

	if (db_info->prev_return_id != -1 && return_id != db_info->prev_return_id) {
		set_return_state(db_info);
		stree = __pop_fake_cur_stree();
		if (!db_info->cull)
			merge_fake_stree(&db_info->stree, stree);
		free_stree(&stree);
		__push_fake_cur_stree();
		db_info->cull = 0;
	}
	db_info->prev_return_id = return_id;

	if (type == LIMITED_VALUE && impossible_limit(db_info->expr, param, key, value))
		db_info->cull = 1;
	if (db_info->cull)
		return 0;

	call_results_to_rl(db_info->expr->right, get_type(strip_expr(db_info->expr->right)), argv[1], &ret_range);
	__add_comparison_info(db_info->expr->left, strip_expr(db_info->expr->right), argv[1]);
	if (!ret_range)
		ret_range = alloc_whole_rl(get_type(strip_expr(db_info->expr->right)));
	ret_range = cast_rl(get_type(db_info->expr->right), ret_range);

	FOR_EACH_PTR(db_return_states_list, tmp) {
		if (tmp->type == type)
			tmp->callback(db_info->expr, param, key, value);
	} END_FOR_EACH_PTR(tmp);
	ret_range = cast_rl(get_type(db_info->expr->left), ret_range);
	store_return_state(db_info, alloc_estate_rl(ret_range));

	return 0;
}

static int db_return_states_assign(struct expression *expr)
{
	struct expression *right;
	struct sm_state *sm;
	struct stree *stree;
	int handled = 0;
	struct db_callback_info db_info = {};

	right = strip_expr(expr->right);

	db_info.prev_return_id = -1;
	db_info.expr = expr;
	db_info.stree = NULL;

	call_return_states_before_hooks();

	__push_fake_cur_stree();
	sql_select_return_states("return_id, return, type, parameter, key, value",
			right, db_assign_return_states_callback, &db_info);
	set_return_state(&db_info);
	stree = __pop_fake_cur_stree();
	if (!db_info.cull)
		merge_fake_stree(&db_info.stree, stree);
	free_stree(&stree);

	FOR_EACH_SM(db_info.stree, sm) {
		__set_sm(sm);
		handled = 1;
	} END_FOR_EACH_SM(sm);

	free_stree(&db_info.stree);
	call_return_states_after_hooks();

	return handled;
}

static int handle_implied_return(struct expression *expr)
{
	struct range_list *rl;

	if (!get_implied_return(expr->right, &rl))
		return 0;
	rl = cast_rl(get_type(expr->left), rl);
	set_extra_expr_mod(expr->left, alloc_estate_rl(rl));
	return 1;
}

static void match_assign_call(struct expression *expr)
{
	struct call_back_list *call_backs;
	const char *fn;
	struct expression *right;
	int handled = 0;
	struct range_list *rl;

	if (expr->op != '=')
		return;

	right = strip_expr(expr->right);
	if (right->fn->type != EXPR_SYMBOL || !right->fn->symbol) {
		handled |= db_return_states_assign(expr);
		if (!handled)
			goto assigned_unknown;
		return;
	}
	if (is_fake_call(right)) {
		if (!get_state_expr(SMATCH_EXTRA, expr->left))
			return;
		set_extra_expr_mod(expr->left, alloc_estate_whole(get_type(expr->left)));
		return;
	}

	fn = right->fn->symbol->ident->name;

	/*
	 * some of these conflict (they try to set smatch extra twice), so we
	 * call them in order from least important to most important.
	 */

	call_backs = search_callback(func_hash, (char *)fn);
	call_call_backs(call_backs, ASSIGN_CALL, fn, expr);

	handled |= db_return_states_assign(expr);
	handled |= assign_ranged_funcs(fn, expr, call_backs);
	handled |= handle_implied_return(expr);

	if (handled)
		return;

assigned_unknown:
	get_absolute_rl(expr->right, &rl);
	rl = cast_rl(get_type(expr->left), rl);
	set_extra_expr_mod(expr->left, alloc_estate_rl(rl));
}

static int db_return_states_callback(void *_info, int argc, char **argv, char **azColName)
{
	struct db_callback_info *db_info = _info;
	struct range_list *ret_range;
	int type, param;
	char *key, *value;
	struct return_implies_callback *tmp;
	struct stree *stree;
	int return_id;
	char buf[64];

	if (argc != 6)
		return 0;

	return_id = atoi(argv[0]);
	type = atoi(argv[2]);
	param = atoi(argv[3]);
	key = argv[4];
	value = argv[5];

	if (db_info->prev_return_id != -1 && return_id != db_info->prev_return_id) {
		stree = __pop_fake_cur_stree();
		if (!db_info->cull)
			merge_fake_stree(&db_info->stree, stree);
		free_stree(&stree);
		__push_fake_cur_stree();
		__unnullify_path();
		db_info->cull = 0;
	}
	db_info->prev_return_id = return_id;

	if (type == LIMITED_VALUE && impossible_limit(db_info->expr, param, key, value))
		db_info->cull = 1;
	if (db_info->cull)
		return 0;

	call_results_to_rl(db_info->expr, get_type(strip_expr(db_info->expr)), argv[1], &ret_range);
	ret_range = cast_rl(get_type(db_info->expr), ret_range);

	FOR_EACH_PTR(db_return_states_list, tmp) {
		if (tmp->type == type)
			tmp->callback(db_info->expr, param, key, value);
	} END_FOR_EACH_PTR(tmp);

	/*
	 * We want to store the return values so that we can split the strees
	 * in smatch_db.c.  This uses set_state() directly because it's not a
	 * real smatch_extra state.
	 */
	snprintf(buf, sizeof(buf), "return %p", db_info->expr);
	set_state(SMATCH_EXTRA, buf, NULL, alloc_estate_rl(ret_range));

	return 0;
}

static void db_return_states(struct expression *expr)
{
	struct sm_state *sm;
	struct stree *stree;
	struct db_callback_info db_info = {};

	if (!__get_cur_stree())  /* no return functions */
		return;

	db_info.prev_return_id = -1;
	db_info.expr = expr;
	db_info.stree = NULL;

	call_return_states_before_hooks();

	__push_fake_cur_stree();
	__unnullify_path();
	sql_select_return_states("return_id, return, type, parameter, key, value",
			expr, db_return_states_callback, &db_info);
	stree = __pop_fake_cur_stree();
	if (!db_info.cull)
		merge_fake_stree(&db_info.stree, stree);
	free_stree(&stree);

	FOR_EACH_SM(db_info.stree, sm) {
		__set_sm(sm);
	} END_FOR_EACH_SM(sm);

	free_stree(&db_info.stree);
	call_return_states_after_hooks();
}

static void db_return_states_call(struct expression *expr)
{
	if (is_assigned_call(expr))
		return;
	db_return_states(expr);
}

static void match_function_call(struct expression *expr)
{
	struct call_back_list *call_backs;

	if (expr->fn->type == EXPR_SYMBOL && expr->fn->symbol) {
		call_backs = search_callback(func_hash, (char *)expr->fn->symbol->ident->name);
		if (call_backs)
			call_call_backs(call_backs, REGULAR_CALL,
					expr->fn->symbol->ident->name, expr);
	}
	db_return_states_call(expr);
}

static void match_macro_assign(struct expression *expr)
{
	struct call_back_list *call_backs;
	const char *macro;
	struct expression *right;

	right = strip_expr(expr->right);
	macro = get_macro_name(right->pos);
	call_backs = search_callback(func_hash, (char *)macro);
	if (!call_backs)
		return;
	call_call_backs(call_backs, MACRO_ASSIGN, macro, expr);
	call_call_backs(call_backs, MACRO_ASSIGN_EXTRA, macro, expr);
}

int get_implied_return(struct expression *expr, struct range_list **rl)
{
	struct call_back_list *call_backs;
	struct fcall_back *tmp;
	int handled = 0;
	char *fn;

	*rl = NULL;

	expr = strip_expr(expr);
	fn = expr_to_var(expr->fn);
	if (!fn)
		goto out;

	call_backs = search_callback(func_hash, fn);

	FOR_EACH_PTR(call_backs, tmp) {
		if (tmp->type == IMPLIED_RETURN) {
			(tmp->u.implied_return)(expr, tmp->info, rl);
			handled = 1;
		}
	} END_FOR_EACH_PTR(tmp);

out:
	free_string(fn);
	return handled;
}

void create_function_hook_hash(void)
{
	func_hash = create_function_hashtable(5000);
}

void register_function_hooks(int id)
{
	add_hook(&match_function_call, CALL_HOOK_AFTER_INLINE);
	add_hook(&match_assign_call, CALL_ASSIGNMENT_HOOK);
	add_hook(&match_macro_assign, MACRO_ASSIGNMENT_HOOK);
}
