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

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

int local_debug;
static int my_id;
char *trace_variable;

static void match_all_values(const char *fn, struct expression *expr, void *info)
{
	struct stree *stree;

	stree = get_all_states_stree(SMATCH_EXTRA);
	__print_stree(stree);
	free_stree(&stree);
}

static void match_cur_stree(const char *fn, struct expression *expr, void *info)
{
	__print_cur_stree();
}

static void match_state(const char *fn, struct expression *expr, void *info)
{
	struct expression *check_arg, *state_arg;
	struct sm_state *sm;
	int found = 0;

	check_arg = get_argument_from_call_expr(expr->args, 0);
	if (check_arg->type != EXPR_STRING) {
		sm_msg("error:  the check_name argument to %s is supposed to be a string literal", fn);
		return;
	}
	state_arg = get_argument_from_call_expr(expr->args, 1);
	if (!state_arg || state_arg->type != EXPR_STRING) {
		sm_msg("error:  the state_name argument to %s is supposed to be a string literal", fn);
		return;
	}

	FOR_EACH_SM(__get_cur_stree(), sm) {
		if (strcmp(check_name(sm->owner), check_arg->string->data) != 0)
			continue;
		if (strcmp(sm->name, state_arg->string->data) != 0)
			continue;
		sm_msg("'%s' = '%s'", sm->name, sm->state->name);
		found = 1;
	} END_FOR_EACH_SM(sm);

	if (!found)
		sm_msg("%s '%s' not found", check_arg->string->data, state_arg->string->data);
}

static void match_states(const char *fn, struct expression *expr, void *info)
{
	struct expression *check_arg;
	struct sm_state *sm;
	int found = 0;

	check_arg = get_argument_from_call_expr(expr->args, 0);
	if (check_arg->type != EXPR_STRING) {
		sm_msg("error:  the check_name argument to %s is supposed to be a string literal", fn);
		return;
	}

	FOR_EACH_SM(__get_cur_stree(), sm) {
		if (strcmp(check_name(sm->owner), check_arg->string->data) != 0)
			continue;
		sm_msg("%s", show_sm(sm));
		found = 1;
	} END_FOR_EACH_SM(sm);

	if (found)
		return;

	if (!id_from_name(check_arg->string->data))
		sm_msg("invalid check name '%s'", check_arg->string->data);
	else
		sm_msg("%s: no states", check_arg->string->data);
}

static void match_print_value(const char *fn, struct expression *expr, void *info)
{
	struct stree *stree;
	struct sm_state *tmp;
	struct expression *arg_expr;

	arg_expr = get_argument_from_call_expr(expr->args, 0);
	if (arg_expr->type != EXPR_STRING) {
		sm_msg("error:  the argument to %s is supposed to be a string literal", fn);
		return;
	}

	stree = __get_cur_stree();
	FOR_EACH_MY_SM(SMATCH_EXTRA, stree, tmp) {
		if (!strcmp(tmp->name, arg_expr->string->data))
			sm_msg("%s = %s", tmp->name, tmp->state->name);
	} END_FOR_EACH_SM(tmp);
}

static void match_print_known(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	struct range_list *rl = NULL;
	char *name;
	int known = 0;
	sval_t sval;

	arg = get_argument_from_call_expr(expr->args, 0);
	if (get_value(arg, &sval))
		known = 1;

	get_implied_rl(arg, &rl);

	name = expr_to_str(arg);
	sm_msg("known: '%s' = '%s'.  implied = '%s'", name, known ? sval_to_str(sval) : "<unknown>", show_rl(rl));
	free_string(name);
}

static void match_print_implied(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	struct range_list *rl = NULL;
	char *name;

	arg = get_argument_from_call_expr(expr->args, 0);
	get_implied_rl(arg, &rl);

	name = expr_to_str(arg);
	sm_msg("implied: %s = '%s'", name, show_rl(rl));
	free_string(name);
}

static void match_real_absolute(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	struct range_list *rl = NULL;
	char *name;

	arg = get_argument_from_call_expr(expr->args, 0);
	get_real_absolute_rl(arg, &rl);

	name = expr_to_str(arg);
	sm_msg("real absolute: %s = '%s'", name, show_rl(rl));
	free_string(name);
}

static void match_print_implied_min(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	sval_t sval;
	char *name;

	arg = get_argument_from_call_expr(expr->args, 0);
	name = expr_to_str(arg);

	if (get_implied_min(arg, &sval))
		sm_msg("implied min: %s = %s", name, sval_to_str(sval));
	else
		sm_msg("implied min: %s = <unknown>", name);

	free_string(name);
}

static void match_print_implied_max(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	sval_t sval;
	char *name;

	arg = get_argument_from_call_expr(expr->args, 0);
	name = expr_to_str(arg);

	if (get_implied_max(arg, &sval))
		sm_msg("implied max: %s = %s", name, sval_to_str(sval));
	else
		sm_msg("implied max: %s = <unknown>", name);

	free_string(name);
}

static void match_user_rl(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	struct range_list *rl;
	char *name;

	arg = get_argument_from_call_expr(expr->args, 0);
	name = expr_to_str(arg);

	get_user_rl(arg, &rl);
	sm_msg("user rl: '%s' = '%s'", name, show_rl(rl));

	free_string(name);
}

static void match_print_hard_max(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	sval_t sval;
	char *name;

	arg = get_argument_from_call_expr(expr->args, 0);
	name = expr_to_str(arg);

	if (get_hard_max(arg, &sval))
		sm_msg("hard max: %s = %s", name, sval_to_str(sval));
	else
		sm_msg("hard max: %s = <unknown>", name);

	free_string(name);
}

static void match_print_fuzzy_max(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	sval_t sval;
	char *name;

	arg = get_argument_from_call_expr(expr->args, 0);
	name = expr_to_str(arg);

	if (get_fuzzy_max(arg, &sval))
		sm_msg("fuzzy max: %s = %s", name, sval_to_str(sval));
	else
		sm_msg("fuzzy max: %s = <unknown>", name);

	free_string(name);
}

static void match_print_absolute(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	struct range_list *rl;
	char *name;

	arg = get_argument_from_call_expr(expr->args, 0);
	name = expr_to_str(arg);

	get_absolute_rl(arg, &rl);
	sm_msg("absolute: %s = %s", name, show_rl(rl));

	free_string(name);
}

static void match_print_absolute_min(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	sval_t sval;
	char *name;

	arg = get_argument_from_call_expr(expr->args, 0);
	name = expr_to_str(arg);

	if (get_absolute_min(arg, &sval))
		sm_msg("absolute min: %s = %s", name, sval_to_str(sval));
	else
		sm_msg("absolute min: %s = <unknown>", name);

	free_string(name);
}

static void match_print_absolute_max(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	sval_t sval;
	char *name;

	arg = get_argument_from_call_expr(expr->args, 0);
	get_absolute_max(arg, &sval);

	name = expr_to_str(arg);
	sm_msg("absolute max: %s = %s", name, sval_to_str(sval));
	free_string(name);
}

static void match_sval_info(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	sval_t sval;
	char *name;

	arg = get_argument_from_call_expr(expr->args, 0);
	name = expr_to_str(arg);

	if (!get_implied_value(arg, &sval)) {
		sm_msg("no sval for '%s'", name);
		goto free;
	}

	sm_msg("implied: %s %c%d ->value = %llx", name, sval_unsigned(sval) ? 'u' : 's', sval_bits(sval), sval.value);
free:
	free_string(name);
}

static void match_member_name(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	char *name, *member_name;

	arg = get_argument_from_call_expr(expr->args, 0);
	name = expr_to_str(arg);
	member_name = get_member_name(arg);
	sm_msg("member name: '%s => %s'", name, member_name);
	free_string(member_name);
	free_string(name);
}

static void print_possible(struct sm_state *sm)
{
	struct sm_state *tmp;

	sm_msg("Possible values for %s", sm->name);
	FOR_EACH_PTR(sm->possible, tmp) {
		printf("%s\n", tmp->state->name);
	} END_FOR_EACH_PTR(tmp);
	sm_msg("===");
}

static void match_possible(const char *fn, struct expression *expr, void *info)
{
	struct stree *stree;
	struct sm_state *tmp;
	struct expression *arg_expr;

	arg_expr = get_argument_from_call_expr(expr->args, 0);
	if (arg_expr->type != EXPR_STRING) {
		sm_msg("error:  the argument to %s is supposed to be a string literal", fn);
		return;
	}

	stree = __get_cur_stree();
	FOR_EACH_MY_SM(SMATCH_EXTRA, stree, tmp) {
		if (!strcmp(tmp->name, arg_expr->string->data))
			print_possible(tmp);
	} END_FOR_EACH_SM(tmp);
}

static void match_strlen(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	struct range_list *rl;
	char *name;

	arg = get_argument_from_call_expr(expr->args, 0);
	get_implied_strlen(arg, &rl);

	name = expr_to_str(arg);
	sm_msg("strlen: '%s' %s characters", name, show_rl(rl));
	free_string(name);
}

static void match_buf_size(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	int elements, bytes;
	char *name;

	arg = get_argument_from_call_expr(expr->args, 0);
	elements = get_array_size(arg);
	bytes = get_array_size_bytes_max(arg);

	name = expr_to_str(arg);
	sm_msg("buf size: '%s' %d elements, %d bytes", name, elements, bytes);
	free_string(name);
}

static void match_buf_size_rl(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	struct range_list *rl;
	int elements, bytes;
	char *name;

	arg = get_argument_from_call_expr(expr->args, 0);
	rl = get_array_size_bytes_rl(arg);
	elements = get_array_size(arg);
	bytes = get_array_size_bytes(arg);

	name = expr_to_str(arg);
	sm_msg("buf size: '%s' %s %d elements, %d bytes", name, show_rl(rl), elements, bytes);
	free_string(name);
}

static void match_note(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg_expr;

	arg_expr = get_argument_from_call_expr(expr->args, 0);
	if (arg_expr->type != EXPR_STRING) {
		sm_msg("error:  the argument to %s is supposed to be a string literal", fn);
		return;
	}
	sm_msg("%s", arg_expr->string->data);
}

static void print_related(struct sm_state *sm)
{
	struct relation *rel;

	if (!estate_related(sm->state))
		return;

	sm_prefix();
	sm_printf("%s: ", sm->name);
	FOR_EACH_PTR(estate_related(sm->state), rel) {
		sm_printf("%s ", rel->name);
	} END_FOR_EACH_PTR(rel);
	sm_printf("\n");
}

static void match_dump_related(const char *fn, struct expression *expr, void *info)
{
	struct stree *stree;
	struct sm_state *tmp;

	stree = __get_cur_stree();
	FOR_EACH_MY_SM(SMATCH_EXTRA, stree, tmp) {
		print_related(tmp);
	} END_FOR_EACH_SM(tmp);
}

static void match_compare(const char *fn, struct expression *expr, void *info)
{
	struct expression *one, *two;
	char *one_name, *two_name;
	int comparison;
	char buf[16];

	one = get_argument_from_call_expr(expr->args, 0);
	two = get_argument_from_call_expr(expr->args, 1);

	comparison = get_comparison(one, two);
	if (!comparison)
		snprintf(buf, sizeof(buf), "<none>");
	else
		snprintf(buf, sizeof(buf), "%s", show_special(comparison));

	one_name = expr_to_str(one);
	two_name = expr_to_str(two);

	sm_msg("%s %s %s", one_name, buf, two_name);

	free_string(one_name);
	free_string(two_name);
}

static void match_debug_on(const char *fn, struct expression *expr, void *info)
{
	option_debug = 1;
}

static void match_debug_check(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;

	arg = get_argument_from_call_expr(expr->args, 0);
	if (!arg || arg->type != EXPR_STRING)
		return;
	option_debug_check = arg->string->data;
	sm_msg("arg = '%s'", option_debug_check);
}

static void match_debug_off(const char *fn, struct expression *expr, void *info)
{
	option_debug_check = (char *)"";
	option_debug = 0;
}

static void match_local_debug_on(const char *fn, struct expression *expr, void *info)
{
	local_debug = 1;
}

static void match_local_debug_off(const char *fn, struct expression *expr, void *info)
{
	local_debug = 0;
}

static void match_debug_implied_on(const char *fn, struct expression *expr, void *info)
{
	option_debug_implied = 1;
}

static void match_debug_implied_off(const char *fn, struct expression *expr, void *info)
{
	option_debug_implied = 0;
}

static void match_about(const char *fn, struct expression *expr, void *info)
{
	struct expression *arg;
	struct sm_state *sm;
	char *name;

	sm_msg("---- about ----");
	match_print_implied(fn, expr, NULL);
	match_buf_size(fn, expr, NULL);
	match_strlen(fn, expr, NULL);
	match_real_absolute(fn, expr, NULL);

	arg = get_argument_from_call_expr(expr->args, 0);
	name = expr_to_str(arg);
	if (!name) {
		sm_msg("info: not a straight forward variable.");
		return;
	}

	FOR_EACH_SM(__get_cur_stree(), sm) {
		if (strcmp(sm->name, name) != 0)
			continue;
		sm_msg("%s", show_sm(sm));
	} END_FOR_EACH_SM(sm);
}

static void match_intersection(const char *fn, struct expression *expr, void *info)
{
	struct expression *one, *two;
	struct range_list *one_rl, *two_rl;
	struct range_list *res;

	one = get_argument_from_call_expr(expr->args, 0);
	two = get_argument_from_call_expr(expr->args, 1);

	get_absolute_rl(one, &one_rl);
	get_absolute_rl(two, &two_rl);

	res = rl_intersection(one_rl, two_rl);
	sm_msg("'%s' intersect '%s' is '%s'", show_rl(one_rl), show_rl(two_rl), show_rl(res));
}

static void match_type(const char *fn, struct expression *expr, void *info)
{
	struct expression *one;
	struct symbol *type;
	char *name;

	one = get_argument_from_call_expr(expr->args, 0);
	type = get_type(one);
	name = expr_to_str(one);
	sm_msg("type of '%s' is: '%s'", name, type_to_str(type));
	free_string(name);
}

static void match_type_rl(const char *fn, struct expression *expr, void *info)
{
	struct expression *one, *two;
	struct symbol *type;
	struct range_list *rl;

	one = get_argument_from_call_expr(expr->args, 0);
	type = get_type(one);

	two = get_argument_from_call_expr(expr->args, 1);
	if (!two || two->type != EXPR_STRING) {
		sm_msg("expected: __smatch_type_rl(type, \"string\")");
		return;
	}
	call_results_to_rl(expr, type, two->string->data, &rl);
	sm_msg("'%s' => '%s'", two->string->data, show_rl(rl));
}

static struct stree *old_stree;
static void trace_var(struct statement *stmt)
{
	struct sm_state *sm, *old;

	if (!trace_variable)
		return;
	if (__inline_fn)
		return;

	FOR_EACH_SM(__get_cur_stree(), sm) {
		if (strcmp(sm->name, trace_variable) != 0)
			continue;
		old = get_sm_state_stree(old_stree, sm->owner, sm->name, sm->sym);
		if (old && old->state == sm->state)
			continue;
		sm_msg("[%d] %s '%s': '%s' => '%s'", stmt->type,
		       check_name(sm->owner),
		       sm->name, old ? old->state->name : "<none>", sm->state->name);
	} END_FOR_EACH_SM(sm);

	free_stree(&old_stree);
	old_stree = clone_stree(__get_cur_stree());
}

static void free_old_stree(struct symbol *sym)
{
	free_stree(&old_stree);
}

void check_debug(int id)
{
	my_id = id;
	add_function_hook("__smatch_about", &match_about, NULL);
	add_function_hook("__smatch_all_values", &match_all_values, NULL);
	add_function_hook("__smatch_state", &match_state, NULL);
	add_function_hook("__smatch_states", &match_states, NULL);
	add_function_hook("__smatch_value", &match_print_value, NULL);
	add_function_hook("__smatch_known", &match_print_known, NULL);
	add_function_hook("__smatch_implied", &match_print_implied, NULL);
	add_function_hook("__smatch_implied_min", &match_print_implied_min, NULL);
	add_function_hook("__smatch_implied_max", &match_print_implied_max, NULL);
	add_function_hook("__smatch_user_rl", &match_user_rl, NULL);
	add_function_hook("__smatch_hard_max", &match_print_hard_max, NULL);
	add_function_hook("__smatch_fuzzy_max", &match_print_fuzzy_max, NULL);
	add_function_hook("__smatch_absolute", &match_print_absolute, NULL);
	add_function_hook("__smatch_absolute_min", &match_print_absolute_min, NULL);
	add_function_hook("__smatch_absolute_max", &match_print_absolute_max, NULL);
	add_function_hook("__smatch_real_absolute", &match_real_absolute, NULL);
	add_function_hook("__smatch_sval_info", &match_sval_info, NULL);
	add_function_hook("__smatch_member_name", &match_member_name, NULL);
	add_function_hook("__smatch_possible", &match_possible, NULL);
	add_function_hook("__smatch_cur_stree", &match_cur_stree, NULL);
	add_function_hook("__smatch_strlen", &match_strlen, NULL);
	add_function_hook("__smatch_buf_size", &match_buf_size, NULL);
	add_function_hook("__smatch_buf_size_rl", &match_buf_size_rl, NULL);
	add_function_hook("__smatch_note", &match_note, NULL);
	add_function_hook("__smatch_dump_related", &match_dump_related, NULL);
	add_function_hook("__smatch_compare", &match_compare, NULL);
	add_function_hook("__smatch_debug_on", &match_debug_on, NULL);
	add_function_hook("__smatch_debug_check", &match_debug_check, NULL);
	add_function_hook("__smatch_debug_off", &match_debug_off, NULL);
	add_function_hook("__smatch_local_debug_on", &match_local_debug_on, NULL);
	add_function_hook("__smatch_local_debug_off", &match_local_debug_off, NULL);
	add_function_hook("__smatch_debug_implied_on", &match_debug_implied_on, NULL);
	add_function_hook("__smatch_debug_implied_off", &match_debug_implied_off, NULL);
	add_function_hook("__smatch_intersection", &match_intersection, NULL);
	add_function_hook("__smatch_type", &match_type, NULL);
	add_function_hook("__smatch_type_rl_helper", match_type_rl, NULL);

	add_hook(free_old_stree, END_FUNC_HOOK);
	add_hook(trace_var, STMT_HOOK_AFTER);
}
