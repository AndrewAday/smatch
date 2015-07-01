/*
 * Copyright (C) 2011 Dan Carpenter.
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
 * There are a couple checks that try to see if a variable
 * comes from the user.  It would be better to unify them
 * into one place.  Also it we should follow the data down
 * the call paths.  Hence this file.
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

STATE(called);

STATE(capped);
STATE(user_data_passed);
STATE(user_data_set);

enum {
	SET_DATA = 1,
	PASSED_DATA = 2,
};

int is_user_macro(struct expression *expr)
{
	char *macro;
	struct range_list *rl;

	macro = get_macro_name(expr->pos);

	if (!macro)
		return 0;
	if (get_implied_rl(expr, &rl) && !is_whole_rl(rl))
		return 0;
	if (strcmp(macro, "ntohl") == 0)
		return SET_DATA;
	if (strcmp(macro, "ntohs") == 0)
		return SET_DATA;
	return 0;
}

static int has_user_data_state(struct expression *expr)
{
	struct stree *stree;
	struct sm_state *sm;
	struct symbol *sym;
	char *name;

	expr = strip_expr(expr);
	if (expr->type == EXPR_PREOP && expr->op == '&')
		expr = strip_expr(expr->unop);

	name = expr_to_str_sym(expr, &sym);
	free_string(name);
	if (!sym)
		return 1;

	stree = __get_cur_stree();
	FOR_EACH_MY_SM(my_id, stree, sm) {
		if (sm->sym == sym)
			return 1;
	} END_FOR_EACH_SM(sm);
	return 0;
}

static int passes_user_data(struct expression *expr)
{
	struct expression *arg;

	FOR_EACH_PTR(expr->args, arg) {
		if (is_user_data(arg))
			return 1;
		if (has_user_data_state(arg))
			return 1;
	} END_FOR_EACH_PTR(arg);

	return 0;
}

static struct expression *db_expr;
static int db_user_data;
static int db_user_data_callback(void *unused, int argc, char **argv, char **azColName)
{
	if (atoi(argv[0]) == PASSED_DATA && !passes_user_data(db_expr))
		return 0;
	db_user_data = 1;
	return 0;
}

static int is_user_fn_db(struct expression *expr)
{
	struct symbol *sym;
	static char sql_filter[1024];

	if (is_fake_call(expr))
		return 0;
	if (expr->fn->type != EXPR_SYMBOL)
		return 0;
	sym = expr->fn->symbol;
	if (!sym)
		return 0;

	if (sym->ctype.modifiers & MOD_STATIC) {
		snprintf(sql_filter, 1024, "file = '%s' and function = '%s';",
			 get_filename(), sym->ident->name);
	} else {
		snprintf(sql_filter, 1024, "function = '%s' and static = 0;",
				sym->ident->name);
	}

	db_expr = expr;
	db_user_data = 0;
	run_sql(db_user_data_callback, NULL,
		"select value from return_states where type=%d and parameter = -1 and key = '$' and %s",
		USER_DATA, sql_filter);
	return db_user_data;
}

static int is_user_function(struct expression *expr)
{
	if (expr->type != EXPR_CALL)
		return 0;
	return is_user_fn_db(expr);
}

static int is_skb_data(struct expression *expr)
{
	struct symbol *sym;
	char *name;
	int len;
	int ret = 0;

	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;

	sym = get_base_type(sym);
	if (!sym || sym->type != SYM_PTR)
		goto free;
	sym = get_base_type(sym);
	if (!sym || sym->type != SYM_STRUCT || !sym->ident)
		goto free;
	if (strcmp(sym->ident->name, "sk_buff") != 0)
		goto free;

	len = strlen(name);
	if (len < 6)
		goto free;
	if (strcmp(name + len - 6, "->data") == 0)
		ret = SET_DATA;

free:
	free_string(name);
	return ret;
}

static int in_container_of_macro(struct expression *expr)
{
	char *macro;

	macro = get_macro_name(expr->pos);

	if (!macro)
		return 0;
	if (strcmp(macro, "container_of") == 0)
		return 1;
	return 0;
}

static int is_user_data_state(struct expression *expr)
{
	struct stree *stree = NULL;
	struct sm_state *tmp;
	struct symbol *sym;
	char *name;
	int user = 0;

	tmp = get_sm_state_expr(my_id, expr);
	if (tmp) {
		if (slist_has_state(tmp->possible, &user_data_set))
			return SET_DATA;
		if (slist_has_state(tmp->possible, &user_data_passed))
			return PASSED_DATA;
		return 0;
	}

	name = expr_to_str_sym(expr, &sym);
	if (!name || !sym)
		goto free;

	stree = __get_cur_stree();
	FOR_EACH_MY_SM(my_id, stree, tmp) {
		if (tmp->sym != sym)
			continue;
		if (!strncmp(tmp->name, name, strlen(tmp->name))) {
			if (slist_has_state(tmp->possible, &user_data_set))
				user = SET_DATA;
			else if (slist_has_state(tmp->possible, &user_data_passed))
				user = PASSED_DATA;
			goto free;
		}
	} END_FOR_EACH_SM(tmp);

free:
	free_string(name);
	return user;
}

int is_user_data(struct expression *expr)
{
	int user_data;

	if (!expr)
		return 0;

	if (is_capped(expr))
		return 0;
	if (in_container_of_macro(expr))
		return 0;

	user_data = is_user_macro(expr);
	if (user_data)
		return user_data;
	user_data = is_user_function(expr);
	if (user_data)
		return user_data;
	user_data = is_skb_data(expr);
	if (user_data)
		return user_data;

	expr = strip_expr(expr);  /* this has to come after is_user_macro() */

	if (expr->type == EXPR_BINOP) {
		user_data = is_user_data(expr->left);
		if (user_data)
			return user_data;
		if (is_array(expr))
			return 0;
		user_data = is_user_data(expr->right);
		if (user_data)
			return user_data;
		return 0;
	}
	if (expr->type == EXPR_PREOP && (expr->op == '&' || expr->op == '*'))
		expr = strip_expr(expr->unop);

	return is_user_data_state(expr);
}

int implied_user_data(struct expression *expr, struct range_list **rl)
{
	if (!is_user_data(expr))
		return 0;
	get_absolute_rl(expr, rl);
	return 1;
}

int is_capped_user_data(struct expression *expr)
{
	struct sm_state *sm;

	sm = get_sm_state_expr(my_id, expr);
	if (!sm)
		return 0;
	if (slist_has_state(sm->possible, &capped))
		return 1;
	return 0;
}

static void set_called(const char *name, struct symbol *sym, char *key, char *value)
{
	set_state(my_id, "this_function", NULL, &called);
}

static void set_param_user_data(const char *name, struct symbol *sym, char *key, char *value)
{
	char fullname[256];

	/* sanity check.  this should always be true. */
	if (strncmp(key, "$", 1) != 0)
		return;
	snprintf(fullname, 256, "%s%s", name, key + 1);
	set_state(my_id, fullname, sym, &user_data_passed);
}

static void match_syscall_definition(struct symbol *sym)
{
	struct symbol *arg;
	char *macro;
	char *name;
	int is_syscall = 0;

	macro = get_macro_name(sym->pos);
	if (macro &&
	    (strncmp("SYSCALL_DEFINE", macro, strlen("SYSCALL_DEFINE")) == 0 ||
	     strncmp("COMPAT_SYSCALL_DEFINE", macro, strlen("COMPAT_SYSCALL_DEFINE")) == 0))
		is_syscall = 1;

	name = get_function();
	if (!option_no_db && get_state(my_id, "this_function", NULL) != &called) {
		if (name && strncmp(name, "sys_", 4) == 0)
			is_syscall = 1;
	}

	if (name && strncmp(name, "compat_sys_", 11) == 0)
		is_syscall = 1;

	if (!is_syscall)
		return;

	FOR_EACH_PTR(sym->ctype.base_type->arguments, arg) {
		set_state(my_id, arg->ident->name, arg, &user_data_set);
	} END_FOR_EACH_PTR(arg);
}

static void match_condition(struct expression *expr)
{
	switch (expr->op) {
	case '<':
	case SPECIAL_LTE:
	case SPECIAL_UNSIGNED_LT:
	case SPECIAL_UNSIGNED_LTE:
		if (is_user_data(expr->left))
			set_true_false_states_expr(my_id, expr->left, &capped, NULL);
		if (is_user_data(expr->right))
			set_true_false_states_expr(my_id, expr->right, NULL, &capped);
		break;
	case '>':
	case SPECIAL_GTE:
	case SPECIAL_UNSIGNED_GT:
	case SPECIAL_UNSIGNED_GTE:
		if (is_user_data(expr->right))
			set_true_false_states_expr(my_id, expr->right, &capped, NULL);
		if (is_user_data(expr->left))
			set_true_false_states_expr(my_id, expr->left, NULL, &capped);
		break;
	case SPECIAL_EQUAL:
		if (is_user_data(expr->left))
			set_true_false_states_expr(my_id, expr->left, &capped, NULL);
		if (is_user_data(expr->right))
			set_true_false_states_expr(my_id, expr->right, &capped, NULL);
		break;
	case SPECIAL_NOTEQUAL:
		if (is_user_data(expr->left))
			set_true_false_states_expr(my_id, expr->left, NULL, &capped);
		if (is_user_data(expr->right))
			set_true_false_states_expr(my_id, expr->right, NULL, &capped);
		break;
	default:
		return;
	}
}

static int handle_get_user(struct expression *expr)
{
	char *name;
	int ret = 0;

	name = get_macro_name(expr->pos);
	if (!name || strcmp(name, "get_user") != 0)
		return 0;

	name = expr_to_var(expr->right);
	if (!name || strcmp(name, "__val_gu") != 0)
		goto free;
	set_state_expr(my_id, expr->left, &user_data_set);
	ret = 1;
free:
	free_string(name);
	return ret;
}

static void match_assign(struct expression *expr)
{
	int user_data;

	if (handle_get_user(expr))
		return;

	user_data = is_user_data(expr->right);
	if (user_data == PASSED_DATA)
		set_state_expr(my_id, expr->left, &user_data_passed);
	else if (user_data == SET_DATA)
		set_state_expr(my_id, expr->left, &user_data_set);
	else if (get_state_expr(my_id, expr->left))
		set_state_expr(my_id, expr->left, &capped);
}

static void tag_struct_members(struct symbol *type, struct expression *expr)
{
	struct symbol *tmp;
	struct expression *member;
	int op = '*';

	if (expr->type == EXPR_PREOP && expr->op == '&') {
		expr = strip_expr(expr->unop);
		op = '.';
	}

	FOR_EACH_PTR(type->symbol_list, tmp) {
		if (!tmp->ident)
			continue;
		member = member_expression(expr, op, tmp->ident);
		set_state_expr(my_id, member, &user_data_set);
	} END_FOR_EACH_PTR(tmp);
}

static void tag_base_type(struct expression *expr)
{
	if (expr->type == EXPR_PREOP && expr->op == '&')
		expr = strip_expr(expr->unop);
	else
		expr = deref_expression(expr);
	set_state_expr(my_id, expr, &user_data_set);
}

static void tag_as_user_data(struct expression *expr)
{
	struct symbol *type;

	expr = strip_expr(expr);

	type = get_type(expr);
	if (!type || type->type != SYM_PTR)
		return;
	type = get_real_base_type(type);
	if (!type)
		return;
	if (type == &void_ctype) {
		set_state_expr(my_id, deref_expression(expr), &user_data_set);
		return;
	}
	if (type->type == SYM_BASETYPE)
		tag_base_type(expr);
	if (type->type == SYM_STRUCT) {
		if (expr->type != EXPR_PREOP || expr->op != '&')
			expr = deref_expression(expr);
		tag_struct_members(type, expr);
	}
}

static void match_user_copy(const char *fn, struct expression *expr, void *_param)
{
	int param = PTR_INT(_param);
	struct expression *dest;

	dest = get_argument_from_call_expr(expr->args, param);
	dest = strip_expr(dest);
	if (!dest)
		return;
	tag_as_user_data(dest);
}

static void match_user_assign_function(const char *fn, struct expression *expr, void *unused)
{
	set_state_expr(my_id, expr->left, &user_data_set);
}

static void match_caller_info(struct expression *expr)
{
	struct expression *tmp;
	int i;

	i = 0;
	FOR_EACH_PTR(expr->args, tmp) {
		if (is_user_data(tmp))
			sql_insert_caller_info(expr, USER_DATA, i, "$", "");
		i++;
	} END_FOR_EACH_PTR(tmp);
}

static void struct_member_callback(struct expression *call, int param, char *printed_name, struct sm_state *sm)
{
	if (sm->state == &capped)
		return;
	sql_insert_caller_info(call, USER_DATA, param, printed_name, "");
}

static void returned_member_callback(int return_id, char *return_ranges, struct expression *expr, char *printed_name, struct smatch_state *state)
{
	if (state == &capped)
		return;
	sql_insert_return_states(return_id, return_ranges, USER_DATA, -1, printed_name, "");
}

static void print_returned_user_data(int return_id, char *return_ranges, struct expression *expr)
{
	struct stree *stree;
	struct sm_state *tmp;
	int param;
	int user_data;
	const char *passed_or_new;

	user_data = is_user_data(expr);
	if (user_data == PASSED_DATA) {
		sql_insert_return_states(return_id, return_ranges, USER_DATA,
				-1, "$", "2");
	}
	if (user_data == SET_DATA) {
		sql_insert_return_states(return_id, return_ranges, USER_DATA,
				-1, "$", "1");
	}

	stree = __get_cur_stree();

	FOR_EACH_MY_SM(my_id, stree, tmp) {
		const char *param_name;

		param = get_param_num_from_sym(tmp->sym);
		if (param < 0)
			continue;

		if (is_capped_var_sym(tmp->name, tmp->sym))
			continue;
		/* ignore states that were already USER_DATA to begin with */
		if (get_state_stree(get_start_states(), my_id, tmp->name, tmp->sym))
			continue;

		param_name = get_param_name(tmp);
		if (!param_name || strcmp(param_name, "$") == 0)
			continue;

		if (slist_has_state(tmp->possible, &user_data_set))
			passed_or_new = "1";
		else if (slist_has_state(tmp->possible, &user_data_passed))
			passed_or_new = "2";
		else
			continue;

		sql_insert_return_states(return_id, return_ranges, USER_DATA,
				param, param_name, passed_or_new);
	} END_FOR_EACH_SM(tmp);
}

static void db_return_states_userdata(struct expression *expr, int param, char *key, char *value)
{
	char *name;
	struct symbol *sym;

	if (expr->type == EXPR_ASSIGNMENT && param == -1 && strcmp(key, "*$") == 0) {
		tag_as_user_data(expr->left);
		return;
	}

	name = return_state_to_var_sym(expr, param, key, &sym);
	if (!name || !sym)
		goto free;

	set_state(my_id, name, sym, &user_data_set);
free:
	free_string(name);
}

void check_user_data(int id)
{
	if (option_project != PROJ_KERNEL)
		return;
	my_id = id;
	select_caller_info_hook(set_called, INTERNAL);
	select_caller_info_hook(set_param_user_data, USER_DATA);
	add_hook(&match_syscall_definition, AFTER_DEF_HOOK);
	add_hook(&match_condition, CONDITION_HOOK);
	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_function_hook("copy_from_user", &match_user_copy, INT_PTR(0));
	add_function_hook("__copy_from_user", &match_user_copy, INT_PTR(0));
	add_function_hook("memcpy_fromiovec", &match_user_copy, INT_PTR(0));
	add_function_assign_hook("memdup_user", &match_user_assign_function, NULL);
	add_function_hook("_kstrtoull", &match_user_copy, INT_PTR(2));

	add_hook(&match_caller_info, FUNCTION_CALL_HOOK);
	add_member_info_callback(my_id, struct_member_callback);
	add_returned_member_callback(my_id, returned_member_callback);
	add_split_return_callback(print_returned_user_data);
	select_return_states_hook(USER_DATA, &db_return_states_userdata);
}
