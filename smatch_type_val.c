/*
 * Copyright (C) 2013 Oracle.
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
 * The plan here is to save all the possible values store to a given struct
 * member.
 *
 * We will load all the values in to the function_type_val table first then
 * run a script on that and load all the resulting values into the type_val
 * table.
 *
 * So in this file we want to take the union of everything assigned to the
 * struct member and insert it into the function_type_val at the end.
 *
 * You would think that we could use smatch_modification_hooks.c or
 * extra_modification_hook() here to get the information here but in the end we
 * need to code everything again a third time.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

struct stree_stack *fn_type_val_stack;
struct stree *fn_type_val;
struct stree *global_type_val;

static char *db_vals;
static int get_vals(void *unused, int argc, char **argv, char **azColName)
{
	db_vals = alloc_string(argv[0]);
	return 0;
}

static void match_inline_start(struct expression *expr)
{
	push_stree(&fn_type_val_stack, fn_type_val);
	fn_type_val = NULL;
}

static void match_inline_end(struct expression *expr)
{
	free_stree(&fn_type_val);
	fn_type_val = pop_stree(&fn_type_val_stack);
}

int get_db_type_rl(struct expression *expr, struct range_list **rl)
{
	char *member;
	struct range_list *tmp;

	member = get_member_name(expr);
	if (!member)
		return 0;

	db_vals = NULL;
	run_sql(get_vals, NULL,
		"select value from type_value where type = '%s';", member);
	free_string(member);
	if (!db_vals)
		return 0;
	str_to_rl(&llong_ctype, db_vals, &tmp);
	tmp = cast_rl(get_type(expr), tmp);
	if (is_whole_rl(tmp))
		return 0;
	*rl = tmp;
	free_string(db_vals);

	return 1;
}

static void add_type_val(char *member, struct range_list *rl)
{
	struct smatch_state *old, *add, *new;

	member = alloc_string(member);
	old = get_state_stree(fn_type_val, my_id, member, NULL);
	add = alloc_estate_rl(rl);
	if (old)
		new = merge_estates(old, add);
	else
		new = add;
	set_state_stree(&fn_type_val, my_id, member, NULL, new);
}

static void add_fake_type_val(char *member, struct range_list *rl, int ignore)
{
	struct smatch_state *old, *add, *new;

	member = alloc_string(member);
	old = get_state_stree(fn_type_val, my_id, member, NULL);
	if (old && strcmp(old->name, "min-max") == 0)
		return;
	if (ignore && old && strcmp(old->name, "ignore") == 0)
		return;
	add = alloc_estate_rl(rl);
	if (old) {
		new = merge_estates(old, add);
	} else {
		new = add;
		if (ignore)
			new->name = alloc_string("ignore");
		else
			new->name = alloc_string("min-max");
	}
	set_state_stree(&fn_type_val, my_id, member, NULL, new);
}

static void add_global_type_val(char *member, struct range_list *rl)
{
	struct smatch_state *old, *add, *new;

	member = alloc_string(member);
	old = get_state_stree(global_type_val, my_id, member, NULL);
	add = alloc_estate_rl(rl);
	if (old)
		new = merge_estates(old, add);
	else
		new = add;
	new = clone_estate_perm(new);
	set_state_stree_perm(&global_type_val, my_id, member, NULL, new);
}

static int has_link_cb(void *has_link, int argc, char **argv, char **azColName)
{
	*(int *)has_link = 1;
	return 0;
}

static int is_ignored_fake_assignment(void)
{
	struct expression *expr;
	struct symbol *type;
	char *member_name;
	int has_link = 0;

	expr = get_faked_expression();
	if (!expr || expr->type != EXPR_ASSIGNMENT)
		return 0;
	if (!is_void_pointer(expr->right))
		return 0;
	member_name = get_member_name(expr->right);
	if (!member_name)
		return 0;

	type = get_type(expr->left);
	if (!type || type->type != SYM_PTR)
		return 0;
	type = get_real_base_type(type);
	if (!type || type->type != SYM_STRUCT)
		return 0;

	run_sql(has_link_cb, &has_link,
		"select * from data_info where type = %d and data = '%s' and value = '%s';",
		TYPE_LINK, member_name, type_to_str(type));
	return has_link;
}

static int is_ignored_container_of(void)
{
	struct expression *expr;
	char *name;

	expr = get_faked_expression();
	if (!expr || expr->type != EXPR_ASSIGNMENT)
		return 0;
	name = get_macro_name(expr->right->pos);
	if (!name)
		return 0;
	if (strcmp(name, "container_of") == 0)
		return 1;
	return 0;
}

static void match_assign_value(struct expression *expr)
{
	char *member, *right_member;
	struct range_list *rl;
	struct symbol *type;

	type = get_type(expr->left);
	if (type && type->type == SYM_STRUCT)
		return;

	member = get_member_name(expr->left);
	if (!member)
		return;

	/* if we're saying foo->mtu = bar->mtu then that doesn't add information */
	right_member = get_member_name(expr->right);
	if (right_member && strcmp(right_member, member) == 0)
		goto free;

	if (is_fake_call(expr->right)) {
		if (is_ignored_container_of())
			goto free;
		add_fake_type_val(member, alloc_whole_rl(get_type(expr->left)), is_ignored_fake_assignment());
		goto free;
	}

	if (expr->op != '=') {
		add_type_val(member, alloc_whole_rl(get_type(expr->left)));
		goto free;
	}
	get_absolute_rl(expr->right, &rl);
	rl = cast_rl(type, rl);
	add_type_val(member, rl);
free:
	free_string(right_member);
	free_string(member);
}

/*
 * If we too:  int *p = &my_struct->member then abandon all hope of tracking
 * my_struct->member.
 */
static void match_assign_pointer(struct expression *expr)
{
	struct expression *right;
	char *member;
	struct range_list *rl;
	struct symbol *type;

	right = strip_expr(expr->right);
	if (right->type != EXPR_PREOP || right->op != '&')
		return;
	right = strip_expr(right->unop);

	member = get_member_name(right);
	if (!member)
		return;
	type = get_type(right);
	rl = alloc_whole_rl(type);
	add_type_val(member, rl);
	free_string(member);
}

static void match_global_assign(struct expression *expr)
{
	char *member;
	struct range_list *rl;

	member = get_member_name(expr->left);
	if (!member)
		return;
	get_absolute_rl(expr->right, &rl);
	add_global_type_val(member, rl);
	free_string(member);
}

static void unop_expr(struct expression *expr)
{
	struct range_list *rl;
	char *member;

	if (expr->op != SPECIAL_DECREMENT && expr->op != SPECIAL_INCREMENT)
		return;

	expr = strip_expr(expr->unop);
	member = get_member_name(expr);
	if (!member)
		return;
	rl = alloc_whole_rl(get_type(expr));
	add_type_val(member, rl);
	free_string(member);
}

static void asm_expr(struct statement *stmt)
{
	struct expression *expr;
	struct range_list *rl;
	char *member;
	int state = 0;

	FOR_EACH_PTR(stmt->asm_outputs, expr) {
		switch (state) {
		case 0: /* identifier */
		case 1: /* constraint */
			state++;
			continue;
		case 2: /* expression */
			state = 0;
			member = get_member_name(expr);
			if (!member)
				continue;
			rl = alloc_whole_rl(get_type(expr));
			add_type_val(member, rl);
			free_string(member);
			continue;
		}
	} END_FOR_EACH_PTR(expr);
}

static void db_param_add(struct expression *expr, int param, char *key, char *value)
{
	struct expression *arg;
	struct symbol *type;
	struct range_list *rl;
	char *member;

	if (strcmp(key, "*$") != 0)
		return;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return;

	arg = get_argument_from_call_expr(expr->args, param);
	arg = strip_expr(arg);
	if (!arg)
		return;
	type = get_member_type_from_key(arg, key);
	if (arg->type != EXPR_PREOP || arg->op != '&')
		return;
	arg = strip_expr(arg->unop);

	member = get_member_name(arg);
	if (!member)
		return;
	call_results_to_rl(expr, type, value, &rl);
	add_type_val(member, rl);
	free_string(member);
}

static void match_end_func_info(struct symbol *sym)
{
	struct sm_state *sm;

	FOR_EACH_SM(fn_type_val, sm) {
		sql_insert_function_type_value(sm->name, sm->state->name);
	} END_FOR_EACH_SM(sm);

	free_stree(&fn_type_val);
}

static void match_end_file(struct symbol_list *sym_list)
{
	struct sm_state *sm;

	FOR_EACH_SM(global_type_val, sm) {
		sql_insert_function_type_value(sm->name, sm->state->name);
	} END_FOR_EACH_SM(sm);
}

void register_type_val(int id)
{
	if (!option_info)
		return;

	my_id = id;

	add_hook(&match_assign_value, ASSIGNMENT_HOOK);
	add_hook(&match_assign_pointer, ASSIGNMENT_HOOK);
	add_hook(&unop_expr, OP_HOOK);
	add_hook(&asm_expr, ASM_HOOK);
	select_return_states_hook(ADDED_VALUE, &db_param_add);

	add_hook(&match_inline_start, INLINE_FN_START);
	add_hook(&match_inline_end, INLINE_FN_END);

	add_hook(&match_end_func_info, END_FUNC_HOOK);

	add_hook(&match_global_assign, GLOBAL_ASSIGNMENT_HOOK);
	add_hook(&match_end_file, END_FILE_HOOK);

}
