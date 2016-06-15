/*
 * Copyright (C) 2014 Oracle.
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
 * This file started out by saying that if you have:
 *
 * 	struct foo one, two;
 * 	...
 * 	one = two;
 *
 * That's equivalent to saying:
 *
 * 	one.x = two.x;
 * 	one.y = two.y;
 *
 * Turning an assignment like that into a bunch of small fake assignments is
 * really useful.
 *
 * The call to memcpy(&one, &two, sizeof(foo)); is the same as "one = two;" so
 * we can re-use the code.  And we may as well use it for memset() too.
 * Assigning pointers is almost the same:
 *
 * 	p1 = p2;
 *
 * Is the same as:
 *
 * 	p1->x = p2->x;
 * 	p1->y = p2->y;
 *
 * The problem is that you can go a bit crazy with pointers to pointers.
 *
 * 	p1->x->y->z->one->two->three = p2->x->y->z->one->two->three;
 *
 * I don't have a proper solution for this problem right now.  I just copy one
 * level and don't nest.  It should handle limitted nesting but intelligently.
 *
 * The other thing is that you end up with a lot of garbage assignments where
 * we record "x could be anything. x->y could be anything. x->y->z->a->b->c
 * could *also* be anything!".  There should be a better way to filter this
 * useless information.
 *
 */

#include "scope.h"
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

enum {
	COPY_NORMAL,
	COPY_MEMCPY,
	COPY_MEMSET,
};

static struct symbol *get_struct_type(struct expression *expr)
{
	struct symbol *type;

	type = get_type(expr);
	if (!type)
		return NULL;
	if (type->type == SYM_PTR)
		type = get_real_base_type(type);
	if (type && type->type == SYM_STRUCT)
		return type;
	return NULL;
}

static struct expression *get_right_base_expr(struct symbol *left_type, struct expression *right)
{
	struct symbol *struct_type;

	if (!right)
		return NULL;

	struct_type = get_struct_type(right);
	if (!struct_type)
		return NULL;
	if (struct_type != left_type)
		return NULL;

	if (right->type == EXPR_PREOP && right->op == '&')
		right = strip_expr(right->unop);

	if (right->type == EXPR_CALL)
		return NULL;

	if (is_pointer(right))
		right = deref_expression(right);

	return right;
}

static struct expression *remove_addr(struct expression *expr)
{
	struct symbol *type;

	expr = strip_expr(expr);

	if (expr->type == EXPR_PREOP && expr->op == '&')
		return strip_expr(expr->unop);
	type = get_type(expr);
	if (!type || type->type != SYM_PTR)
		return expr;

	return deref_expression(expr);
}

static struct expression *faked_expression;
struct expression *get_faked_expression(void)
{
	if (!__in_fake_assign)
		return NULL;
	return faked_expression;
}

static void split_fake_expr(struct expression *expr)
{
	__in_fake_assign++;
	__split_expr(expr);
	__in_fake_assign--;
}

static void set_inner_struct_members(int mode, struct expression *faked, struct expression *left, struct expression *right, struct symbol *member)
{
	struct expression *left_member;
	struct expression *right_member = NULL;  /* silence GCC */
	struct expression *assign;
	struct symbol *base = get_real_base_type(member);
	struct symbol *tmp;

	if (member->ident) {
		left = member_expression(left, '.', member->ident);
		if (mode != COPY_MEMSET && right)
			right = member_expression(right, '.', member->ident);
	}

	FOR_EACH_PTR(base->symbol_list, tmp) {
		struct symbol *type;

		type = get_real_base_type(tmp);
		if (!type)
			continue;

		if (type->type == SYM_ARRAY)
			continue;
		if (type->type == SYM_UNION || type->type == SYM_STRUCT) {
			set_inner_struct_members(mode, faked, left, right, tmp);
			continue;
		}
		if (!tmp->ident)
			continue;

		left_member = member_expression(left, '.', tmp->ident);

		switch (mode) {
		case COPY_NORMAL:
		case COPY_MEMCPY:
			if (right)
				right_member = member_expression(right, '.', tmp->ident);
			else
				right_member = unknown_value_expression(left_member);
			break;
		case COPY_MEMSET:
			right_member = right;
			break;
		}

		assign = assign_expression(left_member, right_member);
		split_fake_expr(assign);
	} END_FOR_EACH_PTR(tmp);
}

static void __struct_members_copy(int mode, struct expression *faked,
				  struct expression *left,
				  struct expression *right)
{
	struct symbol *struct_type, *tmp, *type;
	struct expression *left_member;
	struct expression *right_member;
	struct expression *assign;
	int op = '.';


	if (__in_fake_assign)
		return;
	faked_expression = faked;

	left = strip_expr(left);
	right = strip_expr(right);

	struct_type = get_struct_type(left);
	if (!struct_type) {
		/*
		 * This is not a struct assignment obviously.  But this is where
		 * memcpy() is handled so it feels like a good place to add this
		 * code.
		 */

		type = get_type(left);
		if (!type || type->type != SYM_BASETYPE)
			goto done;

		right = strip_expr(right);
		if (right && right->type == EXPR_PREOP && right->op == '&')
			right = remove_addr(right);
		else
			right = unknown_value_expression(left);
		assign = assign_expression(left, right);
		split_fake_expr(assign);
		goto done;
	}

	if (is_pointer(left)) {
		left = deref_expression(left);
		op = '*';
	}
	if (mode != COPY_MEMSET)
		right = get_right_base_expr(struct_type, right);

	FOR_EACH_PTR(struct_type->symbol_list, tmp) {
		type = get_real_base_type(tmp);
		if (!type)
			continue;
		if (type->type == SYM_ARRAY)
			continue;

		if (type->type == SYM_UNION || type->type == SYM_STRUCT) {
			set_inner_struct_members(mode, faked, left, right, tmp);
			continue;
		}

		if (!tmp->ident)
			continue;

		left_member = member_expression(left, op, tmp->ident);
		right_member = NULL;

		switch (mode) {
		case COPY_NORMAL:
		case COPY_MEMCPY:
			if (right)
				right_member = member_expression(right, op, tmp->ident);
			else
				right_member = unknown_value_expression(left_member);
			break;
		case COPY_MEMSET:
			right_member = right;
			break;
		}
		if (!right_member) {
			sm_msg("internal.  No right member");
			continue;
		}
		assign = assign_expression(left_member, right_member);
		split_fake_expr(assign);
	} END_FOR_EACH_PTR(tmp);

done:
	faked_expression = NULL;
}

static int returns_zeroed_mem(struct expression *expr)
{
	char *fn;

	if (expr->type != EXPR_CALL || expr->fn->type != EXPR_SYMBOL)
		return 0;
	fn = expr_to_var(expr->fn);
	if (!fn)
		return 0;
	if (strcmp(fn, "kcalloc") == 0)
		return 1;
	if (option_project == PROJ_KERNEL && strstr(fn, "zalloc"))
		return 1;
	return 0;
}

void __fake_struct_member_assignments(struct expression *expr)
{
	struct symbol *struct_type;
	struct symbol *left_type;

	if (expr->op != '=')
		return;

	if (is_zero(expr->right))
		return;

	left_type = get_type(expr->left);
	if (left_type &&
	    left_type->type != SYM_PTR &&
	    left_type->type != SYM_STRUCT &&
	    left_type != &ulong_ctype)
		return;

	struct_type = get_struct_type(expr->left);
	if (!struct_type)
		return;

	if (returns_zeroed_mem(expr->right))
		__struct_members_copy(COPY_MEMSET, expr, expr->left, zero_expr());
	else
		__struct_members_copy(COPY_NORMAL, expr, expr->left, expr->right);
}

static void match_memset(const char *fn, struct expression *expr, void *_size_arg)
{
	struct expression *buf;
	struct expression *val;

	buf = get_argument_from_call_expr(expr->args, 0);
	val = get_argument_from_call_expr(expr->args, 1);

	buf = strip_expr(buf);
	__struct_members_copy(COPY_MEMSET, expr, remove_addr(buf), val);
}

static void match_memcpy(const char *fn, struct expression *expr, void *_arg)
{
	struct expression *dest;
	struct expression *src;

	dest = get_argument_from_call_expr(expr->args, 0);
	src = get_argument_from_call_expr(expr->args, 1);

	__struct_members_copy(COPY_MEMCPY, expr, remove_addr(dest), remove_addr(src));
}

static void match_memcpy_unknown(const char *fn, struct expression *expr, void *_arg)
{
	struct expression *dest;

	dest = get_argument_from_call_expr(expr->args, 0);
	__struct_members_copy(COPY_MEMCPY, expr, remove_addr(dest), NULL);
}

static void match_sscanf(const char *fn, struct expression *expr, void *unused)
{
	struct expression *arg;
	int i;

	i = -1;
	FOR_EACH_PTR(expr->args, arg) {
		if (++i < 2)
			continue;
		__struct_members_copy(COPY_MEMCPY, expr, remove_addr(arg), NULL);
	} END_FOR_EACH_PTR(arg);
}

static void unop_expr(struct expression *expr)
{
	if (expr->op != SPECIAL_INCREMENT &&
	    expr->op != SPECIAL_DECREMENT)
		return;

	if (!is_pointer(expr))
		return;
	__struct_members_copy(COPY_MEMCPY, expr, expr->unop, NULL);
}

static void register_clears_param(void)
{
	struct token *token;
	char name[256];
	const char *function;
	int param;

	if (option_project == PROJ_NONE)
		return;

	snprintf(name, 256, "%s.clears_argument", option_project_str);

	token = get_tokens_file(name);
	if (!token)
		return;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return;
	token = token->next;
	while (token_type(token) != TOKEN_STREAMEND) {
		if (token_type(token) != TOKEN_IDENT)
			return;
		function = show_ident(token->ident);
		token = token->next;
		if (token_type(token) != TOKEN_NUMBER)
			return;
		param = atoi(token->number);
		add_function_hook(function, &match_memcpy_unknown, INT_PTR(param));
		token = token->next;
	}
	clear_token_alloc();
}

static void db_param_cleared(struct expression *expr, int param, char *key, char *value)
{
	struct expression *arg;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return;

	/*
	 * FIXME:  __struct_members_copy() requires an expression but
	 * get_variable_from_key() returns a name/sym pair so that doesn't
	 * work here.
	 */
	if (strcmp(key, "$") != 0)
		return;

	arg = get_argument_from_call_expr(expr->args, param);
	if (!arg)
		return;

	if (strcmp(value, "0") == 0)
		__struct_members_copy(COPY_MEMSET, expr, remove_addr(arg), zero_expr());
	else
		__struct_members_copy(COPY_MEMCPY, expr, remove_addr(arg), NULL);
}

void register_struct_assignment(int id)
{
	add_function_hook("memset", &match_memset, NULL);
	add_function_hook("__memset", &match_memset, NULL);

	add_function_hook("memcpy", &match_memcpy, INT_PTR(0));
	add_function_hook("memmove", &match_memcpy, INT_PTR(0));
	add_function_hook("__memcpy", &match_memcpy, INT_PTR(0));
	add_function_hook("__memmove", &match_memcpy, INT_PTR(0));

	add_function_hook("sscanf", &match_sscanf, NULL);

	add_hook(&unop_expr, OP_HOOK);
	register_clears_param();
	select_return_states_hook(PARAM_CLEARED, &db_param_cleared);
}
