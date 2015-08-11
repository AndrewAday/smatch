/*
 * Copyright (C) 2006,2008 Dan Carpenter.
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

#define _GNU_SOURCE 1
#include <unistd.h>
#include <stdio.h>
#include "token.h"
#include "scope.h"
#include "smatch.h"
#include "smatch_expression_stacks.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

int __in_fake_assign;
int final_pass;
int __inline_call;
struct expression  *__inline_fn;

static int __smatch_lineno = 0;

static char *base_file;
static const char *filename;
static char *pathname;
static char *full_filename;
static char *cur_func;
static unsigned int loop_count;
static int last_goto_statement_handled;
int __expr_stmt_count;
int __in_function_def;
static struct expression_list *switch_expr_stack = NULL;
static struct expression_list *post_op_stack = NULL;

struct expression_list *big_expression_stack;
struct statement_list *big_statement_stack;
struct statement *__prev_stmt;
struct statement *__cur_stmt;
struct statement *__next_stmt;
int __in_pre_condition = 0;
int __bail_on_rest_of_function = 0;
static struct timeval fn_start_time;
char *get_function(void) { return cur_func; }
int get_lineno(void) { return __smatch_lineno; }
int inside_loop(void) { return !!loop_count; }
int definitely_inside_loop(void) { return !!(loop_count & ~0x80000000); }
struct expression *get_switch_expr(void) { return top_expression(switch_expr_stack); }
int in_expression_statement(void) { return !!__expr_stmt_count; }

static void split_symlist(struct symbol_list *sym_list);
static void split_declaration(struct symbol_list *sym_list);
static void split_expr_list(struct expression_list *expr_list, struct expression *parent);
static void add_inline_function(struct symbol *sym);
static void parse_inline(struct expression *expr);

int option_assume_loops = 0;
int option_known_conditions = 0;
int option_two_passes = 0;
struct symbol *cur_func_sym = NULL;
struct stree *global_states;

long long valid_ptr_min = 4096;
long long valid_ptr_max = 2117777777;
sval_t valid_ptr_min_sval = {
	.type = &ptr_ctype,
	{.value = 4096},
};
sval_t valid_ptr_max_sval = {
	.type = &ptr_ctype,
	{.value = LONG_MAX - 100000},
};

static void set_valid_ptr_max(void)
{
	if (type_bits(&ptr_ctype) == 32)
		valid_ptr_max = 2117777777;
	else if (type_bits(&ptr_ctype) == 64)
		valid_ptr_max = 2117777777777777777LL;

	valid_ptr_max_sval.value = valid_ptr_max;
}

int outside_of_function(void)
{
	return cur_func_sym == NULL;
}

const char *get_filename(void)
{
	if (option_info)
		return base_file;
	if (option_full_path)
		return full_filename;
	return filename;
}

const char *get_base_file(void)
{
	return base_file;
}

static void set_position(struct position pos)
{
	int len;
	static int prev_stream = -1;

	if (pos.stream == 0 && pos.line == 0)
		return;

	__smatch_lineno = pos.line;

	if (pos.stream == prev_stream)
		return;

	filename = stream_name(pos.stream);

	free(full_filename);
	pathname = getcwd(NULL, 0);
	if (pathname) {
		len = strlen(pathname) + 1 + strlen(filename) + 1;
		full_filename = malloc(len);
		snprintf(full_filename, len, "%s/%s", pathname, filename);
	} else {
		full_filename = alloc_string(filename);
	}
	free(pathname);
}

static void set_parent(struct expression *expr, struct expression *parent)
{
	if (!expr)
		return;
	expr->parent = parent;
}

static void set_parent_stmt(struct statement *stmt, struct statement *parent)
{
	if (!stmt)
		return;
	stmt->parent = parent;
}

int is_assigned_call(struct expression *expr)
{
	struct expression *tmp;

	FOR_EACH_PTR_REVERSE(big_expression_stack, tmp) {
		if (tmp->type == EXPR_ASSIGNMENT && tmp->op == '=' &&
		    strip_expr(tmp->right) == expr)
			return 1;
		if (tmp->pos.line < expr->pos.line)
			return 0;
	} END_FOR_EACH_PTR_REVERSE(tmp);
	return 0;
}

static int is_inline_func(struct expression *expr)
{
	if (expr->type != EXPR_SYMBOL || !expr->symbol)
		return 0;
	if (expr->symbol->ctype.modifiers & MOD_INLINE)
		return 1;
	return 0;
}

static int is_noreturn_func(struct expression *expr)
{
	if (expr->type != EXPR_SYMBOL || !expr->symbol)
		return 0;
	if (expr->symbol->ctype.modifiers & MOD_NORETURN)
		return 1;
	return 0;
}

int inlinable(struct expression *expr)
{
	struct symbol *sym;
	struct statement *last_stmt = NULL;

	if (__inline_fn)  /* don't nest */
		return 0;

	if (expr->type != EXPR_SYMBOL || !expr->symbol)
		return 0;
	if (is_no_inline_function(expr->symbol->ident->name))
		return 0;
	sym = get_base_type(expr->symbol);
	if (sym->stmt && sym->stmt->type == STMT_COMPOUND) {
		if (ptr_list_size((struct ptr_list *)sym->stmt->stmts) > 10)
			return 0;
		if (sym->stmt->type != STMT_COMPOUND)
			return 0;
		last_stmt = last_ptr_list((struct ptr_list *)sym->stmt->stmts);
	}
	if (sym->inline_stmt && sym->inline_stmt->type == STMT_COMPOUND) {
		if (ptr_list_size((struct ptr_list *)sym->inline_stmt->stmts) > 10)
			return 0;
		if (sym->inline_stmt->type != STMT_COMPOUND)
			return 0;
		last_stmt = last_ptr_list((struct ptr_list *)sym->inline_stmt->stmts);
	}

	if (!last_stmt)
		return 0;

	/* the magic numbers in this function are pulled out of my bum. */
	if (last_stmt->pos.line > sym->pos.line + 20)
		return 0;

	return 1;
}

void __process_post_op_stack(void)
{
	struct expression *expr;

	FOR_EACH_PTR(post_op_stack, expr) {
		__pass_to_client(expr, OP_HOOK);
	} END_FOR_EACH_PTR(expr);

	__free_ptr_list((struct ptr_list **)&post_op_stack);
}

static int handle_comma_assigns(struct expression *expr)
{
	struct expression *right;
	struct expression *assign;

	right = strip_expr(expr->right);
	if (right->type != EXPR_COMMA)
		return 0;

	__split_expr(right->left);
	__process_post_op_stack();

	assign = assign_expression(expr->left, right->right);
	__split_expr(assign);

	return 1;
}

static int prev_expression_is_getting_address(struct expression *expr)
{
	struct expression *parent;

	do {
		parent = expr->parent;

		if (!parent)
			return 0;
		if (parent->type == EXPR_PREOP && parent->op == '&')
			return 1;
		if (parent->type == EXPR_PREOP && parent->op == '(')
			goto next;
		if (parent->type == EXPR_DEREF && parent->op == '.')
			goto next;

		return 0;
next:
		expr = parent;
	} while (1);
}

void __split_expr(struct expression *expr)
{
	if (!expr)
		return;

	// sm_msg(" Debug expr_type %d %s", expr->type, show_special(expr->op));

	if (__in_fake_assign && expr->type != EXPR_ASSIGNMENT)
		return;
	if (__in_fake_assign >= 4)  /* don't allow too much nesting */
		return;

	push_expression(&big_expression_stack, expr);
	set_position(expr->pos);
	__pass_to_client(expr, EXPR_HOOK);

	switch (expr->type) {
	case EXPR_PREOP:
		set_parent(expr->unop, expr);

		if (expr->op == '*' &&
		    !prev_expression_is_getting_address(expr))
			__pass_to_client(expr, DEREF_HOOK);
		__split_expr(expr->unop);
		__pass_to_client(expr, OP_HOOK);
		break;
	case EXPR_POSTOP:
		set_parent(expr->unop, expr);

		__split_expr(expr->unop);
		push_expression(&post_op_stack, expr);
		break;
	case EXPR_STATEMENT:
		__expr_stmt_count++;
		__split_stmt(expr->statement);
		__expr_stmt_count--;
		break;
	case EXPR_LOGICAL:
	case EXPR_COMPARE:
		set_parent(expr->left, expr);
		set_parent(expr->right, expr);

		__pass_to_client(expr, LOGIC_HOOK);
		__handle_logic(expr);
		break;
	case EXPR_BINOP:
		set_parent(expr->left, expr);
		set_parent(expr->right, expr);

		__pass_to_client(expr, BINOP_HOOK);
	case EXPR_COMMA:
		set_parent(expr->left, expr);
		set_parent(expr->right, expr);

		__split_expr(expr->left);
		__process_post_op_stack();
		__split_expr(expr->right);
		break;
	case EXPR_ASSIGNMENT: {
		struct expression *tmp;

		set_parent(expr->left, expr);
		set_parent(expr->right, expr);

		if (!expr->right)
			break;

		__pass_to_client(expr, RAW_ASSIGNMENT_HOOK);

		/* foo = !bar() */
		if (__handle_condition_assigns(expr))
			break;
		/* foo = (x < 5 ? foo : 5); */
		if (__handle_select_assigns(expr))
			break;
		/* foo = ({frob(); frob(); frob(); 1;}) */
		if (__handle_expr_statement_assigns(expr))
			break;
		/* foo = (3, 4); */
		if (handle_comma_assigns(expr))
			break;

		__split_expr(expr->right);
		if (outside_of_function())
			__pass_to_client(expr, GLOBAL_ASSIGNMENT_HOOK);
		else
			__pass_to_client(expr, ASSIGNMENT_HOOK);

		__fake_struct_member_assignments(expr);

		tmp = strip_expr(expr->right);
		if (expr->op == '=' && tmp->type == EXPR_CALL) {
			__pass_to_client(expr, CALL_ASSIGNMENT_HOOK);
			if (!is_fake_call(tmp))
				__pass_to_client(tmp, FUNCTION_CALL_HOOK_AFTER);
		}
		if (get_macro_name(tmp->pos) &&
		    get_macro_name(expr->pos) != get_macro_name(tmp->pos))
			__pass_to_client(expr, MACRO_ASSIGNMENT_HOOK);
		__split_expr(expr->left);
		break;
	}
	case EXPR_DEREF:
		set_parent(expr->deref, expr);

		__pass_to_client(expr, DEREF_HOOK);
		__split_expr(expr->deref);
		break;
	case EXPR_SLICE:
		set_parent(expr->base, expr);

		__split_expr(expr->base);
		break;
	case EXPR_CAST:
	case EXPR_FORCE_CAST:
		set_parent(expr->cast_expression, expr);

		__pass_to_client(expr, CAST_HOOK);
		__split_expr(expr->cast_expression);
		break;
	case EXPR_SIZEOF:
		if (expr->cast_expression)
			__pass_to_client(strip_parens(expr->cast_expression),
					 SIZEOF_HOOK);
		break;
	case EXPR_OFFSETOF:
	case EXPR_ALIGNOF:
		evaluate_expression(expr);
		break;
	case EXPR_CONDITIONAL:
	case EXPR_SELECT:
		set_parent(expr->conditional, expr);
		set_parent(expr->cond_true, expr);
		set_parent(expr->cond_false, expr);

		if (known_condition_true(expr->conditional)) {
			__split_expr(expr->cond_true);
			break;
		}
		if (known_condition_false(expr->conditional)) {
			__split_expr(expr->cond_false);
			break;
		}
		__pass_to_client(expr, SELECT_HOOK);
		__split_whole_condition(expr->conditional);
		__split_expr(expr->cond_true);
		__push_true_states();
		__use_false_states();
		__split_expr(expr->cond_false);
		__merge_true_states();
		break;
	case EXPR_CALL:
		set_parent(expr->fn, expr);

		if (sym_name_is("__builtin_constant_p", expr->fn))
			break;
		split_expr_list(expr->args, expr);
		__split_expr(expr->fn);
		if (is_inline_func(expr->fn))
			add_inline_function(expr->fn->symbol);
		if (inlinable(expr->fn))
			__inline_call = 1;
		__process_post_op_stack();
		__pass_to_client(expr, FUNCTION_CALL_HOOK);
		__inline_call = 0;
		if (inlinable(expr->fn)) {
			parse_inline(expr);
		}
		__pass_to_client(expr, CALL_HOOK_AFTER_INLINE);
		if (!is_assigned_call(expr))
			__pass_to_client(expr, FUNCTION_CALL_HOOK_AFTER);
		if (is_noreturn_func(expr->fn))
			nullify_path();
		break;
	case EXPR_INITIALIZER:
		split_expr_list(expr->expr_list, expr);
		break;
	case EXPR_IDENTIFIER:
		set_parent(expr->ident_expression, expr);
		__split_expr(expr->ident_expression);
		break;
	case EXPR_INDEX:
		set_parent(expr->idx_expression, expr);
		__split_expr(expr->idx_expression);
		break;
	case EXPR_POS:
		set_parent(expr->init_expr, expr);
		__split_expr(expr->init_expr);
		break;
	case EXPR_SYMBOL:
		__pass_to_client(expr, SYM_HOOK);
		break;
	case EXPR_STRING:
		__pass_to_client(expr, STRING_HOOK);
		break;
	default:
		break;
	};
	pop_expression(&big_expression_stack);
}

static int is_forever_loop(struct statement *stmt)
{
	struct expression *expr;

	expr = strip_expr(stmt->iterator_pre_condition);
	if (!expr)
		expr = stmt->iterator_post_condition;
	if (!expr) {
		/* this is a for(;;) loop... */
		return 1;
	}

	if (expr->type == EXPR_VALUE && expr->value == 1)
		return 1;

	return 0;
}

static int loop_num;
static char *get_loop_name(int num)
{
	char buf[256];

	snprintf(buf, 255, "-loop%d", num);
	buf[255] = '\0';
	return alloc_sname(buf);
}

/*
 * Pre Loops are while and for loops.
 */
static void handle_pre_loop(struct statement *stmt)
{
	int once_through; /* we go through the loop at least once */
	struct sm_state *extra_sm = NULL;
	int unchanged = 0;
	char *loop_name;
	struct stree *stree = NULL;
	struct sm_state *sm = NULL;

	loop_name = get_loop_name(loop_num);
	loop_num++;

	__split_stmt(stmt->iterator_pre_statement);
	__prev_stmt = stmt->iterator_pre_statement;

	once_through = implied_condition_true(stmt->iterator_pre_condition);

	loop_count++;
	__push_continues();
	__push_breaks();

	__merge_gotos(loop_name);

	extra_sm = __extra_handle_canonical_loops(stmt, &stree);
	__in_pre_condition++;
	__pass_to_client(stmt, PRELOOP_HOOK);
	__split_whole_condition(stmt->iterator_pre_condition);
	__in_pre_condition--;
	FOR_EACH_SM(stree, sm) {
		set_state(sm->owner, sm->name, sm->sym, sm->state);
	} END_FOR_EACH_SM(sm);
	free_stree(&stree);
	if (extra_sm)
		extra_sm = get_sm_state(extra_sm->owner, extra_sm->name, extra_sm->sym);

	if (option_assume_loops)
		once_through = 1;

	__split_stmt(stmt->iterator_statement);
	if (is_forever_loop(stmt)) {
		__merge_continues();
		__save_gotos(loop_name);

		__push_fake_cur_stree();
		__split_stmt(stmt->iterator_post_statement);
		stree = __pop_fake_cur_stree();

		__discard_false_states();
		__use_breaks();

		if (!__path_is_null())
			__merge_stree_into_cur(stree);
		free_stree(&stree);
	} else {
		__merge_continues();
		unchanged = __iterator_unchanged(extra_sm);
		__split_stmt(stmt->iterator_post_statement);
		__prev_stmt = stmt->iterator_post_statement;
		__cur_stmt = stmt;

		__save_gotos(loop_name);
		__in_pre_condition++;
		__split_whole_condition(stmt->iterator_pre_condition);
		__in_pre_condition--;
		nullify_path();
		__merge_false_states();
		if (once_through)
			__discard_false_states();
		else
			__merge_false_states();

		if (extra_sm && unchanged)
			__extra_pre_loop_hook_after(extra_sm,
						stmt->iterator_post_statement,
						stmt->iterator_pre_condition);
		__merge_breaks();
	}
	loop_count--;
}

/*
 * Post loops are do {} while();
 */
static void handle_post_loop(struct statement *stmt)
{
	char *loop_name;

	loop_name = get_loop_name(loop_num);
	loop_num++;
	loop_count++;

	__push_continues();
	__push_breaks();
	__merge_gotos(loop_name);
	__split_stmt(stmt->iterator_statement);
	__merge_continues();
	if (!is_zero(stmt->iterator_post_condition))
		__save_gotos(loop_name);

	if (is_forever_loop(stmt)) {
		__use_breaks();
	} else {
		__split_whole_condition(stmt->iterator_post_condition);
		__use_false_states();
		__merge_breaks();
	}
	loop_count--;
}

static int empty_statement(struct statement *stmt)
{
	if (!stmt)
		return 0;
	if (stmt->type == STMT_EXPRESSION && !stmt->expression)
		return 1;
	return 0;
}

static int last_stmt_on_same_line(void)
{
	struct statement *stmt;
	int i = 0;

	FOR_EACH_PTR_REVERSE(big_statement_stack, stmt) {
		if (!i++)
			continue;
		if  (stmt->pos.line == get_lineno())
			return 1;
		return 0;
	} END_FOR_EACH_PTR_REVERSE(stmt);
	return 0;
}

static void split_asm_constraints(struct expression_list *expr_list)
{
	struct expression *expr;
	int state = 0;

	FOR_EACH_PTR(expr_list, expr) {
		switch (state) {
		case 0: /* identifier */
		case 1: /* constraint */
			state++;
			continue;
		case 2: /* expression */
			state = 0;
			__split_expr(expr);
			continue;
		}
	} END_FOR_EACH_PTR(expr);
}

static int is_case_val(struct statement *stmt, sval_t sval)
{
	sval_t case_sval;

	if (stmt->type != STMT_CASE)
		return 0;
	if (!stmt->case_expression) {
		__set_default();
		return 1;
	}
	if (!get_value(stmt->case_expression, &case_sval))
		return 0;
	if (case_sval.value == sval.value)
		return 1;
	return 0;
}

static void split_known_switch(struct statement *stmt, sval_t sval)
{
	struct statement *tmp;

	__split_expr(stmt->switch_expression);

	push_expression(&switch_expr_stack, stmt->switch_expression);
	__save_switch_states(top_expression(switch_expr_stack));
	nullify_path();
	__push_default();
	__push_breaks();

	stmt = stmt->switch_statement;

	__push_scope_hooks();
	FOR_EACH_PTR(stmt->stmts, tmp) {
		__smatch_lineno = tmp->pos.line;
		if (is_case_val(tmp, sval)) {
			__merge_switches(top_expression(switch_expr_stack),
					 stmt->case_expression);
			__pass_case_to_client(top_expression(switch_expr_stack),
					      stmt->case_expression);
		}
		if (__path_is_null())
			continue;
		__split_stmt(tmp);
		if (__path_is_null()) {
			__set_default();
			goto out;
		}
	} END_FOR_EACH_PTR(tmp);
out:
	__call_scope_hooks();
	if (!__pop_default())
		__merge_switches(top_expression(switch_expr_stack),
				 NULL);
	__discard_switches();
	__merge_breaks();
	pop_expression(&switch_expr_stack);
}

static int taking_too_long(void)
{
	int ms;

	ms = ms_since(&fn_start_time);
	if (ms > 1000 * 60 * 5)  /* five minutes */
		return 1;
	return 0;
}

static int is_last_stmt(struct statement *cur_stmt)
{
	struct symbol *fn = get_base_type(cur_func_sym);
	struct statement *stmt;

	if (!fn)
		return 0;
	stmt = fn->stmt;
	if (!stmt)
		stmt = fn->inline_stmt;
	if (!stmt || stmt->type != STMT_COMPOUND)
		return 0;
	stmt = last_ptr_list((struct ptr_list *)stmt->stmts);
	if (stmt && stmt->type == STMT_LABEL)
		stmt = stmt->label_statement;
	if (stmt == cur_stmt)
		return 1;
	return 0;
}

static void handle_backward_goto(struct statement *goto_stmt)
{
	const char *goto_name, *label_name;
	struct statement *func_stmt;
	struct symbol *base_type = get_base_type(cur_func_sym);
	struct statement *tmp;
	int found = 0;

	if (!option_info)
		return;
	if (last_goto_statement_handled)
		return;
	last_goto_statement_handled = 1;

	if (!goto_stmt->goto_label ||
	    goto_stmt->goto_label->type != SYM_LABEL ||
	    !goto_stmt->goto_label->ident)
		return;
	goto_name = goto_stmt->goto_label->ident->name;

	func_stmt = base_type->stmt;
	if (!func_stmt)
		func_stmt = base_type->inline_stmt;
	if (!func_stmt)
		return;
	if (func_stmt->type != STMT_COMPOUND)
		return;

	FOR_EACH_PTR(func_stmt->stmts, tmp) {
		if (!found) {
			if (tmp->type != STMT_LABEL)
				continue;
			if (!tmp->label_identifier ||
			    tmp->label_identifier->type != SYM_LABEL ||
			    !tmp->label_identifier->ident)
				continue;
			label_name = tmp->label_identifier->ident->name;
			if (strcmp(goto_name, label_name) != 0)
				continue;
			found = 1;
		}
		__split_stmt(tmp);
	} END_FOR_EACH_PTR(tmp);
}

static void fake_a_return(void)
{
	struct symbol *return_type;

	nullify_path();
	__unnullify_path();

	return_type = get_real_base_type(cur_func_sym);
	return_type = get_real_base_type(return_type);
	if (return_type != &void_ctype) {
		__pass_to_client(unknown_value_expression(NULL), RETURN_HOOK);
		nullify_path();
	}

	__pass_to_client(cur_func_sym, END_FUNC_HOOK);
	__pass_to_client(cur_func_sym, AFTER_FUNC_HOOK);
}

static void split_compound(struct statement *stmt)
{
	struct statement *prev = NULL;
	struct statement *cur = NULL;
	struct statement *next;

	__push_scope_hooks();

	FOR_EACH_PTR(stmt->stmts, next) {
		/* just set them all ahead of time */
		set_parent_stmt(next, stmt);

		if (cur) {
			__prev_stmt = prev;
			__next_stmt = next;
			__cur_stmt = cur;
			__split_stmt(cur);
		}
		prev = cur;
		cur = next;
	} END_FOR_EACH_PTR(next);
	if (cur) {
		__prev_stmt = prev;
		__cur_stmt = cur;
		__next_stmt = NULL;
		__split_stmt(cur);
	}

	__call_scope_hooks();
}

void __split_stmt(struct statement *stmt)
{
	sval_t sval;

	if (!stmt)
		goto out;

	if (__bail_on_rest_of_function || out_of_memory() || taking_too_long()) {
		static char *printed = NULL;

		__bail_on_rest_of_function = 1;
		if (printed != cur_func)
			sm_msg("Function too hairy.  Giving up.");
		fake_a_return();
		final_pass = 0;  /* turn off sm_msg() from here */
		printed = cur_func;
		return;
	}

	add_ptr_list(&big_statement_stack, stmt);
	free_expression_stack(&big_expression_stack);
	set_position(stmt->pos);
	__pass_to_client(stmt, STMT_HOOK);

	switch (stmt->type) {
	case STMT_DECLARATION:
		split_declaration(stmt->declaration);
		break;
	case STMT_RETURN:
		__split_expr(stmt->ret_value);
		__pass_to_client(stmt->ret_value, RETURN_HOOK);
		__process_post_op_stack();
		nullify_path();
		break;
	case STMT_EXPRESSION:
		__split_expr(stmt->expression);
		break;
	case STMT_COMPOUND:
		split_compound(stmt);
		break;
	case STMT_IF:
		set_parent_stmt(stmt->if_true, stmt);
		set_parent_stmt(stmt->if_false, stmt);

		if (known_condition_true(stmt->if_conditional)) {
			__split_stmt(stmt->if_true);
			break;
		}
		if (known_condition_false(stmt->if_conditional)) {
			__split_stmt(stmt->if_false);
			break;
		}
		if (option_known_conditions &&
		    implied_condition_true(stmt->if_conditional)) {
			sm_info("this condition is true.");
			__split_stmt(stmt->if_true);
			break;
		}
		if (option_known_conditions &&
		    implied_condition_false(stmt->if_conditional)) {
			sm_info("this condition is false.");
			__split_stmt(stmt->if_false);
			break;
		}
		__split_whole_condition(stmt->if_conditional);
		__split_stmt(stmt->if_true);
		if (empty_statement(stmt->if_true) &&
			last_stmt_on_same_line() &&
			!get_macro_name(stmt->if_true->pos))
			sm_msg("warn: if();");
		__push_true_states();
		__use_false_states();
		__split_stmt(stmt->if_false);
		__merge_true_states();
		break;
	case STMT_ITERATOR:
		set_parent_stmt(stmt->iterator_pre_statement, stmt);
		set_parent_stmt(stmt->iterator_statement, stmt);
		set_parent_stmt(stmt->iterator_post_statement, stmt);

		if (stmt->iterator_pre_condition)
			handle_pre_loop(stmt);
		else if (stmt->iterator_post_condition)
			handle_post_loop(stmt);
		else {
			// these are for(;;) type loops.
			handle_pre_loop(stmt);
		}
		break;
	case STMT_SWITCH:
		set_parent_stmt(stmt->switch_statement, stmt);

		if (get_value(stmt->switch_expression, &sval)) {
			split_known_switch(stmt, sval);
			break;
		}
		__split_expr(stmt->switch_expression);
		push_expression(&switch_expr_stack, stmt->switch_expression);
		__save_switch_states(top_expression(switch_expr_stack));
		nullify_path();
		__push_default();
		__push_breaks();
		__split_stmt(stmt->switch_statement);
		if (!__pop_default())
			__merge_switches(top_expression(switch_expr_stack),
				      NULL);
		__discard_switches();
		__merge_breaks();
		pop_expression(&switch_expr_stack);
		break;
	case STMT_CASE:
		__merge_switches(top_expression(switch_expr_stack),
				      stmt->case_expression);
		__pass_case_to_client(top_expression(switch_expr_stack),
				      stmt->case_expression);
		if (!stmt->case_expression)
			__set_default();
		__split_expr(stmt->case_expression);
		__split_expr(stmt->case_to);
		__split_stmt(stmt->case_statement);
		break;
	case STMT_LABEL:
		if (stmt->label_identifier &&
		    stmt->label_identifier->type == SYM_LABEL &&
		    stmt->label_identifier->ident) {
			loop_count |= 0x80000000;
			__merge_gotos(stmt->label_identifier->ident->name);
		}
		__split_stmt(stmt->label_statement);
		break;
	case STMT_GOTO:
		__split_expr(stmt->goto_expression);
		if (stmt->goto_label && stmt->goto_label->type == SYM_NODE) {
			if (!strcmp(stmt->goto_label->ident->name, "break")) {
				__process_breaks();
			} else if (!strcmp(stmt->goto_label->ident->name,
					   "continue")) {
				__process_continues();
			}
		} else if (stmt->goto_label &&
			   stmt->goto_label->type == SYM_LABEL &&
			   stmt->goto_label->ident) {
			__save_gotos(stmt->goto_label->ident->name);
		}
		nullify_path();
		if (is_last_stmt(stmt))
			handle_backward_goto(stmt);
		break;
	case STMT_NONE:
		break;
	case STMT_ASM:
		__pass_to_client(stmt, ASM_HOOK);
		__split_expr(stmt->asm_string);
		split_asm_constraints(stmt->asm_outputs);
		split_asm_constraints(stmt->asm_inputs);
		split_asm_constraints(stmt->asm_clobbers);
		break;
	case STMT_CONTEXT:
		break;
	case STMT_RANGE:
		__split_expr(stmt->range_expression);
		__split_expr(stmt->range_low);
		__split_expr(stmt->range_high);
		break;
	}
	__pass_to_client(stmt, STMT_HOOK_AFTER);
out:
	__process_post_op_stack();
}

static void split_expr_list(struct expression_list *expr_list, struct expression *parent)
{
	struct expression *expr;

	FOR_EACH_PTR(expr_list, expr) {
		set_parent(expr, parent);
		__split_expr(expr);
		__process_post_op_stack();
	} END_FOR_EACH_PTR(expr);
}

static void split_sym(struct symbol *sym)
{
	if (!sym)
		return;
	if (!(sym->namespace & NS_SYMBOL))
		return;

	__split_stmt(sym->stmt);
	__split_expr(sym->array_size);
	split_symlist(sym->arguments);
	split_symlist(sym->symbol_list);
	__split_stmt(sym->inline_stmt);
	split_symlist(sym->inline_symbol_list);
}

static void split_symlist(struct symbol_list *sym_list)
{
	struct symbol *sym;

	FOR_EACH_PTR(sym_list, sym) {
		split_sym(sym);
	} END_FOR_EACH_PTR(sym);
}

typedef void (fake_cb)(struct expression *expr);

static int member_to_number(struct expression *expr, struct ident *member)
{
	struct symbol *type, *tmp;
	char *name;
	int i;

	if (!member)
		return -1;
	name = member->name;

	type = get_type(expr);
	if (!type || type->type != SYM_STRUCT)
		return -1;

	i = -1;
	FOR_EACH_PTR(type->symbol_list, tmp) {
		i++;
		if (!tmp->ident)
			continue;
		if (strcmp(name, tmp->ident->name) == 0)
			return i;
	} END_FOR_EACH_PTR(tmp);
	return -1;
}

static struct ident *number_to_member(struct expression *expr, int num)
{
	struct symbol *type, *member;
	int i = 0;

	type = get_type(expr);
	if (!type || type->type != SYM_STRUCT)
		return NULL;

	FOR_EACH_PTR(type->symbol_list, member) {
		if (i == num)
			return member->ident;
		i++;
	} END_FOR_EACH_PTR(member);
	return NULL;
}

static void fake_element_assigns_helper(struct expression *array, struct expression_list *expr_list, fake_cb *fake_cb);

struct member_set {
	struct ident *ident;
	int set;
};

static struct member_set *alloc_member_set(struct symbol *type)
{
	struct member_set *member_set;
	struct symbol *member;
	int member_count;
	int member_idx;

	member_count = ptr_list_size((struct ptr_list *)type->symbol_list);
	member_set = malloc(member_count * sizeof(*member_set));
	member_idx = 0;
	FOR_EACH_PTR(type->symbol_list, member) {
		member_set[member_idx].ident = member->ident;
		member_set[member_idx].set = 0;
		member_idx++;
	} END_FOR_EACH_PTR(member);

	return member_set;
}

static void mark_member_as_set(struct symbol *type, struct member_set *member_set, struct ident *ident)
{
	int member_count = ptr_list_size((struct ptr_list *)type->symbol_list);
	int i;

	for (i = 0; i < member_count; i++) {
		if (member_set[i].ident == ident) {
			member_set[i].set = 1;
			return;
		}
	}
//	crap.  this is buggy.
//	sm_msg("internal smatch error in initializer %s.%s", type->ident->name, ident->name);
}

static void set_inner_struct_members(struct expression *expr, struct symbol *member)
{
	struct expression *edge_member, *assign;
	struct symbol *base = get_real_base_type(member);
	struct symbol *tmp;

	if (member->ident)
		expr = member_expression(expr, '.', member->ident);

	FOR_EACH_PTR(base->symbol_list, tmp) {
		struct symbol *type;

		type = get_real_base_type(tmp);
		if (!type)
			continue;

		if (tmp->ident) {
			edge_member = member_expression(expr, '.', tmp->ident);
			if (get_state_expr(SMATCH_EXTRA, edge_member))
				continue;
		}

		if (type->type == SYM_UNION || type->type == SYM_STRUCT) {
			set_inner_struct_members(expr, tmp);
			continue;
		}

		if (!tmp->ident)
			continue;

		assign = assign_expression(edge_member, zero_expr());
		__split_expr(assign);
	} END_FOR_EACH_PTR(tmp);


}

static void set_unset_to_zero(struct symbol *type, struct expression *expr)
{
	struct symbol *tmp;
	struct expression *member, *assign;
	int op = '*';

	if (expr->type == EXPR_PREOP && expr->op == '&') {
		expr = strip_expr(expr->unop);
		op = '.';
	}

	FOR_EACH_PTR(type->symbol_list, tmp) {
		type = get_real_base_type(tmp);
		if (!type)
			continue;

		if (tmp->ident) {
			member = member_expression(expr, op, tmp->ident);
			if (get_state_expr(SMATCH_EXTRA, member))
				continue;
		}

		if (type->type == SYM_UNION || type->type == SYM_STRUCT) {
			set_inner_struct_members(expr, tmp);
			continue;
		}
		if (type->type == SYM_ARRAY)
			continue;
		if (!tmp->ident)
			continue;

		assign = assign_expression(member, zero_expr());
		__split_expr(assign);
	} END_FOR_EACH_PTR(tmp);
}

static void fake_member_assigns_helper(struct expression *symbol, struct expression_list *members, fake_cb *fake_cb)
{
	struct expression *deref, *assign, *tmp;
	struct symbol *struct_type, *type;
	struct ident *member;
	int member_idx;
	struct member_set *member_set;

	struct_type = get_type(symbol);
	if (!struct_type ||
	    (struct_type->type != SYM_STRUCT && struct_type->type != SYM_UNION))
		return;

	member_set = alloc_member_set(struct_type);

	member_idx = 0;
	FOR_EACH_PTR(members, tmp) {
		member = number_to_member(symbol, member_idx);
		while (tmp->type == EXPR_IDENTIFIER) {
			member = tmp->expr_ident;
			member_idx = member_to_number(symbol, member);
			tmp = tmp->ident_expression;
		}
		mark_member_as_set(struct_type, member_set, member);
		member_idx++;
		deref = member_expression(symbol, '.', member);
		if (tmp->type == EXPR_INITIALIZER) {
			type = get_type(deref);
			if (type && type->type == SYM_ARRAY)
				fake_element_assigns_helper(deref, tmp->expr_list, fake_cb);
			else
				fake_member_assigns_helper(deref, tmp->expr_list, fake_cb);
		} else {
			assign = assign_expression(deref, tmp);
			fake_cb(assign);
		}
	} END_FOR_EACH_PTR(tmp);

	set_unset_to_zero(struct_type, symbol);
}

static void fake_member_assigns(struct symbol *sym, fake_cb *fake_cb)
{
	fake_member_assigns_helper(symbol_expression(sym),
				   sym->initializer->expr_list, fake_cb);
}

static void fake_element_assigns_helper(struct expression *array, struct expression_list *expr_list, fake_cb *fake_cb)
{
	struct expression *offset, *binop, *assign, *tmp;
	struct symbol *type;
	int idx;

	if (ptr_list_size((struct ptr_list *)expr_list) > 1000)
		return;

	idx = 0;
	FOR_EACH_PTR(expr_list, tmp) {
		if (tmp->type == EXPR_INDEX) {
			if (tmp->idx_from != tmp->idx_to)
				return;
			idx = tmp->idx_from;
			if (!tmp->idx_expression)
				goto next;
			tmp = tmp->idx_expression;
		}
		offset = value_expr(idx);
		binop = array_element_expression(array, offset);
		if (tmp->type == EXPR_INITIALIZER) {
			type = get_type(binop);
			if (type && type->type == SYM_ARRAY)
				fake_element_assigns_helper(binop, tmp->expr_list, fake_cb);
			else
				fake_member_assigns_helper(binop, tmp->expr_list, fake_cb);
		} else {
			assign = assign_expression(binop, tmp);
			fake_cb(assign);
		}
next:
		idx++;
	} END_FOR_EACH_PTR(tmp);
}

static void fake_element_assigns(struct symbol *sym, fake_cb *fake_cb)
{
	fake_element_assigns_helper(symbol_expression(sym), sym->initializer->expr_list, fake_cb);
}

static void fake_assign_expr(struct symbol *sym)
{
	struct expression *assign, *symbol;

	symbol = symbol_expression(sym);
	assign = assign_expression(symbol, sym->initializer);
	__split_expr(assign);
}

static void call_split_expr(struct expression *expr)
{
	__split_expr(expr);
}

static void do_initializer_stuff(struct symbol *sym)
{
	if (!sym->initializer)
		return;

	if (sym->initializer->type == EXPR_INITIALIZER) {
		if (get_real_base_type(sym)->type == SYM_ARRAY)
			fake_element_assigns(sym, call_split_expr);
		else
			fake_member_assigns(sym, call_split_expr);
	} else {
		fake_assign_expr(sym);
	}
}

static void split_declaration(struct symbol_list *sym_list)
{
	struct symbol *sym;

	FOR_EACH_PTR(sym_list, sym) {
		__pass_to_client(sym, DECLARATION_HOOK);
		do_initializer_stuff(sym);
		split_sym(sym);
	} END_FOR_EACH_PTR(sym);
}

static void call_global_assign_hooks(struct expression *assign)
{
	__pass_to_client(assign, GLOBAL_ASSIGNMENT_HOOK);
}

static void fake_global_assign(struct symbol *sym)
{
	struct expression *assign, *symbol;

	if (get_real_base_type(sym)->type == SYM_ARRAY) {
		if (sym->initializer && sym->initializer->type == EXPR_INITIALIZER) {
			fake_element_assigns(sym, call_global_assign_hooks);
		} else if (sym->initializer) {
			symbol = symbol_expression(sym);
			assign = assign_expression(symbol, sym->initializer);
			__pass_to_client(assign, GLOBAL_ASSIGNMENT_HOOK);
		} else {
			fake_element_assigns_helper(symbol_expression(sym), NULL, call_global_assign_hooks);
		}
	} else if (get_real_base_type(sym)->type == SYM_STRUCT) {
		if (sym->initializer && sym->initializer->type == EXPR_INITIALIZER) {
			fake_member_assigns(sym, call_global_assign_hooks);
		} else if (sym->initializer) {
			symbol = symbol_expression(sym);
			assign = assign_expression(symbol, sym->initializer);
			__pass_to_client(assign, GLOBAL_ASSIGNMENT_HOOK);
		} else {
			fake_member_assigns_helper(symbol_expression(sym), NULL, call_global_assign_hooks);
		}
	} else {
		symbol = symbol_expression(sym);
		if (sym->initializer)
			assign = assign_expression(symbol, sym->initializer);
		else
			assign = assign_expression(symbol, zero_expr());
		__pass_to_client(assign, GLOBAL_ASSIGNMENT_HOOK);
	}
}

static void start_function_definition(struct symbol *sym)
{
	__in_function_def = 1;
	__pass_to_client(sym, FUNC_DEF_HOOK);
	__in_function_def = 0;
	__pass_to_client(sym, AFTER_DEF_HOOK);

}

static void split_function(struct symbol *sym)
{
	struct symbol *base_type = get_base_type(sym);

	if (!base_type->stmt && !base_type->inline_stmt)
		return;

	gettimeofday(&fn_start_time, NULL);
	cur_func_sym = sym;
	if (sym->ident)
		cur_func = sym->ident->name;
	__smatch_lineno = sym->pos.line;
	loop_count = 0;
	last_goto_statement_handled = 0;
	sm_debug("new function:  %s\n", cur_func);
	__stree_id = 0;
	if (option_two_passes) {
		__unnullify_path();
		loop_num = 0;
		final_pass = 0;
		start_function_definition(sym);
		__split_stmt(base_type->stmt);
		__split_stmt(base_type->inline_stmt);
		nullify_path();
	}
	__unnullify_path();
	loop_num = 0;
	final_pass = 1;
	start_function_definition(sym);
	__split_stmt(base_type->stmt);
	__split_stmt(base_type->inline_stmt);
	__pass_to_client(sym, END_FUNC_HOOK);
	__pass_to_client(sym, AFTER_FUNC_HOOK);

	clear_all_states();
	cur_func_sym = NULL;
	cur_func = NULL;
	free_data_info_allocs();
	free_expression_stack(&switch_expr_stack);
	__free_ptr_list((struct ptr_list **)&big_statement_stack);
	__bail_on_rest_of_function = 0;
}

static void parse_inline(struct expression *call)
{
	struct symbol *base_type;
	int loop_num_bak = loop_num;
	int final_pass_bak = final_pass;
	char *cur_func_bak = cur_func;
	struct statement_list *big_statement_stack_bak = big_statement_stack;
	struct expression_list *big_expression_stack_bak = big_expression_stack;
	struct expression_list *switch_expr_stack_bak = switch_expr_stack;
	struct symbol *cur_func_sym_bak = cur_func_sym;

	__pass_to_client(call, INLINE_FN_START);
	final_pass = 0;  /* don't print anything */
	__inline_fn = call;

	base_type = get_base_type(call->fn->symbol);
	cur_func_sym = call->fn->symbol;
	if (call->fn->symbol->ident)
		cur_func = call->fn->symbol->ident->name;
	else
		cur_func = NULL;
	set_position(call->fn->symbol->pos);

	save_all_states();
	big_statement_stack = NULL;
	big_expression_stack = NULL;
	switch_expr_stack = NULL;

	sm_debug("inline function:  %s\n", cur_func);
	__unnullify_path();
	loop_num = 0;
	start_function_definition(call->fn->symbol);
	__split_stmt(base_type->stmt);
	__split_stmt(base_type->inline_stmt);
	__pass_to_client(call->fn->symbol, END_FUNC_HOOK);
	__pass_to_client(call->fn->symbol, AFTER_FUNC_HOOK);

	free_expression_stack(&switch_expr_stack);
	__free_ptr_list((struct ptr_list **)&big_statement_stack);
	nullify_path();
	free_goto_stack();

	loop_num = loop_num_bak;
	final_pass = final_pass_bak;
	cur_func_sym = cur_func_sym_bak;
	cur_func = cur_func_bak;
	big_statement_stack = big_statement_stack_bak;
	big_expression_stack = big_expression_stack_bak;
	switch_expr_stack = switch_expr_stack_bak;

	restore_all_states();
	set_position(call->pos);
	__inline_fn = NULL;
	__pass_to_client(call, INLINE_FN_END);
}

static struct symbol_list *inlines_called;
static void add_inline_function(struct symbol *sym)
{
	static struct symbol_list *already_added;
	struct symbol *tmp;

	FOR_EACH_PTR(already_added, tmp) {
		if (tmp == sym)
			return;
	} END_FOR_EACH_PTR(tmp);

	add_ptr_list(&already_added, sym);
	add_ptr_list(&inlines_called, sym);
}

static void process_inlines(void)
{
	struct symbol *tmp;

	FOR_EACH_PTR(inlines_called, tmp) {
		split_function(tmp);
	} END_FOR_EACH_PTR(tmp);
	free_ptr_list(&inlines_called);
}

static struct symbol *get_last_scoped_symbol(struct symbol_list *big_list, int use_static)
{
	struct symbol *sym;

	FOR_EACH_PTR_REVERSE(big_list, sym) {
		if (!sym->scope)
			continue;
		if (use_static && sym->ctype.modifiers & MOD_STATIC)
			return sym;
		if (!use_static && !(sym->ctype.modifiers & MOD_STATIC))
			return sym;
	} END_FOR_EACH_PTR_REVERSE(sym);

	return NULL;
}

static void split_inlines_in_scope(struct symbol *sym)
{
	struct symbol *base;
	struct symbol_list *scope_list;
	int stream;

	scope_list = sym->scope->symbols;
	stream = sym->pos.stream;

	/* find the last static symbol in the file */
	FOR_EACH_PTR_REVERSE(scope_list, sym) {
		if (sym->pos.stream != stream)
			continue;
		if (sym->type != SYM_NODE)
			continue;
		base = get_base_type(sym);
		if (!base)
			continue;
		if (base->type != SYM_FN)
			continue;
		if (!base->inline_stmt)
			continue;
		add_inline_function(sym);
	} END_FOR_EACH_PTR_REVERSE(sym);

	process_inlines();
}

static void split_inlines(struct symbol_list *sym_list)
{
	struct symbol *sym;

	sym = get_last_scoped_symbol(sym_list, 0);
	if (sym)
		split_inlines_in_scope(sym);
	sym = get_last_scoped_symbol(sym_list, 1);
	if (sym)
		split_inlines_in_scope(sym);
}

static struct stree *clone_estates_perm(struct stree *orig)
{
	struct stree *ret = NULL;
	struct sm_state *tmp;

	FOR_EACH_SM(orig, tmp) {
		set_state_stree_perm(&ret, tmp->owner, tmp->name, tmp->sym, clone_estate_perm(tmp->state));
	} END_FOR_EACH_SM(tmp);

	return ret;
}

static void split_functions(struct symbol_list *sym_list)
{
	struct symbol *sym;

	__unnullify_path();
	FOR_EACH_PTR(sym_list, sym) {
		set_position(sym->pos);
		if (sym->type != SYM_NODE || get_base_type(sym)->type != SYM_FN) {
			__pass_to_client(sym, BASE_HOOK);
			fake_global_assign(sym);
		}
	} END_FOR_EACH_PTR(sym);
	global_states = clone_estates_perm(get_all_states_stree(SMATCH_EXTRA));
	nullify_path();

	FOR_EACH_PTR(sym_list, sym) {
		set_position(sym->pos);
		if (sym->type == SYM_NODE && get_base_type(sym)->type == SYM_FN) {
			split_function(sym);
			process_inlines();
		}
	} END_FOR_EACH_PTR(sym);
	split_inlines(sym_list);
	__pass_to_client(sym_list, END_FILE_HOOK);
}

void smatch(int argc, char **argv)
{

	struct string_list *filelist = NULL;
	struct symbol_list *sym_list;

	if (argc < 2) {
		printf("Usage:  smatch [--debug] <filename.c>\n");
		exit(1);
	}
	sparse_initialize(argc, argv, &filelist);
	set_valid_ptr_max();
	FOR_EACH_PTR_NOTAG(filelist, base_file) {
		if (option_file_output) {
			char buf[256];

			snprintf(buf, sizeof(buf), "%s.smatch", base_file);
			sm_outfd = fopen(buf, "w");
			if (!sm_outfd) {
				printf("Error:  Cannot open %s\n", base_file);
				exit(1);
			}
		}
		sym_list = sparse_keep_tokens(base_file);
		split_functions(sym_list);
	} END_FOR_EACH_PTR_NOTAG(base_file);
}
