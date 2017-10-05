/*
 * Copyright (C) 2017 Oracle.
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

static int my_id;


static inline void prefix() {
	printf("%s:%d %s() ", get_filename(), get_lineno(), get_function());
}

static void print_member_type(struct expression *expr)
{
	char *member;

	member = get_member_name(expr);
	if (!member)
		return;
	// sm_msg("info: uses %s", member);
	prefix();
	printf("found condition: uses %s\n", member);
	free_string(member);
}

static void match_condition(struct expression *expr)
{
	if (expr->type == EXPR_COMPARE || expr->type == EXPR_BINOP) {
		match_condition(expr->left);
		match_condition(expr->right);
		return;
	}
	print_member_type(expr);
}

void check_condition_data(int id)
{
	my_id = id;

	add_hook(&match_condition, CONDITION_HOOK);
}
