/*
 * smatch/check_unwind.c
 *
 * Copyright (C) 2010 Dan Carpenter.
 *
 * Licensed under the Open Software License version 1.1
 *
 */

/*
 * This is a kernel check to make sure we unwind everything on
 * on errors.
 *
 */

#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

#define EBUSY 16
#define MAX_ERRNO 4095

static int my_id;

STATE(allocated);
STATE(unallocated);

static void request_granted(const char *fn, struct expression *call_expr,
			struct expression *assign_expr, void *_arg_no)
{
	struct expression *arg_expr;
	int arg_no = (int)_arg_no;

	if (arg_no == -1)
		arg_expr = assign_expr->left;
	else
		arg_expr = get_argument_from_call_expr(call_expr->args, arg_no);
	set_state_expr(my_id, arg_expr, &allocated);
}

static void request_denied(const char *fn, struct expression *call_expr,
			struct expression *assign_expr, void *_arg_no)
{
	struct expression *arg_expr;
	int arg_no = (int)_arg_no;

	if (arg_no == -1)
		arg_expr = assign_expr->left;
	else
		arg_expr = get_argument_from_call_expr(call_expr->args, arg_no);
	set_state_expr(my_id, arg_expr, &unallocated);
}

static void match_release(const char *fn, struct expression *expr, void *_arg_no)
{
	struct expression *arg_expr;
	int arg_no = (int)_arg_no;

	arg_expr = get_argument_from_call_expr(expr->args, arg_no);
	if (!get_state_expr(my_id, arg_expr))
		return;
	set_state_expr(my_id, arg_expr, &unallocated);
}

static int func_returns_int()
{
	struct symbol *type;

	type = get_base_type(cur_func_sym);
	if (!type || type->type != SYM_FN)
		return 0;
	type = get_base_type(type);
	if (type->ctype.base_type == &int_type) {
		return 1;
	}
	return 0;
}

static void match_return(struct expression *ret_value)
{
	struct state_list *slist;
	struct sm_state *tmp;

	if (!func_returns_int())
		return;
	if (!implied_not_equal(ret_value, 0))
		return;

	slist = get_all_states(my_id);
	FOR_EACH_PTR(slist, tmp) {
		if (slist_has_state(tmp->possible, &allocated))
			sm_msg("warn: '%s' was not released on error", tmp->name);
	} END_FOR_EACH_PTR(tmp);
	free_slist(&slist);
}

void check_unwind(int id)
{
	if (option_project != PROJ_KERNEL)
		return;
	my_id = id;

	return_implies_state("request_resource", 0, 0, &request_granted, INT_PTR(1));
	return_implies_state("request_resource", -EBUSY, -EBUSY, &request_denied, INT_PTR(1));
	add_function_hook("release_resource", &match_release, INT_PTR(0));

	return_implies_state("__request_region", 1, POINTER_MAX, &request_granted, INT_PTR(1));
	return_implies_state("__request_region", 0, 0, &request_denied, INT_PTR(1));
	add_function_hook("__release_region", &match_release, INT_PTR(1));

	return_implies_state("ioremap", 1, POINTER_MAX, &request_granted, INT_PTR(-1));
	return_implies_state("ioremap", 0, 0, &request_denied, INT_PTR(-1));
	add_function_hook("iounmap", &match_release, INT_PTR(0));

	return_implies_state("pci_iomap", 1, POINTER_MAX, &request_granted, INT_PTR(-1));
	return_implies_state("pci_iomap", 0, 0, &request_denied, INT_PTR(-1));
	add_function_hook("pci_iounmap", &match_release, INT_PTR(1));

	return_implies_state("__create_workqueue_key", 1, POINTER_MAX, &request_granted,
			INT_PTR(-1));
	return_implies_state("__create_workqueue_key", 0, 0, &request_denied, INT_PTR(-1));
	add_function_hook("destroy_workqueue", &match_release, INT_PTR(0));

	return_implies_state("request_irq", 0, 0, &request_granted, INT_PTR(0));
	return_implies_state("request_irq", -MAX_ERRNO, -1, &request_denied, INT_PTR(0));
	add_function_hook("free_irq", &match_release, INT_PTR(0));

	return_implies_state("register_netdev", 0, 0, &request_granted, INT_PTR(0));
	return_implies_state("register_netdev", -MAX_ERRNO, -1, &request_denied, INT_PTR(0));
	add_function_hook("unregister_netdev", &match_release, INT_PTR(0));

	return_implies_state("misc_register", 0, 0, &request_granted, INT_PTR(0));
	return_implies_state("misc_register", -MAX_ERRNO, -1, &request_denied, INT_PTR(0));
	add_function_hook("misc_deregister", &match_release, INT_PTR(0));

	add_hook(&match_return, RETURN_HOOK);
}