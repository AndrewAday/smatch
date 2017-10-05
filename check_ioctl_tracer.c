/*
 * Copyright (C) 2016 Oracle.
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
 * This is part of infrastructure to create trinity fuzzer templates.
 */

#include "smatch.h"
#include "smatch_extra.h"

static int my_id;

STATE(ioctl_cmd);
STATE(ioctl_arg);

static struct smatch_state *merge_func(struct smatch_state *s1, struct smatch_state *s2)
{
       if (s1 == &ioctl_cmd || s2 == &ioctl_cmd)
               return &ioctl_cmd;

       if (s1 == &ioctl_arg || s2 == &ioctl_arg)
               return &ioctl_arg;

       return &merged;
}

static void match_assign(struct expression *expr)
{
       struct smatch_state *state;

       state = get_state_expr(my_id, expr->right);
       if (!state)
               return;
       set_state_expr(my_id, expr->left, state);
}

static void set_param(const char *name, struct symbol *sym, char *key, char *value, struct smatch_state *state)
{
       char fullname[256];

       if (strcmp(key, "*$") == 0)
               snprintf(fullname, sizeof(fullname), "*%s", name);
       else if (strncmp(key, "$", 1) == 0)
               snprintf(fullname, 256, "%s%s", name, key + 1);
       else
               return;

       set_state(my_id, fullname, sym, state);
}

static void set_param_cmd(const char *name, struct symbol *sym, char *key, char *value)
{
       if (!name) {
               struct range_list *rl;
               struct smatch_state *state;

               str_to_rl(&uint_ctype, value, &rl);
               state = alloc_estate_rl(rl);
               set_extra_nomod("#ioctl_cmd", NULL, state);
               return;
       }
       set_param(name, sym, key, value, &ioctl_cmd);
}

static void set_param_arg(const char *name, struct symbol *sym, char *key, char *value)
{
       set_param(name, sym, key, value, &ioctl_arg);
}

static struct range_list *get_cmd_rl(void)
{
       struct smatch_state *state;
       struct symbol *arg;

       state = get_state(SMATCH_EXTRA, "#ioctl_cmd", NULL);
       if (state) {
               if (estate_is_whole(state))
                       return NULL;
               return estate_rl(state);
       }

       FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, arg) {
               if (get_state(my_id, arg->ident->name, arg) != &ioctl_cmd)
                       continue;
               state = get_state(SMATCH_EXTRA, arg->ident->name, arg);
               if (!state || estate_is_whole(state))
                       return NULL;
               return estate_rl(state);
       } END_FOR_EACH_PTR(arg);

       return NULL;
}

static void match_call_info(struct expression *expr)
{
       struct expression *arg;
       struct range_list *rl;
       int i, arg_nr, cmd_nr;

       i = -1;
       arg_nr = -1;
       cmd_nr = -1;
       FOR_EACH_PTR(expr->args, arg) {
               i++;

               if (cmd_nr == -1 && get_state_expr(my_id, arg) == &ioctl_cmd)
                       cmd_nr = i;

               if (arg_nr == -1 && get_state_expr(my_id, arg) == &ioctl_arg)
                       arg_nr = i;

               if (cmd_nr != -1 && arg_nr != -1) {
                       sql_insert_caller_info(expr, IOCTL_ARG, arg_nr, "$", "");
                       sql_insert_caller_info(expr, IOCTL_CMD, cmd_nr, "$", "");
                       return;
               }

       } END_FOR_EACH_PTR(arg);
       if (arg_nr == -1)
               return;

       rl = get_cmd_rl();
       if (!rl)
               return;
       sql_insert_caller_info(expr, IOCTL_ARG, arg_nr, "$", "");
       sql_insert_caller_info(expr, IOCTL_CMD, -1, "", show_rl(rl));
}

static void match_copy(struct expression *dst, struct expression *src)
{
       struct smatch_state *state;
       struct range_list *rl;

       sm_msg("MATCHED COPY");

       state = get_state_expr(my_id, src);
       rl = get_cmd_rl();
       sm_msg("STATE %s %s rl = '%s'", expr_to_str(src), state ? state->name : "none", show_rl(rl));


       if (get_state_expr(my_id, src) != &ioctl_arg)
               return;
       rl = get_cmd_rl();
       if (!rl)
               return;
       sm_msg("info: ioctl_cmd: %s arg_type: %s", show_rl(rl), type_to_str(get_type(dst)));
}

static void match_copy_from_user(const char *fn, struct expression *expr, void *_unused)
{
       struct expression *src, *dst;

       src = get_argument_from_call_expr(expr->args, 1);
       src = strip_expr(src);
       if (!src)
               return;

       dst = get_argument_from_call_expr(expr->args, 0);
       dst = strip_expr(dst);
       if (!dst)
               return;

       match_copy(dst, src);
}

static void match_memdup_user(const char *fn, struct expression *expr, void *_unused)
{
       struct expression *src, *dst;
       struct expression *call;

       call = strip_expr(expr->right);
       src = get_argument_from_call_expr(call->args, 0);
       src = strip_expr(src);
       if (!src)
               return;

       dst = expr->left;

       match_copy(dst, src);
}

static void match_ioctl_syscall(struct symbol *sym)
{
       static int wrong_file;
       struct symbol *arg;
       int i;

       /* The wrong_file short cut only works with --info */
       if (wrong_file)
               return;
       if (!cur_func_sym->ident)
               return;

       if (strcmp(get_filename(), "fs/ioctl.c") != 0) {
               wrong_file = 1;
               return;
       }
       if (strcmp(cur_func_sym->ident->name, "SYSC_ioctl") != 0)
               return;

       i = -1;
       FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, arg) {
               i++;
               if (i == 1)
                       set_state(my_id, arg->ident->name, arg, &ioctl_cmd);
               if (i == 2)
                       set_state(my_id, arg->ident->name, arg, &ioctl_arg);
       } END_FOR_EACH_PTR(arg);
}

void check_ioctl_tracer(int id)
{
       my_id = id;

       if (option_project != PROJ_KERNEL)
               return;
       if (!option_info)
               return;

       add_hook(&match_ioctl_syscall, FUNC_DEF_HOOK);

       add_hook(&match_assign, ASSIGNMENT_HOOK);
       add_merge_hook(my_id, &merge_func);

       add_hook(&match_call_info, FUNCTION_CALL_HOOK);
       select_caller_info_hook(set_param_cmd, IOCTL_CMD);
       select_caller_info_hook(set_param_arg, IOCTL_ARG);

       add_function_hook("copy_from_user", &match_copy_from_user, NULL);
       add_function_hook("__copy_from_user", &match_copy_from_user, NULL);

       add_function_assign_hook("memdup_user", &match_memdup_user, NULL);
}
