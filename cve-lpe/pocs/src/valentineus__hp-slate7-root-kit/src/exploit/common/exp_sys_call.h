/*
 * Copyright (C) 2013 Hiroyuki Ikezoe
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef _EXP_SYS_H_
#define _EXP_SYS_H_

#include <stdbool.h>
#include <stdio.h>

#define __NR_exp_       222

extern unsigned long int exp_sys_call_address;
bool setup_exp_sys_call_address(void);
unsigned long get_sys_table_base(void);

#endif /* _EXP_SYS_H_ */
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
