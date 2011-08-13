/* =========================================================
 *       Filename:  wrap.c
 *
 *    Description:
 *
 *         Author:  Yang Zhang, armx86@gmail.com
 *        Created:  13.02.11
 *       Revision:
 * ======================================================== */

#include <stdio.h>
#include "rbtree.h"

struct whitelist {
        struct rb_node node;
        unsigned ip;
};

struct whitelist *is_ip_in_whitelist(struct rb_root *root, unsigned wanted)
{
        struct rb_node *node = root->rb_node;
        struct whitelist *unit;
        while (node) {
                unit = rb_entry(node, struct whitelist, node);
                if (wanted < unit->ip) {
                        node = node->rb_left;
                } else if (wanted > unit->ip) {
                        node = node->rb_right;
                        /* found */
                } else {
                        return unit;
                }
        }
        return NULL;
}

int add_to_whitelist(struct rb_root *root, struct whitelist *wanted)
{
        struct rb_node *node = root->rb_node;
        struct whitelist *unit;
        if (!node) {return FALSE;}
        while (1) {
                unit = rb_entry(node, struct whitelist, node);
                if (wanted->ip < unit->ip) {
                        if (node->rb_left) {
                                node = node->rb_left;
                        } else {
                                rb_link_node(&wanted->node, 
                                                node, 
                                                &node->rb_left);
                                break;
                        }
                } else if (wanted->ip > unit->ip) {
                        if (node->rb_right) {
                                node = node->rb_right;
                        } else {
                                rb_link_node(&wanted->node,
                                                node,
                                                &node->rb_right);
                                break;
                        }
                /* found a same */
                } else {
                        /* return FALSE */
                        return TRUE;
                }
        }
        rb_insert_color(&wanted->node, root);
        return TRUE;
}

int main(int argc, const char *argv[])
{
        int ret, i;
        struct rb_root root;
        struct whitelist whitelist[16];
        struct rb_node *node;

        whitelist[0].ip = -1;
        whitelist[1].ip = 1;
        whitelist[2].ip = 10;
        whitelist[3].ip = 600;
        whitelist[4].ip = 39;
        whitelist[5].ip = 0;
        whitelist[6].ip = 88;
        whitelist[7].ip = 11111111;
        whitelist[8].ip = 33333333;
        whitelist[9].ip = 99999999;
        whitelist[10].ip = 8;
        whitelist[11].ip = 192238225;
        whitelist[12].ip = 23232;
        whitelist[13].ip = 111;
        whitelist[14].ip = 999;
        whitelist[15].ip = 888;

        /* root hasn't rb_node, but a pointer to that type, so 2nd arg is NULL */
        rb_link_node(&whitelist[0].node, NULL, &root.rb_node);
        rb_insert_color(&whitelist[0].node, &root);

        for (i = 0; i < 16; ++i) {
                ret = add_to_whitelist(&root, &whitelist[i]);
                if (!ret)
                        printf("insert whitelist[%d] error\n", i);
        }
        if (is_ip_in_whitelist(&root, 8))
                printf("8 is ok\n");
        if (is_ip_in_whitelist(&root, -1))
                printf("-1 is ok\n");
        if (is_ip_in_whitelist(&root, 0))
                printf("0 is ok\n");
        if (is_ip_in_whitelist(&root, 1))
                printf("1 is ok\n");
        if (is_ip_in_whitelist(&root, 192238225))
                printf("192238225 is ok\n");
        if (!is_ip_in_whitelist(&root, 2))
                printf("2 is not in rbtree\n");

        for (node = rb_first(&root); node; node = rb_next(node))
                printf("ip %u\n", ((struct whitelist *)node)->ip);
        return 0;
}
