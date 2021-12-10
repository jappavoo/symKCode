#include <stdio.h>

extern int (*virtnet_poll)(void *,int);

int main(int argc, char **argv)
{
  fprintf(stderr, "%s: begin\n", argv[0]);
  printf("& virtnet_poll: %p\n", virtnet_poll);
  fprintf(stderr, "%s: begin\n", argv[0]);
  return (long long)virtnet_poll;
}
