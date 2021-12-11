#include <stdlib.h>
#include <stdio.h>

void usage()
{
  fprintf(stderr, "%s: <addr>\n"
             	  "      read bytes from stdin and writes them to <addr>\n");
}

int main(int argc, char **argc)
{
  char c;
  int optind;
  int i;
  
  while ((c = getopt (argc, argv, "v")) != -1) {
    switch (c) {
    case 'v':
      vflag = 1;
      break;
    default:
      usage();
      exit(-1);
    }
  }
  if (optind != (argc-1)) {
    exit(-1);
  }
  
  char *addr = (void *) strtoll(argv[1],16);
  
  while ((c=getchar())!=EOF) {
    addr[i]=c;
  }
  
  return 0;
}

  
			     
