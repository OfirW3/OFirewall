#include <stdio.h>
#include <stdlib.h>
#include "Firewall.h"

dynamic *dynMake_(unsigned int entrysize){ //Dynamic array constructor
    dynamic *p;
    unsigned int size = sizeof(struct s_dynamic) + (BLOCK_SIZE * entrysize); //Size of the minimal dynamic array length + size of the entries
    p = (dynamic*)(malloc(size));
    assert(p);
    zero(p, size);

    p->count = 0;
    p->capacity = BLOCK_SIZE;
    p->size = BLOCK_SIZE * entrysize; 

    return p;
}

int main(){
    printf("%d",sizeof(unsigned int));
    return 0;
}