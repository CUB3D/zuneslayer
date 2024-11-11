#include <stdlib.h>

#include "fixes.h"

#include <string.h>

#include "util.h"

/* Assert calloc */
void *acalloc(size_t nmemb, size_t size, char *name)
{
    void *res = calloc(nmemb, size);
    if (nmemb * size == 0)
    {
        warn("acalloc: %s requests allocating 0 bytes.\n", name);
    }
    else if (res == NULL)
    {
        FATAL("Could not allocate %ul bytes for %s", nmemb * size, name);
    }
    return res;
}

/* Assert realloc/calloc */
void *arecalloc(void *ptr, size_t old_nmemb, size_t nmemb,
                size_t size, char *name)
{
    void *res = realloc(ptr, nmemb * size);
    if (res == NULL)
    {
        FATAL("Could not allocate %ul bytes for %s", nmemb * size, name);
    }
    /* Initialize new memory */
    memset((void*)((size_t)res + old_nmemb * size), 0, (nmemb - old_nmemb) * size);
    return res;
}


double fmax(double left, double right)
    { return (left > right) ? left : right; }

    double fmin(double left, double right)
    { return (left < right) ? left : right; }

double trunc(double d){ return (d>0) ? floor(d) : ceil(d) ; }

