#ifndef FS_H
#define FS_H

void *acalloc(size_t nmemb, size_t size,  char *name);
void *arecalloc(void *ptr, size_t old_nmemb, size_t nmemb,
                size_t size,  char *name);

double fmax(double left, double right);

    double fmin(double left, double right);

double trunc(double d);

#endif
