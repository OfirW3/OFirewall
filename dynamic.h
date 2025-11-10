#pragma once
#include <stdio.h>
#include <stdlib.h>

#define DECLARE_DYNAMIC(type, name) \
typedef struct s_dynamic_##name{ \
    type *data; \
    uint32_t size; \
    uint32_t capacity; \
} dynamic_##name; \
\
static void dynInit_##name(dynamic_##name *arr, unsigned int capacity) { \
    arr->data = NULL; \
    arr->size = 0; \
    arr->capacity = capacity; \
} \
\
static void dynInsertValue_##name(type value, dynamic_##name *arr) { \
    if (arr->size == arr->capacity) { \
        arr->capacity = arr->capacity * 2; \
    } \
    if (arr->capacity == 0) { \
        arr->capacity = 8; \
    } \
    arr->data = (type*)realloc(arr->data, sizeof(type) * arr->capacity); \
    if (arr->data == NULL) { \
        printf("Allocation failed"); \
        exit(1); \
    } \
    arr->data[arr->size] = value; \
    arr->size++; \
} \
\
static void dynRemoveByIndex_##name(unsigned int index, dynamic_##name *arr) { \
    if (index >= arr->size) return; \
    for (unsigned int i = index; i < arr->size - 1; i++) { \
        arr->data[i] = arr->data[i + 1]; \
    } \
    arr->size--; \
} \
\
static type *dynGetByIndex_##name(uint16_t index, dynamic_##name *arr) { \
    if (index < arr->size) return &arr->data[index]; \
    return NULL; \
} \
\
static void dynFree_##name(dynamic_##name *arr) { \
    free(arr->data); \
    arr->data = NULL; \
    arr->size = 0; \
    arr->capacity = 0; \
} 
