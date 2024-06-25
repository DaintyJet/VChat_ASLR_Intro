#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>

#define STACK_NUM 10
//#define INT

// Create a constant global variable should be in rdata
const char* const_global = "HELLO WORLD";
// Create a static global variable should be in data
static char* static_global = "HELLO WORLD TWO";
// Create a global that should be placed in bss
int bss_data;

// Function to check offsets
void some_function(void) {
    int x = 1;
    return;
}

int main(int argc, char* argv[]) {
    int test = 1, *s_ptr = 2;
    long j = 3;
    // If we were to do char* = "String" then we would only store a pointer which may be 
    // relocated towards the edge of the stack, by creating an array on the stack it should 
    // be kept closer to the head of the stack
    char something[16]; strcpy(something, "THIS IS OUR FUN");
    void* m_ptr = 4, * h_ptr = 5, * v_ptr = 6;
    HANDLE h_heap;

#ifdef INT
    __asm int 3
#endif // INT

    __asm {
        LABEL: mov edx, LABEL
        mov j, edx
    }

    // Allocating on heap using c std lib
    m_ptr = (void*)malloc(sizeof(char) * 2);
    *((char*)m_ptr) = "A";

    // Allocate on a heap we allocate
    h_heap = HeapCreate(HEAP_GENERATE_EXCEPTIONS, 0, 0);
    h_ptr = HeapAlloc(h_heap, HEAP_GENERATE_EXCEPTIONS, sizeof(char) * 2);
    *((char*)h_ptr) = "B";

    // Virtual Allocation of a page
    v_ptr = VirtualAlloc(NULL, sizeof(char) * 2, MEM_COMMIT, PAGE_READWRITE);
    *((char*)v_ptr) = "C";

    // General Locations
    printf("\nSection Addresses\n");
    printf("Location of STACK: %08p\n", &test);
    printf("Location of .rdata: %08p\n", &const_global);
    printf("Location of .data: %08p\n", &static_global);
    printf("Location of .bss: %08p\n", &bss_data);
    printf("Location of .text: %08p\n", j);

    printf("\nHEAP ALLOCAITONS\n");
    printf("Location of malloc alloc: %08p\n", m_ptr);
    printf("Location of HeapCreate alloc: %08p\n", h_ptr);
    printf("Location of Virtual alloc: %08p\n", v_ptr);

    printf("\nFunction Offset\n");
    printf("Offset Value between `main` and `some_function`: %08p\n", (long)main - (long)some_function);


    // Printing out the stack
    printf("\nSTACK DATA:\n");
    for (test, s_ptr = &test; test < STACK_NUM; test++, ++s_ptr)
        printf("%-2d: %08p %08x\n", test - 1 , (void*)s_ptr, (*s_ptr));
    
#ifdef INT
    __asm int 3
#endif // INT

    return 0; 
}