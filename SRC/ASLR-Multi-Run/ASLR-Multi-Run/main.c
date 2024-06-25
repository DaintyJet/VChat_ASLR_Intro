#include <Windows.h>
#include <stdio.h>


//#define CONST_GLOBAL 1
//#define GLOBAL 1
//#define BSS 1
//#define STACK 1
//#define M_HEAP 1
//#define H_HEAP 1
//#define V_ALLOC 1
//#define TEXT_P 1

// Create a constant global variable should be in rdata
const char* const_global = "HELLO WORLD";
// Create a static global variable should be in data
static char* static_global = "HELLO WORLD TWO";
// Create a global that should be placed in bss
int bss_data;


int main(void) {
    int test = 1;
    void* m_ptr = 4, * h_ptr = 5, * v_ptr = 6;
    HANDLE h_heap;

#ifdef M_HEAP
    // Allocating on heap using c std lib
    m_ptr = (void*)malloc(sizeof(char) * 2);
    *((char*)m_ptr) = "A";
    printf("%p\n", m_ptr);
#endif 
#ifdef H_HEAP
    // Allocate on a heap we allocate
    h_heap = HeapCreate(HEAP_GENERATE_EXCEPTIONS, 0, 0);
    h_ptr = HeapAlloc(h_heap, HEAP_GENERATE_EXCEPTIONS, sizeof(char) * 2);
    *((char*)h_ptr) = "B";
    printf("%p\n", h_ptr);
#endif 
#ifdef V_ALLOC
    // Virtual Allocation of a page
    v_ptr = VirtualAlloc(NULL, sizeof(char) * 2, MEM_COMMIT, PAGE_READWRITE);
    *((char*)v_ptr) = "C";
    printf("%p\n", v_ptr);
#endif 
#ifdef TEXT_P
    printf("%p\n", main);
#endif 
#ifdef CONST_GLOBAL
    printf("%p\n", &const_global);
#endif 
#ifdef GLOBAL
    printf("%p\n", &static_global);
#endif 
#ifdef BSS
    printf("%p\n", &bss_data);
#endif 
#ifdef STACK
    printf("%p\n", &test);
#endif

}