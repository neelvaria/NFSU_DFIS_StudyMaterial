#include <stdio.h>
#include <string.h>

// ============================================================================
// PART 1: SCOPE AND LIFETIME OF VARIABLES
// ============================================================================

// Global variable: Allocated in the fixed data segment. 
// Visible globally across the file. Lifetime matches the program runtime.
int globalVar = 100;

void demonstrateVariableLifetimes() {
    // Local variable: Allocated on the runtime stack frame.
    // Visible only inside this function. Destroyed when the function returns.
    int localVar = 10;

    // Static variable: Allocated in the fixed data segment.
    // Visible only inside this function, but permanently retains value between calls.
    static int staticVar = 0;

    localVar++;
    staticVar++;
    globalVar++;

    printf("[Inside Function] Local: %d | Static: %d | Global: %d\n", 
           localVar, staticVar, globalVar);
}

// ============================================================================
// PART 2: RECURSIVE ALGORITHMS (Stack Mechanics)
// ============================================================================

/**
 * Calculates the factorial of a number.
 * Demonstrates basic linear recursion and sequential stack growth.
 */
unsigned long long factorial(int n) {
    // Base case
    if (n <= 1) {
        return 1;
    }
    // Recursive step
    return n * factorial(n - 1);
}

/**
 * Calculates the N-th Fibonacci number.
 * Demonstrates tree recursion (binary branching stack frames).
 */
int fibonacci(int n) {
    // Base cases
    if (n <= 0) return 0;
    if (n == 1) return 1;
    
    // Recursive step
    return fibonacci(n - 1) + fibonacci(n - 2);
}

/**
 * Performs a binary search on a sorted integer array.
 * Demonstrates divide-and-conquer execution on the stack.
 */
int binarySearch(const int arr[], int low, int high, int target) {
    // Base case: Element not found
    if (low > high) {
        return -1;
    }

    int mid = low + (high - low) / 2;

    // Base case: Element found
    if (arr[mid] == target) {
        return mid;
    }

    // Recursive steps
    if (arr[mid] > target) {
        return binarySearch(arr, low, mid - 1, target);
    }
    return binarySearch(arr, mid + 1, high, target);
}

/**
 * Reverses a character array string in-place using recursion.
 * Demonstrates index modification and value swapping per stack frame.
 */
void reverseString(char str[], int left, int right) {
    // Base case: Pointers meet or cross
    if (left >= right) {
        return;
    }

    // Process/Swap characters
    char temp = str[left];
    str[left] = str[right];
    str[right] = temp;

    // Recursive step
    reverseString(str, left + 1, right - 1);
}

// ============================================================================
// MAIN EXECUTION DRIVER
// ============================================================================

int main() {
    // 1. Scope & Lifetime Analysis
    printf("--- 1. Variable Scope & Lifetime Demo ---\n");
    printf("Initial Global Var: %d\n", globalVar);
    demonstrateVariableLifetimes();
    demonstrateVariableLifetimes(); // Called again to show static retention
    printf("Final Global Var: %d\n\n", globalVar);

    // 2. Recursion Demonstrations
    printf("--- 2. Recursive Algorithms Demo ---\n");

    // Factorial
    int factNum = 5;
    printf("Factorial of %d = %llu\n", factNum, factorial(factNum));

    // Fibonacci
    int fibTerm = 6;
    printf("Fibonacci term %d = %d\n", fibTerm, fibonacci(fibTerm));

    // Binary Search (Array must be sorted)
    int sortedData[] = {10, 23, 35, 47, 59, 70, 88};
    int dataSize = sizeof(sortedData) / sizeof(sortedData[0]);
    int target = 47;
    int searchResult = binarySearch(sortedData, 0, dataSize - 1, target);
    printf("Binary Search for %d found at index: %d\n", target, searchResult);

    // String Reversal
    char text[] = "Recursion";
    printf("Original String: %s\n", text);
    reverseString(text, 0, (int)strlen(text) - 1);
    printf("Reversed String: %s\n", text);

    return 0;
}
