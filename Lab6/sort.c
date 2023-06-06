#include <stdio.h>

void quicksort(register long *numbers, register int left, register int right) {
    if (left < right) {
        register long pivot = numbers[right], temp;
        register int i = left - 1;

        for (register int j = left; j < right; ++j) {
            if (numbers[j] < pivot) {
                ++i;
                temp = numbers[i];
                numbers[i] = numbers[j];
                numbers[j] = temp;
            }
        }

        temp = numbers[i + 1];
        numbers[i + 1] = numbers[right];
        numbers[right] = temp;

        quicksort(numbers, left, i);
        quicksort(numbers, i + 2, right);
    }
}

void sort_funcptr_t(long *numbers, int n) {
    quicksort(numbers, 0, n - 1);
}