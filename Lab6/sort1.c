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

void sort_funcptr_t (register long *numbers, register int n) {
    if (n < 120) {
        for (register int i = 1; i < n; i++) {
            register int key = numbers[i];
            register int j = i - 1;

            while (j >= 0 && numbers[j] > key) {
                numbers[j + 1] = numbers[j];
                j = j - 1;
            }
            numbers[j + 1] = key;
        }
    }
    else {
        quicksort(numbers, 0, n - 1);
    }
}