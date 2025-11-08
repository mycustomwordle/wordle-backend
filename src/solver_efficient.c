#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h> // Required for log2
#include "solver_efficient.h"
#include "wordle_core.h"

// The number of possible feedback patterns (3^6 = 729 for up to 6-letter words).
#define MAX_PATTERNS 729

// Structure for pattern counting in longer words
typedef struct {
    int* patterns;
    int* counts;
    int size;
    int capacity;
} PatternMap;


// Converts a feedback pattern (base 3) into a unique integer index.
static int pattern_to_int(const Feedback* feedback) {
    int index = 0;
    int power_of_3 = 1;
    for (int i = 0; i < feedback->word_len; i++) {
        index += feedback->pattern[i] * power_of_3;
        power_of_3 *= 3;
    }
    return index;
}

// Calculates the information entropy for a given guess against a list of possibilities.
static double calculate_entropy(const char* guess, const WordList* possibilities) {
    int word_len = possibilities->word_len;
    
    // For longer words, use a dynamic pattern map to avoid huge arrays
    if (word_len > 6) {
        PatternMap map;
        map.capacity = possibilities->count > 100 ? 100 : possibilities->count;
        map.patterns = malloc(map.capacity * sizeof(int));
        map.counts = malloc(map.capacity * sizeof(int));
        map.size = 0;
        
        for (size_t i = 0; i < possibilities->count; i++) {
            const char* candidate = possibilities->words[i];
            Feedback feedback = get_feedback(guess, candidate, word_len);
            int index = pattern_to_int(&feedback);
            
            // Find or add pattern
            int found = -1;
            for (int j = 0; j < map.size; j++) {
                if (map.patterns[j] == index) {
                    found = j;
                    break;
                }
            }
            
            if (found >= 0) {
                map.counts[found]++;
            } else if (map.size < map.capacity) {
                map.patterns[map.size] = index;
                map.counts[map.size] = 1;
                map.size++;
            }
        }
        
        double entropy = 0.0;
        for (int i = 0; i < map.size; i++) {
            if (map.counts[i] > 0) {
                double p = (double)map.counts[i] / possibilities->count;
                entropy -= p * (log(p) / log(2.0));
            }
        }
        
        free(map.patterns);
        free(map.counts);
        return entropy;
    } else {
        // For shorter words (<=6 letters), use fast array-based approach
        int pattern_counts[MAX_PATTERNS] = {0};

        for (size_t i = 0; i < possibilities->count; i++) {
            const char* candidate = possibilities->words[i];
            Feedback feedback = get_feedback(guess, candidate, word_len);
            int index = pattern_to_int(&feedback);
            if (index < MAX_PATTERNS) {
                pattern_counts[index]++;
            }
        }

        double entropy = 0.0;
        for (int i = 0; i < MAX_PATTERNS; i++) {
            if (pattern_counts[i] > 0) {
                double p = (double)pattern_counts[i] / possibilities->count;
                entropy -= p * (log(p) / log(2.0));
            }
        }
        return entropy;
    }
}

// Finds the best guess by iterating through the full dictionary to maximize entropy.
static const char* find_best_guess(const WordList* full_dictionary, const WordList* possibilities) {
    if (possibilities->count == 1) {
        return possibilities->words[0]; // Only one word left
    }
    
    if (possibilities->count == 2) {
        // For 2 words, just pick the first
        return possibilities->words[0];
    }

    // Use entropy calculation - search full dictionary for larger possibility sets
    double max_entropy = -1.0;
    const char* best_guess = NULL;

    // For very small possibility counts, search within possibilities
    // For larger counts, search full dictionary for better information gain
    const WordList* search_list = (possibilities->count <= 5) ? possibilities : full_dictionary;

    for (size_t i = 0; i < search_list->count; i++) {
        const char* current_guess = search_list->words[i];
        double entropy = calculate_entropy(current_guess, possibilities);

        if (entropy > max_entropy) {
            max_entropy = entropy;
            best_guess = current_guess;
        }
    }
    return best_guess ? best_guess : possibilities->words[0];
}

// Function to get best starting word from best_entropy.txt for a given word length
static char* get_best_entropy_word(int word_length) {
    FILE* file = fopen("data/best_entropy.txt", "r");
    if (!file) return NULL;
    
    char line[256];
    char filename[50];
    char word[50];
    double entropy;
    int count;
    
    // Format expected: count11.txt	ancestorial	11.095845	3501
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "%s\t%s\t%lf\t%d", filename, word, &entropy, &count) == 4) {
            // Extract the number from filename (e.g., "count11.txt" -> 11)
            int len;
            if (sscanf(filename, "count%d.txt", &len) == 1) {
                if (len == word_length) {
                    fclose(file);
                    return my_strdup(word);
                }
            }
        }
    }
    
    fclose(file);
    return NULL;
}

void solve_efficient(const WordList* word_list, const char* solution) {
    printf("--- Starting Efficient Solver ---\n");

    if (!word_list || word_list->count == 0) {
        printf("Dictionary is empty. Cannot solve.\n");
        return;
    }

    // Create a mutable copy of the word list to filter down.
    WordList* possibilities = malloc(sizeof(WordList));
    possibilities->words = malloc(word_list->count * sizeof(char*));
    for(size_t i = 0; i < word_list->count; ++i) {
        possibilities->words[i] = my_strdup(word_list->words[i]);
    }
    possibilities->count = word_list->count;
    possibilities->capacity = word_list->count;
    possibilities->word_len = word_list->word_len;

    int guesses = 0;
    const char* guess;
    char* best_entropy_word = NULL;
    
    if (possibilities->word_len == 3) {
        guess = "are";
    } else if (possibilities->word_len == 4) {
        guess = "some";
    } else if (possibilities->word_len == 5) {
        guess = "salet";
    } else if (possibilities->word_len == 6) {
        guess = "course";
    } else if (possibilities->word_len == 7) {
        guess = "another";
    } else if (possibilities->word_len == 8) {
        guess = "children";
    } else if (possibilities->word_len == 9) {
        guess = "continues";
    } else if (possibilities->word_len == 10) {
        guess = "chattering";
    } else {
        // For word lengths > 10, try to get from best_entropy.txt
        best_entropy_word = get_best_entropy_word(possibilities->word_len);
        if (best_entropy_word) {
            guess = best_entropy_word;
        } else {
            guess = find_best_starting_word(word_list);
        }
    }

    while (guesses < 10 && possibilities->count > 0) {
        guesses++;
        printf("Guess %d: (%zu possibilities left)\n", guesses, possibilities->count);

        if (guesses > 1) { // Find best guess after the first one.
            guess = find_best_guess(word_list, possibilities);
        }
        printf("Guessing: '%s' (Entropy-based choice)\n", guess);

        Feedback feedback = get_feedback(guess, solution, possibilities->word_len);

        if (is_solved(&feedback)) {
            printf("Solved in %d guesses! The word is '%s'.\n\n", guesses, solution);
            free_word_list(possibilities);
            if (best_entropy_word) free(best_entropy_word);
            return;
        }

        WordList* next_possibilities = filter_word_list(possibilities, guess, &feedback);
        
        free_word_list(possibilities);
        possibilities = next_possibilities;

        if (!possibilities || possibilities->count == 0) {
            break;
        }

        guess = find_best_guess(word_list, possibilities);
    }
    
    printf("Failed to solve.\n");
    if(possibilities) free_word_list(possibilities);
    if (best_entropy_word) free(best_entropy_word);
    printf("\n");
}
