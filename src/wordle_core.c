#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include "wordle_core.h"

// Simple strdup implementation
char* my_strdup(const char* s) {
    size_t len = strlen(s) + 1;
    char* d = malloc(len);
    if (d) strcpy(d, s);
    return d;
}

// Initial capacity for the dynamic word list array.
#define INITIAL_CAPACITY 128

WordList* load_word_list(const char* filepath, int word_len) {
    FILE* file = fopen(filepath, "r");
    if (!file) {
        perror("Failed to open word list file");
        return NULL;
    }

    WordList* list = malloc(sizeof(WordList));
    if (!list) return NULL;

    list->words = malloc(INITIAL_CAPACITY * sizeof(char*));
    if (!list->words) {
        free(list);
        return NULL;
    }
    list->count = 0;
    list->capacity = INITIAL_CAPACITY;
    list->word_len = word_len;

    char buffer[MAX_WORD_LENGTH + 2]; // Buffer for word + newline + null terminator.

    while (fgets(buffer, sizeof(buffer), file)) {
        // Remove trailing newline character.
        buffer[strcspn(buffer, "\r\n")] = 0;

        // Extract the word before any space.
        char* word = strtok(buffer, " ");
        if (word && strlen(word) == word_len) {
            // Resize the array if capacity is reached.
            if (list->count >= list->capacity) {
                list->capacity *= 2;
                char** new_words = realloc(list->words, list->capacity * sizeof(char*));
                if (!new_words) {
                    // On failure, clean up and exit.
                    free_word_list(list);
                    fclose(file);
                    return NULL;
                }
                list->words = new_words;
            }
            list->words[list->count] = my_strdup(word);
            list->count++;
        }
    }

    fclose(file);
    return list;
}

void free_word_list(WordList* list) {
    if (!list) return;
    for (size_t i = 0; i < list->count; i++) {
        free(list->words[i]);
    }
    free(list->words);
    free(list);
}

Feedback get_feedback(const char* guess, const char* solution, int word_len) {
    Feedback feedback;
    feedback.word_len = word_len;
    
    char solution_copy[MAX_WORD_LENGTH + 1];
    strcpy(solution_copy, solution);

    // Initialize all feedback to GRAY.
    for (int i = 0; i < word_len; i++) {
        feedback.pattern[i] = GRAY;
    }

    // First pass: identify all GREEN letters.
    for (int i = 0; i < word_len; i++) {
        if (guess[i] == solution_copy[i]) {
            feedback.pattern[i] = GREEN;
            solution_copy[i] = '_'; // Mark character as used.
        }
    }

    // Second pass: identify all YELLOW letters.
    for (int i = 0; i < word_len; i++) {
        if (feedback.pattern[i] == GREEN) continue;

        for (int j = 0; j < word_len; j++) {
            if (guess[i] == solution_copy[j]) {
                feedback.pattern[i] = YELLOW;
                solution_copy[j] = '_'; // Mark character as used.
                break;
            }
        }
    }
    return feedback;
}

WordList* filter_word_list(const WordList* list, const char* last_guess, const Feedback* feedback) {
    WordList* new_list = malloc(sizeof(WordList));
    if (!new_list) return NULL;

    new_list->words = malloc(list->count * sizeof(char*)); // Allocate for worst-case.
    if (!new_list->words) {
        free(new_list);
        return NULL;
    }

    new_list->count = 0;
    new_list->capacity = list->count;
    new_list->word_len = list->word_len;

    for (size_t i = 0; i < list->count; i++) {
        const char* candidate = list->words[i];
        bool is_match = true;

        Feedback candidate_feedback = get_feedback(last_guess, candidate, list->word_len);

        for (int j = 0; j < list->word_len; j++) {
            if (candidate_feedback.pattern[j] != feedback->pattern[j]) {
                is_match = false;
                break;
            }
        }

        if (is_match) {
            new_list->words[new_list->count++] = my_strdup(candidate);
        }
    }

    return new_list;
}

int count_unique_letters(const char* word, int len) {
    bool seen[26] = {false};
    int count = 0;
    for(int i = 0; i < len; i++) {
        char c = tolower(word[i]);
        if(c >= 'a' && c <= 'z' && !seen[c - 'a']) {
            seen[c - 'a'] = true;
            count++;
        }
    }
    return count;
}

int count_vowels(const char* word, int len) {
    int count = 0;
    for(int i = 0; i < len; i++) {
        char c = tolower(word[i]);
        if(c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
            count++;
        }
    }
    return count;
}

int score_word(const char* word, int len) {
    return count_unique_letters(word, len) * 2 + count_vowels(word, len);
}

const char* find_best_starting_word(const WordList* list) {
    int max_score = -1;
    const char* best = NULL;
    for(size_t i = 0; i < list->count; i++) {
        int score = score_word(list->words[i], list->word_len);
        if(score > max_score) {
            max_score = score;
            best = list->words[i];
        }
    }
    return best ? best : list->words[0];
}

bool is_solved(const Feedback* feedback) {
    for (int i = 0; i < feedback->word_len; i++) {
        if (feedback->pattern[i] != GREEN) {
            return false;
        }
    }
    return true;
}
