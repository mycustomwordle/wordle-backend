#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>
#include <math.h>
#include <sys/stat.h>
#include <strings.h>
#include <cjson/cJSON.h>
#include <curl/curl.h>

// Rate limiting structures
#define MAX_RATE_ENTRIES 1000
typedef struct {
    char ip[INET_ADDRSTRLEN];
    time_t window_start;
    int request_count;
} RateLimitEntry;

RateLimitEntry rate_limits[MAX_RATE_ENTRIES];
pthread_mutex_t rate_limit_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function to get maximum attempts based on word length
int get_max_attempts(int word_length) {
    if (word_length <= 5) return 6;
    else if (word_length == 6) return 7;
    else if (word_length == 7) return 8;
    else return 10; // for 8, 9, 10+
}

// Include backend headers
#include "include/wordle_core.h"
#include "include/solver_fast.h"
#include "include/solver_efficient.h"

char* get_best_entropy_word(int word_length);

// Database connection strings
char *supabase_url = NULL;
char *apikey = NULL;
char *service_key = NULL;
char *cors_origin = NULL;

// Session state structure (loaded from database per request)
typedef struct {
    char session_id[37];
    char game_code[9];
    char secret_word[51];
    int word_length;
    int max_attempts;
    cJSON* guesses;  // JSONB array
    int current_possibilities;
    bool is_won;
    bool is_game_over;
} SessionState;

void init_supabase() {
    supabase_url = getenv("SUPABASE_URL");
    apikey = getenv("PUBLIC_KEY");
    service_key = getenv("SECRET_KEY");
    cors_origin = getenv("FRONTEND_ORIGIN");
    if (!cors_origin) cors_origin = "*";
    if (!supabase_url || !apikey || !service_key) {
        fprintf(stderr, "Supabase env vars not set\n");
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

char* generate_share_code() {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char* code = malloc(9); // 8 chars + null
    srand(time(NULL) ^ (intptr_t)pthread_self()); // Thread-safe random
    for (int i = 0; i < 8; i++) {
        code[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    code[8] = '\0';
    return code;
}

char* generate_session_id() {
    // Generate UUID-like session ID (36 chars)
    char* id = malloc(37);
    if (!id) return NULL;
    srand(time(NULL) ^ (intptr_t)pthread_self());

    unsigned int part1 = (unsigned int)rand();
    unsigned int part2 = (unsigned int)(rand() & 0xFFFF);
    unsigned int part3 = (unsigned int)(rand() & 0xFFFF);
    unsigned int part4 = (unsigned int)(rand() & 0xFFFF);
    unsigned long long part5 = (((unsigned long long)rand() << 32) | (unsigned long long)rand()) & 0x0000FFFFFFFFFFFFULL;

    snprintf(id, 37, "%08x-%04x-%04x-%04x-%012llx",
             part1,
             part2,
             part3,
             part4,
             part5);
    id[36] = '\0';
    return id;
}

struct MemoryStruct {
    char *memory;
    size_t size;
};

size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    if (mem->size + realsize >= 16384) return 0; // overflow
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

// Create a new game in shared_games_v2
bool create_shared_game(const char* game_code, const char* secret_word, int word_length, int max_attempts) {
    if (!supabase_url || !service_key) return false;
    
    CURL *curl = curl_easy_init();
    if (!curl) return false;
    
    char url[512];
    snprintf(url, sizeof(url), "%s/rest/v1/shared_games_v2", supabase_url);
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Prefer: return=minimal");
    char auth[512];
    snprintf(auth, sizeof(auth), "Authorization: Bearer %s", service_key);
    headers = curl_slist_append(headers, auth);
    char key[512];
    snprintf(key, sizeof(key), "apikey: %s", apikey);
    headers = curl_slist_append(headers, key);
    
    time_t now = time(NULL);
    time_t exp = now + 86400; // 24 hours
    char created[32], expires[32];
    strftime(created, sizeof(created), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    strftime(expires, sizeof(expires), "%Y-%m-%dT%H:%M:%SZ", gmtime(&exp));
    
    char body[1024];
    snprintf(body, sizeof(body), 
             "{\"game_code\":\"%s\",\"secret_word\":\"%s\",\"word_length\":%d,\"max_attempts\":%d,\"created_at\":\"%s\",\"expires_at\":\"%s\"}",
             game_code, secret_word, word_length, max_attempts, created, expires);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    CURLcode res = curl_easy_perform(curl);
    bool success = (res == CURLE_OK);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success;
}

// Create a new player session
bool create_player_session(const char* session_id, const char* game_code, int possibilities) {
    if (!supabase_url || !service_key) return false;
    
    CURL *curl = curl_easy_init();
    if (!curl) return false;
    
    char url[512];
    snprintf(url, sizeof(url), "%s/rest/v1/player_sessions", supabase_url);
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Prefer: return=minimal");
    char auth[512];
    snprintf(auth, sizeof(auth), "Authorization: Bearer %s", service_key);
    headers = curl_slist_append(headers, auth);
    char key[512];
    snprintf(key, sizeof(key), "apikey: %s", apikey);
    headers = curl_slist_append(headers, key);
    
    char body[1024];
    snprintf(body, sizeof(body), 
             "{\"session_id\":\"%s\",\"game_code\":\"%s\",\"current_possibilities\":%d,\"guesses\":[]}",
             session_id, game_code, possibilities);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    CURLcode res = curl_easy_perform(curl);
    bool success = (res == CURLE_OK);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success;
}

// Load session state from database (uses complete_game_state view)
SessionState* load_session_state(const char* session_id) {
    if (!supabase_url || !apikey) return NULL;
    
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    
    char url[512];
    snprintf(url, sizeof(url), "%s/rest/v1/complete_game_state?session_id=eq.%s&select=*", 
             supabase_url, session_id);
    
    struct curl_slist *headers = NULL;
    char key[512];
    snprintf(key, sizeof(key), "apikey: %s", apikey);
    headers = curl_slist_append(headers, key);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    struct MemoryStruct chunk = {0};
    chunk.memory = malloc(16384);
    if (!chunk.memory) {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return NULL;
    }
    chunk.size = 0;
    
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        free(chunk.memory);
        return NULL;
    }
    
    cJSON *json = cJSON_Parse(chunk.memory);
    free(chunk.memory);
    
    if (!json || !cJSON_IsArray(json) || cJSON_GetArraySize(json) == 0) {
        if (json) cJSON_Delete(json);
        return NULL;
    }
    
    cJSON *item = cJSON_GetArrayItem(json, 0);
    
    SessionState* state = malloc(sizeof(SessionState));
    memset(state, 0, sizeof(SessionState));
    
    cJSON *session_id_json = cJSON_GetObjectItem(item, "session_id");
    cJSON *share_code = cJSON_GetObjectItem(item, "share_code");
    cJSON *secret = cJSON_GetObjectItem(item, "secret_word");
    cJSON *wlen = cJSON_GetObjectItem(item, "word_length");
    cJSON *maxatt = cJSON_GetObjectItem(item, "max_attempts");
    cJSON *guesses = cJSON_GetObjectItem(item, "guesses");
    cJSON *poss = cJSON_GetObjectItem(item, "possibilities");
    cJSON *won = cJSON_GetObjectItem(item, "is_won");
    cJSON *over = cJSON_GetObjectItem(item, "is_game_over");
    
    if (session_id_json) strncpy(state->session_id, session_id_json->valuestring, 36);
    if (share_code) strncpy(state->game_code, share_code->valuestring, 8);
    if (secret) strncpy(state->secret_word, secret->valuestring, 50);
    if (wlen) state->word_length = wlen->valueint;
    if (maxatt) state->max_attempts = maxatt->valueint;
    if (poss && !cJSON_IsNull(poss)) state->current_possibilities = poss->valueint;
    if (won) state->is_won = cJSON_IsTrue(won);
    if (over) state->is_game_over = cJSON_IsTrue(over);
    
    // Clone guesses array
    if (guesses && cJSON_IsArray(guesses)) {
        state->guesses = cJSON_Duplicate(guesses, 1);
    } else {
        state->guesses = cJSON_CreateArray();
    }
    
    cJSON_Delete(json);
    return state;
}

// Update player session in database
bool update_player_session(const char* session_id, cJSON* guesses, int possibilities, bool is_won, bool is_game_over) {
    if (!supabase_url || !service_key) return false;
    
    CURL *curl = curl_easy_init();
    if (!curl) return false;
    
    char url[512];
    snprintf(url, sizeof(url), "%s/rest/v1/player_sessions?session_id=eq.%s", 
             supabase_url, session_id);
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Prefer: return=minimal");
    char auth[512];
    snprintf(auth, sizeof(auth), "Authorization: Bearer %s", service_key);
    headers = curl_slist_append(headers, auth);
    char key[512];
    snprintf(key, sizeof(key), "apikey: %s", apikey);
    headers = curl_slist_append(headers, key);
    
    char* guesses_str = cJSON_PrintUnformatted(guesses);
    char body[8192];
    snprintf(body, sizeof(body), 
             "{\"guesses\":%s,\"current_possibilities\":%d,\"is_won\":%s,\"is_game_over\":%s}",
             guesses_str, possibilities, is_won ? "true" : "false", is_game_over ? "true" : "false");
    free(guesses_str);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    CURLcode res = curl_easy_perform(curl);
    bool success = (res == CURLE_OK);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success;
}

// Get game info by game_code
cJSON* get_game_by_code(const char* game_code) {
    if (!supabase_url || !apikey) return NULL;
    
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    
    char url[512];
    snprintf(url, sizeof(url), "%s/rest/v1/shared_games_v2?game_code=eq.%s", 
             supabase_url, game_code);
    
    struct curl_slist *headers = NULL;
    char key[512];
    snprintf(key, sizeof(key), "apikey: %s", apikey);
    headers = curl_slist_append(headers, key);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    struct MemoryStruct chunk = {0};
    chunk.memory = malloc(16384);
    if (!chunk.memory) {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return NULL;
    }
    chunk.size = 0;
    
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        free(chunk.memory);
        return NULL;
    }
    
    cJSON *json = cJSON_Parse(chunk.memory);
    free(chunk.memory);
    
    if (!json || !cJSON_IsArray(json) || cJSON_GetArraySize(json) == 0) {
        if (json) cJSON_Delete(json);
        return NULL;
    }
    
    cJSON *item = cJSON_GetArrayItem(json, 0);
    cJSON *result = cJSON_Duplicate(item, 1);
    cJSON_Delete(json);
    return result;
}

void free_session_state(SessionState* state) {
    if (!state) return;
    if (state->guesses) cJSON_Delete(state->guesses);
    free(state);
}

static void url_decode(char* str) {
    if (!str) return;
    char* src = str;
    char* dest = str;
    while (*src) {
        if (*src == '+') {
            *dest++ = ' ';
            src++;
        } else if (*src == '%' && isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2])) {
            char hex[3] = { src[1], src[2], '\0' };
            *dest++ = (char)strtol(hex, NULL, 16);
            src += 3;
        } else {
            *dest++ = *src++;
        }
    }
    *dest = '\0';
}

static void to_lowercase(char* str) {
    if (!str) return;
    for (char* p = str; *p; ++p) {
        *p = (char)tolower((unsigned char)*p);
    }
}

static bool is_alpha_string(const char* str) {
    if (!str || !*str) return false;
    for (const char* p = str; *p; ++p) {
        if (!isalpha((unsigned char)*p)) {
            return false;
        }
    }
    return true;
}

static bool is_word_in_list(const WordList* list, const char* word) {
    if (!list || !word) return false;
    for (size_t i = 0; i < list->count; ++i) {
        if (strcmp(list->words[i], word) == 0) {
            return true;
        }
    }
    return false;
}

static WordList* clone_word_list(const WordList* source) {
    if (!source) return NULL;

    WordList* copy = malloc(sizeof(WordList));
    if (!copy) return NULL;

    copy->words = malloc(source->count * sizeof(char*));
    if (!copy->words) {
        free(copy);
        return NULL;
    }

    copy->count = source->count;
    copy->capacity = source->count;
    copy->word_len = source->word_len;

    for (size_t i = 0; i < source->count; ++i) {
        copy->words[i] = my_strdup(source->words[i]);
        if (!copy->words[i]) {
            for (size_t j = 0; j < i; ++j) {
                free(copy->words[j]);
            }
            free(copy->words);
            free(copy);
            return NULL;
        }
    }

    return copy;
}

static bool fill_feedback_from_json(cJSON* feedback_array, Feedback* out_feedback, int word_len) {
    if (!feedback_array || !out_feedback || !cJSON_IsArray(feedback_array)) return false;

    out_feedback->word_len = word_len;
    for (int i = 0; i < word_len; ++i) {
        cJSON* item = cJSON_GetArrayItem(feedback_array, i);
        const char* color = item ? cJSON_GetStringValue(item) : NULL;
        if (color && strcasecmp(color, "green") == 0) {
            out_feedback->pattern[i] = GREEN;
        } else if (color && strcasecmp(color, "yellow") == 0) {
            out_feedback->pattern[i] = YELLOW;
        } else {
            out_feedback->pattern[i] = GRAY;
        }
    }
    return true;
}

static void uppercase_copy(const char* src, char* dest, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        dest[i] = (char)toupper((unsigned char)src[i]);
    }
    dest[len] = '\0';
}

static void lowercase_copy(const char* src, char* dest, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        dest[i] = (char)tolower((unsigned char)src[i]);
    }
    dest[len] = '\0';
}

// Function to pick random word from possibilities
char* pick_random_word(WordList* list) {
    if (!list || list->count == 0) return NULL;
    srand(time(NULL));
    int index = rand() % list->count;
    return my_strdup(list->words[index]);
}

// Function to get words starting with prefix
WordList* get_words_starting_with_prefix(const char* prefix, int len) {
    char filepath[256];
    sprintf(filepath, "data/numbered/count%d.txt", len);
    WordList* all = load_word_list(filepath, len);
    if (!all) return NULL;
    WordList* filtered = malloc(sizeof(WordList));
    filtered->words = malloc(all->count * sizeof(char*));
    filtered->count = 0;
    filtered->capacity = all->count;
    filtered->word_len = len;
    int prefix_len = strlen(prefix);
    for (size_t i = 0; i < all->count; i++) {
        if (strncmp(all->words[i], prefix, prefix_len) == 0) {
            filtered->words[filtered->count++] = my_strdup(all->words[i]);
        }
    }
    free_word_list(all);
    return filtered;
}

// Parameter parsing helpers
static char* extract_param_value(const char* body, const char* param_name) {
    if (!body || !param_name) return NULL;
    
    char search[64];
    snprintf(search, sizeof(search), "%s=", param_name);
    const char* start = strstr(body, search);
    if (!start) return NULL;
    
    start += strlen(search);
    const char* end = strchr(start, '&');
    size_t len = end ? (size_t)(end - start) : strlen(start);
    
    char* value = malloc(len + 1);
    if (!value) return NULL;
    strncpy(value, start, len);
    value[len] = '\0';
    
    url_decode(value);
    return value;
}

static bool parse_session_id(const char* body_or_query, char* out, size_t out_size) {
    char* value = extract_param_value(body_or_query, "session_id");
    if (!value) {
        // Try sessionId as well
        value = extract_param_value(body_or_query, "sessionId");
    }
    if (!value) return false;
    
    // Validate UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars)
    if (strlen(value) != 36) {
        free(value);
        return false;
    }
    // Check dashes at positions 8,13,18,23
    if (value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-') {
        free(value);
        return false;
    }
    // Check that all other characters are hex digits
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) continue;
        if (!isxdigit((unsigned char)value[i])) {
            free(value);
            return false;
        }
    }
    
    strncpy(out, value, out_size - 1);
    out[out_size - 1] = '\0';
    free(value);
    return true;
}

static bool parse_game_code(const char* body, char* out, size_t out_size) {
    // Try JSON first
    cJSON* json = cJSON_Parse(body);
    if (json) {
        cJSON* code = cJSON_GetObjectItem(json, "code");
        if (code && cJSON_IsString(code)) {
            strncpy(out, code->valuestring, out_size - 1);
            out[out_size - 1] = '\0';
            cJSON_Delete(json);
            // Validate game code format: 8 uppercase alphanumeric characters
            if (strlen(out) != 8) return false;
            for (int i = 0; i < 8; i++) {
                if (!isalnum((unsigned char)out[i]) || !isupper((unsigned char)out[i])) {
                    return false;
                }
            }
            return true;
        }
        cJSON_Delete(json);
    }
    
    // Try form-encoded
    char* value = extract_param_value(body, "code");
    if (!value) {
        value = extract_param_value(body, "game_code");
    }
    if (!value) return false;
    
    // Validate game code format: 8 uppercase alphanumeric characters
    if (strlen(value) != 8) {
        free(value);
        return false;
    }
    for (int i = 0; i < 8; i++) {
        if (!isalnum((unsigned char)value[i]) || !isupper((unsigned char)value[i])) {
            free(value);
            return false;
        }
    }
    
    strncpy(out, value, out_size - 1);
    out[out_size - 1] = '\0';
    free(value);
    return true;
}

// HTTP response helpers

#include "wordle_core.h"

static const char* get_status_text(int status_code) {
    switch (status_code) {
        case 200: return "200 OK";
        case 201: return "201 Created";
        case 204: return "204 No Content";
        case 400: return "400 Bad Request";
        case 404: return "404 Not Found";
        case 405: return "405 Method Not Allowed";
        case 429: return "429 Too Many Requests";
        case 501: return "501 Not Implemented";
        default: return "500 Internal Server Error";
    }
}

static void send_json_response(int client_socket, int status_code, const char* body) {
    if (!body) {
        body = "{}";
    }
    size_t body_len = strlen(body);
    char header[1024];  // Increased buffer size for safety
    int header_len = snprintf(header, sizeof(header),
             "HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nAccess-Control-Allow-Origin: %s\r\nAccess-Control-Allow-Headers: Content-Type\r\nAccess-Control-Allow-Methods: GET,POST,OPTIONS\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nConnection: close\r\n\r\n",
             get_status_text(status_code), body_len, cors_origin);
    if (header_len >= sizeof(header)) {
        // Header too long, send error
        const char* error_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
        send(client_socket, error_response, strlen(error_response), 0);
        return;
    }
    send(client_socket, header, header_len, 0);
    if (body_len > 0) {
        send(client_socket, body, body_len, 0);
    }
}

static void send_method_not_allowed(int client_socket) {
    send_json_response(client_socket, 405, "{\"error\":\"Method not allowed\"}");
}

static void send_not_found(int client_socket) {
    send_json_response(client_socket, 404, "{\"error\":\"Not found\"}");
}

static void send_bad_request(int client_socket, const char* message) {
    char buffer[512];
    snprintf(buffer, sizeof(buffer), "{\"error\":\"%s\"}", message ? message : "Bad request");
    send_json_response(client_socket, 400, buffer);
}

static void send_options_response(int client_socket) {
    char response[512];
    int len = snprintf(response, sizeof(response),
             "HTTP/1.1 204 No Content\r\n"
             "Allow: GET,POST,OPTIONS\r\n"
             "Access-Control-Allow-Origin: %s\r\n"
             "Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n"
             "Access-Control-Allow-Headers: Content-Type\r\n"
             "X-Content-Type-Options: nosniff\r\n"
             "X-Frame-Options: DENY\r\n"
             "Connection: close\r\n\r\n", cors_origin);
    if (len >= sizeof(response)) {
        const char* error = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
        send(client_socket, error, strlen(error), 0);
        return;
    }
    send(client_socket, response, len, 0);
}

static char* json_escape(const char* input) {
    if (!input) {
        return my_strdup("");
    }

    size_t extra = 0;
    for (const char* p = input; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            extra++;
        } else if (*p == '\n' || *p == '\r' || *p == '\t') {
            extra++;
        }
    }

    size_t len = strlen(input);
    char* escaped = malloc(len + extra + 1);
    if (!escaped) {
        return my_strdup("");
    }

    char* dest = escaped;
    for (const char* p = input; *p; ++p) {
        if (*p == '"') {
            *dest++ = '\\';
            *dest++ = '"';
        } else if (*p == '\\') {
            *dest++ = '\\';
            *dest++ = '\\';
        } else if (*p == '\n') {
            *dest++ = '\\';
            *dest++ = 'n';
        } else if (*p == '\r') {
            *dest++ = '\\';
            *dest++ = 'r';
        } else if (*p == '\t') {
            *dest++ = '\\';
            *dest++ = 't';
        } else {
            *dest++ = *p;
        }
    }
    *dest = '\0';
    return escaped;
}

// Build JSON response from session state
static char* build_response_from_session(SessionState* state, const char* error_msg) {
    cJSON* response = cJSON_CreateObject();
    
    if (state) {
        cJSON_AddStringToObject(response, "sessionId", state->session_id);
        cJSON_AddStringToObject(response, "shareCode", state->game_code);
        cJSON_AddBoolToObject(response, "gameActive", true);
        cJSON_AddBoolToObject(response, "isGameOver", state->is_game_over);
        cJSON_AddBoolToObject(response, "isWon", state->is_won);
        cJSON_AddNumberToObject(response, "wordLength", state->word_length);
        cJSON_AddNumberToObject(response, "maxAttempts", state->max_attempts);
        cJSON_AddNumberToObject(response, "possibilities", state->current_possibilities);
        cJSON_AddStringToObject(response, "error", error_msg ? error_msg : "");
        
        // Add guesses array (convert to uppercase for display)
        cJSON* guesses_out = cJSON_CreateArray();
        if (state->guesses && cJSON_IsArray(state->guesses)) {
            int count = cJSON_GetArraySize(state->guesses);
            for (int i = 0; i < count; i++) {
                cJSON* guess = cJSON_GetArrayItem(state->guesses, i);
                cJSON* word_obj = cJSON_GetObjectItem(guess, "word");
                if (word_obj && cJSON_IsString(word_obj)) {
                    // Convert to uppercase for display
                    char upper_word[MAX_WORD_LENGTH + 1];
                    const char* w = word_obj->valuestring;
                    for (int j = 0; j < MAX_WORD_LENGTH && w[j]; j++) {
                        upper_word[j] = toupper((unsigned char)w[j]);
                    }
                    upper_word[strlen(w)] = '\0';
                    
                    cJSON* guess_out = cJSON_CreateObject();
                    cJSON_AddStringToObject(guess_out, "word", upper_word);
                    cJSON* feedback = cJSON_GetObjectItem(guess, "feedback");
                    if (feedback) {
                        cJSON_AddItemToObject(guess_out, "feedback", cJSON_Duplicate(feedback, 1));
                    }
                    cJSON_AddItemToArray(guesses_out, guess_out);
                }
            }
        }
        cJSON_AddItemToObject(response, "guesses", guesses_out);
        
        // Secret word (null unless game over)
        if (state->is_game_over && state->secret_word[0]) {
            cJSON_AddStringToObject(response, "secretWord", state->secret_word);
        } else {
            cJSON_AddNullToObject(response, "secretWord");
        }
        
        int guesses_count = state->guesses ? cJSON_GetArraySize(state->guesses) : 0;
        int remaining = state->max_attempts - guesses_count;
        cJSON_AddNumberToObject(response, "remainingAttempts", remaining > 0 ? remaining : 0);
    } else {
        cJSON_AddBoolToObject(response, "gameActive", false);
        cJSON_AddBoolToObject(response, "isGameOver", false);
        cJSON_AddBoolToObject(response, "isWon", false);
        cJSON_AddStringToObject(response, "error", error_msg ? error_msg : "No active session");
        cJSON_AddNumberToObject(response, "wordLength", 5);
        cJSON_AddNumberToObject(response, "maxAttempts", 6);
        cJSON_AddNumberToObject(response, "possibilities", 0);
        cJSON_AddItemToObject(response, "guesses", cJSON_CreateArray());
        cJSON_AddNullToObject(response, "secretWord");
        cJSON_AddNumberToObject(response, "remainingAttempts", 6);
    }
    
    char* json_str = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);
    return json_str;
}

// Copy from solver_efficient.c
// For words <= 6 letters, use fixed size array (3^6 = 729)
// For longer words, use a simpler heuristic-based approach
#define MAX_PATTERNS_SMALL 729

// Structure for pattern counting in longer words
typedef struct {
    int* patterns;
    int* counts;
    int size;
    int capacity;
} PatternMap;

static int pattern_to_int(const Feedback* feedback) {
    int index = 0;
    int power_of_3 = 1;
    for (int i = 0; i < feedback->word_len; i++) {
        index += feedback->pattern[i] * power_of_3;
        power_of_3 *= 3;
    }
    return index;
}

static double calculate_entropy(const char* guess, const WordList* possibilities) {
    int word_len = possibilities->word_len;
    
    // For longer words, use a simplified approach - just count unique patterns
    if (word_len > 6) {
        // Use a dynamic pattern map
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
        // For shorter words, use the fast array-based approach
        int pattern_counts[MAX_PATTERNS_SMALL] = {0};
        
        for (size_t i = 0; i < possibilities->count; i++) {
            const char* candidate = possibilities->words[i];
            Feedback feedback = get_feedback(guess, candidate, word_len);
            int index = pattern_to_int(&feedback);
            if (index < MAX_PATTERNS_SMALL) {
                pattern_counts[index]++;
            }
        }

        double entropy = 0.0;
        for (int i = 0; i < MAX_PATTERNS_SMALL; i++) {
            if (pattern_counts[i] > 0) {
                double p = (double)pattern_counts[i] / possibilities->count;
                entropy -= p * (log(p) / log(2.0));
            }
        }
        return entropy;
    }
}

static const char* find_best_guess(const WordList* full_dictionary, const WordList* possibilities) {
    if (possibilities->count == 1) {
        return possibilities->words[0];
    }
    
    if (possibilities->count == 2) {
        return possibilities->words[0];
    }

    double max_entropy = -1.0;
    const char* best_guess = NULL;

    const WordList* search_list = (possibilities->count <= 5) ? possibilities : full_dictionary;
    size_t max_candidates = (search_list == full_dictionary && search_list->count > 100) ? 100 : search_list->count;

    for (size_t i = 0; i < max_candidates; i++) {
        const char* current_guess = search_list->words[i];
        double entropy = calculate_entropy(current_guess, possibilities);

        if (entropy > max_entropy) {
            max_entropy = entropy;
            best_guess = current_guess;
        }
    }
    return best_guess ? best_guess : possibilities->words[0];
}

// Rate limiting function
bool check_rate_limit(const char* client_ip) {
    time_t now = time(NULL);
    int window_seconds = 60; // 1 minute window
    int max_requests = 100; // Max requests per window

    pthread_mutex_lock(&rate_limit_mutex);

    // Find or create entry for this IP
    int entry_index = -1;
    for (int i = 0; i < MAX_RATE_ENTRIES; i++) {
        if (rate_limits[i].ip[0] == '\0' || strcmp(rate_limits[i].ip, client_ip) == 0) {
            entry_index = i;
            break;
        }
    }

    if (entry_index == -1) {
        // No space, allow request (fail open)
        pthread_mutex_unlock(&rate_limit_mutex);
        return true;
    }

    RateLimitEntry* entry = &rate_limits[entry_index];

    if (entry->ip[0] == '\0') {
        // New entry
        strncpy(entry->ip, client_ip, INET_ADDRSTRLEN - 1);
        entry->window_start = now;
        entry->request_count = 1;
        pthread_mutex_unlock(&rate_limit_mutex);
        return true;
    }

    // Check if window has expired
    if (now - entry->window_start >= window_seconds) {
        entry->window_start = now;
        entry->request_count = 1;
        pthread_mutex_unlock(&rate_limit_mutex);
        return true;
    }

    // Check request count
    if (entry->request_count >= max_requests) {
        pthread_mutex_unlock(&rate_limit_mutex);
        return false;
    }

    entry->request_count++;
    pthread_mutex_unlock(&rate_limit_mutex);
    return true;
}

// Handle requests
void handle_request(int client_socket, char* request) {
    char method[16];  // Increased size
    char uri[1024];   // Increased size

    if (sscanf(request, "%15s %1023s", method, uri) != 2) {
        send_bad_request(client_socket, "Malformed request");
        return;
    }

    // Validate method
    if (strlen(method) >= sizeof(method) - 1) {
        send_bad_request(client_socket, "Method too long");
        return;
    }

    // Validate URI
    if (strlen(uri) >= sizeof(uri) - 1) {
        send_bad_request(client_socket, "URI too long");
        return;
    }

    if (strcmp(method, "OPTIONS") == 0) {
        send_options_response(client_socket);
        return;
    }

    char* body = strstr(request, "\r\n\r\n");
    if (body) {
        body += 4;
        // Limit body size to prevent DoS
        if (strlen(body) > 8192) {  // 8KB limit
            send_bad_request(client_socket, "Request body too large");
            return;
        }
    }

    char* query = NULL;
    char* path = uri;
    char* question = strchr(uri, '?');
    if (question) {
        *question = '\0';
        query = question + 1;
    }

    if (strcmp(path, "/api/state") == 0) {
        if (strcmp(method, "GET") != 0) {
            send_method_not_allowed(client_socket);
            return;
        }
        
        // Parse session_id from query string
        char session_id[37] = "";
        if (query && !parse_session_id(query, session_id, sizeof(session_id))) {
            send_json_response(client_socket, 200, "{\"gameActive\":false,\"error\":\"No session ID\"}");
            return;
        }
        
        if (!session_id[0]) {
            send_json_response(client_socket, 200, "{\"gameActive\":false}");
            return;
        }
        
        // Load session
        SessionState* state = load_session_state(session_id);
        if (!state) {
            send_json_response(client_socket, 404, "{\"error\":\"Session not found\",\"gameActive\":false}");
            return;
        }
        
        char* response = build_response_from_session(state, NULL);
        send_json_response(client_socket, 200, response);
        
        free(response);
        free_session_state(state);
        return;
    } else if (strcmp(path, "/api/reset") == 0) {
        if (strcmp(method, "POST") != 0) {
            send_method_not_allowed(client_socket);
            return;
        }
        // Just return empty state - frontend will clear localStorage
        send_json_response(client_socket, 200, "{\"gameActive\":false,\"error\":\"\"}");
        return;
    } else if (strcmp(path, "/api/start") == 0) {
        if (strcmp(method, "POST") != 0) {
            send_method_not_allowed(client_socket);
            return;
        }
        if (!body) {
            send_bad_request(client_socket, "Missing request body");
            return;
        }

        // Parse parameters
        char body_copy[512];
        strncpy(body_copy, body, sizeof(body_copy) - 1);
        body_copy[sizeof(body_copy) - 1] = '\0';

        int word_length = 5;
        char word_param[64] = "";
        int max_attempts = -1;
        char* saveptr = NULL;
        char* token = strtok_r(body_copy, "&", &saveptr);
        while (token) {
            if (strncmp(token, "length=", 7) == 0) {
                word_length = atoi(token + 7);
            } else if (strncmp(token, "word=", 5) == 0) {
                strncpy(word_param, token + 5, sizeof(word_param) - 1);
            } else if (strncmp(token, "attempts=", 9) == 0) {
                max_attempts = atoi(token + 9);
            }
            token = strtok_r(NULL, "&", &saveptr);
        }

        url_decode(word_param);
        to_lowercase(word_param);

        // Validate parameters
        if (word_length < 3 || word_length > MAX_WORD_LENGTH) {
            send_bad_request(client_socket, "Invalid word length");
            return;
        }

        if (max_attempts < 1) {
            max_attempts = get_max_attempts(word_length);
        }

        // Load dictionary
        char filepath[256];
        snprintf(filepath, sizeof(filepath), "data/numbered/count%d.txt", word_length);
        WordList* dict = load_word_list(filepath, word_length);
        
        if (!dict) {
            send_bad_request(client_socket, "Unable to load dictionary");
            return;
        }

        // Validate word
        if ((int)strlen(word_param) != word_length) {
            char error[128];
            snprintf(error, sizeof(error), "Word must be %d letters", word_length);
            send_bad_request(client_socket, error);
            free_word_list(dict);
            return;
        }

        if (!is_word_in_list(dict, word_param)) {
            char error[128];
            snprintf(error, sizeof(error), "'%s' is not in the word list", word_param);
            send_bad_request(client_socket, error);
            free_word_list(dict);
            return;
        }

        int possibilities = dict->count;
        free_word_list(dict);

        // Generate IDs
        char* game_code = generate_share_code();
        char* session_id = generate_session_id();
        
        // Create game in database
        if (!create_shared_game(game_code, word_param, word_length, max_attempts)) {
            send_bad_request(client_socket, "Failed to create game");
            free(game_code);
            free(session_id);
            return;
        }
        
        // Create player session
        if (!create_player_session(session_id, game_code, possibilities)) {
            send_bad_request(client_socket, "Failed to create session");
            free(game_code);
            free(session_id);
            return;
        }
        
    printf("Created game: %s (session: %s)\n", game_code, session_id);
        fflush(stdout);
        
        // Build response directly without reloading from database
        // (Database write may have replication delay)
        cJSON* response_json = cJSON_CreateObject();
        cJSON_AddStringToObject(response_json, "sessionId", session_id);
        cJSON_AddStringToObject(response_json, "shareCode", game_code);
        cJSON_AddBoolToObject(response_json, "gameActive", true);
        cJSON_AddBoolToObject(response_json, "isGameOver", false);
        cJSON_AddBoolToObject(response_json, "isWon", false);
        cJSON_AddNumberToObject(response_json, "wordLength", word_length);
        cJSON_AddNumberToObject(response_json, "maxAttempts", max_attempts);
        cJSON_AddNumberToObject(response_json, "possibilities", possibilities);
        cJSON_AddStringToObject(response_json, "error", "");
        cJSON_AddItemToObject(response_json, "guesses", cJSON_CreateArray());
        cJSON_AddNullToObject(response_json, "secretWord");
        cJSON_AddNumberToObject(response_json, "remainingAttempts", max_attempts);
        
        char* response = cJSON_PrintUnformatted(response_json);
        cJSON_Delete(response_json);
        send_json_response(client_socket, 200, response);
        
    free(response);
    free(game_code);
    free(session_id);
        return;
    } else if (strcmp(path, "/api/guess") == 0) {
        if (strcmp(method, "POST") != 0) {
            send_method_not_allowed(client_socket);
            return;
        }
        if (!body) {
            send_bad_request(client_socket, "Missing request body");
            return;
        }

        // Parse session_id and guess from body
        char body_copy[512];
        strncpy(body_copy, body, sizeof(body_copy) - 1);
        body_copy[sizeof(body_copy) - 1] = '\0';

        char session_id[37] = "";
        char guess_raw[64] = "";
        
        char* saveptr = NULL;
        char* token = strtok_r(body_copy, "&", &saveptr);
        while (token) {
            if (strncmp(token, "session_id=", 11) == 0) {
                strncpy(session_id, token + 11, sizeof(session_id) - 1);
            } else if (strncmp(token, "guess=", 6) == 0) {
                strncpy(guess_raw, token + 6, sizeof(guess_raw) - 1);
            }
            token = strtok_r(NULL, "&", &saveptr);
        }

        url_decode(session_id);
        url_decode(guess_raw);

        if (!session_id[0]) {
            send_bad_request(client_socket, "Missing session_id");
            return;
        }

        // Trim and lowercase guess
        char* trimmed = guess_raw;
        while (*trimmed && isspace((unsigned char)*trimmed)) trimmed++;
        char* end = trimmed + strlen(trimmed);
        while (end > trimmed && isspace((unsigned char)*(end - 1))) end--;
        *end = '\0';

        char guess[64] = "";
        strncpy(guess, trimmed, sizeof(guess) - 1);
        to_lowercase(guess);

        // Load session
        SessionState* state = load_session_state(session_id);
        if (!state) {
            send_bad_request(client_socket, "Session not found");
            return;
        }

        // Check if game is over
        if (state->is_game_over) {
            char* response = build_response_from_session(state, "Game is already over");
            send_json_response(client_socket, 200, response);
            free(response);
            free_session_state(state);
            return;
        }

        // Load dictionary
        char filepath[256];
        snprintf(filepath, sizeof(filepath), "data/numbered/count%d.txt", state->word_length);
        WordList* dict = load_word_list(filepath, state->word_length);
        if (!dict) {
            char* response = build_response_from_session(state, "Failed to load dictionary");
            send_json_response(client_socket, 200, response);
            free(response);
            free_session_state(state);
            return;
        }

        // Validate guess
        if (strlen(guess) != (size_t)state->word_length) {
            char error[128];
            snprintf(error, sizeof(error), "Guess must be %d letters", state->word_length);
            char* response = build_response_from_session(state, error);
            send_json_response(client_socket, 200, response);
            free(response);
            free_session_state(state);
            free_word_list(dict);
            return;
        }

        if (!is_alpha_string(guess)) {
            char* response = build_response_from_session(state, "Use letters only");
            send_json_response(client_socket, 200, response);
            free(response);
            free_session_state(state);
            free_word_list(dict);
            return;
        }

        if (!is_word_in_list(dict, guess)) {
            char error[128];
            char upper_guess[64];
            strncpy(upper_guess, guess, sizeof(upper_guess) - 1);
            for (size_t i = 0; upper_guess[i]; i++) {
                upper_guess[i] = toupper((unsigned char)upper_guess[i]);
            }
            snprintf(error, sizeof(error), "'%s' is not in the word list", upper_guess);
            char* response = build_response_from_session(state, error);
            send_json_response(client_socket, 200, response);
            free(response);
            free_session_state(state);
            free_word_list(dict);
            return;
        }

        // Get feedback
        Feedback feedback = get_feedback(guess, state->secret_word, state->word_length);

        // Create guess object
        cJSON* guess_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(guess_obj, "word", guess);
        cJSON* feedback_array = cJSON_CreateArray();
        for (int i = 0; i < state->word_length; i++) {
            const char* color = feedback.pattern[i] == GREEN ? "green" :
                               feedback.pattern[i] == YELLOW ? "yellow" : "grey";
            cJSON_AddItemToArray(feedback_array, cJSON_CreateString(color));
        }
        cJSON_AddItemToObject(guess_obj, "feedback", feedback_array);

        // Add to guesses array
        cJSON_AddItemToArray(state->guesses, guess_obj);

        // Filter possibilities
        WordList* filtered = filter_word_list(dict, guess, &feedback);
        state->current_possibilities = filtered ? filtered->count : 0;

        // Check win condition
        state->is_won = is_solved(&feedback);
        state->is_game_over = state->is_won || 
                              (cJSON_GetArraySize(state->guesses) >= state->max_attempts);

        // Update database
        update_player_session(session_id, state->guesses, state->current_possibilities,
                             state->is_won, state->is_game_over);

        printf("Guess processed: %s -> %d possibilities\n", guess, state->current_possibilities);
        fflush(stdout);

        // Return updated state
        char* response = build_response_from_session(state, NULL);
        send_json_response(client_socket, 200, response);

        free(response);
        free_session_state(state);
        free_word_list(dict);
        if (filtered) free_word_list(filtered);
        return;
    } else if (strcmp(path, "/api/solve") == 0) {
        if (strcmp(method, "POST") != 0) {
            send_method_not_allowed(client_socket);
            return;
        }
        if (!body) {
            send_bad_request(client_socket, "Missing request body");
            return;
        }

        char body_copy[512];
        strncpy(body_copy, body, sizeof(body_copy) - 1);
        body_copy[sizeof(body_copy) - 1] = '\0';

        char solver_type[32] = "";
        char session_id[37] = "";

        char* saveptr = NULL;
        char* token = strtok_r(body_copy, "&", &saveptr);
        while (token) {
            if (strncmp(token, "type=", 5) == 0) {
                strncpy(solver_type, token + 5, sizeof(solver_type) - 1);
            } else if (strncmp(token, "session_id=", 11) == 0) {
                strncpy(session_id, token + 11, sizeof(session_id) - 1);
            }
            token = strtok_r(NULL, "&", &saveptr);
        }

        url_decode(solver_type);
        url_decode(session_id);
        to_lowercase(solver_type);

        if (!solver_type[0]) {
            send_bad_request(client_socket, "Missing solver type");
            return;
        }
        if (strcmp(solver_type, "fast") != 0 && strcmp(solver_type, "efficient") != 0) {
            send_bad_request(client_socket, "Unknown solver type");
            return;
        }

        if (!session_id[0] && !parse_session_id(body, session_id, sizeof(session_id))) {
            send_bad_request(client_socket, "Missing session_id");
            return;
        }

        SessionState* state = load_session_state(session_id);
        if (!state) {
            send_bad_request(client_socket, "Session not found");
            return;
        }

        if (!state->secret_word[0]) {
            char* response = build_response_from_session(state, "Secret word unavailable");
            send_json_response(client_socket, 500, response);
            free(response);
            free_session_state(state);
            return;
        }

        if (state->is_game_over) {
            cJSON* payload = cJSON_CreateObject();
            cJSON_AddStringToObject(payload, "status", "complete");
            cJSON_AddStringToObject(payload, "message", "Game is already over.");
            char* result = cJSON_PrintUnformatted(payload);
            cJSON_Delete(payload);
            send_json_response(client_socket, 200, result);
            free(result);
            free_session_state(state);
            return;
        }

        char filepath[256];
        snprintf(filepath, sizeof(filepath), "data/numbered/count%d.txt", state->word_length);
        WordList* full_dict = load_word_list(filepath, state->word_length);
        if (!full_dict) {
            char* response = build_response_from_session(state, "Failed to load dictionary");
            send_json_response(client_socket, 500, response);
            free(response);
            free_session_state(state);
            return;
        }

        WordList* possibilities = clone_word_list(full_dict);
        if (!possibilities) {
            free_word_list(full_dict);
            char* response = build_response_from_session(state, "Failed to prepare possibilities");
            send_json_response(client_socket, 500, response);
            free(response);
            free_session_state(state);
            return;
        }

        size_t existing_guesses = state->guesses ? (size_t)cJSON_GetArraySize(state->guesses) : 0;
        for (size_t i = 0; i < existing_guesses; ++i) {
            cJSON* guess_item = cJSON_GetArrayItem(state->guesses, (int)i);
            if (!guess_item) continue;
            cJSON* word_json = cJSON_GetObjectItem(guess_item, "word");
            cJSON* feedback_json = cJSON_GetObjectItem(guess_item, "feedback");
            if (!cJSON_IsString(word_json) || !cJSON_IsArray(feedback_json)) {
                continue;
            }

            char guess_lower[64];
            lowercase_copy(word_json->valuestring, guess_lower, state->word_length);
            Feedback prior_feedback;
            fill_feedback_from_json(feedback_json, &prior_feedback, state->word_length);

            WordList* next = filter_word_list(possibilities, guess_lower, &prior_feedback);
            free_word_list(possibilities);
            possibilities = next;
            if (!possibilities) {
                break;
            }
        }

        if (!possibilities) {
            free_word_list(full_dict);
            free_session_state(state);
            send_bad_request(client_socket, "Unable to continue solver");
            return;
        }

        state->current_possibilities = possibilities->count;

        size_t total_guesses = existing_guesses;
        int guesses_added = 0;
        char* best_entropy_alloc = NULL;

        while (!state->is_game_over && total_guesses < (size_t)state->max_attempts && possibilities && possibilities->count > 0) {
            const char* next_guess = NULL;
            const char* first_choice = NULL;
            int len = possibilities->word_len;

            if (strcmp(solver_type, "fast") == 0) {
                if (total_guesses == 0) {
                    if (len == 3) first_choice = "are";
                    else if (len == 4) first_choice = "some";
                    else if (len == 5) first_choice = "salet";
                    else if (len == 6) first_choice = "course";
                    else if (len == 7) first_choice = "another";
                    else if (len == 8) first_choice = "children";
                    else if (len == 9) first_choice = "continues";
                    else if (len == 10) first_choice = "chattering";
                    if (first_choice && !is_word_in_list(possibilities, first_choice)) {
                        first_choice = NULL;
                    }
                }

                if (first_choice) {
                    next_guess = first_choice;
                } else {
                    int best_score = -1;
                    const char* best_word = NULL;
                    for (size_t i = 0; i < possibilities->count; ++i) {
                        int score = score_word(possibilities->words[i], len);
                        if (score > best_score) {
                            best_score = score;
                            best_word = possibilities->words[i];
                        }
                    }
                    next_guess = best_word ? best_word : possibilities->words[0];
                }
            } else {
                if (total_guesses == 0) {
                    if (len == 3) first_choice = "are";
                    else if (len == 4) first_choice = "some";
                    else if (len == 5) first_choice = "salet";
                    else if (len == 6) first_choice = "course";
                    else if (len == 7) first_choice = "another";
                    else if (len == 8) first_choice = "children";
                    else if (len == 9) first_choice = "continues";
                    else if (len == 10) first_choice = "chattering";
                    else {
                        best_entropy_alloc = get_best_entropy_word(len);
                        first_choice = best_entropy_alloc;
                    }
                    if (first_choice && len <= 10 && !is_word_in_list(possibilities, first_choice) && !is_word_in_list(full_dict, first_choice)) {
                        first_choice = NULL;
                    }
                }

                if (first_choice) {
                    next_guess = first_choice;
                } else {
                    next_guess = find_best_guess(full_dict, possibilities);
                }
            }

            if (!next_guess) {
                break;
            }

            char guess_lower[64];
            lowercase_copy(next_guess, guess_lower, state->word_length);
            Feedback feedback = get_feedback(guess_lower, state->secret_word, state->word_length);

            cJSON* guess_obj = cJSON_CreateObject();
            char guess_upper[64];
            uppercase_copy(guess_lower, guess_upper, state->word_length);
            cJSON_AddStringToObject(guess_obj, "word", guess_upper);
            cJSON* fb_array = cJSON_CreateArray();
            for (int i = 0; i < state->word_length; ++i) {
                const char* color = feedback.pattern[i] == GREEN ? "green" :
                                   (feedback.pattern[i] == YELLOW ? "yellow" : "grey");
                cJSON_AddItemToArray(fb_array, cJSON_CreateString(color));
            }
            cJSON_AddItemToObject(guess_obj, "feedback", fb_array);
            cJSON_AddItemToArray(state->guesses, guess_obj);

            total_guesses++;
            guesses_added++;

            WordList* next_poss = filter_word_list(possibilities, guess_lower, &feedback);
            free_word_list(possibilities);
            possibilities = next_poss;
            state->current_possibilities = possibilities ? possibilities->count : 0;

            state->is_won = is_solved(&feedback);
            state->is_game_over = state->is_won || (total_guesses >= (size_t)state->max_attempts);

            if (best_entropy_alloc) {
                free(best_entropy_alloc);
                best_entropy_alloc = NULL;
            }

            if (state->is_game_over) {
                break;
            }
        }

        if (best_entropy_alloc) {
            free(best_entropy_alloc);
            best_entropy_alloc = NULL;
        }

        int final_possibilities = possibilities ? (int)possibilities->count : 0;

        if (possibilities) {
            free_word_list(possibilities);
        }
        free_word_list(full_dict);

        bool db_updated = update_player_session(state->session_id, state->guesses, final_possibilities, state->is_won, state->is_game_over);
        if (!db_updated) {
            char* response = build_response_from_session(state, "Failed to update session");
            send_json_response(client_socket, 500, response);
            free(response);
            free_session_state(state);
            return;
        }

        int total_guess_count = (int)cJSON_GetArraySize(state->guesses);
        int remaining_attempts = state->max_attempts - total_guess_count;
        if (remaining_attempts < 0) remaining_attempts = 0;

        char message[256];
        if (guesses_added == 0) {
            snprintf(message, sizeof(message), "No solver moves available (type: %s).", solver_type);
        } else if (state->is_won) {
            snprintf(message, sizeof(message), "Solver %s solved the puzzle in %d added guess%s.",
                     solver_type, guesses_added, guesses_added == 1 ? "" : "es");
        } else if (state->is_game_over) {
            snprintf(message, sizeof(message), "Solver %s used all remaining attempts.", solver_type);
        } else {
            snprintf(message, sizeof(message), "Solver %s added %d guess%s.",
                     solver_type, guesses_added, guesses_added == 1 ? "" : "es");
        }

        cJSON* payload = cJSON_CreateObject();
        cJSON_AddStringToObject(payload, "status", "ok");
        cJSON_AddStringToObject(payload, "solver", solver_type);
        cJSON_AddNumberToObject(payload, "existingGuesses", (int)existing_guesses);
        cJSON_AddNumberToObject(payload, "addedGuesses", guesses_added);
        cJSON_AddBoolToObject(payload, "isWon", state->is_won);
        cJSON_AddBoolToObject(payload, "isGameOver", state->is_game_over);
        cJSON_AddNumberToObject(payload, "remainingAttempts", remaining_attempts);
        cJSON_AddNumberToObject(payload, "possibilities", final_possibilities);
        cJSON_AddStringToObject(payload, "message", message);

        char* result = cJSON_PrintUnformatted(payload);
        cJSON_Delete(payload);
        send_json_response(client_socket, 200, result);
        free(result);
        free_session_state(state);
        return;
    } else if (strcmp(path, "/api/suggestions") == 0) {
        if (strcmp(method, "GET") != 0) {
            send_method_not_allowed(client_socket);
            return;
        }

        char prefix[64] = "";
        int len = 5; // Default word length for suggestions

        if (query && *query) {
            char query_copy[512];
            strncpy(query_copy, query, sizeof(query_copy) - 1);
            query_copy[sizeof(query_copy) - 1] = '\0';
            char* saveptr = NULL;
            char* token = strtok_r(query_copy, "&", &saveptr);
            while (token) {
                if (strncmp(token, "prefix=", 7) == 0) {
                    strncpy(prefix, token + 7, sizeof(prefix) - 1);
                } else if (strncmp(token, "length=", 7) == 0) {
                    len = atoi(token + 7);
                }
                token = strtok_r(NULL, "&", &saveptr);
            }
        }

        url_decode(prefix);
        to_lowercase(prefix);

        WordList* suggestions = get_words_starting_with_prefix(prefix, len);
        char response[1024 * 20];
        size_t offset = 0;
        offset += snprintf(response + offset, sizeof(response) - offset, "[");
        if (suggestions && suggestions->count > 0) {
            size_t limit = suggestions->count > 100 ? 100 : suggestions->count;
            for (size_t i = 0; i < limit; ++i) {
                offset += snprintf(response + offset, sizeof(response) - offset,
                                   "\"%s\"%s",
                                   suggestions->words[i],
                                   (i < limit - 1) ? "," : "");
            }
        }
        offset += snprintf(response + offset, sizeof(response) - offset, "]");

        send_json_response(client_socket, 200, response);
        if (suggestions) {
            free_word_list(suggestions);
        }
        return;
    } else if (strcmp(path, "/api/join") == 0) {
        if (strcmp(method, "POST") != 0) {
            send_method_not_allowed(client_socket);
            return;
        }
        if (!body) {
            send_bad_request(client_socket, "Missing request body");
            return;
        }
        
        // Parse game_code from JSON body
        char game_code[9] = "";
        if (!parse_game_code(body, game_code, sizeof(game_code))) {
            send_bad_request(client_socket, "Missing or invalid game code");
            return;
        }

        // Get game info from database
        cJSON* game = get_game_by_code(game_code);
        if (!game) {
            send_bad_request(client_socket, "Game not found");
            return;
        }

        // Extract game parameters
        cJSON* wlen = cJSON_GetObjectItem(game, "word_length");
        cJSON* maxatt = cJSON_GetObjectItem(game, "max_attempts");
        
        if (!wlen || !maxatt) {
            cJSON_Delete(game);
            send_bad_request(client_socket, "Invalid game data");
            return;
        }

        int word_length = wlen->valueint;
        int max_attempts = maxatt->valueint;

        // Load dictionary to get possibilities count
        char filepath[256];
        snprintf(filepath, sizeof(filepath), "data/numbered/count%d.txt", word_length);
        WordList* dict = load_word_list(filepath, word_length);
        int possibilities = dict ? dict->count : 0;
        if (dict) free_word_list(dict);

        // Generate new session for this player
        char* session_id = generate_session_id();

        if (!create_player_session(session_id, game_code, possibilities)) {
            send_bad_request(client_socket, "Failed to create session");
            cJSON_Delete(game);
            free(session_id);
            return;
        }

        printf("Player joined game %s (session: %s)\n", game_code, session_id);
        fflush(stdout);

        // Build response directly (avoid database replication delay)
        cJSON* response_json = cJSON_CreateObject();
        cJSON_AddStringToObject(response_json, "sessionId", session_id);
        cJSON_AddStringToObject(response_json, "shareCode", game_code);
        cJSON_AddBoolToObject(response_json, "gameActive", true);
        cJSON_AddBoolToObject(response_json, "isGameOver", false);
        cJSON_AddBoolToObject(response_json, "isWon", false);
        cJSON_AddNumberToObject(response_json, "wordLength", word_length);
        cJSON_AddNumberToObject(response_json, "maxAttempts", max_attempts);
        cJSON_AddNumberToObject(response_json, "possibilities", possibilities);
        cJSON_AddStringToObject(response_json, "error", "");
        cJSON_AddItemToObject(response_json, "guesses", cJSON_CreateArray());
        cJSON_AddNullToObject(response_json, "secretWord");
        cJSON_AddNumberToObject(response_json, "remainingAttempts", max_attempts);
        
        char* response = cJSON_PrintUnformatted(response_json);
        cJSON_Delete(response_json);
        send_json_response(client_socket, 200, response);

        free(response);
        cJSON_Delete(game);
        free(session_id);
        return;
    } else if (strcmp(path, "/api/config") == 0) {
        if (strcmp(method, "GET") != 0) {
            send_method_not_allowed(client_socket);
            return;
        }

        char* port_env = getenv("PORT");
        int port = port_env ? atoi(port_env) : 8080;

        char config[128];
        snprintf(config, sizeof(config), "{\"port\":%d}", port);
        send_json_response(client_socket, 200, config);
        return;
    }

    send_not_found(client_socket);
}

// Function declarations
int simulate_solve_fast(const WordList* initial_list, const char* solution);
int simulate_solve_efficient(const WordList* word_list, const char* solution);

// Simulate fast solve and return tries

int simulate_solve_fast(const WordList* initial_list, const char* solution) {
    if (!initial_list || !solution) return -1;
    WordList* possibilities = malloc(sizeof(WordList));
    if (!possibilities) return -1;
    possibilities->words = malloc(initial_list->count * sizeof(char*));
    if (!possibilities->words) {
        free(possibilities);
        return -1;
    }
    for(size_t i = 0; i < initial_list->count; ++i) {
        possibilities->words[i] = my_strdup(initial_list->words[i]);
    }
    possibilities->count = initial_list->count;
    possibilities->capacity = initial_list->count;
    possibilities->word_len = initial_list->word_len;

    int guesses = 0;
    while (guesses < 10 && possibilities && possibilities->count > 0) {
        guesses++;
        const char* guess;
        /* Use the predetermined first guesses for the first automated guess */
        if (guesses == 1) {
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
                guess = find_best_starting_word(possibilities);
            }
        } else {
            /* If the user has already guessed, or it's not the first automated guess, use the fast starter. */
            guess = find_best_starting_word(possibilities);
        }

        Feedback feedback = get_feedback(guess, solution, possibilities->word_len);
        if (is_solved(&feedback)) {
            free_word_list(possibilities);
            return guesses;
        }
        WordList* next_possibilities = filter_word_list(possibilities, guess, &feedback);
        free_word_list(possibilities);
        possibilities = next_possibilities;
    }
    if (possibilities) free_word_list(possibilities);
    return -1; // Failed
}

// Function to get best starting word from best_entropy.txt for a given word length
char* get_best_entropy_word(int word_length) {
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

// Simulate efficient solve and return tries
int simulate_solve_efficient(const WordList* word_list, const char* solution) {
    if (!word_list || !solution) return -1;
    WordList* possibilities = malloc(sizeof(WordList));
    if (!possibilities) return -1;
    possibilities->words = malloc(word_list->count * sizeof(char*));
    if (!possibilities->words) {
        free(possibilities);
        return -1;
    }
    for(size_t i = 0; i < word_list->count; ++i) {
        possibilities->words[i] = my_strdup(word_list->words[i]);
    }
    possibilities->count = word_list->count;
    possibilities->capacity = word_list->count;
    possibilities->word_len = word_list->word_len;

    int guesses = 0;
    const char* guess;
    char* best_entropy_word = NULL;
    
    /* Use predetermined first guess for simulation */
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

    while (guesses < 10 && possibilities && possibilities->count > 0) {
        guesses++;
        if (guesses > 1) {
            guess = find_best_guess(word_list, possibilities);
        }
        Feedback feedback = get_feedback(guess, solution, possibilities->word_len);
        if (is_solved(&feedback)) {
            free_word_list(possibilities);
            if (best_entropy_word) free(best_entropy_word);
            return guesses;
        }
        WordList* next_possibilities = filter_word_list(possibilities, guess, &feedback);
        free_word_list(possibilities);
        possibilities = next_possibilities;
    }
    if (possibilities) free_word_list(possibilities);
    if (best_entropy_word) free(best_entropy_word);
    return -1;
}

// Thread function for handling client
void* handle_client(void* arg) {
    int client_socket = *(int*)arg;
    free(arg);

    // Get client IP for rate limiting
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(client_socket, (struct sockaddr*)&client_addr, &addr_len);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

    // Check rate limit
    if (!check_rate_limit(client_ip)) {
        send_json_response(client_socket, 429, "{\"error\":\"Too many requests\"}");
        close(client_socket);
        return NULL;
    }

    char buffer[16384];
    ssize_t bytes_read = 0;
    size_t expected_total = 0;
    char* header_end = NULL;

    // Read the request in full so POST bodies are available for parsing.
    while (bytes_read < (ssize_t)(sizeof(buffer) - 1)) {
        ssize_t chunk = recv(client_socket, buffer + bytes_read, sizeof(buffer) - 1 - bytes_read, 0);
        if (chunk <= 0) {
            break;
        }
        bytes_read += chunk;
        buffer[bytes_read] = '\0';

        if (!header_end) {
            header_end = strstr(buffer, "\r\n\r\n");
            if (header_end) {
                size_t header_size = (size_t)(header_end - buffer + 4);
                expected_total = header_size;
                char* content_length_header = strstr(buffer, "Content-Length:");
                if (content_length_header) {
                    content_length_header += strlen("Content-Length:");
                    while (*content_length_header == ' ' || *content_length_header == '\t') {
                        content_length_header++;
                    }
                    long content_length = strtol(content_length_header, NULL, 10);
                    if (content_length > 0) {
                        expected_total += (size_t)content_length;
                    }
                }
                if (expected_total == header_size) {
                    break;
                }
            }
        }

        if (expected_total && (size_t)bytes_read >= expected_total) {
            break;
        }
    }

    if (bytes_read <= 0) {
        close(client_socket);
        return NULL;
    }

    buffer[bytes_read] = '\0';
    handle_request(client_socket, buffer);
    close(client_socket);
    return NULL;
}

int main() {
    // Make stdout unbuffered so we see debug output immediately
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    
    // Initialize rate limiting
    memset(rate_limits, 0, sizeof(rate_limits));
    
    init_supabase();
    
    int port = 8080;
    char* port_env = getenv("PORT");
    if (port_env) {
        port = atoi(port_env);
    }
    
    char* bind_ip_env = getenv("BIND_IP");
    
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (bind_ip_env) {
        inet_pton(AF_INET, bind_ip_env, &server_addr.sin_addr);
    } else {
        server_addr.sin_addr.s_addr = INADDR_ANY;
    }

    bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_socket, 10);

    printf("Server running on port %d\n", port);
    fflush(stdout);

    while (1) {
        int* client_socket = malloc(sizeof(int));
        *client_socket = accept(server_socket, NULL, NULL);
        pthread_t thread;
        pthread_create(&thread, NULL, handle_client, client_socket);
        pthread_detach(thread);
    }

    close(server_socket);
    return 0;
}
