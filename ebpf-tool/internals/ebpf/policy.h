#ifndef POLICY_H
#define POLICY_H

#ifndef in_file
#include <stddef.h>
#include <stdint.h>
#endif

#define MAX_STR_LEN 256
#define MAX_ELEMENTS 16 // Max paths, UIDs, or rules per block

typedef struct {
  uint32_t user_uid[MAX_ELEMENTS];
  uint32_t user_uid_count;
  char binary_paths[MAX_ELEMENTS][MAX_STR_LEN];
  uint32_t binary_paths_count;
} Permissions;

typedef struct {
  Permissions allow;
  uint32_t has_allow; // 1 if allow is set, 0 otherwise
} AccessControl;

typedef struct {
  char paths[MAX_ELEMENTS][MAX_STR_LEN];
  uint32_t paths_count;
  AccessControl read;
  AccessControl write;
} FilePolicy;

typedef struct {
  char paths[MAX_ELEMENTS][MAX_STR_LEN];
  uint32_t paths_count;
  AccessControl read;
  AccessControl write;
} DirectoryPolicy;

typedef struct {
  char name[MAX_STR_LEN];
  char description[MAX_STR_LEN];
  FilePolicy restricted_files[MAX_ELEMENTS];
  uint32_t restricted_files_count;
  DirectoryPolicy restricted_directories[MAX_ELEMENTS];
  uint32_t restricted_directories_count;
} Policy;

#endif // POLICY_H
