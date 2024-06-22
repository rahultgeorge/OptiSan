#include <stdio.h>
#include <string.h>

/*
 * Example workload to bypass ASAN's redzone (O0
Enter buffer:
ZZZZZZZZZZZZZZZZZZZZZZZZZ
Enter insert pos:
-65
Enter string to insert:
A
1 string to insert length
47 0 -65
ZZZZZZZZZZZZZZZZZZZZZZZZZ A
Authenticated successfully
 *
 */


typedef struct fauxAuthenticationDS {
    unsigned int isAuthenticated;
    unsigned int secondObject;
} authDataStruct;

void authenticateUser(struct fauxAuthenticationDS authData) {
    authData.isAuthenticated = 0;
    authData.secondObject = 0;
}


void vulnerableFunction() {
    authDataStruct authData;
    char unsafeBuffer[26];
    int insertPos = 0;
    char newStr[32];

    authenticateUser(authData);
    printf("Enter buffer:\n");
    //Unsafe op
    scanf("%s", unsafeBuffer);

    printf("Enter insert pos:\n");
    scanf("%d", &insertPos);

    //Unsafe op 2
    printf("Enter string to insert:\n");
    //Unsafe op 3
    scanf("%s", newStr);

    //Unsafe op 4 memory operation involving buffer
    printf("%d string to insert length\n", strlen(newStr));

    for (int i = 0; i < strlen(newStr); i++) {
        unsafeBuffer[insertPos + i] = newStr[i];
    }


    // Reachable uses of the victim/impacted objects
    printf("%u %u %d\n", authData.isAuthenticated, authData.secondObject, insertPos);
    printf("%s %s\n", unsafeBuffer, newStr);
    if (authData.isAuthenticated) {
        printf("Authenticated successfully\n");
    } else {
        printf("Failed to authenticate:%u \n", authData.isAuthenticated);
    }

}

int main() {
    vulnerableFunction();

    return 0;


}
