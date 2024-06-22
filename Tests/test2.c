#include <stdio.h>
#include <string.h>

/*2nd test case
 * Unsafe operation which can bypass caller's stack data
 *ZZZZZZZZZZZZZZZZZZZZZZZZZ

 */


typedef struct fauxAuthenticationDS {
    unsigned int isAuthenticated;
    unsigned int secondObject;
} authDataStruct;

void unsafeNetworkFunction() {
    char unsafeBuffer[26];
    int insertPos = 0;
    char newStr[32];

    printf("Enter buffer:\n");
    //Unsafe op 1
    scanf("%s", unsafeBuffer);

    printf("Enter insert pos:\n");
    scanf("%d", &insertPos);

    printf("Enter string to insert:\n");
    //Unsafe op 2
    scanf("%s", newStr);

    //Unsafe op 3 memory operation involving buffer
    printf("%d string to insert length\n", strlen(newStr));

    for (int i = 0; i < strlen(newStr); i++) {
        unsafeBuffer[insertPos + i] = newStr[i];
    }

    printf("%s %s\n", unsafeBuffer, newStr);


}


unsigned int authenticateUser() {
    struct fauxAuthenticationDS authData;
    //Failed authentication
    authData.isAuthenticated = 0;
    authData.secondObject = 0;
    unsafeNetworkFunction();
    printf("\t Auth data:%u %u\n",authData.isAuthenticated,authData.secondObject );
    return authData.isAuthenticated;
}


int main() {
    unsigned int isAuthenticated = authenticateUser();
    if (isAuthenticated) {
        printf("Authenticated successfully\n");
    } else {
        printf("Failed to authenticate:%u \n", isAuthenticated);
    }
    return 0;


}
