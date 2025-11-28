#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
// We actually want to implement the functions here, so we define extern as empty
#define extern
#include <security/pam_appl.h>

#include "shim/shared/message.h"
#include "shim/shared/buffered_fd.h"
#include "shim/shared/util.h"
#include "shim/lib/remote.h"

int PAM_SHIM_REQUEST_MAGIC = 0x50414d53;

// The header only forward declares pam_handle, we can fill in whatever we want.
struct pam_handle {
    void *pam_server_handle;
    struct pam_conv *conv;
    struct remote remote;
};

int pam_start_confdir(const char *service_name, const char *user,
                      const struct pam_conv *pam_conversation,
                      const char *confdir, pam_handle_t **pamh) {
    int result = PAM_SYSTEM_ERR;

    pam_handle_t *handle = malloc(sizeof(*handle));
    if (!handle) {
        return PAM_BUF_ERR;
    }

    handle->pam_server_handle = NULL; // Placeholder for actual server handle, will be filled later
    handle->conv = (struct pam_conv *)pam_conversation;
    if (!remote_init(&handle->remote)) {
        free(handle);
        return PAM_SYSTEM_ERR;
    }

    struct shim_request start_request = {
        .type = PAM_SHIM_REQUEST_START,
        .data.start = {
            .service_name = service_name,
            .user = user,
            .confdir = confdir,
        },
    };
    struct shim_response start_response = {0};

    if (!remote_send(&handle->remote, &start_request)) goto cleanup;

    if (!remote_receive(&handle->remote, &start_response) || start_response.type != PAM_SHIM_RESPONSE_HANDLE)
        goto cleanup;

    if (start_response.data.handle.pam_status != PAM_SUCCESS) {
        result = start_response.data.handle.pam_status;
        goto cleanup;
    }

    handle->pam_server_handle = start_response.data.handle.handle;
    *pamh = handle;
    return PAM_SUCCESS;

cleanup:
    shim_response_destroy(&start_response);
    remote_close(&handle->remote);
    free(handle);
    return result;
}

int pam_start(const char *service_name, const char *user,
              const struct pam_conv *pam_conversation,
              pam_handle_t **pamh) {
    return pam_start_confdir(service_name, user, pam_conversation, NULL, pamh);
}

int pam_end(pam_handle_t *pamh, int pam_status) {
    int result = PAM_SYSTEM_ERR;

    struct shim_request end_request = {
        .type = PAM_SHIM_REQUEST_END,
        .data.default_call = {
            .handle = pamh->pam_server_handle,
            .flags = pam_status,
        },
    };
    struct shim_response end_response = {0};

    if (!remote_send(&pamh->remote, &end_request)) goto cleanup;   

    if (!remote_receive(&pamh->remote, &end_response) || end_response.type != PAM_SHIM_RESPONSE_RESULT) goto cleanup;

    result = end_response.data.result.pam_status;

cleanup:
    shim_response_destroy(&end_response);
    remote_close(&pamh->remote);
    free(pamh);
    return result;
}

#define TRY(expr) if (!(expr)) return PAM_SYSTEM_ERR;
int pam_authenticate(pam_handle_t *pamh, int flags) {
    int result = PAM_SYSTEM_ERR;

    struct shim_request auth_request = {
        .type = PAM_SHIM_REQUEST_AUTHENTICATE,
        .data.default_call = {
            .handle = pamh->pam_server_handle,
            .flags = flags,
        },
    };
    struct shim_response auth_response = {0};

    TRY(remote_send(&pamh->remote, &auth_request));

    for (;;) {
        TRY(remote_receive(&pamh->remote, &auth_response));
        if (auth_response.type == PAM_SHIM_RESPONSE_CONVERSATION) {
            const struct pam_message **messages = auth_response.data.conversation.messages;
            size_t message_count = auth_response.data.conversation.message_count;

            struct pam_response *responses = NULL;
            int conv_result = pamh->conv->conv((int)message_count,
                                               messages,
                                               &responses,
                                               pamh->conv->appdata_ptr);

            if (conv_result != PAM_SUCCESS) {
                result = conv_result;
                free_responses(responses, message_count);
                break;
            }

            if (message_count > 0 && !responses) {
                result = PAM_BUF_ERR;
                break;
            }

            struct shim_request auth_response_request = {
                .type = PAM_SHIM_REQUEST_AUTHENTICATE_RESPONSE,
                .data.authenticate_response = {
                    .messages = responses,
                    .message_count = message_count,
                },
            };

            bool sent = remote_send(&pamh->remote, &auth_response_request);
            free_responses(responses, message_count);
            if (sent) {
                shim_response_destroy(&auth_response);
                continue;
            }
        } else if (auth_response.type == PAM_SHIM_RESPONSE_RESULT) {
            result = auth_response.data.result.pam_status;
        }

        break;
    }

    shim_response_destroy(&auth_response);
    return result;
}

static int pam_default_impl(pam_handle_t *pamh, int flags, enum shim_request_type req_type) {
    struct shim_request default_request = {
        .type = req_type,
        .data.default_call = {
            .handle = pamh->pam_server_handle,
            .flags = flags,
        },
    };
    TRY(remote_send(&pamh->remote, &default_request));

    struct shim_response default_response = {0};
    TRY(remote_receive(&pamh->remote, &default_response));
    if (default_response.type != PAM_SHIM_RESPONSE_RESULT) {
        shim_response_destroy(&default_response);
        return PAM_SYSTEM_ERR;
    }

    return default_response.data.result.pam_status;
}

const char *pam_strerror(pam_handle_t *pamh, int errnum)
{
    switch (errnum) {
    case PAM_SUCCESS:
      return "Success";
    case PAM_ABORT:
      return "Critical error - immediate abort";
    case PAM_OPEN_ERR:
      return "Failed to load module";
    case PAM_SYMBOL_ERR:
      return "Symbol not found";
    case PAM_SERVICE_ERR:
      return "Error in service module";
    case PAM_SYSTEM_ERR:
      return "System error";
    case PAM_BUF_ERR:
      return "Memory buffer error";
    case PAM_PERM_DENIED:
      return "Permission denied";
    case PAM_AUTH_ERR:
      return "Authentication failure";
    case PAM_CRED_INSUFFICIENT:
      return "Insufficient credentials to access authentication data";
    case PAM_AUTHINFO_UNAVAIL:
      return "Authentication service cannot retrieve authentication info";
    case PAM_USER_UNKNOWN:
      return "User not known to the underlying authentication module";
    case PAM_MAXTRIES:
      return "Have exhausted maximum number of retries for service";
    case PAM_NEW_AUTHTOK_REQD:
      return "Authentication token is no longer valid; new one required";
    case PAM_ACCT_EXPIRED:
      return "User account has expired";
    case PAM_SESSION_ERR:
      return "Cannot make/remove an entry for the specified session";
    case PAM_CRED_UNAVAIL:
      return "Authentication service cannot retrieve user credentials";
    case PAM_CRED_EXPIRED:
      return "User credentials expired";
    case PAM_CRED_ERR:
      return "Failure setting user credentials";
    case PAM_NO_MODULE_DATA:
      return "No module specific data is present";
    case PAM_BAD_ITEM:
      return "Bad item passed to pam_*_item()";
    case PAM_CONV_ERR:
      return "Conversation error";
    case PAM_AUTHTOK_ERR:
      return "Authentication token manipulation error";
    case PAM_AUTHTOK_RECOVERY_ERR:
      return "Authentication information cannot be recovered";
    case PAM_AUTHTOK_LOCK_BUSY:
      return "Authentication token lock busy";
    case PAM_AUTHTOK_DISABLE_AGING:
      return "Authentication token aging disabled";
    case PAM_TRY_AGAIN:
      return "Failed preliminary check by password service";
    case PAM_IGNORE:
      return "The return value should be ignored by PAM dispatch";
    case PAM_MODULE_UNKNOWN:
      return "Module is unknown";
    case PAM_AUTHTOK_EXPIRED:
      return "Authentication token expired";
    case PAM_CONV_AGAIN:
      return "Conversation is waiting for event";
    case PAM_INCOMPLETE:
      return "Application needs to call libpam again";
    }

    return "Unknown PAM error";
}

#define IMPL(fun, req_type) \
int fun(pam_handle_t *pamh, int flags) { \
    return pam_default_impl(pamh, flags, req_type); \
}
IMPL(pam_setcred, PAM_SHIM_REQUEST_SET_CRED)
IMPL(pam_acct_mgmt, PAM_SHIM_REQUEST_ACCT_MGMT)
IMPL(pam_open_session, PAM_SHIM_REQUEST_OPEN_SESSION)
IMPL(pam_close_session, PAM_SHIM_REQUEST_CLOSE_SESSION)
IMPL(pam_chauthtok, PAM_SHIM_REQUEST_CHAUTHTOK)
#undef IMPL
