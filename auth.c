#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <security/pam_appl.h>

#define PAM_SERVICE_NAME "pamtest"
typedef struct {
	char *username;
	char *password;
} creds_t;

static int s_pam_talker(int n, const struct pam_message **m, struct pam_response **r, void *u)
{
	if (!m || !r || !u) return PAM_CONV_ERR;

	creds_t *creds = (creds_t*)u;

	struct pam_response *res = calloc(n, sizeof(struct pam_response));
	if (!res) return PAM_CONV_ERR;

	int i;
	for (i = 0; i < n; i++) {
		res[i].resp_retcode = 0;
		/* the only heuristic that works:
		     PAM_PROMPT_ECHO_ON  = asking for username
		     PAM_PROMPT_ECHO_OFF = asking for password
		 */
		switch (m[i]->msg_style) {
		case PAM_PROMPT_ECHO_ON:
			res[i].resp = strdup(creds->username);
			break;

		case PAM_PROMPT_ECHO_OFF:
			res[i].resp = strdup(creds->password);
			break;

		default:
			free(res);
			return PAM_CONV_ERR;
		}
	}

	*r = res;
	return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
	int rc;
	pam_handle_t *pam = NULL;
	creds_t creds = {
		.username = "authuser",
		.password = "secret!",
	};
	struct pam_conv convo = {
		s_pam_talker,
		(void*)(&creds),
	};

	rc = pam_start(PAM_SERVICE_NAME, creds.username, &convo, &pam);
	assert(rc == PAM_SUCCESS);

	rc = pam_authenticate(pam, PAM_DISALLOW_NULL_AUTHTOK);
	if (rc != PAM_SUCCESS) {
		fprintf(stderr, "authn failed: %s\n", pam_strerror(pam, errno));
		pam_end(pam, PAM_SUCCESS);
		return 1;
	}

	rc = pam_acct_mgmt(pam, PAM_DISALLOW_NULL_AUTHTOK);
	if (rc != PAM_SUCCESS) {
		fprintf(stderr, "authz failed: %s\n", pam_strerror(pam, errno));
		pam_end(pam, PAM_SUCCESS);
		return 2;
	}

	printf("OK!\n");
	pam_end(pam, PAM_SUCCESS);
	return 0;
}
