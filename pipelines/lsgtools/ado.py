
import sys
import requests
import base64

from . import log

this = sys.modules[__name__]
this.PR_API_BASE_URL = None
this.AUTH_HDRS = None


def init_defaults(org, project, repo_id, pr_id, token_type, access_token):
    this.PR_API_BASE_URL = pr_get_api_url(org, project, repo_id, pr_id)
    this.AUTH_HDRS = get_auth_headers(token_type, access_token)


def pr_get_api_url(org, project, repo_id, pr_id):
    if pr_id is None:
        # For creating or possibly attachig other things
        return f"https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo_id}/pullRequests"
    else:
        # For accessing
        return f"https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo_id}/pullRequests/{pr_id}"


def get_auth_headers(token_type, access_token):
    if token_type == "OAUTH":
        auth_headers = {
            "Authorization": f"Bearer {access_token}",
        }
    else:
        b64_token = base64.b64encode(f":{access_token}".encode("ascii")).decode("ascii")
        auth_headers = {
            "Authorization": f"Basic {b64_token}",
        }
    return auth_headers


def pr_add_comment(comment_text, pr_api_base_url=None, auth_headers=None):
    if pr_api_base_url is None:
        pr_api_base_url = this.PR_API_BASE_URL
    if auth_headers is None:
        auth_headers = this.AUTH_HDRS
    payload = {
        "comments": [
            {
                "parentCommentId": 0,
                "content": comment_text,
                "commentType": 1,
            }
        ],
        "status": 1
    }

    api_url = f"{pr_api_base_url}/threads?api-version=6.0"
    resp = requests.post(api_url, json=payload, headers=auth_headers)
    log.info(f"Comment API returned {resp.status_code}")
    if (resp.status_code != 200):
        log.err(resp.text)


def pr_get_commits(pr_api_base_url=None, auth_headers=None):
    if pr_api_base_url is None:
        pr_api_base_url = this.PR_API_BASE_URL
    if auth_headers is None:
        auth_headers = this.AUTH_HDRS

    commits_api_url = f"{pr_api_base_url}/commits?api-version=6.0"
    resp = requests.get(commits_api_url, headers=auth_headers)
    if (resp.status_code != 200):
        log.err(resp.text)
    return resp.json()


def pr_create(pr_api_base_url=None, auth_headers=None, payload=None):
    if pr_api_base_url is None:
        pr_api_base_url = this.PR_API_BASE_URL
    if auth_headers is None:
        auth_headers = this.AUTH_HDRS
    if payload is None:
        raise Exception("Payload cannot be empty")

    api_url = f"{pr_api_base_url}?api-version=6.0"

    log.debug(api_url)
    for i, k in enumerate(payload):
        log.debug("'{}': '{}'".format(k, payload[k]))

    resp = requests.post(api_url, json=payload, headers=auth_headers)
    log.info(f"PR creation returned {resp.status_code}")
    if (resp.status_code != 201):
        log.err(resp.text)
        return False

    # If needed, the response body can be parsed at this point,
    # to read out some newly created resource information.
    return True
