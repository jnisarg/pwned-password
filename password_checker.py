import requests
import hashlib

URL = "https://api.pwnedpasswords.com/range/"


def request_api_data(query_char):
    url = URL + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetched: {res.status_code}, please check api url or query.")
    else:
        return res


def get_password_leaks_count(hashes, hash_to_check):
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    hashes = (line.split(":") for line in response.text.splitlines())
    return get_password_leaks_count(hashes, tail)
