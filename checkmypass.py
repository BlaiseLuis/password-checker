from builtins import RuntimeError, print
import requests
import hashlib
import sys

# Get approval from the server and persmission to input and compare hashes


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check api and try again')
    else:
        return res


def number_of_leaks(hashes, hash):
    # splitting hash into tail and count
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash:
            return count
    return 0


def pwned_api_check(password):
    shapass = (hashlib.sha1(password.encode('utf-8')))  # encoding
    shaword = (shapass.hexdigest().upper())
    head_5, tail = shaword[:5], shaword[5:]  # splitting into head and tail
    response = request_api_data(head_5)  # comparing with hashes on server
    return number_of_leaks(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f' Your password was found {count} times. You should consider changing your password')
        else:
            print(f'Your password hasn\'t been hacked before. Carry on!')


if __name__ == '__main__':
    main(sys.argv[1:])
